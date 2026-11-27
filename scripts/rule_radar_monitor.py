#!/usr/bin/env python3
"""DMEvia Rule Radar candidate monitor.

This first release polls official Federal Register CMS/FDA documents and FDA
medical-product safety RSS feeds. It creates unpublished Pending Review
records only. It never approves or publishes alerts.

Each official source is isolated: an unavailable feed or agency endpoint is
reported without preventing the remaining sources from being checked.
Individual source-page verification failures also hold only that candidate.

Important: generated summaries are structured extracts, not legal advice or
independent legal interpretation. The administrator must verify every item.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
RPC_URL = f"{SUPABASE_URL}/rest/v1/rpc/submit_verified_rule_radar_for_review"
HEADERS = {
    "apikey": SERVICE_ROLE_KEY,
    "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
    "Content-Type": "application/json",
}
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "DMEvia-RuleRadar/1.0 (official-source monitor)"})

DME_TERMS = re.compile(
    r"\b(durable medical equipment|DMEPOS|prosthe(tic|ses)|orthotic|"
    r"wheelchair|power mobility|mobility device|oxygen equipment|oxygen concentrator|"
    r"CPAP|PAP device|continuous glucose monitor|glucose monitor|CGM|"
    r"home medical equipment|DME supplier|medical supply supplier|"
    r"enteral nutrition|infusion pump|hospital bed|negative pressure wound therapy|"
    r"HCPCS|surgical dressings|diabetic shoe|therapeutic shoe)\b", re.I
)
ACTION_TERMS = re.compile(
    r"\b(rule|proposed|final|notice|guidance|coverage|payment|reimbursement|"
    r"enrollment|prior authorization|prior-authorization|recall|safety|"
    r"billing|supplier|fee schedule|transmittal|policy|medicaid|medicare)\b", re.I
)
FDA_FEEDS = [
    ("FDA Recalls and Safety Alerts", "https://www.fda.gov/AboutFDA/ContactFDA/StayInformed/RSSFeeds/Recalls/rss.xml"),
    ("FDA MedWatch Safety Alerts", "https://www.fda.gov/about-fda/contact-fda/stay-informed/rss-feeds/medwatch/rss.xml"),
]
FEDERAL_REGISTER_AGENCIES = ["centers-for-medicare-medicaid-services", "food-and-drug-administration"]
TOTAL_SOURCE_ENDPOINTS = len(FDA_FEEDS) + len(FEDERAL_REGISTER_AGENCIES)


def clean(value: str | None) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def date_only(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        try:
            return parsedate_to_datetime(value).date().isoformat()
        except Exception:
            return None


def fingerprint(url: str, title: str) -> str:
    return hashlib.sha256((url.strip().lower() + "\n" + title.strip().lower()).encode()).hexdigest()


def is_relevant(title: str, abstract: str) -> bool:
    text = f"{title} {abstract}"
    return bool(DME_TERMS.search(text) and ACTION_TERMS.search(text))


def fetch_text(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Source URL must use HTTPS.")
    response = SESSION.get(url, timeout=30)
    response.raise_for_status()
    return clean(response.text)


def impact_for(title: str, abstract: str) -> str:
    text = f"{title} {abstract}".lower()
    if any(x in text for x in ["recall", "safety alert", "immediate", "termination", "fraud"]):
        return "high"
    if any(x in text for x in ["final rule", "effective date", "payment", "fee schedule", "prior authorization"]):
        return "high"
    return "medium"


def build_payload(source_name: str, url: str, title: str, abstract: str,
                  published: str | None, effective: str | None, agency: str,
                  source_excerpt: str, fp: str) -> dict:
    title_clean = clean(title)[:210]
    excerpt = clean(source_excerpt)[:1800]
    abstract_clean = clean(abstract)[:5000]
    slug_base = re.sub(r"[^a-z0-9]+", "-", title_clean.lower()).strip("-")[:145] or "regulatory-update"
    slug = f"{slug_base}-{fp[:10]}"
    summary = abstract_clean[:900] or excerpt[:900] or "Official-source update identified for administrator review."
    body = (
        "AUTOMATED SOURCE EXTRACT — ADMINISTRATOR VERIFICATION REQUIRED\n\n"
        f"Official source: {source_name}\n"
        f"Agency: {agency}\n"
        f"Publication date: {published or 'Not identified in source metadata'}\n"
        f"Effective date: {effective or 'Not identified in source metadata'}\n\n"
        "What the official source says (extract):\n"
        f"{abstract_clean or excerpt}\n\n"
        "DMEvia relevance signal: the source title/abstract contains one or more DME-related terms. "
        "This automated match does not establish that every DME supplier is affected. "
        "Confirm scope, applicability, dates, affected products/HCPCS and jurisdiction against "
        "the complete official document before approval.\n\n"
        f"Source record: {url}"
    )
    return {
        "source_name": source_name,
        "source_url": url,
        "source_title": title_clean,
        "source_excerpt": excerpt[:1200],
        "source_fingerprint": fp,
        "title": title_clean,
        "slug": slug,
        "category": agency,
        "summary": summary,
        "body": body,
        "source_published_at": published,
        "effective_date": effective,
        "impact_level": impact_for(title_clean, abstract_clean),
        "jurisdiction": "Federal",
        "affected_products": [],
        "recommended_action": "Open the official source, confirm whether DMEPOS suppliers are affected, document the applicable dates and requirements, and obtain administrator review before publication.",
        "update_type": "recall" if "recall" in title_clean.lower() else "regulatory_update",
    }


def submit(payload: dict) -> None:
    response = SESSION.post(RPC_URL, headers=HEADERS, json={"p_payload": payload}, timeout=30)
    if response.status_code >= 400:
        # Do not print request headers or environment values.
        raise RuntimeError(f"Supabase review submission failed ({response.status_code}): {response.text[:700]}")
    print(f"Submitted to Pending Review: {payload['title']} [{response.status_code}]")


def federal_register_candidates(since: str, source_errors: list[str]):
    for agency in FEDERAL_REGISTER_AGENCIES:
        source_label = f"Federal Register — {agency}"
        try:
            params = [
                ("conditions[agencies][]", agency),
                ("conditions[publication_date][gte]", since),
                ("per_page", "100"),
                ("order", "newest"),
            ]
            response = SESSION.get(
                "https://www.federalregister.gov/api/v1/documents.json",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            docs = response.json().get("results", [])
            for doc in docs:
                title = clean(doc.get("title"))
                abstract = clean(doc.get("abstract"))
                url = doc.get("html_url") or ""
                if not url.startswith("https://www.federalregister.gov/") or not is_relevant(title, abstract):
                    continue
                yield (
                    "Federal Register — " + agency.replace("-", " ").title(),
                    url, title, abstract, date_only(doc.get("publication_date")),
                    date_only(doc.get("effective_on")), agency.replace("-", " ").title(), abstract,
                )
        except Exception as exc:
            message = f"{source_label}: {type(exc).__name__}: {str(exc)[:300]}"
            source_errors.append(message)
            print(f"WARNING: {message}", file=sys.stderr)


def fda_rss_candidates(source_errors: list[str]):
    for feed_name, feed_url in FDA_FEEDS:
        try:
            response = SESSION.get(feed_url, timeout=30)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            for item in root.findall(".//item"):
                title = clean(item.findtext("title"))
                url = clean(item.findtext("link"))
                description = clean(item.findtext("description"))
                published = date_only(item.findtext("pubDate"))
                if not url.startswith("https://www.fda.gov/") or not is_relevant(title, description):
                    continue
                yield (
                    feed_name, url, title, description, published, None,
                    "U.S. Food and Drug Administration", description,
                )
        except Exception as exc:
            message = f"{feed_name}: {type(exc).__name__}: {str(exc)[:300]}"
            source_errors.append(message)
            print(f"WARNING: {message}", file=sys.stderr)


def main():
    since = (datetime.now(timezone.utc).date() - timedelta(days=10)).isoformat()
    candidates = []
    source_errors: list[str] = []

    # Each endpoint catches its own errors, so one unavailable source cannot
    # prevent results from the other official sources from being collected.
    candidates.extend(federal_register_candidates(since, source_errors))
    candidates.extend(fda_rss_candidates(source_errors))

    seen = set()
    submitted = 0
    held = 0
    submission_errors = 0

    for source_name, url, title, abstract, published, effective, agency, excerpt in candidates:
        fp = fingerprint(url, title)
        if fp in seen:
            continue
        seen.add(fp)

        # Verify each official record independently. A dead or blocked page
        # holds only that candidate; it must not stop the remaining checks.
        try:
            page_text = fetch_text(url)
            evidence = clean(excerpt)
            if len(evidence) < 40 or evidence[:160].lower() not in page_text.lower():
                print(f"Held (source excerpt could not be confirmed on page): {title}")
                held += 1
                continue
        except Exception as exc:
            print(
                f"WARNING: Held candidate because official page verification failed "
                f"({type(exc).__name__}: {str(exc)[:250]}): {title}",
                file=sys.stderr,
            )
            held += 1
            continue

        payload = build_payload(source_name, url, title, abstract, published, effective, agency, evidence, fp)
        try:
            submit(payload)
            submitted += 1
        except Exception as exc:
            submission_errors += 1
            print(f"ERROR submitting {title}: {exc}", file=sys.stderr)

    print(
        f"Monitor complete. Candidates examined: {len(seen)}; "
        f"submitted to Pending Review: {submitted}; held: {held}; "
        f"submission errors: {submission_errors}; source endpoint errors: {len(source_errors)}."
    )
    if source_errors:
        print("Source errors (monitor continued):")
        for error in source_errors:
            print(f" - {error}")
    print("No alert was approved or published by this workflow.")

    # A partial outage is a degraded but useful run. Fail only when every
    # configured source endpoint failed, making a total monitoring outage clear.
    if len(source_errors) >= TOTAL_SOURCE_ENDPOINTS:
        raise SystemExit("All configured official source endpoints failed; no reliable monitoring was possible.")


if __name__ == "__main__":
    main()
