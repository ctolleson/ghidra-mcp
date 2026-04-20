#!/usr/bin/env python3
"""FCC ID Lookup MCP Server.

Looks up FCC IDs against public FCC equipment authorization sources
(fccid.io, fcc.report) and returns device metadata useful for firmware
reverse engineering: manufacturer, product, documents, and candidate MCU
identifiers matched against a local chip database.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP

from chip_db import CHIP_DB, match_chips_in_text
from pdf_ocr import extract_pdf_text

# ── Configuration ──────────────────────────────────────────────────────

USER_AGENT = "fcc-id-mcp/1.0 (firmware RE tool; +https://github.com/)"
CACHE_TTL_DAYS = 7
RATE_LIMIT_SECONDS = 1.0
HTTP_TIMEOUT = 30.0
MAX_REDIRECTS = 5

BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_DB_PATH = CACHE_DIR / "fcc_cache.db"
DOWNLOADS_DIR = BASE_DIR / "downloads"

mcp = FastMCP("FCCIDLookup")

_last_request_time: float = 0.0
_rate_lock = asyncio.Lock()


# ── FCC ID Normalization ──────────────────────────────────────────────


def normalize_fcc_id(raw: str) -> dict[str, str]:
    """Normalize an FCC ID string.

    Grantee code is 3 chars if it starts with a letter, 5 chars if it starts
    with a digit. Product code is everything after.
    """
    if not raw:
        raise ValueError("FCC ID is empty")
    stripped = re.sub(r"(?i)^FCC\s*ID\s*[:\-]?\s*", "", raw.strip())
    compact = re.sub(r"[^A-Za-z0-9]", "", stripped).upper()
    if len(compact) < 4:
        raise ValueError(f"FCC ID too short: {raw!r}")

    grantee_len = 5 if compact[0].isdigit() else 3
    if len(compact) <= grantee_len:
        raise ValueError(f"FCC ID missing product code: {raw!r}")

    grantee = compact[:grantee_len]
    product = compact[grantee_len:]
    return {
        "normalized": f"{grantee}-{product}",
        "compact": compact,
        "grantee_code": grantee,
        "product_code": product,
    }


# ── Cache ─────────────────────────────────────────────────────────────


def _init_cache() -> sqlite3.Connection:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fcc_lookups (
            fcc_id TEXT PRIMARY KEY,
            result_json TEXT NOT NULL,
            source TEXT NOT NULL,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _cache_get(fcc_id: str) -> dict[str, Any] | None:
    conn = _init_cache()
    try:
        row = conn.execute(
            "SELECT result_json, expires_at FROM fcc_lookups WHERE fcc_id = ?",
            (fcc_id,),
        ).fetchone()
        if not row:
            return None
        result_json, expires_at = row
        if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
            return None
        return json.loads(result_json)
    finally:
        conn.close()


def _cache_put(fcc_id: str, result: dict[str, Any], source: str) -> None:
    conn = _init_cache()
    try:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=CACHE_TTL_DAYS)
        conn.execute(
            """
            INSERT OR REPLACE INTO fcc_lookups
                (fcc_id, result_json, source, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (fcc_id, json.dumps(result), source, now.isoformat(), expires.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


# ── HTTP with Rate Limiting ───────────────────────────────────────────


async def _rate_limited_get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    global _last_request_time
    async with _rate_lock:
        elapsed = time.monotonic() - _last_request_time
        if elapsed < RATE_LIMIT_SECONDS:
            await asyncio.sleep(RATE_LIMIT_SECONDS - elapsed)
        _last_request_time = time.monotonic()
    return await client.get(url, follow_redirects=True)


def _new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        timeout=HTTP_TIMEOUT,
        max_redirects=MAX_REDIRECTS,
    )


# ── Parsing Helpers ───────────────────────────────────────────────────


def _clean_text(s: str | None) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def _normalize_date(raw: str) -> str:
    """Normalize a date string to YYYY-MM-DD. Accepts YYYY-MM-DD, YYYY/MM/DD,
    MM/DD/YYYY, MM-DD-YYYY. Returns '' if the input is unparseable."""
    if not raw:
        return ""
    s = raw.strip()
    m = re.match(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$", s)
    if m:
        y, mo, d = m.groups()
        return f"{y}-{int(mo):02d}-{int(d):02d}"
    m = re.match(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{2,4})$", s)
    if m:
        mo, d, y = m.groups()
        if len(y) == 2:
            y = "20" + y
        return f"{y}-{int(mo):02d}-{int(d):02d}"
    return ""


def _absolute_url(base: str, href: str) -> str:
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("/"):
        m = re.match(r"^(https?://[^/]+)", base)
        return (m.group(1) if m else "") + href
    return base.rstrip("/") + "/" + href


# Confidential/available status heuristics for common document labels.
_CONFIDENTIAL_HINTS = {"schematic", "block diagram", "parts list", "bill of material",
                       "operational description", "operation description",
                       "theory of operation"}


def _doc_status(label: str, has_link: bool) -> str:
    lower = label.lower()
    if not has_link:
        return "unavailable"
    if any(hint in lower for hint in _CONFIDENTIAL_HINTS):
        return "possibly_confidential"
    return "available"


# ── fccid.io Scraper ──────────────────────────────────────────────────


async def _scrape_fccid_io(client: httpx.AsyncClient, fcc_id: str) -> dict[str, Any] | None:
    url = f"https://fccid.io/{fcc_id}"
    resp = await _rate_limited_get(client, url)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    html = resp.text
    if "Page Not Found" in html or "no record of an FCC ID" in html.lower():
        return None

    soup = BeautifulSoup(html, "lxml")
    title = _clean_text(soup.title.string if soup.title else "")
    page_text = soup.get_text(" ", strip=True).replace("\xa0", " ")

    # Grantee + product: fccid.io's og:title is
    #   "FCC ID {fcc_id} {product description} by {grantee name}"
    grantee_name = ""
    product_description = ""
    og_title = soup.find("meta", attrs={"property": "og:title"}) \
        or soup.find("meta", attrs={"name": "twitter:title"})
    og_title_text = _clean_text(og_title["content"]) if og_title and og_title.get("content") else ""
    m = re.match(r"FCC ID\s+\S+\s+(.+?)\s+by\s+(.+)$", og_title_text, re.IGNORECASE)
    if m:
        product_description = m.group(1).strip()
        grantee_name = m.group(2).strip()

    # Fallback for grantee name: first link like https://fccid.io/{GRANTEE_CODE}
    if not grantee_name:
        grantee_pattern = re.compile(r"^https?://fccid\.io/[A-Z0-9]{3,5}/?$", re.IGNORECASE)
        for a in soup.find_all("a", href=True):
            if grantee_pattern.match(a["href"]):
                txt = _clean_text(a.get_text())
                if txt and txt.upper() != a["href"].rstrip("/").rsplit("/", 1)[-1].upper():
                    grantee_name = txt
                    break

    # Fallback for product description: parse <title>.
    if not product_description and title:
        m = re.match(r"(.+?)\s+FCC\s*ID\s+\S+", title, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            if grantee_name:
                # Strip leading grantee prefix if present (full, comma-split, or first word).
                for prefix in (grantee_name, grantee_name.split(",")[0], grantee_name.split(" ")[0]):
                    if prefix and candidate.lower().startswith(prefix.lower()):
                        candidate = candidate[len(prefix):].strip(" -—.,")
                        break
            product_description = candidate

    # Dates: prefer "Date of Grant" / "Application Dated" phrases (nbsp-separated on fccid.io).
    application_date = ""
    approval_date = ""
    m = re.search(r"Application\s*Dated[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})",
                  page_text, re.IGNORECASE)
    if m:
        application_date = _normalize_date(m.group(1))
    m = re.search(r"Date\s*of\s*Grant[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})",
                  page_text, re.IGNORECASE)
    if m:
        approval_date = _normalize_date(m.group(1))

    # Fallback application date: the "Applications" table header is "App # | Purpose | Date | Unique ID".
    if not application_date:
        for tbl in soup.find_all("table"):
            head = tbl.find("tr")
            if not head:
                continue
            htxt = head.get_text(" | ", strip=True)
            if re.search(r"\bApp\s*#\b", htxt) and "Purpose" in htxt and "Date" in htxt:
                rows = tbl.find_all("tr")
                if len(rows) > 1:
                    for cell in rows[1].find_all(["td", "th"]):
                        m2 = re.search(r"(\d{4}-\d{2}-\d{2})", cell.get_text(strip=True))
                        if m2:
                            application_date = m2.group(1)
                            break
                break

    # Frequency ranges: the "Frequency Range | Power Output | Rule Parts | Line Entry" table is authoritative.
    freq_ranges: list[str] = []
    for tbl in soup.find_all("table"):
        head = tbl.find("tr")
        if not head:
            continue
        htxt = head.get_text(" | ", strip=True)
        if re.search(r"\bFrequency\s+Range\b", htxt, re.IGNORECASE) and "Line Entry" in htxt:
            for row in tbl.find_all("tr")[1:]:
                cells = [_clean_text(c.get_text()) for c in row.find_all(["td", "th"])]
                if cells and cells[0]:
                    freq_ranges.append(cells[0])
            break

    # Fallback: regex for GHz/MHz ranges in page text.
    if not freq_ranges:
        for match in re.findall(
            r"(\d{1,5}(?:\.\d+)?\s*[-–]\s*\d{1,5}(?:\.\d+)?\s*(?:MHz|GHz))",
            page_text,
        ):
            candidate = _clean_text(match)
            if candidate not in freq_ranges:
                freq_ranges.append(candidate)
    freq_ranges = freq_ranges[:10]

    # Documents: walk the "Document | Type | Submitted | Available" table so
    # we can also report confidential-but-listed entries (rows with no <a>).
    documents: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    seen_names: set[str] = set()
    doc_link_pattern = re.compile(
        rf"/{re.escape(fcc_id)}/([^/?#]+)/([^/?#]+)", re.IGNORECASE
    )

    for tbl in soup.find_all("table"):
        head = tbl.find("tr")
        if not head:
            continue
        header_cells = [_clean_text(c.get_text()) for c in head.find_all(["td", "th"])]
        header_txt = " | ".join(header_cells)
        if "Document" not in header_txt or "Type" not in header_txt:
            continue

        for row in tbl.find_all("tr")[1:]:
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            name_cell = cells[0]
            type_cell = cells[1]
            anchor = name_cell.find("a", href=True)

            name = _clean_text(name_cell.get_text())
            type_label = _clean_text(type_cell.get_text())
            if not name:
                continue

            if anchor:
                href = anchor["href"]
                abs_url = _absolute_url(url, href)
                m = doc_link_pattern.search(href)
                category = m.group(1).replace("-", " ") if m else (type_label or name)
                if abs_url in seen_urls:
                    continue
                seen_urls.add(abs_url)
                seen_names.add(name.lower())
                documents.append({
                    "type": name,
                    "category": category,
                    "url": abs_url,
                    "status": "available",
                })
            else:
                key = name.lower()
                if key in seen_names:
                    continue
                seen_names.add(key)
                documents.append({
                    "type": name,
                    "category": type_label or name,
                    "url": "",
                    "status": "confidential_no_public_copy",
                })

    # Fallback: if no document table was found, fall back to anchor discovery.
    if not documents:
        for a in soup.find_all("a", href=True):
            href = a["href"]
            m = doc_link_pattern.search(href)
            if not m:
                continue
            abs_url = _absolute_url(url, href)
            if abs_url in seen_urls:
                continue
            seen_urls.add(abs_url)
            category = m.group(1).replace("-", " ")
            label = _clean_text(a.get_text()) or category
            documents.append({
                "type": label,
                "category": category,
                "url": abs_url,
                "status": "available",
            })

    return {
        "grantee_name": grantee_name,
        "product_description": product_description,
        "application_date": application_date,
        "approval_date": approval_date,
        "frequency_ranges": freq_ranges,
        "documents": documents,
        "page_title": title,
        "page_url": url,
    }


# ── fcc.report Scraper (Fallback) ─────────────────────────────────────


async def _scrape_fcc_report(client: httpx.AsyncClient, fcc_id: str) -> dict[str, Any] | None:
    url = f"https://fcc.report/FCC-ID/{fcc_id}"
    resp = await _rate_limited_get(client, url)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    html = resp.text
    if "not found" in html.lower()[:4000]:
        return None

    soup = BeautifulSoup(html, "lxml")

    title = _clean_text(soup.title.string if soup.title else "")
    h1 = _clean_text(soup.h1.get_text() if soup.h1 else "")

    grantee_name = ""
    product_description = ""
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        product_description = _clean_text(meta_desc["content"])

    # Documents: link patterns on fcc.report typically point at PDF exhibits.
    documents: list[dict[str, Any]] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if not href.lower().endswith(".pdf"):
            continue
        label = _clean_text(a.get_text()) or href.rsplit("/", 1)[-1]
        documents.append({
            "type": label,
            "url": _absolute_url(url, href),
            "status": _doc_status(label, True),
        })

    if not documents and not product_description:
        return None

    return {
        "grantee_name": grantee_name,
        "product_description": product_description,
        "application_date": "",
        "approval_date": "",
        "frequency_ranges": [],
        "documents": documents,
        "page_title": title,
        "page_url": url,
    }


# ── Top-level lookup pipeline ─────────────────────────────────────────


async def _do_lookup(fcc_id_norm: dict[str, str]) -> dict[str, Any]:
    normalized = fcc_id_norm["normalized"]

    cached = _cache_get(normalized)
    if cached:
        cached["cache_hit"] = True
        return cached

    errors: list[str] = []
    result: dict[str, Any] | None = None
    source = ""

    async with _new_client() as client:
        for source_name, scraper in (
            ("fccid.io", _scrape_fccid_io),
            ("fcc.report", _scrape_fcc_report),
        ):
            try:
                result = await scraper(client, normalized)
                if result:
                    source = source_name
                    break
            except httpx.HTTPError as exc:
                errors.append(f"{source_name}: {exc}")
            except Exception as exc:  # defensive: scraping can fail on HTML changes
                errors.append(f"{source_name}: {type(exc).__name__}: {exc}")

    if not result:
        return {
            "fcc_id": normalized,
            "grantee_code": fcc_id_norm["grantee_code"],
            "product_code": fcc_id_norm["product_code"],
            "found": False,
            "errors": errors or ["no data at any source"],
            "cache_hit": False,
        }

    parts = [p for p in (result.get("grantee_name"), result.get("product_description")) if p]
    summary = " — ".join(parts) if parts else "FCC filing found with limited metadata."
    if result.get("approval_date"):
        summary += f" Approved {result['approval_date']}."
    if result.get("frequency_ranges"):
        summary += f" Bands: {', '.join(result['frequency_ranges'][:3])}."

    payload = {
        "fcc_id": normalized,
        "grantee_code": fcc_id_norm["grantee_code"],
        "product_code": fcc_id_norm["product_code"],
        "grantee_name": result.get("grantee_name", ""),
        "product_description": result.get("product_description", ""),
        "application_date": result.get("application_date", ""),
        "approval_date": result.get("approval_date", ""),
        "frequency_ranges": result.get("frequency_ranges", []),
        "source": source,
        "source_url": result.get("page_url", ""),
        "summary": summary,
        "documents": result.get("documents", []),
        "found": True,
        "cache_hit": False,
    }

    _cache_put(normalized, payload, source)
    return payload


# ── MCP Tools ─────────────────────────────────────────────────────────


@mcp.tool()
async def lookup_fcc_id(fcc_id: str, include_documents: bool = True) -> str:
    """Look up an FCC ID and return device metadata: manufacturer, product,
    approval dates, frequency bands, and available filing documents.

    Accepts hyphenated or compact formats (e.g. '2AEMI-HNGW05' or
    '2AEMIHNGW05'). Results are cached for 7 days."""
    try:
        norm = normalize_fcc_id(fcc_id)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})

    payload = await _do_lookup(norm)

    if not include_documents and "documents" in payload:
        doc_count = len(payload["documents"])
        payload = {**payload}
        payload.pop("documents", None)
        payload["document_count"] = doc_count

    return json.dumps(payload, indent=2)


# Document categories ordered by how likely they are to yield an MCU hit
# cheaply. Block Diagrams are tiny PDFs with explicit chip labels; OpDesc is
# narrative prose that usually names the main IC; Internal Photos are image
# PDFs (need OCR); Test Reports are huge but occasionally embed chip names.
_OCR_DOC_PRIORITY: list[tuple[str, list[str]]] = [
    ("block_diagram", ["block diagram"]),
    ("operational_description", ["operational description", "operation description"]),
    ("internal_photos", ["internal photos", "internal photo"]),
    ("test_report", ["test report"]),
]


def _match_doc(documents: list[dict[str, Any]], category_keywords: list[str]) -> dict[str, Any] | None:
    for doc in documents:
        if doc.get("status") != "available" or not doc.get("url"):
            continue
        label = (doc.get("type", "") + " " + doc.get("category", "")).lower()
        if any(kw in label for kw in category_keywords):
            return doc
    return None


@mcp.tool()
async def extract_device_specs(fcc_id: str, enable_ocr: bool = True) -> str:
    """Match an FCC ID's filing metadata against a local chip database to
    infer MCU family, architecture, and recommended Ghidra loading settings.

    Strategy:
      1. Scan scraped metadata text (title, product description, body) for
         known chip identifiers. Fast, no download.
      2. If no match and ``enable_ocr`` is true, walk through available filing
         PDFs — Block Diagram, Operational Description, Internal Photos, Test
         Report — extracting embedded text (cheap) and falling back to
         tesseract OCR on rendered pages (slow). Stop at the first match.

    Downloads and OCR output are cached under ``downloads/<FCC_ID>/`` so
    repeat calls for the same device are fast."""
    try:
        norm = normalize_fcc_id(fcc_id)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})

    payload = await _do_lookup(norm)
    if not payload.get("found"):
        return json.dumps({
            "fcc_id": norm["normalized"],
            "found": False,
            "errors": payload.get("errors", []),
        }, indent=2)

    documents = payload.get("documents", [])
    trace: list[dict[str, Any]] = []

    # Stage 1 — scan scraped metadata text (cheap, no downloads).
    text_sources: list[str] = [
        payload.get("grantee_name", ""),
        payload.get("product_description", ""),
        payload.get("summary", ""),
    ]
    for doc in documents:
        text_sources.append(doc.get("type", ""))
        text_sources.append(doc.get("category", ""))

    source_url = payload.get("source_url", "")
    page_text = ""
    if source_url:
        try:
            async with _new_client() as client:
                resp = await _rate_limited_get(client, source_url)
                resp.raise_for_status()
                page_text = BeautifulSoup(resp.text, "lxml").get_text(" ", strip=True)
        except Exception:
            page_text = ""
    text_sources.append(page_text)

    combined_text = "\n".join(t for t in text_sources if t)
    mcu_keys, flash_mentions = match_chips_in_text(combined_text)
    trace.append({
        "stage": "metadata_text",
        "chars_scanned": len(combined_text),
        "mcu_matches": mcu_keys,
        "flash_matches": flash_mentions,
    })

    # Stage 2 — walk available filing PDFs, cheapest first.
    if not mcu_keys and enable_ocr:
        async with _new_client() as client:
            for category_key, keywords in _OCR_DOC_PRIORITY:
                doc = _match_doc(documents, keywords)
                if not doc:
                    trace.append({"stage": category_key, "status": "not_available"})
                    continue
                try:
                    extraction = await extract_pdf_text(
                        client,
                        norm["normalized"],
                        doc["url"],
                        DOWNLOADS_DIR,
                    )
                except Exception as exc:  # defensive
                    trace.append({
                        "stage": category_key,
                        "doc_type": doc.get("type", ""),
                        "status": "exception",
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                    continue

                doc_mcus, doc_flashes = match_chips_in_text(extraction["combined_text"])
                for f in doc_flashes:
                    if f not in flash_mentions:
                        flash_mentions.append(f)
                trace.append({
                    "stage": category_key,
                    "doc_type": doc.get("type", ""),
                    "pdf_url": extraction["url"],
                    "size_bytes": extraction["size_bytes"],
                    "from_cache": extraction["from_cache"],
                    "embedded_chars": len(extraction["embedded_text"]),
                    "ocr_used": extraction["ocr_used"],
                    "ocr_chars": len(extraction["ocr_text"]),
                    "mcu_matches": doc_mcus,
                    "flash_matches": doc_flashes,
                    "error": extraction.get("error", ""),
                })
                if doc_mcus:
                    mcu_keys = doc_mcus
                    break

    evidence: list[str] = []
    if payload.get("product_description"):
        evidence.append(f"Product description: {payload['product_description']}")
    if payload.get("frequency_ranges"):
        evidence.append("Frequency bands: " + ", ".join(payload["frequency_ranges"]))
    if flash_mentions:
        evidence.append("Flash chip mentions: " + ", ".join(flash_mentions))

    if not mcu_keys:
        confidential_docs = [
            d["type"] for d in documents
            if d.get("status") == "confidential_no_public_copy"
        ]
        note_parts = [
            "No known MCU identifier detected in any available source.",
        ]
        if confidential_docs:
            note_parts.append(
                "These documents were filed but are marked confidential: "
                + ", ".join(confidential_docs)
                + " — the chip is likely named in one of them."
            )
        internal_photos = _match_doc(documents, ["internal photos"])
        if internal_photos:
            note_parts.append(
                "Manual inspection recommended: "
                + internal_photos["url"]
            )
        return json.dumps({
            "fcc_id": norm["normalized"],
            "found": True,
            "mcu": None,
            "confidence": "none",
            "evidence": evidence,
            "trace": trace,
            "note": " ".join(note_parts),
            "filing": {
                "grantee_name": payload.get("grantee_name", ""),
                "product_description": payload.get("product_description", ""),
                "source_url": payload.get("source_url", ""),
            },
            "flash_mentions": flash_mentions,
            "confidential_documents": confidential_docs,
        }, indent=2)

    primary_key = mcu_keys[0]
    chip = CHIP_DB[primary_key]
    confidence = "high" if len(mcu_keys) == 1 else "medium"

    evidence.insert(0, f"Matched chip identifier: {primary_key}")
    if len(mcu_keys) > 1:
        evidence.append("Other candidates: " + ", ".join(mcu_keys[1:]))

    return json.dumps({
        "fcc_id": norm["normalized"],
        "found": True,
        "mcu": {
            "identifier": primary_key,
            "architecture": chip["architecture"],
            "endianness": chip["endianness"],
            "ghidra_language": chip["ghidra_language"],
            "flash_base": chip["flash_base"],
            "radios": chip["radios"],
            "notes": chip["notes"],
        },
        "recommended_ghidra_settings": {
            "language": chip["ghidra_language"],
            "base_address": chip["flash_base"],
            "notes": chip["notes"],
        },
        "confidence": confidence,
        "evidence": evidence,
        "trace": trace,
        "flash_mentions": flash_mentions,
        "alternate_candidates": mcu_keys[1:],
        "filing": {
            "grantee_name": payload.get("grantee_name", ""),
            "product_description": payload.get("product_description", ""),
            "source_url": payload.get("source_url", ""),
        },
    }, indent=2)


# ── Entry point ───────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FCC ID Lookup MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport mode (default: stdio)",
    )
    parser.add_argument("--mcp-host", default="127.0.0.1", help="Host for SSE mode")
    parser.add_argument("--mcp-port", type=int, default=8082, help="Port for SSE mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
