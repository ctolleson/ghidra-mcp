"""PDF fetch, text-extraction, and OCR fallback for fcc-id-mcp.

fccid.io serves documents at URLs like:
    https://fccid.io/{FCC_ID}/{Category}/{Slug}             (HTML viewer)
    https://fccid.io/{FCC_ID}/{Category}/{Slug}.pdf         (raw PDF)

We derive the PDF URL by appending ``.pdf`` to the document-page URL, download
it (with on-disk cache), try pymupdf's embedded-text extraction first, and only
fall back to tesseract OCR when the embedded text is too thin to be useful.

OCR preprocessing runs each page image at 4 rotations so rotated silk-screen
text (common in PCB photos) can still be recognized.
"""

from __future__ import annotations

import hashlib
import io
import re
import shutil
from pathlib import Path
from typing import Any

import httpx

# Tesseract is optional — if it or its dependencies fail to import we degrade
# to text-only extraction with a clear diagnostic in the result payload.
try:
    import fitz  # pymupdf
except ImportError:  # pragma: no cover
    fitz = None  # type: ignore[assignment]

try:
    import pytesseract
    from PIL import Image, ImageOps, ImageFilter
except ImportError:  # pragma: no cover
    pytesseract = None  # type: ignore[assignment]
    Image = ImageOps = ImageFilter = None  # type: ignore[assignment]


def derive_pdf_url(doc_page_url: str) -> str:
    """Return the raw PDF URL for a fccid.io document viewer URL."""
    if doc_page_url.lower().endswith(".pdf"):
        return doc_page_url
    return doc_page_url.rstrip("/") + ".pdf"


def _cache_paths(fcc_id: str, doc_page_url: str, downloads_dir: Path) -> tuple[Path, Path]:
    """Returns (pdf_path, ocr_text_path) for a given (fcc_id, doc_url) pair."""
    digest = hashlib.sha1(doc_page_url.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", doc_page_url.rsplit("/", 1)[-1])[:64] or "doc"
    base = downloads_dir / fcc_id
    base.mkdir(parents=True, exist_ok=True)
    pdf_path = base / f"{digest}_{slug}.pdf"
    ocr_path = base / f"{digest}_{slug}.ocr.txt"
    return pdf_path, ocr_path


async def fetch_pdf(
    client: httpx.AsyncClient,
    doc_page_url: str,
    pdf_path: Path,
    *,
    max_bytes: int = 25 * 1024 * 1024,
) -> dict[str, Any]:
    """Download the PDF to ``pdf_path`` if not already cached.

    Returns a small diagnostics dict: {'path', 'size_bytes', 'from_cache', 'url'}.
    """
    pdf_url = derive_pdf_url(doc_page_url)
    if pdf_path.exists() and pdf_path.stat().st_size > 0:
        return {
            "path": str(pdf_path),
            "size_bytes": pdf_path.stat().st_size,
            "from_cache": True,
            "url": pdf_url,
        }

    resp = await client.get(pdf_url, follow_redirects=True)
    resp.raise_for_status()
    content = resp.content
    if len(content) > max_bytes:
        raise ValueError(f"PDF too large ({len(content)} bytes > {max_bytes})")

    tmp = pdf_path.with_suffix(pdf_path.suffix + ".part")
    tmp.write_bytes(content)
    tmp.replace(pdf_path)
    return {
        "path": str(pdf_path),
        "size_bytes": pdf_path.stat().st_size,
        "from_cache": False,
        "url": pdf_url,
    }


def _embedded_text(pdf_path: Path) -> str:
    if fitz is None:
        return ""
    try:
        doc = fitz.open(str(pdf_path))
    except Exception:
        return ""
    try:
        return "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()


def _is_text_substantial(text: str) -> bool:
    """Return True if embedded text alone is probably enough to skip OCR.

    We require at least 200 alnum chars AND >=30 unique words of length >= 4.
    """
    if not text:
        return False
    alnum = sum(ch.isalnum() for ch in text)
    words = {w for w in re.findall(r"[A-Za-z][A-Za-z0-9-]{3,}", text)}
    return alnum >= 200 and len(words) >= 30


def _ocr_page(img_bytes: bytes) -> str:
    """OCR one page at 4 rotations with light preprocessing."""
    if pytesseract is None or Image is None:
        return ""
    base = Image.open(io.BytesIO(img_bytes))
    base = ImageOps.grayscale(base)
    base = ImageOps.autocontrast(base)
    base = base.filter(ImageFilter.SHARPEN)
    chunks: list[str] = []
    for rotation in (0, 90, 180, 270):
        img = base.rotate(rotation, expand=True) if rotation else base
        try:
            chunks.append(pytesseract.image_to_string(img))
        except Exception:
            continue
    return "\n".join(chunks)


def ocr_pdf(
    pdf_path: Path,
    *,
    dpi: int = 400,
    max_pages: int = 12,
) -> str:
    """Render each page of ``pdf_path`` and OCR it at 4 rotations.

    Capped at ``max_pages`` pages — FCC internal-photo and block-diagram PDFs
    are typically short, and larger PDFs (e.g. full test reports) tend to have
    useful text as embedded glyphs rather than images anyway.
    """
    if fitz is None or pytesseract is None:
        return ""
    doc = fitz.open(str(pdf_path))
    try:
        parts: list[str] = []
        for i, page in enumerate(doc):
            if i >= max_pages:
                break
            pix = page.get_pixmap(dpi=dpi)
            parts.append(_ocr_page(pix.tobytes("png")))
        return "\n".join(parts)
    finally:
        doc.close()


async def extract_pdf_text(
    client: httpx.AsyncClient,
    fcc_id: str,
    doc_page_url: str,
    downloads_dir: Path,
    *,
    force_ocr: bool = False,
) -> dict[str, Any]:
    """Download + extract text from a fccid.io document.

    Returns:
        {
          'url': str,                # raw PDF url
          'pdf_path': str,           # local cache path
          'size_bytes': int,
          'from_cache': bool,        # download cache hit
          'embedded_text': str,      # pymupdf text (may be empty)
          'ocr_text': str,           # tesseract text ('' if OCR skipped)
          'ocr_used': bool,          # True iff OCR was attempted
          'combined_text': str,      # embedded + OCR concatenated
          'error': str,              # set only on failure
        }
    """
    result: dict[str, Any] = {
        "url": derive_pdf_url(doc_page_url),
        "pdf_path": "",
        "size_bytes": 0,
        "from_cache": False,
        "embedded_text": "",
        "ocr_text": "",
        "ocr_used": False,
        "combined_text": "",
        "error": "",
    }

    if fitz is None:
        result["error"] = "pymupdf (fitz) not installed"
        return result

    pdf_path, ocr_cache = _cache_paths(fcc_id, doc_page_url, downloads_dir)
    try:
        fetch_info = await fetch_pdf(client, doc_page_url, pdf_path)
    except httpx.HTTPError as exc:
        result["error"] = f"download failed: {exc}"
        return result
    except ValueError as exc:
        result["error"] = str(exc)
        return result

    result.update({
        "pdf_path": fetch_info["path"],
        "size_bytes": fetch_info["size_bytes"],
        "from_cache": fetch_info["from_cache"],
    })

    embedded = _embedded_text(pdf_path)
    result["embedded_text"] = embedded

    if not force_ocr and _is_text_substantial(embedded):
        result["combined_text"] = embedded
        return result

    ocr_text = ""
    if ocr_cache.exists() and ocr_cache.stat().st_size > 0 and not force_ocr:
        try:
            ocr_text = ocr_cache.read_text(encoding="utf-8")
        except Exception:
            ocr_text = ""

    if not ocr_text:
        if pytesseract is None:
            result["error"] = "pytesseract not installed; cannot OCR image-based PDF"
            result["combined_text"] = embedded
            return result
        if shutil.which("tesseract") is None:
            result["error"] = "tesseract binary not found in PATH"
            result["combined_text"] = embedded
            return result
        try:
            ocr_text = ocr_pdf(pdf_path)
        except Exception as exc:
            result["error"] = f"ocr failed: {exc}"
            result["combined_text"] = embedded
            return result
        try:
            ocr_cache.write_text(ocr_text, encoding="utf-8")
        except Exception:
            pass

    result["ocr_text"] = ocr_text
    result["ocr_used"] = True
    result["combined_text"] = (embedded + "\n" + ocr_text).strip()
    return result
