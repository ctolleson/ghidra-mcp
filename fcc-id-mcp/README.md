# fcc-id-mcp — FCC ID Lookup MCP Server

Look up FCC IDs against public FCC equipment authorization sources (fccid.io, fcc.report) and return device metadata useful for firmware reverse engineering: manufacturer, model, available documents, frequency bands, and candidate MCU identifiers matched to Ghidra loading settings.

Pairs with the Ghidra MCP server in the parent repo — query this first to learn what chip you're dealing with, then load the firmware in Ghidra with the right architecture and base address.

---

## Tools

| Tool | Description |
|------|-------------|
| `lookup_fcc_id` | Return grantee name, product description, approval dates, frequency bands, and available filing documents. Accepts hyphenated or compact FCC ID formats. Results cached for 7 days. |
| `extract_device_specs` | Scan filing metadata for known MCU identifiers (ESP8266/ESP32, nRF52, STM32, CC2640, RTL8710, BCM43438) and return Ghidra-ready architecture and base address. |

### Scope

- Scrapes fccid.io (primary) and fcc.report (fallback).
- `lookup_fcc_id` reports both **available** documents (with PDF URLs) and **confidential_no_public_copy** entries — useful context when the chip is named in a withheld block diagram.
- `extract_device_specs` progressively downloads PDFs (block diagram → operational description → internal photos → test report), tries pymupdf text extraction first, and falls back to **tesseract OCR** at 4 rotations with preprocessing when embedded text is thin.
- Downloads and OCR output are cached under `downloads/<FCC_ID>/` so repeat calls are fast.
- `download_fcc_document`, `search_fcc_by_grantee`, and `identify_device_from_description` are not yet implemented.

### OCR prerequisites

OCR needs the `tesseract` binary installed system-wide. On macOS:

```bash
brew install tesseract
```

Pass `enable_ocr=false` to `extract_device_specs` to skip the PDF-download stage entirely if you just want the fast metadata scan.

---

## Setup

1. From the `fcc-id-mcp/` directory:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Verify the server launches:
   ```bash
   python fcc_id_mcp.py
   ```
   It runs on stdio and waits for an MCP client — ctrl-C to exit.

---

## Register with Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "fcc-id": {
      "command": "/ABSOLUTE/PATH/TO/ghidra-mcp/fcc-id-mcp/venv/bin/python",
      "args": [
        "/ABSOLUTE/PATH/TO/ghidra-mcp/fcc-id-mcp/fcc_id_mcp.py"
      ]
    }
  }
}
```

Use absolute paths — Claude Desktop doesn't expand `~`. Restart Claude Desktop after editing.

## Register with Claude Code

```bash
claude mcp add fcc-id "/ABSOLUTE/PATH/TO/fcc-id-mcp/venv/bin/python /ABSOLUTE/PATH/TO/fcc-id-mcp/fcc_id_mcp.py"
```

---

## Respectful scraping

- 1 request per second rate limit across all requests.
- 7-day result cache (SQLite at `cache/fcc_cache.db`).
- Descriptive User-Agent identifying the tool.

Both fccid.io and fcc.report are free public services — don't disable the rate limiter.

---

## Extending the chip database

Edit `chip_db.py` to add more MCU entries. Each entry needs:
- `architecture`, `endianness`, `ghidra_language` — for Ghidra loader config
- `flash_base` — base address to load firmware at
- `radios` — list of radio types (for cross-checking against frequency bands)
- `notes` — free-form notes for the analyst

Also add a detection regex to `_CHIP_PATTERNS` so the identifier matches in scraped text.
