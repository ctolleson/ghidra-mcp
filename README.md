# Ghidra MCP — Firmware Reverse Engineering Bridge

An MCP (Model Context Protocol) server that connects AI assistants to Ghidra for firmware reverse engineering. Gives LLMs direct access to Ghidra's analysis capabilities — decompilation, cross-references, memory maps, and 30+ firmware-specific tools — through a standard protocol.

---

## Available Tools

### Environment Context

| Tool | Description |
|------|-------------|
| `get_binary_info` | Core metadata about the loaded binary: architecture, endianness, compiler, base address, symbol/function counts. Call first to orient. |
| `get_memory_map` | All memory blocks with permissions (RWX), types, and volatility flags. Identifies MMIO regions, flash, RAM, and peripheral address spaces. |

### Reconnaissance & Discovery

| Tool | Description |
|------|-------------|
| `search_strings` | Case-insensitive keyword search across all defined strings. Find hardcoded credentials, URLs, debug messages, AT commands, error strings. |
| `get_function_list` | List functions, optionally filtered by name substring. Supports pagination. |
| `search_bytes` | Search for byte sequences using hex patterns with `??` wildcards. Find crypto constants, RTOS magic numbers, bootloader signatures. |
| `get_imports` | List imported symbols from external libraries (libc, libssl, etc.). |
| `get_exports` | List exported symbols and entry points. |
| `get_segments` | ELF/PE segments or firmware memory sections with permissions (.text, .data, .bss, .rodata, .isr_vector). |
| `get_data_items` | List defined data items (globals, constants, tables) with optional type filter. Supports pagination. |
| `disassemble_at` | Raw disassembly at a given address. Essential for ISR handlers, bootloader stubs, or inline assembly where the decompiler struggles. |

### Code Analysis

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile a function into C-like pseudocode. The primary tool for understanding firmware logic. |
| `get_function_info` | Detailed structural info: parameters, local variables, stack frame, calling convention, call graph. Auto-flags calls to unsafe functions. |
| `get_xrefs_to` | All cross-references pointing TO an address — who calls this function or uses this data. |
| `get_xrefs_from` | All cross-references FROM an address — what functions and data this code references. |
| `read_raw_bytes` | Read raw bytes at an address (up to 4096). Hex dump + ASCII for examining data structures, headers, keys. |
| `trace_call_path` | Find all call paths between two functions. Core taint analysis: "Can input from `uart_read` reach `strcpy`?" Bounded BFS on the call graph. |

### Annotation

| Tool | Description |
|------|-------------|
| `rename_function` | Rename a function in the Ghidra database (e.g., `FUN_00010000` → `uart_init`). |
| `add_comment` | Add a plate comment at an address — vulnerability notes, register descriptions, analysis summaries. |
| `define_data` | Interpret raw bytes as a specific type: string, pointer, int8–int64, uint8–uint64, float, double. |
| `rename_data` | Create or rename a label at a data address — MMIO registers, globals, config tables. |

### Firmware-Specific Analysis

| Tool | Description |
|------|-------------|
| `get_interrupt_vector_table` | Parse the IVT to identify reset handler, ISRs, and initial stack pointer. Flags anomalies like vectors pointing to RAM. |
| `find_function_prologues` | Scan for architecture-specific function prologues to discover functions missed by auto-analysis. Critical for stripped binaries. |
| `identify_mmio_accesses` | Find all instructions that read/write MMIO regions. Identifies which functions talk to hardware peripherals (UART, SPI, GPIO, DMA). |
| `find_register_patterns` | Detect read-modify-write (RMW) sequences on hardware registers — the canonical pattern for peripheral configuration. |
| `detect_rtos` | Identify the RTOS: FreeRTOS, Zephyr, ThreadX, VxWorks, Mbed OS, RIOT, NuttX, Contiki, or bare-metal. |
| `find_function_pointer_tables` | Scan for arrays of code pointers — dispatch tables, vtables, callback arrays, command handler tables. |
| `get_string_clusters` | Group spatially close strings to reveal logical modules and subsystems in stripped binaries. |
| `get_function_hashes` | Compute structural hashes for firmware version diffing. Compare hashes across builds to find patched, new, or removed functions. |

### Vulnerability Scanning

| Tool | Description |
|------|-------------|
| `find_dangerous_sinks` | Locate all calls to dangerous functions (strcpy, sprintf, system, gets) across the binary. Categories: buffer_overflow, format_string, command_injection, memory. |
| `find_format_string_vulns` | Find printf-family calls where the format string is not a constant literal — potential format string vulnerabilities. |
| `find_hardcoded_credentials` | Hunt for hardcoded passwords, API keys, and secrets using pattern matching, entropy analysis, and proximity to auth functions. |
| `find_crypto_constants` | Scan for known crypto constants (AES S-box, SHA-256 init vectors, CRC32 tables, etc.) to identify algorithms in use. |

---

## Prerequisites

1. **Ghidra 12.0.1** (strict requirement)
   - Download from the [official release page](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.1_build).
   - The extension is version-stamped `12.0.1`. Installing it into a different
     Ghidra release triggers an "Extension Version Mismatch" dialog (Ghidra
     compares `extension.properties` against its own version string). You can
     click through it, but the supported target is 12.0.1.

2. **JDK 21 or newer** — required to build the extension.
   - Ghidra 12.x sets `application.java.min=21`; JDK 17 is no longer sufficient.
   - Verify with `java -version` before building.

3. **Gradle 8.5+** — `winget install Gradle.Gradle` (Windows), `brew install gradle` (Mac),
   or your package manager.

4. **Python 3.10+**

5. **Node.js / npx** (optional, for testing with MCP Inspector).

---

## Step 1: Build the Ghidra Extension

1. Clone this repository.
2. Tell the build where Ghidra lives. Either export `GHIDRA_INSTALL_DIR`:
   ```bash
   # Mac / Linux
   export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.1_PUBLIC
   ```
   ```powershell
   # Windows (PowerShell)
   $env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.1_PUBLIC"
   ```
   ...or pass it on the command line in step 3 with
   `-PghidraInstallDir=/path/to/ghidra_12.0.1_PUBLIC`.

   The build fails fast with a clear message if the path is unset or does not
   look like a Ghidra installation.

3. Build the project:
   ```bash
   cd ghidra-mcp-extension
   gradle build
   ```
4. If successful, a ZIP file will be created at `dist/ghidra-mcp.zip`.

---

## Step 2: Install Extension in Ghidra

1. Open Ghidra.
2. From the Project Manager window, go to **File** -> **Install Extensions**.
3. Click the green **Plus (+)** icon.
4. Navigate to `dist/` and select `ghidra-mcp.zip`.
5. Click **OK**. Ensure the checkbox next to `ghidra-mcp` is checked.
6. **Restart Ghidra.**

### Activate the Plugin

Only necessary if Ghidra didn't prompt you to automatically configure the new plugin.

1. Open a binary in the **CodeBrowser** (Dragon icon).
2. Go to **File** -> **Configure...**.
3. Click the **Plug Icon** (top right) or "Add Plugin".
4. Search for `GhidraMCPPlugin` and check the box.
   - It is listed under the **Miscellaneous** package, not under a
     "FirmwareMCP" heading — Ghidra falls back to Miscellaneous for plugins
     that do not register their own `PluginPackage`.
5. You should see in the console:
   > `[INFO] MCP HTTP Server started on port 8080`

---

## Step 3: Run the MCP Server (Python)

1. Navigate to the `mcp_server` directory.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Run the firmware bridge server:
   ```bash
   python mcp_server/bridge_mcp_firmware.py
   ```
   Options:
   - `--ghidra-server http://host:port` — connect to a remote Ghidra instance
   - `--transport sse --mcp-port 8081` — run in SSE mode instead of stdio

The Python bridge talks plain HTTP to the plugin on port 8080 and is
independent of the Ghidra version.

---

## Step 4: Verify Setup

Use the **MCP Inspector** to verify the pipeline without needing an LLM key.

1. Ensure Ghidra is running and port 8080 is open (`lsof -i :8080`).
2. Run the inspector:
   ```bash
   npx @modelcontextprotocol/inspector python mcp_server/bridge_mcp_firmware.py
   ```
3. A web interface opens (usually `http://localhost:5173`).
4. Find any tool in the list (e.g., `get_binary_info`) and click **Run Tool**.

---

## Step 5: Connect It to Your MCP Client

The bridge speaks MCP over **stdio** by default, so any MCP client launches it
directly. Point your client at the Python interpreter from the venv you created
in Step 3 and the bridge script. Use **absolute paths** — clients do not inherit
your shell's working directory or `PATH`.

Find your interpreter path after activating the venv:

```bash
# Mac / Linux
cd mcp_server && source venv/bin/activate && which python
# Windows (PowerShell): (Resolve-Path venv\Scripts\python.exe).Path
```

### Claude Code (CLI)

```bash
claude mcp add firmware-mcp -- /abs/path/to/mcp_server/venv/bin/python \
  /abs/path/to/mcp_server/bridge_mcp_firmware.py
```

Or add a project-scoped `.mcp.json` in your own working repo (note: this repo
git-ignores `.mcp.json`, so create your own):

```json
{
  "mcpServers": {
    "firmware-mcp": {
      "command": "/abs/path/to/mcp_server/venv/bin/python",
      "args": ["/abs/path/to/mcp_server/bridge_mcp_firmware.py"]
    }
  }
}
```

### Claude Desktop

Edit the config file (create it if missing):

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "firmware-mcp": {
      "command": "/abs/path/to/mcp_server/venv/bin/python",
      "args": ["/abs/path/to/mcp_server/bridge_mcp_firmware.py"]
    }
  }
}
```

Fully quit and reopen Claude Desktop, then confirm `firmware-mcp` appears in the
tools menu.

### Connecting to a remote or non-default Ghidra

If the Ghidra plugin runs on another host or port, append it to `args`:

```json
"args": [
  "/abs/path/to/mcp_server/bridge_mcp_firmware.py",
  "--ghidra-server", "http://192.168.1.50:8080"
]
```

> **Security note:** the Ghidra plugin binds `127.0.0.1:8080` with **no
> authentication** and exposes mutating tools (`rename_function`,
> `define_data`, ...). Only expose it beyond localhost on a trusted network.

Whichever client you use, Ghidra must be running with a binary open in the
CodeBrowser and the plugin active (`[INFO] MCP HTTP Server started on port 8080`)
before the tools will return data.

---

## Ghidra Version Compatibility

| Ghidra | Status |
|--------|--------|
| 12.0.1 | **Supported.** Builds and loads clean; verified end to end against a real install. |
| 12.0.2 – 12.0.4, 12.1.x | Expected to work — same JDK 21 floor, and every API this plugin calls is unchanged (12.0.3 was also verified end to end). Re-stamp `version=` in `extension.properties` to match your build, or click through the mismatch dialog. |
| 11.4.x | Source-compatible (`CommentType` exists, same JDK 21 floor), but the extension is stamped 12.0.1. Untested. |
| 11.3.x and earlier | **Not supported.** `add_comment` uses `CommentType`, which was introduced in Ghidra 11.4. |

### Notes on the 12.0.x migration

- `add_comment` now calls `Listing.setComment(Address, CommentType, String)`.
  The old `CodeUnit.PLATE_COMMENT` int constants are deprecated for removal
  (`since = "11.4"`) and will disappear in a future release.
- `build.gradle` targets Java 21 and reads the Ghidra path from
  `GHIDRA_INSTALL_DIR` instead of a hardcoded directory.
- `Module.manifest` uses Ghidra's colon-delimited key syntax. The previous
  `GHIDRA_MODULE_NAME=` / `GHIDRA_MODULE_DESC=` lines were not valid manifest
  keys and logged a parse error on every Ghidra startup.
