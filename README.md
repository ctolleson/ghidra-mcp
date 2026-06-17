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

1. **Ghidra 11.3.1 or 12.0.1**
   - Download from the [official release page](https://github.com/NationalSecurityAgency/ghidra/releases).
   - **A pre-compiled extension for Ghidra 12.0.1 is already included** in
     `ghidra-mcp-extension/dist/ghidra-mcp-12.0.1.zip`. If you are on 12.0.1 you can **skip
     Step 1 (Build)** entirely and go straight to Step 2 (Install).

2. **Java 17 or 21** (JDK) — required to build the extension.

3. **Gradle** — install via `brew install gradle` (Mac) or your package manager.

4. **Python 3.10+**

5. **Node.js / npx** (optional, for testing with MCP Inspector).

---

## Step 1: Build the Ghidra Extension

> **Prebuilt extensions are already included** in `ghidra-mcp-extension/dist/`:
> - `dist/ghidra-mcp.zip` — Ghidra **11.3.1**
> - `dist/ghidra-mcp-12.0.1.zip` — Ghidra **12.0.1** (already compiled and verified against 12.0.1)
>
> If you are using either of these Ghidra versions, **skip to Step 2: Install**. Build from
> source only when targeting a different Ghidra version.

1. Clone this repository.
2. Point the build at your local Ghidra install — either edit the `ghidraInstallDir` default in
   `ghidra-mcp-extension/build.gradle`, or pass it on the command line (no file edit needed):
   ```groovy
   // build.gradle default:
   def ghidraInstallDir = "/Applications/ghidra_11.3.1_PUBLIC"
   ```
3. Build the project:
   ```bash
   cd ghidra-mcp-extension
   # use the default in build.gradle:
   gradle build
   # or override per-build for another version (e.g. 12.0.1):
   gradle build -PghidraInstallDir=/Applications/ghidra_12.0.1_PUBLIC
   ```
4. If successful, a ZIP is created in `dist/` (e.g. `dist/ghidra-mcp.zip`). When building for a new
   Ghidra version, set `version` and `ghidra_version` in `extension.properties` to that version so
   Ghidra accepts the extension.

---

## Step 2: Install Extension in Ghidra

1. Open Ghidra.
2. From the Project Manager window, go to **File** -> **Install Extensions**.
3. Click the green **Plus (+)** icon.
4. Navigate to `dist/` and select the ZIP for your Ghidra version: `ghidra-mcp.zip` (11.3.1) or `ghidra-mcp-12.0.1.zip` (12.0.1).
5. Click **OK**. Ensure the checkbox next to `ghidra-mcp` is checked.
6. **Restart Ghidra.**

### Activate the Plugin

Only necessary if Ghidra didn't prompt you to automatically configure the new plugin.

1. Open a binary in the **CodeBrowser** (Dragon icon).
2. Go to **File** -> **Configure...**.
3. Click the **Plug Icon** (top right) or "Add Plugin".
4. Search for `GhidraMCPPlugin` and check the box.
5. You should see in the console:
   > `[INFO] MCP HTTP Server started on port 8080`

---

## Step 3: Run the MCP Server (Python)

1. Navigate to the `mcp_server` directory.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install mcp httpx
   ```
3. Run the firmware bridge server:
   ```bash
   python mcp_server/bridge_mcp_firmware.py
   ```
   Options:
   - `--ghidra-server http://host:port` — connect to a remote Ghidra instance
   - `--transport sse --mcp-port 8081` — run in SSE mode instead of stdio

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
