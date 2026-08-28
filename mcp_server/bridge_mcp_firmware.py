#!/usr/bin/env python3
"""FirmwareMCP Bridge - Connects Claude to Ghidra for firmware reverse engineering."""

import argparse
import os
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FirmwareMCP")
ghidra_server = "http://127.0.0.1:8080"

# Per-request HTTP timeout (seconds). Kept short so a stuck whole-binary scan on
# Ghidra's single Swing thread fails fast instead of freezing Claude for minutes.
# Override with FIRMWARE_MCP_TIMEOUT for the rare heavy call.
REQUEST_TIMEOUT = float(os.environ.get("FIRMWARE_MCP_TIMEOUT", "30"))

# Hard cap on the characters returned from any single tool call. Whole-binary
# scans and list endpoints can return tens of thousands of tokens; unbounded,
# that output is pinned into the conversation and re-sent on every subsequent
# turn, ballooning context cost. Truncate and tell the model to narrow/paginate.
# Override with FIRMWARE_MCP_MAX_CHARS. ~16 KB ≈ 4-5k tokens.
MAX_RESPONSE_CHARS = int(os.environ.get("FIRMWARE_MCP_MAX_CHARS", "16000"))


def _truncate(text: str) -> str:
    """Cap tool output so a single call can't flood the model's context."""
    if text is None or len(text) <= MAX_RESPONSE_CHARS:
        return text
    omitted = len(text) - MAX_RESPONSE_CHARS
    return (
        text[:MAX_RESPONSE_CHARS]
        + f"\n\n[... output truncated: {omitted} more characters omitted. "
        "Narrow the query (use filter_text / a smaller limit / offset pagination, "
        "or target a specific address) to see the rest.]"
    )


async def safe_get(path: str, params: dict = None) -> str:
    """GET request to the Ghidra plugin HTTP server."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(f"{ghidra_server}{path}", params=params)
            resp.raise_for_status()
            return _truncate(resp.text)
    except Exception as e:
        return f"Error: {e}"


async def safe_post(path: str, params: dict = None) -> str:
    """POST request to the Ghidra plugin HTTP server."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(f"{ghidra_server}{path}", params=params)
            resp.raise_for_status()
            return _truncate(resp.text)
    except Exception as e:
        return f"Error: {e}"


# ── Environment Context ────────────────────────────────────────────────


@mcp.tool()
async def get_binary_info() -> str:
    """Retrieves core metadata about the loaded firmware image including
    architecture, endianness, compiler, base address, and symbol/function counts.
    Call this first to understand what you're analyzing."""
    return await safe_get("/get_binary_info")


@mcp.tool()
async def get_memory_map() -> str:
    """Returns all memory blocks with permissions (RWX), types, and volatility flags.
    Essential for identifying MMIO regions, flash, RAM, and peripheral address spaces
    in firmware images."""
    return await safe_get("/get_memory_map")


# ── Reconnaissance and Discovery ───────────────────────────────────────


@mcp.tool()
async def search_strings(keyword: str) -> str:
    """Searches all defined strings in the binary for a keyword match (case-insensitive).
    Use this to find hardcoded credentials, URLs, debug messages, error strings,
    AT commands, or any text embedded in firmware. Max 200 results."""
    return await safe_get("/search_strings", {"keyword": keyword})


@mcp.tool()
async def get_function_list(filter_text: str = "", offset: int = 0, limit: int = 100) -> str:
    """Lists all functions, optionally filtered by name substring.
    Use filter_text to search for specific function names (e.g., 'uart', 'spi', 'main').
    Supports pagination via offset/limit (max 500)."""
    params = {"offset": str(offset), "limit": str(limit)}
    if filter_text:
        params["filter_text"] = filter_text
    return await safe_get("/get_function_list", params)


@mcp.tool()
async def search_bytes(hex_pattern: str) -> str:
    """Searches the binary for a specific byte sequence. Use space-separated hex bytes,
    ?? as wildcard. Examples: 'FF 00 A1 B2', '63 7C 77 7B' (AES S-box).
    Critical for finding crypto constants, RTOS magic numbers, bootloader signatures,
    and architecture-specific function prologues. Max 100 results."""
    return await safe_get("/search_bytes", {"hex_pattern": hex_pattern})


@mcp.tool()
async def get_imports(filter_text: str = "") -> str:
    """Lists imported functions/symbols from external libraries.
    For Linux-based IoT firmware, reveals libc/libssl/etc. calls.
    Many bare-metal firmware images are statically linked and may have few imports."""
    params = {}
    if filter_text:
        params["filter_text"] = filter_text
    return await safe_get("/get_imports", params)


@mcp.tool()
async def get_exports() -> str:
    """Lists all exported symbols/entry points in the binary.
    Useful for identifying the firmware's public API or entry points."""
    return await safe_get("/get_exports")


@mcp.tool()
async def get_segments() -> str:
    """Lists ELF/PE segments or firmware memory sections with permissions.
    Look for .text, .data, .bss, .rodata, .isr_vector, .heap, .stack sections."""
    return await safe_get("/get_segments")


@mcp.tool()
async def get_data_items(filter_type: str = "", offset: int = 0, limit: int = 100) -> str:
    """Lists defined data items (globals, constants, tables) with optional type filter.
    Filter by type name like 'string', 'pointer', 'int'. Supports pagination."""
    params = {"offset": str(offset), "limit": str(limit)}
    if filter_type:
        params["filter_type"] = filter_type
    return await safe_get("/get_data_items", params)


@mcp.tool()
async def disassemble_at(address: str, num_instructions: int = 20) -> str:
    """Returns raw assembly instructions at the given address.
    Essential when the decompiler produces unreliable output for hand-written
    assembly like ISR handlers, bootloader stubs, or inline asm. Max 200 instructions."""
    return await safe_get("/disassemble_at", {
        "address": address,
        "num_instructions": str(num_instructions),
    })


# ── Code Analysis ──────────────────────────────────────────────────────


@mcp.tool()
async def decompile_function(address: str) -> str:
    """Decompiles the function at the given hex address into C-like pseudocode.
    The primary tool for understanding firmware logic. Pass the function's entry
    point address (from get_function_list or get_xrefs_to)."""
    return await safe_get("/decompile_function", {"address": address})


@mcp.tool()
async def get_function_info(address: str) -> str:
    """Gets detailed structural info about a function: parameters, local variables,
    stack frame, calling convention, call graph, and potential vulnerability warnings.
    Automatically flags calls to unsafe functions like strcpy, sprintf, gets."""
    return await safe_get("/get_function_info", {"address": address})


@mcp.tool()
async def get_xrefs_to(address: str) -> str:
    """Gets all cross-references pointing TO the given address.
    Shows who calls/references this function or data. Essential for tracing
    how a function is reached or where a global variable is used."""
    return await safe_get("/get_xrefs_to", {"address": address})


@mcp.tool()
async def get_xrefs_from(address: str) -> str:
    """Gets all cross-references FROM the given address/function.
    Shows what functions/data this code references. Useful for understanding
    a function's dependencies and data flow."""
    return await safe_get("/get_xrefs_from", {"address": address})


@mcp.tool()
async def read_raw_bytes(address: str, length: int = 64) -> str:
    """Reads raw bytes from memory at the given address (max 4096 bytes).
    Returns hex dump and ASCII representation. Use for examining data structures,
    firmware headers, encryption keys, or verifying byte patterns."""
    return await safe_get("/read_raw_bytes", {
        "address": address,
        "length": str(length),
    })


# ── Annotation / Mutation ──────────────────────────────────────────────


@mcp.tool()
async def rename_function(address: str, new_name: str) -> str:
    """Renames a function in the Ghidra database. The name must be a valid C
    identifier. Use this to apply meaningful names discovered during analysis
    (e.g., rename FUN_00010000 to 'uart_init')."""
    return await safe_post("/rename_function", {
        "address": address,
        "new_name": new_name,
    })


@mcp.tool()
async def add_comment(address: str, comment: str) -> str:
    """Adds a plate comment at the specified address in Ghidra.
    Use to annotate findings: vulnerability notes, protocol details,
    hardware register descriptions, or analysis summaries."""
    return await safe_post("/add_comment", {
        "address": address,
        "comment": comment,
    })


@mcp.tool()
async def define_data(address: str, data_type: str) -> str:
    """Forces Ghidra to interpret raw bytes at an address as a specific data type.
    Supported types: string, pointer, int8, int16, int32, int64,
    uint8, uint16, uint32, uint64, float, double.
    Use to define undiscovered strings, pointer tables, or struct fields."""
    return await safe_post("/define_data", {
        "address": address,
        "data_type": data_type,
    })


@mcp.tool()
async def rename_data(address: str, new_name: str) -> str:
    """Creates or renames a label/symbol at a data address.
    Use to label MMIO registers, global variables, or configuration tables
    with meaningful names."""
    return await safe_post("/rename_data", {
        "address": address,
        "new_name": new_name,
    })


@mcp.tool()
async def rename_variable(function_address: str, old_name: str, new_name: str) -> str:
    """Renames a local variable or parameter shown in the decompiler for the function
    at function_address. Pass the exact current decompiler name as old_name (e.g. 'iVar1',
    'local_18', 'uStack_14', 'param_1'); new_name must be a valid C identifier. If the
    name isn't found, the error lists the function's available variable names so you can
    retry. Decompile the function first to see the current names."""
    return await safe_post("/rename_variable", {
        "function_address": function_address,
        "old_name": old_name,
        "new_name": new_name,
    })


@mcp.tool()
async def create_function(address: str, name: str = "") -> str:
    """Creates a function at the given address, disassembling the entry point first
    if needed. Use this to promote code that Ghidra didn't auto-detect as a function
    (e.g. interrupt handlers reached only through the vector table, which often lack
    a standard push-prologue). Optionally pass a valid C identifier to name it;
    otherwise it adopts any existing label at that address. Returns the function's
    entry and name. Safe to call if a function already exists there (reports it)."""
    params = {"address": address}
    if name:
        params["name"] = name
    return await safe_post("/create_function", params)


# ── Extended Firmware Analysis ─────────────────────────────────────────


@mcp.tool()
async def get_interrupt_vector_table(address: str = "", num_entries: int = 48, entry_size: int = 4) -> str:
    """Parse the interrupt vector table (IVT) at the given address (or image base).
    First step for ARM Cortex-M firmware: identifies reset handler, ISRs, and
    initial stack pointer. Flags anomalies like vectors pointing to RAM (hooks)."""
    params = {"num_entries": str(num_entries), "entry_size": str(entry_size)}
    if address:
        params["address"] = address
    return await safe_get("/get_interrupt_vector_table", params)


@mcp.tool()
async def find_function_prologues(architecture: str = "auto", create_functions: str = "false") -> str:
    """Scan executable memory for architecture-specific function prologues to discover
    functions missed by auto-analysis. Critical for stripped binaries and raw firmware
    blobs. Set create_functions='true' to auto-create function definitions at discoveries."""
    return await safe_get("/find_function_prologues", {
        "architecture": architecture, "create_functions": create_functions
    })


@mcp.tool()
async def identify_mmio_accesses(mmio_start: str = "", mmio_end: str = "", filter_function: str = "") -> str:
    """Find all instructions that read/write Memory-Mapped I/O (MMIO) regions.
    Identifies which functions talk to hardware peripherals (UART, SPI, GPIO, DMA).
    Auto-detects MMIO from volatile memory blocks, or specify a range manually."""
    params = {}
    if mmio_start: params["mmio_start"] = mmio_start
    if mmio_end: params["mmio_end"] = mmio_end
    if filter_function: params["filter_function"] = filter_function
    return await safe_get("/identify_mmio_accesses", params)


@mcp.tool()
async def find_register_patterns(target_address: str = "", function_address: str = "") -> str:
    """Detect read-modify-write (RMW) sequences on hardware registers.
    The canonical pattern for setting/clearing peripheral register bits.
    Reveals hardware init routines and peripheral configuration logic."""
    params = {}
    if target_address: params["target_address"] = target_address
    if function_address: params["function_address"] = function_address
    return await safe_get("/find_register_patterns", params)


@mcp.tool()
async def find_crypto_constants(algorithms: str = "all") -> str:
    """Scan for known cryptographic constants (AES S-box, SHA-256 init values,
    CRC32 tables, DES permutations, ChaCha20 sigma, etc.) to identify which
    crypto algorithms the firmware uses and which functions implement them."""
    return await safe_get("/find_crypto_constants", {"algorithms": algorithms})


@mcp.tool()
async def find_hardcoded_credentials(entropy_threshold: float = 4.0, include_low_entropy: str = "true") -> str:
    """Hunt for hardcoded credentials, API keys, and secrets using pattern matching,
    entropy analysis, and proximity to authentication functions. Covers credential
    pairs, base64 blobs, hex-encoded keys, PEM markers, and connection strings."""
    return await safe_get("/find_hardcoded_credentials", {
        "entropy_threshold": str(entropy_threshold),
        "include_low_entropy": include_low_entropy
    })


@mcp.tool()
async def trace_call_path(source: str, sink: str, max_depth: int = 10, max_paths: int = 5) -> str:
    """Find all call paths from a source function to a sink function.
    Core taint analysis primitive: 'Can input from uart_read reach strcpy/system?'
    Performs bounded BFS on the call graph."""
    return await safe_get("/trace_call_path", {
        "source": source, "sink": sink,
        "max_depth": str(max_depth), "max_paths": str(max_paths)
    })


@mcp.tool()
async def find_dangerous_sinks(categories: str = "all") -> str:
    """Locate all calls to dangerous functions (strcpy, sprintf, system, gets, etc.)
    across the entire binary. The standard starting point for vuln research.
    Categories: buffer_overflow, format_string, command_injection, memory, all."""
    return await safe_get("/find_dangerous_sinks", {"categories": categories})


@mcp.tool()
async def find_format_string_vulns(include_snprintf: str = "true") -> str:
    """Find printf-family calls where the format string is NOT a constant literal.
    These are format string vulnerabilities - the format arg comes from a variable
    or parameter that could be attacker-controlled."""
    return await safe_get("/find_format_string_vulns", {"include_snprintf": include_snprintf})


@mcp.tool()
async def detect_rtos() -> str:
    """Identify the Real-Time Operating System (RTOS) used in the firmware.
    Detects FreeRTOS, Zephyr, ThreadX, VxWorks, Mbed OS, RIOT, NuttX, Contiki,
    or bare-metal. Provides analysis hints specific to the detected RTOS."""
    return await safe_get("/detect_rtos")


@mcp.tool()
async def find_function_pointer_tables(min_entries: int = 3) -> str:
    """Scan data regions for arrays of consecutive code pointers - dispatch tables,
    vtables, callback arrays, command handler tables. These define control flow
    that static analysis misses and are critical for understanding firmware architecture."""
    return await safe_get("/find_function_pointer_tables", {"min_entries": str(min_entries)})


@mcp.tool()
async def get_string_clusters(max_gap: int = 64, min_cluster_size: int = 3) -> str:
    """Find groups of spatially close strings in memory. Related strings (command names,
    error messages, menu items) are stored contiguously in firmware. Clustering reveals
    logical modules and subsystems in stripped binaries."""
    return await safe_get("/get_string_clusters", {
        "max_gap": str(max_gap), "min_cluster_size": str(min_cluster_size)
    })


@mcp.tool()
async def get_function_hashes(hash_algorithm: str = "opcode_only", filter_text: str = "", offset: int = 0, limit: int = 200) -> str:
    """Compute structural hashes for functions to enable firmware version diffing.
    Export hashes from two firmware versions and compare: changed hashes = patched
    functions, new hashes = new code, missing hashes = removed code.
    Modes: opcode_only, structural, exact."""
    params = {"hash_algorithm": hash_algorithm, "offset": str(offset), "limit": str(limit)}
    if filter_text: params["filter_text"] = filter_text
    return await safe_get("/get_function_hashes", params)


def parse_args():
    parser = argparse.ArgumentParser(description="FirmwareMCP Bridge")
    parser.add_argument("--ghidra-server", default="http://127.0.0.1:8080",
                        help="URL of the Ghidra plugin HTTP server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                        help="MCP transport mode")
    parser.add_argument("--mcp-host", default="127.0.0.1", help="Host for SSE mode")
    parser.add_argument("--mcp-port", type=int, default=8081, help="Port for SSE mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ghidra_server = args.ghidra_server

    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
