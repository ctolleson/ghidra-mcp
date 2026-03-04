#!/usr/bin/env python3
"""FirmwareMCP Bridge - Connects Claude to Ghidra for firmware reverse engineering."""

import argparse
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FirmwareMCP")
ghidra_server = "http://127.0.0.1:8080"


async def safe_get(path: str, params: dict = None) -> str:
    """GET request to the Ghidra plugin HTTP server."""
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.get(f"{ghidra_server}{path}", params=params)
            resp.raise_for_status()
            return resp.text
    except Exception as e:
        return f"Error: {e}"


async def safe_post(path: str, params: dict = None) -> str:
    """POST request to the Ghidra plugin HTTP server."""
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{ghidra_server}{path}", params=params)
            resp.raise_for_status()
            return resp.text
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
