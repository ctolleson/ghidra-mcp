"""Static chip database for mapping IoT MCU identifiers to Ghidra-relevant specs."""

from __future__ import annotations

import re
from typing import Any

CHIP_DB: dict[str, dict[str, Any]] = {
    "ESP8266EX": {
        "architecture": "xtensa",
        "endianness": "little",
        "ghidra_language": "Xtensa:LE:32:default",
        "flash_base": "0x40200000",
        "radios": ["WiFi 2.4GHz 802.11 b/g/n"],
        "notes": "ESP8266 flash cached region starts at 0x40200000.",
    },
    "ESP32-WROOM-32": {
        "architecture": "xtensa_lx6",
        "endianness": "little",
        "ghidra_language": "Xtensa:LE:32:default",
        "flash_base": "0x400C0000",
        "radios": ["WiFi 2.4GHz", "Bluetooth 4.2/BLE"],
        "notes": "Dual-core LX6, flash cache at 0x400C0000.",
    },
    "ESP32-S3": {
        "architecture": "xtensa_lx7",
        "endianness": "little",
        "ghidra_language": "Xtensa:LE:32:default",
        "flash_base": "0x42000000",
        "radios": ["WiFi 2.4GHz", "BLE 5.0"],
        "notes": "LX7 cores, flash mapped at 0x42000000.",
    },
    "ESP32-C3": {
        "architecture": "riscv",
        "endianness": "little",
        "ghidra_language": "RISCV:LE:32:RV32I",
        "flash_base": "0x42000000",
        "radios": ["WiFi 2.4GHz", "BLE 5.0"],
        "notes": "RISC-V single-core, flash at 0x42000000.",
    },
    "NRF52832": {
        "architecture": "arm_cortex_m4",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x00000000",
        "radios": ["BLE 5.0", "2.4GHz proprietary"],
        "notes": "Nordic Cortex-M4, flash at 0x00000000.",
    },
    "NRF52840": {
        "architecture": "arm_cortex_m4",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x00000000",
        "radios": ["BLE 5.0", "Thread", "Zigbee", "2.4GHz proprietary"],
        "notes": "Nordic Cortex-M4F with multiprotocol radio.",
    },
    "STM32F407": {
        "architecture": "arm_cortex_m4",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x08000000",
        "radios": [],
        "notes": "ST Cortex-M4F, flash at 0x08000000. Requires external radio.",
    },
    "STM32L4": {
        "architecture": "arm_cortex_m4",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x08000000",
        "radios": [],
        "notes": "ST low-power Cortex-M4, flash at 0x08000000.",
    },
    "CC2640R2F": {
        "architecture": "arm_cortex_m3",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x00000000",
        "radios": ["BLE 5.0"],
        "notes": "TI SimpleLink BLE Cortex-M3.",
    },
    "RTL8710": {
        "architecture": "arm_cortex_m3",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x08000000",
        "radios": ["WiFi 2.4GHz"],
        "notes": "Realtek Ameba WiFi SoC.",
    },
    "BCM43438": {
        "architecture": "arm_cortex_m3",
        "endianness": "little",
        "ghidra_language": "ARM:LE:32:Cortex",
        "flash_base": "0x00000000",
        "radios": ["WiFi 2.4GHz", "BLE"],
        "notes": "Broadcom/Cypress combo WiFi+BLE.",
    },
}

# Patterns used to detect chip identifiers in text extracted from PDFs or HTML.
# Each pattern maps matched text to a canonical CHIP_DB key.
_CHIP_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bESP8266(?:EX|-?\d+)?\b", re.IGNORECASE), "ESP8266EX"),
    (re.compile(r"\bESP[-_]?12[A-Z]?\b", re.IGNORECASE), "ESP8266EX"),
    (re.compile(r"\bESP32[-_]?WROOM[-_]?32\b", re.IGNORECASE), "ESP32-WROOM-32"),
    (re.compile(r"\bESP32[-_]?S3\b", re.IGNORECASE), "ESP32-S3"),
    (re.compile(r"\bESP32[-_]?C3\b", re.IGNORECASE), "ESP32-C3"),
    (re.compile(r"\bnRF52832\b", re.IGNORECASE), "NRF52832"),
    (re.compile(r"\bnRF52840\b", re.IGNORECASE), "NRF52840"),
    (re.compile(r"\bSTM32F40[57]\b", re.IGNORECASE), "STM32F407"),
    (re.compile(r"\bSTM32L4[A-Z0-9]*\b", re.IGNORECASE), "STM32L4"),
    (re.compile(r"\bCC2640(?:R2F)?\b", re.IGNORECASE), "CC2640R2F"),
    (re.compile(r"\bRTL87(?:10|11)[A-Z0-9]*\b", re.IGNORECASE), "RTL8710"),
    (re.compile(r"\bBCM4343[0-9A-Z]*\b", re.IGNORECASE), "BCM43438"),
    (re.compile(r"\bCYW43438\b", re.IGNORECASE), "BCM43438"),
]

# Flash chip patterns — not a full MCU match, but useful evidence.
_FLASH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bW25Q[0-9]{2,3}[A-Z]*\b", re.IGNORECASE),
    re.compile(r"\bMX25L[0-9]{3,4}[A-Z]*\b", re.IGNORECASE),
    re.compile(r"\bGD25Q[0-9]{2,3}[A-Z]*\b", re.IGNORECASE),
]


def match_chips_in_text(text: str) -> tuple[list[str], list[str]]:
    """Scan text for chip identifiers.

    Returns (mcu_keys, flash_mentions). mcu_keys are canonical CHIP_DB keys;
    flash_mentions are the raw matched strings.
    """
    if not text:
        return [], []

    mcus: list[str] = []
    seen: set[str] = set()
    for pattern, key in _CHIP_PATTERNS:
        if pattern.search(text) and key not in seen:
            mcus.append(key)
            seen.add(key)

    flashes: list[str] = []
    flash_seen: set[str] = set()
    for pattern in _FLASH_PATTERNS:
        for match in pattern.findall(text):
            upper = match.upper()
            if upper not in flash_seen:
                flashes.append(upper)
                flash_seen.add(upper)

    return mcus, flashes
