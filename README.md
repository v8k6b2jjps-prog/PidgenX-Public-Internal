# PidGenX Minimal Patch Documentation

This document describes the **PidGenX Minimal Patch**, which modifies Microsoft's `pidgenx.dll` (used in Windows product key validation) to expose decoded key parameters—specifically the **Decoded M/ActData** and **Algorithm GUID**—directly through the DPID output buffers (`m_abCdKey`)[cite: 1, 3].

---

## Overview & Architecture

During product key validation, `pidgenx.dll` parses, decodes, and validates keys using internal structures (`PID_OBJ` and `MSFT_PKEY_DATA`)[cite: 2]. By default, certain decoded fields are kept internal. This patch alters specific offset instructions in both x86 and x64 binaries so that these cryptographic and licensing parameters are copied into the DPID return structures[cite: 1, 3].

### Mapped DPID Offsets
* **DPID4 + `0x328` (`m_abCdKey`)**: Receives the decoded **M / ActData** (containing flags, upgrade status, serial numbers, and security components)[cite: 1, 2, 3].
* **DPID3 + `0x34` (`m_abCdKey`)**: Receives the **Algorithm GUID** (identifying whether the key uses the 2005, 2009, or legacy verification algorithm)[cite: 1, 2, 3].

---

## Internal Structures Reference

For developers analyzing the binary or writing tools to consume the patched output, the underlying internal layout is detailed below[cite: 2]:

### `MSFT_PKEY_DATA` (Size: `0x58` bytes)
Shared across 2005 and 2009 validation schemas[cite: 2].

| Offset | Field | Description |
| :--- | :--- | :--- |
| `0x00` | `Reserved` | Reserved / `0`[cite: 2] |
| `0x08` | `Algorithm` | Algorithm GUID (constant per algorithm class)[cite: 2] |
| `0x18` | `GroupID` | Group ID[cite: 2] |
| `0x1C` | `serialLow` | Channel (`fullSerial / 1,000,000`)[cite: 2] |
| `0x20` | `SerialHigh` | Sequence (`fullSerial % 1,000,000`)[cite: 2] |
| `0x24` | `LicenseFlags` | License flags (bit 0 = upgrade)[cite: 2] |
| `0x28` | `Security` | Security value[cite: 2] |
| `0x30` | `HaveRawKey` | Populated status flag[cite: 2] |
| `0x34` | `Solved` | Validation success flag (`0` = pending/invalid, `1` = success)[cite: 2] |
| `0x38` | `RawKeyMaterial[16]` | Base-24 decoded raw key material[cite: 2] |
| `0x48` | `DecodedM / ActData` | Variable union slot (Legacy, 2005 M, or 2009 ActData)[cite: 2] |

---

## Patch Definitions

### x64 Architecture Patches
* **DPID4 (Decoded M/ActData -> `0x328`)**[cite: 1, 3]
  * **Search Pattern:** `0F 10 ?? 58 48 8D` (Mask: `FF FF 00 FF FF FF`)[cite: 1, 3]
  * **Modification:** Changes offset byte from `0x58` to `0x68`[cite: 1, 3]
* **DPID3 (Algorithm GUID -> `0x34`)**[cite: 1, 3]
  * **Search Pattern:** `0F 10 ?? 58 48 B9` (Mask: `FF FF 00 FF FF FF`)[cite: 1, 3]
  * **Modification:** Changes offset byte from `0x58` to `0x28`[cite: 1, 3]

### x86 Architecture Patches
* **DPID4 (Decoded M/ActData -> `0x328`)**[cite: 1, 3]
  * **Search Pattern:** `8D 76 50` (Exact Match)[cite: 1, 3]
  * **Modification:** Changes offset byte from `0x50` to `0x60`[cite: 1, 3]
* **DPID3 (Algorithm GUID -> `0x34`)**[cite: 1, 3]
  * **Search Pattern:** `8D 77 50` (Exact Match)[cite: 1, 3]
  * **Modification:** Changes offset byte from `0x50` to `0x20`[cite: 1, 3]
