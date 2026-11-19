# PidGenX Minimal Patch Documentation

This document describes the **PidGenX Minimal Patch**, which modifies Microsoft's `pidgenx.dll` (used in Windows product key validation) to expose decoded key parameters—specifically the **Decoded M/ActData** and **Algorithm GUID**—directly through the DPID output buffers (`m_abCdKey`), alongside the **Overlap Patch** (credited to **WA**).

---

## Overview & Architecture

During product key validation, `pidgenx.dll` parses, decodes, and validates keys using internal structures (`PID_OBJ` and `MSFT_PKEY_DATA`). By default, certain decoded fields are kept internal. This patch alters specific offset instructions in x86, x64, and ARM64 binaries so that these cryptographic and licensing parameters are copied into the DPID return structures, and includes the Overlap patch to adjust conditional jump behavior during validation.

### Mapped DPID Offsets & Patch Targets
- **DPID4 + `0x328` (`m_abCdKey`)**: Receives the decoded **M / ActData** (containing flags, upgrade status, serial numbers, and security components).
- **DPID3 + `0x34` (`m_abCdKey`)**: Receives the **Algorithm GUID** (identifying whether the key uses the 2005, 2009, or legacy verification algorithm).
- **Overlap Patch (`jbe` adjustment)**: Modifies the `0F 86` conditional branch target bytes (`[?? ?? FF FF]` on x64 and `[?? ??] 00 00` on x86) to zero out the relative displacement (`00 00 00 00` on x64 and `[00 00] 00 00` on x86), targeting the first match.

---

## Internal Structures Reference

For developers analyzing the binary or writing tools to consume the patched output, the underlying internal layout is detailed below:

### `MSFT_PKEY_DATA` (Size: `0x58` bytes)
Shared across 2005 and 2009 validation schemas.

| Offset | Field | Description |
| :--- | :--- | :--- |
| `0x00` | `Reserved` | Reserved / `0` |
| `0x08` | `Algorithm` | Algorithm GUID (constant per algorithm class) |
| `0x18` | `GroupID` | Group ID |
| `0x1C` | `serialLow` | Channel (`fullSerial / 1,000,000`) |
| `0x20` | `SerialHigh` | Sequence (`fullSerial % 1,000,000`) |
| `0x24` | `LicenseFlags` | License flags (bit 0 = upgrade) |
| `0x28` | `Security` | Security value |
| `0x30` | `HaveRawKey` | Populated status flag |
| `0x34` | `Solved` | Validation success flag (`0` = pending/invalid, `1` = success) |
| `0x38` | `RawKeyMaterial[16]` | Base-24 decoded raw key material |
| `0x48` | `DecodedM / ActData` | Variable union slot (Legacy, 2005 M, or 2009 ActData) |

---

## Patch Definitions

### x64 Architecture Patches
- **DPID4 (Decoded M/ActData -> `0x328`, First one)**
  - **Search Pattern:** `0F 10 ?? 58 48 8D` (Wildcards: `44, 45, 46, 47`)
  - **Replacement:** `0F 10 ?? 68 48 8D` (Wildcards: `44, 45, 46, 47`; changes offset byte from `0x58` to `0x68`)
- **DPID3 (Algorithm GUID -> `0x34`, First one)**
  - **Search Pattern:** `0F 10 ?? 58 48 B9` (Wildcards: `44, 45, 46, 47`)
  - **Replacement:** `0F 10 ?? 28 48 B9` (Wildcards: `44, 45, 46, 47`; changes offset byte from `0x58` to `0x28`)
- **Overlap Patch (`jbe ?? -> nop`, First one)**
  - **Search Pattern:** `0F 86 [?? ?? FF FF]`
  - **Replacement:** `0F 86 [00 00 00 00]`

### x86 Architecture Patches
- **DPID4 (Decoded M/ActData -> `0x328`, First one)**
  - **Search Pattern:** `8D 76 50` (Exact Match)
  - **Replacement:** `8D 76 60` (Changes offset byte from `0x50` to `0x60`)
- **DPID3 (Algorithm GUID -> `0x34`, First one)**
  - **Search Pattern:** `8D 77 50` (Exact Match)
  - **Replacement:** `8D 77 20` (Changes offset byte from `0x50` to `0x20`)
- **Overlap Patch (`jbe ?? -> nop`, First one)**
  - **Search Pattern:** `0F 86 [?? ??] 00 00`
  - **Replacement:** `0F 86 [00 00] 00 00`

### ARM64 Architecture Patches
- **DPID4 (Decoded M/ActData -> `0x328`, First one)**
  - **Search Pattern:** `?? 82 C5 3C 88 A2 0C 91` (`ldur q?,[x21,#0x58]; add x8,x20,#0x328`)
  - **Replacement:** `?? 82 C6 3C 88 A2 0C 91` (`ldur q?,[x21,#0x68]; add x8,x20,#0x328`; `x2 hits`)
- **DPID3 (Algorithm GUID -> `0x34`, First one)**
  - **Search Pattern:** `?? 82 C5 3C 68 08 00 58 ?? 42 83 3C` (`ldur q?,[x21,#0x58]; ldr x8,#lit; stur q?,[x20,#0x34]`)
  - **Replacement:** `?? 82 C2 3C 68 08 00 58 ?? 42 83 3C` (`ldur q?,[x21,#0x28]; ldr x8,#lit; stur q?,[x20,#0x34]`; `x2 hits`)

---

## Credits
- **WA** — Original Overlap patch
