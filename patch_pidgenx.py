#!/usr/bin/env python3
"""
PidGenX DLL Patcher
Patches pidgenx DLLs to expose decoded fields through DPID output buffers:
  DPID4+0x328 (m_abCdKey) <- Decoded M/ActData   (Upgrade, Serial, Security)
  DPID3+0x34  (m_abCdKey) <- Algorithm GUID      (pkey2005/pkey2009/legacy)
"""
import sys
import struct
import shutil
from pathlib import Path

# --- Patch definitions ---
# Patch definitions: (mask, search, patch_offset, patch_byte)
# mask: None = exact match, or bytes where 0xFF = must match, 0x00 = wildcard
PATCHES_X64 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        # 0F 10 ?? 58 48 8D — movups xmm0,[reg+58h]; lea ...
        "search": bytes([0x0F, 0x10, 0x00, 0x58, 0x48, 0x8D]),
        "mask":   bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 3,  # byte to change
        "from": 0x58, "to": 0x68,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        # 0F 10 ?? 58 48 B9 — movups xmm0,[reg+58h]; mov rcx,imm
        "search": bytes([0x0F, 0x10, 0x00, 0x58, 0x48, 0xB9]),
        "mask":   bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 3,
        "from": 0x58, "to": 0x28,
    },
}

PATCHES_X86 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        "search": bytes([0x8D, 0x76, 0x50]),
        "mask":   None,  # exact match
        "offset": 2,
        "from": 0x50, "to": 0x60,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        "search": bytes([0x8D, 0x77, 0x50]),
        "mask":   None,
        "offset": 2,
        "from": 0x50, "to": 0x20,
    },
}


def detect_arch(data: bytes) -> str:
    """Detect PE architecture from Optional Header magic."""
    if data[:2] != b"MZ":
        sys.exit("Error: not a valid PE file (no MZ header)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b"PE\x00\x00":
        sys.exit("Error: not a valid PE file (no PE signature)")
    magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    if magic == 0x20B:
        return "x64"
    elif magic == 0x10B:
        return "x86"
    else:
        sys.exit(f"Error: unknown PE magic 0x{magic:X}")


def find_masked(data: bytes, pattern: bytes, mask: bytes) -> list[int]:
    """Find all positions where pattern matches data under mask.
    mask byte 0xFF = must match, 0x00 = wildcard (any byte)."""
    hits = []
    plen = len(pattern)
    for i in range(len(data) - plen + 1):
        ok = True
        for j in range(plen):
            if mask[j] and data[i + j] != pattern[j]:
                ok = False
                break
        if ok:
            hits.append(i)
    return hits


def apply_patches(data: bytearray, patches: dict) -> int:
    """Apply all patches. Returns number of patches applied."""
    applied = 0
    for name, patch in patches.items():
        search = patch["search"]
        mask = patch["mask"]
        off = patch["offset"]
        val_from = patch["from"]
        val_to = patch["to"]

        if mask is not None:
            hits = find_masked(data, search, mask)
        else:
            # Exact match — use fast bytes.find
            hits = []
            pos = 0
            while True:
                pos = data.find(search, pos)
                if pos < 0:
                    break
                hits.append(pos)
                pos += 1

        if len(hits) == 1:
            site = hits[0]
            if data[site + off] == val_from:
                data[site + off] = val_to
                print(f"  {name}: patched at file offset 0x{site:X}  (byte {off}: 0x{val_from:02X} -> 0x{val_to:02X})")
                applied += 1
            elif data[site + off] == val_to:
                print(f"  {name}: already patched, skipping")
            else:
                print(f"  {name}: unexpected byte 0x{data[site+off]:02X} at offset {off} - skipping")
        elif len(hits) > 1:
            print(f"  {name}: ERROR - pattern found {len(hits)} times, expected 1 - skipping")
        else:
            print(f"  {name}: pattern NOT FOUND - skipping")

    return applied


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pidgenx.dll> [output.dll]")
        print("  If output is omitted, saves as <name>_patched.dll")
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.is_file():
        sys.exit(f"Error: file not found: {src}")

    if len(sys.argv) >= 3:
        dst = Path(sys.argv[2])
    else:
        dst = src.with_stem(src.stem + "_patched")

    data = bytearray(src.read_bytes())
    arch = detect_arch(data)
    print(f"File: {src.name}")
    print(f"Arch: {arch}")
    print(f"Size: {len(data)} bytes")
    print()

    patches = PATCHES_X64 if arch == "x64" else PATCHES_X86
    applied = apply_patches(data, patches)

    print()
    if applied > 0:
        dst.write_bytes(data)
        print(f"Saved: {dst}  ({applied} patch(es) applied)")
    else:
        print("No patches applied, output not written.")


if __name__ == "__main__":
    main()
