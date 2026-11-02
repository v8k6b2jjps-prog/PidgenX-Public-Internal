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

# ARM64: ldur q_,[x21,#0x58] — 128-bit NEON unscaled load from PID_OBJ+0x58
# Offset 0x58 encoded in imm9 field, byte[2] of the 4-byte instruction.
# Two copies of each function exist in the DLL (PidGenX / PidGenX2 paths).
PATCHES_ARM64 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        # ldur q?,[x21,#0x58]; add x8,x20,#0x328
        # ?? 82 C5 3C  88 A2 0C 91
        "search": bytes([0x00, 0x82, 0xC5, 0x3C, 0x88, 0xA2, 0x0C, 0x91]),
        "mask":   bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        "offset": 2,  # byte[2] of ldur encodes imm9 offset
        "from": 0xC5, "to": 0xC6,  # imm9: 0x58 -> 0x68
        "expected": 2,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        # ldur q?,[x21,#0x58]; ldr x8,#lit; stur q?,[x20,#0x34]
        # ?? 82 C5 3C  68 08 00 58  ?? 42 83 3C
        "search": bytes([0x00, 0x82, 0xC5, 0x3C, 0x68, 0x08, 0x00, 0x58,
                         0x00, 0x42, 0x83, 0x3C]),
        "mask":   bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 2,
        "from": 0xC5, "to": 0xC2,  # imm9: 0x58 -> 0x28
        "expected": 2,
    },
}


def detect_arch(data: bytes) -> str:
    """Detect PE architecture from COFF machine type + Optional Header magic."""
    if data[:2] != b"MZ":
        sys.exit("Error: not a valid PE file (no MZ header)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b"PE\x00\x00":
        sys.exit("Error: not a valid PE file (no PE signature)")
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    if machine == 0xAA64:
        return "arm64"
    elif magic == 0x20B:
        return "x64"
    elif magic == 0x10B:
        return "x86"
    else:
        sys.exit(f"Error: unknown PE arch (machine=0x{machine:X}, magic=0x{magic:X})")


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

        expected = patch.get("expected", 1)

        # If no hits with original byte, check if already patched
        if len(hits) == 0 and mask is not None:
            patched_search = bytearray(search)
            patched_search[off] = val_to
            check = find_masked(data, bytes(patched_search), mask)
            if len(check) == expected:
                print(f"  {name}: already patched ({expected} site(s)), skipping")
                continue

        if len(hits) == expected:
            patched_this = 0
            for idx, site in enumerate(hits):
                label = f"{name}" if expected == 1 else f"{name} [{idx+1}/{expected}]"
                if data[site + off] == val_from:
                    data[site + off] = val_to
                    print(f"  {label}: patched at file offset 0x{site:X}  (byte {off}: 0x{val_from:02X} -> 0x{val_to:02X})")
                    patched_this += 1
                elif data[site + off] == val_to:
                    print(f"  {label}: already patched, skipping")
                else:
                    print(f"  {label}: unexpected byte 0x{data[site+off]:02X} at offset {off} - skipping")
            applied += patched_this
        elif len(hits) > expected:
            print(f"  {name}: ERROR - pattern found {len(hits)} times, expected {expected} - skipping")
        else:
            print(f"  {name}: pattern NOT FOUND (found {len(hits)}, expected {expected}) - skipping")

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

    if arch == "arm64":
        patches = PATCHES_ARM64
    elif arch == "x64":
        patches = PATCHES_X64
    else:
        patches = PATCHES_X86
    applied = apply_patches(data, patches)

    print()
    if applied > 0:
        dst.write_bytes(data)
        print(f"Saved: {dst}  ({applied} patch(es) applied)")
    else:
        print("No patches applied, output not written.")


if __name__ == "__main__":
    main()
