#!/usr/bin/env python3
"""
PidGenX DLL Patcher
Patches pidgenx DLLs to:
  1. Expose decoded fields through DPID output buffers:
       DPID4+0x328 (m_abCdKey) <- Decoded M/ActData  (Upgrade, Serial, Security)
       DPID3+0x34  (m_abCdKey) <- Algorithm GUID      (pkey2005/pkey2009/legacy)
  2. Neutralize the pkeyconfig range-overlap check (jbe -> nop) so configs with a
     touching/overlapping KeyRange boundary still load (returns S_OK instead of
     0x8A010001 "valid but can't be verified").

Two patch actions are supported per entry:
  - "byte"  : change a single byte from 'from' to 'to' at 'offset'
  - "zero"  : set 'zero_len' bytes starting at 'zero_at' to 0x00 (used for the
              jbe rel32 displacement). Idempotent: re-zeroing is a no-op.
"""
import sys
import struct
from pathlib import Path

# --- Patch definitions ---
# mask: bytes where 0xFF = must match, 0x00 = wildcard (any byte)

PATCHES_X64 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        # 0F 10 ?? 58 48 8D — movups xmm0,[reg+58h]; lea ...
        "search": bytes([0x0F, 0x10, 0x00, 0x58, 0x48, 0x8D]),
        "mask":   bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 3, "from": 0x58, "to": 0x68,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        # 0F 10 ?? 58 48 B9 — movups xmm0,[reg+58h]; mov rcx,imm
        "search": bytes([0x0F, 0x10, 0x00, 0x58, 0x48, 0xB9]),
        "mask":   bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 3, "from": 0x58, "to": 0x28,
    },
    "Overlap check (jbe rel32 -> 0)": {
        # 8B ?? 34  39 ?? 30  0F 86 ?? ?? ?? ??
        #   mov r32,[base+0x34] ; cmp [base+0x30],r32 ; jbe <rel32>
        # Registers (ModRM) vary per build -> wildcarded. rel32 fully wildcarded
        # so it catches both forward (00 00) and backward (FF FF) layouts and is
        # idempotent on an already-patched DLL.
        "search": bytes([0x8B, 0x00, 0x34, 0x39, 0x00, 0x30, 0x0F, 0x86, 0, 0, 0, 0]),
        "mask":   bytes([0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]),
        "zero_at": 8, "zero_len": 4,
    },
}

PATCHES_X86 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        "search": bytes([0x8D, 0x76, 0x50]), "mask": None,
        "offset": 2, "from": 0x50, "to": 0x60,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        "search": bytes([0x8D, 0x77, 0x50]), "mask": None,
        "offset": 2, "from": 0x50, "to": 0x20,
    },
    "Overlap check (jbe rel32 -> 0)": {
        # 8B ?? 24  3B ?? 28  0F 86 ?? ?? ?? ??
        #   mov r32,[base+0x24] ; cmp r32,[base+0x28] ; jbe <rel32>
        "search": bytes([0x8B, 0x00, 0x24, 0x3B, 0x00, 0x28, 0x0F, 0x86, 0, 0, 0, 0]),
        "mask":   bytes([0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]),
        "zero_at": 8, "zero_len": 4,
    },
}

PATCHES_ARM64 = {
    "DPID4 (Decoded M/ActData -> 0x328)": {
        "search": bytes([0x00, 0x82, 0xC5, 0x3C, 0x88, 0xA2, 0x0C, 0x91]),
        "mask":   bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        "offset": 2, "from": 0xC5, "to": 0xC6, "expected": 2,
    },
    "DPID3 (Algorithm GUID -> 0x34)": {
        "search": bytes([0x00, 0x82, 0xC5, 0x3C, 0x68, 0x08, 0x00, 0x58,
                         0x00, 0x42, 0x83, 0x3C]),
        "mask":   bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0x00, 0xFF, 0xFF, 0xFF]),
        "offset": 2, "from": 0xC5, "to": 0xC2, "expected": 2,
    },
    "Overlap check (b.ls -> nop)": {
        # ldr w,[x,#0x34] ; ldr w,[x,#0x30] ; cmp w,w ; b.ls <overlap error>
        #   6B 35 40 B9  4A 31 40 B9  5F 01 0B 6B  ?9 ?? ?? 54
        # The identical 12-byte prefix is shared by the b.ls (overlap, cond=LS=9)
        # AND a b.hi (Start>End, cond=HI=8) right above it, so we pin the condition
        # nibble: byte[12] low nibble must be 9 (LS). byte[15]=0x54 = B.cond.
        # Replace the whole b.ls with NOP so the overlap case falls through.
        # (Zeroing would make b.ls branch to itself = infinite loop.)
        "search": bytes([0x6B, 0x35, 0x40, 0xB9, 0x4A, 0x31, 0x40, 0xB9,
                         0x5F, 0x01, 0x0B, 0x6B, 0x09, 0x00, 0x00, 0x54]),
        "mask":   bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00, 0xFF]),
        "set_at": 12, "set_bytes": bytes([0x1F, 0x20, 0x03, 0xD5]),  # NOP
        "expected": 2,
    },
}


def detect_arch(data: bytes) -> str:
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


def find_masked(data: bytes, pattern: bytes, mask: bytes) -> list:
    """Bitwise masked search: mask byte 0xFF = full match, 0x00 = wildcard,
    partial masks (e.g. 0x0F) match only the selected bits."""
    hits = []
    plen = len(pattern)
    for i in range(len(data) - plen + 1):
        ok = True
        for j in range(plen):
            if (data[i + j] & mask[j]) != (pattern[j] & mask[j]):
                ok = False
                break
        if ok:
            hits.append(i)
    return hits


def _find(data, search, mask):
    if mask is not None:
        return find_masked(data, search, mask)
    hits, pos = [], 0
    while True:
        pos = data.find(search, pos)
        if pos < 0:
            break
        hits.append(pos)
        pos += 1
    return hits


def apply_patches(data: bytearray, patches: dict) -> int:
    applied = 0
    for name, patch in patches.items():
        search, mask = patch["search"], patch["mask"]
        expected = patch.get("expected", 1)
        is_zero = "zero_len" in patch
        is_set = "set_bytes" in patch
        hits = _find(data, search, mask)

        # already-patched detection (search no longer matches once patched)
        if len(hits) < expected and mask is not None:
            probe, pmask = bytearray(search), bytearray(mask)
            if is_set:
                sa, sb = patch["set_at"], patch["set_bytes"]
                probe[sa:sa+len(sb)] = sb
                for i in range(len(sb)):
                    pmask[sa+i] = 0xFF
            elif not is_zero:
                probe[patch["offset"]] = patch["to"]
            if not is_zero and len(find_masked(data, bytes(probe), bytes(pmask))) == expected:
                print(f"  {name}: already patched ({expected} site(s)), skipping")
                continue

        if len(hits) != expected:
            tag = "ERROR -" if len(hits) > expected else "NOT FOUND -"
            print(f"  {name}: {tag} pattern found {len(hits)}x, expected {expected} - skipping")
            continue

        for idx, site in enumerate(hits):
            label = name if expected == 1 else f"{name} [{idx+1}/{expected}]"
            if is_zero:
                za, zl = patch["zero_at"], patch["zero_len"]
                region = data[site+za:site+za+zl]
                if all(b == 0 for b in region):
                    print(f"  {label}: already patched (rel32=0) at 0x{site:X}, skipping")
                else:
                    data[site+za:site+za+zl] = b"\x00" * zl
                    print(f"  {label}: patched at 0x{site:X}  (rel32 {region.hex(' ')} -> 00 00 00 00)")
                    applied += 1
            elif is_set:
                sa, sb = patch["set_at"], patch["set_bytes"]
                cur = bytes(data[site+sa:site+sa+len(sb)])
                if cur == sb:
                    print(f"  {label}: already patched at 0x{site:X}, skipping")
                else:
                    data[site+sa:site+sa+len(sb)] = sb
                    print(f"  {label}: patched at 0x{site:X}  ({cur.hex(' ')} -> {sb.hex(' ')})")
                    applied += 1
            else:
                off, vf, vt = patch["offset"], patch["from"], patch["to"]
                cur = data[site+off]
                if cur == vf:
                    data[site+off] = vt
                    print(f"  {label}: patched at 0x{site:X}  (byte {off}: 0x{vf:02X} -> 0x{vt:02X})")
                    applied += 1
                elif cur == vt:
                    print(f"  {label}: already patched at 0x{site:X}, skipping")
                else:
                    print(f"  {label}: unexpected byte 0x{cur:02X} at offset {off} - skipping")
    return applied


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pidgenx.dll> [output.dll]")
        sys.exit(1)
    src = Path(sys.argv[1])
    if not src.is_file():
        sys.exit(f"Error: file not found: {src}")
    dst = Path(sys.argv[2]) if len(sys.argv) >= 3 else src.with_stem(src.stem + "_patched")

    data = bytearray(src.read_bytes())
    arch = detect_arch(data)
    print(f"File: {src.name}\nArch: {arch}\nSize: {len(data)} bytes\n")

    patches = {"arm64": PATCHES_ARM64, "x64": PATCHES_X64}.get(arch, PATCHES_X86)
    applied = apply_patches(data, patches)

    print()
    if applied > 0:
        dst.write_bytes(data)
        print(f"Saved: {dst}  ({applied} patch(es) applied)")
    else:
        print("No patches applied, output not written.")


if __name__ == "__main__":
    main()
