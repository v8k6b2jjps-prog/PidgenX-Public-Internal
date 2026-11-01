// ============================================================================
//  MSFT_PKEY_DATA — 0x58 bytes.  Shared by 2005 and 2009.
//  Layout is identical on x86 and x64 (no pointers inside).
//  Begins at PID_OBJ+0x20 (x64) / PID_OBJ+0x18 (x86).
//  Decoder writes it in place via &obj->Data.
// ============================================================================

typedef struct _MSFT_PKEY_DATA {       // size = 0x58 (both arches)
    uint64_t Reserved;                 // 0x00  = 0
    GUID     Algorithm;                // 0x08  2009:{660672EF-7809-4CFD-8D54-41B7FB738988}
                                       //       2005:{B8731595-A2F6-430B-A799-FBFFB81A8D73}
                                       //        986:{2B864AA3-A736-4D50-8604-EBB3BD7D7C61}
                                       //        985:{9F44BF99-4976-4BFD-B00A-A8AEFBA45484}
                                       //        980:{35BFEDB3-9131-4F58-9D9A-5B32D10F50E0}
                                       //   constant per algorithm (GetClsidAlgorithm);
                                       //   NOT key-specific, NOT the ProductId ActConfigId GUID
    uint32_t GroupID;                  // 0x18
    uint32_t serialLow;                // 0x1C  channel  = fullSerial / 1_000_000
    uint32_t SerialHigh;               // 0x20  sequence = fullSerial % 1_000_000
    uint32_t LicenseFlags;             // 0x24  bit0 = upgrade
    uint64_t Security;                 // 0x28
    uint32_t HaveRawKey;               // 0x30  1 once RawKeyMaterial@0x38 is populated (set early, both algos)
    uint32_t Solved;                   // 0x34  0 until validation succeeds; 1 on success
                                       //       (2005: 0 through pipeline → 1 after MITM; 2009: 1 at parse;
                                       //        stays 0 on an invalid key)
    uint8_t  RawKeyMaterial[16];       // 0x38  base-24 decoded, group-first
    union {                            // 0x48  16-byte slot (consumed by sub_180015728 for output)
        uint8_t  Legacy[4];            //  9XX : upgrade | serial<<1                       [In] 31  bits, [Out] 12 bytes, sub_18008D4E0
        uint8_t  DecodedM[6];          //  2005: upgrade | serial<<1 | (sec & 0x3FF)<<31   [In] 41  bits, [Out] 12 bytes, sub_18008DA70 = sub_18008D4E0 + sec merge; M via sub_180090ADC
        uint8_t  ActData[13];          //  2009: upgrade | serial<<1 | group<<31 | sec<<51 [In] 104 bits, [Out] 13 bytes, sub_18008DE60 -> sub_180008A58
                                       //  widths: upgrade=1  serial=30  group=20  sec: 9XX=0, 2005=10, 2009=53
    };
} MSFT_PKEY_DATA;                      // ends 0x58

// ============================================================================
//  PID_OBJ — x64: 0x98 bytes, x86: 0x88 bytes.
//  Embeds MSFT_PKEY_DATA at +0x20 (x64) / +0x18 (x86).
//  The 8-byte difference comes from RefCount (8→4) and ProductIdStr* (8→4).
//
//                        x64 offset    x86 offset
//  ──────────────────────────────────────────────
//  RefCount              0x00 (8B)     0x00 (4B)
//  ProductIdStr*         0x08 (8B)     0x04 (4B)
//  ValidationTime        0x10 (8B)     0x08 (8B)
//  Serial                0x18 (4B)     0x10 (4B)
//  _pad                  0x1C (4B)     0x14 (4B)
//  Data (MSFT_PKEY_DATA) 0x20          0x18
//  ──────────────────────────────────────────────
//
//  Key fields in PID_OBJ terms (Data offset + header):
//
//  MSFT_PKEY_DATA field   Data+off     x64        x86
//  ───────────────────────────────────────────────────
//  Reserved               +0x00        0x20       0x18
//  Algorithm GUID         +0x08        0x28       0x20
//  GroupID                +0x18        0x38       0x30
//  serialLow              +0x1C        0x3C       0x34
//  SerialHigh             +0x20        0x40       0x38
//  LicenseFlags           +0x24        0x44       0x3C
//  Security               +0x28        0x48       0x40
//  HaveRawKey             +0x30        0x50       0x48
//  Solved                 +0x34        0x54       0x4C
//  RawKeyMaterial[16]     +0x38        0x58       0x50
//  DecodedM/ActData       +0x48        0x68       0x60
//  ───────────────────────────────────────────────────
// ============================================================================

typedef struct _PID_OBJ {
#ifdef _WIN64
                                       //         x64          x86
    uint64_t       RefCount;           // 0x00  (8 bytes)
    wchar_t*       ProductIdStr;       // 0x08  (8-byte ptr)
    FILETIME       ValidationTime;     // 0x10  (8 bytes)
    uint32_t       Serial;             // 0x18  (4 bytes)     full un-split serial
    uint32_t       _pad1C;             // 0x1C  (4 bytes)     alignment to 0x20

    MSFT_PKEY_DATA Data;               // 0x20 .. 0x78

    void*    pGroupConfig;             // 0x78 -> group record {flag, ActConfigId GUID, GroupID, sub-ptrs}
    void*    pEditionTable;            // 0x80 -> edition records
    void*    pGroupIndex;              // 0x88 -> master index
    uint64_t ReservedNonce;            // 0x90  8 random bytes from CryptGenRandom (per-object nonce/salt)
                                       // total: 0x98
#else
	
    uint32_t       RefCount;           // 0x00  (4 bytes)
    wchar_t*       ProductIdStr;       // 0x04  (4-byte ptr)
    FILETIME       ValidationTime;     // 0x08  (8 bytes)
    uint32_t       Serial;             // 0x10  (4 bytes)     full un-split serial
    uint32_t       _pad14;             // 0x14  (4 bytes)     alignment to 0x18

    MSFT_PKEY_DATA Data;               // 0x18 .. 0x70

    void*    pGroupConfig;             // 0x70 -> group record
    void*    pEditionTable;            // 0x74 -> edition records
    void*    pGroupIndex;              // 0x78 -> master index
    uint64_t ReservedNonce;            // 0x7C  8 random bytes from CryptGenRandom
                                       // total: 0x84  (may pad to 0x88 for alignment)
#endif
} PID_OBJ;
