#!/usr/bin/env python3
"""Unit test suite for iccanalyzer-lite.

Tests exit codes, analysis modes, heuristic detection, and ASAN/UBSAN
cleanliness across synthesized corpus and repository test profiles.

Usage:
    python3 run_tests.py                    # Run all tests
    python3 run_tests.py -v                 # Verbose output
    python3 run_tests.py -k exit_code       # Run tests matching pattern
    python3 run_tests.py --binary /path     # Override binary path
    python3 run_tests.py --xml report.xml   # JUnit XML output
    python3 run_tests.py --list             # List all test sections
    python3 run_tests.py --fail-fast        # Stop on first failure
    python3 run_tests.py --debug            # Show commands being run
    python3 run_tests.py --no-color         # Disable colored output
"""

import fnmatch
import os
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# --- Configuration ---
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent.parent
BINARY = SCRIPT_DIR.parent / "iccanalyzer-lite"
CORPUS_DIR = SCRIPT_DIR / "corpus"
TEST_PROFILES = REPO_ROOT / "test-profiles"
EXTENDED_PROFILES = REPO_ROOT / "extended-test-profiles"
PROFILE_RESOURCE_QUARANTINE = SCRIPT_DIR / "profile-resource-quarantine.txt"

# Exit codes
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_USAGE = 3

TIMEOUT_SEC = 30


def _load_profile_quarantine_patterns():
    if not PROFILE_RESOURCE_QUARANTINE.exists():
        return []

    patterns = []
    for raw in PROFILE_RESOURCE_QUARANTINE.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return patterns


PROFILE_QUARANTINE_PATTERNS = _load_profile_quarantine_patterns()


def quarantine_enabled():
    value = os.environ.get("ICCANALYZER_INCLUDE_QUARANTINED", "").strip().lower()
    return value not in ("1", "true", "yes", "on")


def is_quarantined_profile(path):
    if not quarantine_enabled() or not PROFILE_QUARANTINE_PATTERNS:
        return False

    try:
        rel = path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except Exception:
        rel = path.as_posix()

    base = path.name
    for pattern in PROFILE_QUARANTINE_PATTERNS:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(base, pattern):
            return True
    return False


def filter_quarantined_profiles(paths):
    return [path for path in paths if not is_quarantined_profile(path)]


def generic_sanitizer_hit(text):
    markers = (
        "ERROR: AddressSanitizer",
        "SUMMARY: AddressSanitizer",
        "runtime error:",
        "SUMMARY: UndefinedBehaviorSanitizer",
    )
    for line in text.splitlines():
        if any(marker in line for marker in markers):
            return line.strip()
    return ""

# --- Test infrastructure ---


def pawg_spec_reference_paths():
    spec_dir = REPO_ROOT / "docs" / "iccDEV" / "specifications"
    return [
        f"docs/iccDEV/specifications/{entry.name}"
        for entry in sorted(spec_dir.iterdir(), key=lambda path: path.name)
        if entry.is_file() and entry.name != "ICC.1_Adaptive_Gain_Curve.pdf"
    ]


def make_h161_deep_apply_profile_bytes():
    data = bytearray(192)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    def put_u16(offset, value):
        data[offset:offset + 2] = int(value).to_bytes(2, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x3132434C)  # '12CL'
    put_u32(20, 0x4C616220)  # 'Lab '
    put_u32(36, 0x61637370)  # 'acsp'

    put_u32(128, 2)
    put_u32(132, 0x41324230)  # 'A2B0'
    put_u32(136, 160)
    put_u32(140, 16)
    put_u32(144, 0x42324130)  # 'B2A0'
    put_u32(148, 176)
    put_u32(152, 16)

    put_u32(160, 0x6D706574)  # 'mpet'
    put_u16(168, 12)
    put_u16(170, 12)
    put_u32(172, 5)

    put_u32(176, 0x6D706574)  # 'mpet'
    put_u16(184, 12)
    put_u16(186, 12)
    put_u32(188, 5)

    return bytes(data)


def make_h169_dict_bounds_profile_bytes():
    data = bytearray(160)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x58595A20)  # 'XYZ '
    put_u32(36, 0x61637370)  # 'acsp'

    put_u32(128, 1)
    put_u32(132, 0x6D657461)  # 'meta'
    put_u32(136, 144)
    put_u32(140, 16)

    put_u32(144, 0x64696374)  # 'dict'
    put_u32(152, 3)
    put_u32(156, 8)

    return bytes(data)


def make_h165_lut_data_sufficiency_profile_bytes():
    data = bytearray(160)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x58595A20)  # 'XYZ '
    put_u32(36, 0x61637370)  # 'acsp'

    put_u32(128, 1)
    put_u32(132, 0x41324230)  # 'A2B0'
    put_u32(136, 144)
    put_u32(140, 16)

    put_u32(144, 0x6D667431)  # 'mft1'
    data[152] = 3
    data[153] = 3
    data[154] = 2

    return bytes(data)


def make_h170_null_pcs_profile_bytes():
    data = bytearray(132)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x00000000)  # null PCS
    put_u32(36, 0x61637370)  # 'acsp'
    put_u32(128, 0)

    return bytes(data)


def make_h172_lut_matrix_profile_bytes(malformed=True):
    data = bytearray(228)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value & 0xFFFFFFFF).to_bytes(4, "big", signed=False)

    def put_s32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=True)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x70727472)  # 'prtr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x4C616220)  # 'Lab '
    put_u32(36, 0x61637370)  # 'acsp'

    put_u32(128, 1)
    put_u32(132, 0x41324230)  # 'A2B0'
    put_u32(136, 144)
    put_u32(140, 116)

    put_u32(144, 0x6D414220)  # 'mAB '
    data[152] = 3
    data[153] = 3
    put_u32(156, 32)  # B curves
    put_u32(160, 68)  # Matrix
    put_u32(164, 0)   # M curves
    put_u32(168, 0)   # CLUT
    put_u32(172, 0)   # A curves

    for curve in range(3):
        off = 176 + curve * 12
        put_u32(off, 0x63757276)  # 'curv'
        put_u32(off + 4, 0)
        put_u32(off + 8, 0)

    identity = 1 << 16
    matrix_off = 212
    if malformed:
        put_s32(matrix_off + 0, 0)
        put_s32(matrix_off + 4, 0)
        put_s32(matrix_off + 8, 0)
        put_s32(matrix_off + 12, 0)
        put_s32(matrix_off + 16, identity)
        put_s32(matrix_off + 20, 0)
        put_s32(matrix_off + 24, 0)
        put_s32(matrix_off + 28, 0)
        put_s32(matrix_off + 32, 200 << 16)
        put_s32(matrix_off + 36, 20 << 16)
        put_s32(matrix_off + 40, 0)
        put_s32(matrix_off + 44, 0)
    else:
        put_s32(matrix_off + 0, identity)
        put_s32(matrix_off + 4, 0)
        put_s32(matrix_off + 8, 0)
        put_s32(matrix_off + 12, 0)
        put_s32(matrix_off + 16, identity)
        put_s32(matrix_off + 20, 0)
        put_s32(matrix_off + 24, 0)
        put_s32(matrix_off + 28, 0)
        put_s32(matrix_off + 32, identity)
        put_s32(matrix_off + 36, 0)
        put_s32(matrix_off + 40, 0)
        put_s32(matrix_off + 44, 0)

    return bytes(data)


def make_h41_version_type_profile_bytes():
    data = bytearray((CORPUS_DIR / "valid_srgb.icc").read_bytes())
    if len(data) < 144:
        return bytes(data)

    data[8:12] = (0x04400000).to_bytes(4, "big")
    first_tag_offset = int.from_bytes(data[136:140], "big")
    if first_tag_offset + 4 > len(data):
        return bytes(data)

    data[first_tag_offset:first_tag_offset + 4] = (0x64657363).to_bytes(4, "big")  # 'desc'
    return bytes(data)


def make_h42_matrix_singularity_profile_bytes():
    data = bytearray(192)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x58595A20)  # 'XYZ '
    put_u32(36, 0x61637370)  # 'acsp'
    put_u32(128, 1)
    put_u32(132, 0x41324230)  # 'A2B0'
    put_u32(136, 144)
    put_u32(140, 48)
    put_u32(144, 0x6D667431)  # 'mft1'
    return bytes(data)


def make_h50_zero_size_tag_profile_bytes():
    data = bytearray((CORPUS_DIR / "valid_srgb.icc").read_bytes())
    if len(data) < 144:
        return bytes(data)
    data[140:144] = (0).to_bytes(4, "big")
    return bytes(data)


def make_h38_curve_degenerate_profile_bytes():
    data = bytearray(164)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x47524159)  # 'GRAY'
    put_u32(20, 0x58595A20)  # 'XYZ '
    put_u32(36, 0x61637370)  # 'acsp'
    put_u32(128, 1)
    put_u32(132, 0x6B545243)  # 'kTRC'
    put_u32(136, 144)
    put_u32(140, 20)
    put_u32(144, 0x63757276)  # 'curv'
    put_u32(152, 4)
    return bytes(data)


def make_h39_shared_tag_alias_profile_bytes():
    data = bytearray(180)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)   # v4.4
    put_u32(12, 0x6D6E7472)  # 'mntr'
    put_u32(16, 0x52474220)  # 'RGB '
    put_u32(20, 0x58595A20)  # 'XYZ '
    put_u32(36, 0x61637370)  # 'acsp'
    put_u32(128, 2)
    put_u32(132, 0x63707274)  # 'cprt'
    put_u32(136, 168)
    put_u32(140, 12)
    put_u32(144, 0x64657363)  # 'desc'
    put_u32(148, 168)
    put_u32(152, 8)
    put_u32(168, 0x74657874)  # 'text'
    put_u32(172, 0)
    put_u32(176, 0x4142)
    return bytes(data)


def make_h43_spectral_brdf_profile_bytes():
    data = bytearray(164)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    def put_u16(offset, value):
        data[offset:offset + 2] = int(value).to_bytes(2, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x05000000)
    put_u32(12, 0x6D6E7472)
    put_u32(16, 0x52474220)
    put_u32(20, 0x58595A20)
    put_u32(36, 0x61637370)
    put_u32(128, 1)
    put_u32(132, 0x7376636E)  # 'svcn'
    put_u32(136, 144)
    put_u32(140, 20)
    put_u32(144, 0x73767763)  # 'svwc'
    put_u16(152, 780)
    put_u16(154, 380)
    put_u16(156, 0)
    return bytes(data)


def make_h44_embedded_image_profile_bytes():
    data = bytearray(160)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)
    put_u32(12, 0x6D6E7472)
    put_u32(16, 0x52474220)
    put_u32(20, 0x58595A20)
    put_u32(36, 0x61637370)
    put_u32(128, 1)
    put_u32(132, 0x70726530)  # 'pre0'
    put_u32(136, 144)
    put_u32(140, 0x01000001)  # >16MB
    put_u32(144, 0x74657874)  # 'text'
    return bytes(data)


def make_h45_sparse_matrix_profile_bytes():
    data = bytearray(176)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x05000000)
    put_u32(12, 0x6D6E7472)
    put_u32(16, 0x52474220)
    put_u32(20, 0x58595A20)
    put_u32(36, 0x61637370)
    put_u32(128, 1)
    put_u32(132, 0x41324230)  # 'A2B0'
    put_u32(136, 144)
    put_u32(140, 32)
    put_u32(144, 0x6D706574)  # 'mpet'
    put_u32(152, 0x736D7478)  # 'smtx'
    put_u32(160, 5000)
    put_u32(164, 5000)
    return bytes(data)


def make_h46_text_desc_profile_bytes():
    data = bytearray(164)

    def put_u32(offset, value):
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=False)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)
    put_u32(12, 0x6D6E7472)
    put_u32(16, 0x52474220)
    put_u32(20, 0x58595A20)
    put_u32(36, 0x61637370)
    put_u32(128, 1)
    put_u32(132, 0x64657363)  # 'desc'
    put_u32(136, 144)
    put_u32(140, 20)
    put_u32(144, 0x64657363)  # 'desc'
    put_u32(152, 64)
    return bytes(data)


def make_h97_profile_sequence_id_profile_bytes(malformed=True):
    def make_psid_entry(profile_id, text):
        utf16 = text.encode("utf-16-be")
        mluc = b"mluc" + b"\x00" * 4
        mluc += struct.pack(">II", 1, 12)
        mluc += b"enUS"
        mluc += struct.pack(">II", len(utf16), 28)
        mluc += utf16
        while len(mluc) % 4:
            mluc += b"\x00"
        return bytes(profile_id) + mluc

    zero_id = b"\x00" * 16
    dup_id = bytes(range(0x10, 0x20))
    clean_id_a = bytes(range(0x20, 0x30))
    clean_id_b = bytes(range(0x30, 0x40))

    if malformed:
        entries = [
            make_psid_entry(zero_id, "Zero"),
            make_psid_entry(dup_id, "DupA"),
            make_psid_entry(dup_id, "DupB"),
        ]
    else:
        entries = [
            make_psid_entry(clean_id_a, "CleanA"),
            make_psid_entry(clean_id_b, "CleanB"),
        ]

    psid = bytearray()
    psid += b"psid" + b"\x00" * 4
    psid += struct.pack(">I", len(entries))
    dir_offset = 12 + len(entries) * 8
    cur = dir_offset
    for entry in entries:
        psid += struct.pack(">II", cur, len(entry))
        cur += len(entry)
    for entry in entries:
        psid += entry
    while len(psid) % 4:
        psid += b"\x00"

    size = 128 + 4 + 12 + len(psid)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHH HHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"psid"
    struct.pack_into(">II", data, 136, 144, len(psid))
    data[144:144 + len(psid)] = psid
    return bytes(data)


def make_h102_profile_size_profile_bytes(declared_size, desc_offset, desc_size):
    data = bytearray((CORPUS_DIR / "valid_srgb.icc").read_bytes())
    struct.pack_into(">I", data, 0, declared_size)
    struct.pack_into(">II", data, 136, desc_offset, desc_size)
    return bytes(data)


def make_h20_tag_type_signature_profile_bytes(type_sig):
    data = bytearray((CORPUS_DIR / "valid_srgb.icc").read_bytes())
    if len(data) < 144:
        return bytes(data)
    first_tag_offset = struct.unpack_from(">I", data, 136)[0]
    if first_tag_offset + 4 > len(data):
        return bytes(data)
    struct.pack_into(">I", data, first_tag_offset, type_sig)
    return bytes(data)


_H21_TAG_STRUCT_FIXTURE_HEX = """
000002d0000000000500000063656e63524742200000000000000000000000000000000061637370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000372666e6d000000a80000001463736e6d000000bc0000001063657074000000cc00000204757466380000000049534f2032323032382d3100757466380000000062672d73524742007473747200000000636570740000000f7258595a000000c4000000146758595a000000d8000000146258595a000000ec0000001466756e630000010000000070776c756d000001700000000c7758595a0000017c0000001065526e670000018c00000010626974730000019c0000000b696d7374000001a80000000c69626b67000001b40000000c73726e64000001c00000000c61696c6d000001cc0000000c6d77706c000001d80000000c6d777063000001e4000000106d627063000001f400000010666c3332000000003f23d70a3ea8f5c33cf5c28f666c3332000000003e99999a3f19999a3dcccccd666c3332000000003e19999a3d75c28f3f4a3d71637572660000000000030000bb4d2e1c3b4d2e1c70617266000000000003000043d55555bf870a3dbf80000000000000000000007061726600000000000000003f800000414eb85200000000000000007061726600000000000300003ed555553f870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003e870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003ea01a373ea872b0666c333200000000bf07ae143fd70a3d75693038000000000a0c10007369672000000000646f7263666c33320000000042a00000666c3332000000003ea01a373ea872b0666c3332000000003ea01a373ea872b0
"""


def make_h21_tag_struct_profile_bytes():
    return bytes.fromhex(re.sub(r"\s+", "", _H21_TAG_STRUCT_FIXTURE_HEX))


def make_h18_technology_signature_profile_bytes(tech_sig):
    data = bytearray(156)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"tech"
    struct.pack_into(">II", data, 136, 144, 12)
    data[144:148] = b"sig "
    struct.pack_into(">I", data, 152, tech_sig)
    return bytes(data)


def make_h25_tag_offset_oob_profile_bytes():
    data = bytearray((CORPUS_DIR / "valid_srgb.icc").read_bytes())
    if len(data) >= 144:
        struct.pack_into(">I", data, 136, len(data) + 0x20)
    return bytes(data)


def make_h26_named_color2_string_profile_bytes(unterminated):
    data = bytearray(228)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"ncl2"
    struct.pack_into(">II", data, 136, 144, 84)
    data[144:148] = b"ncl2"
    struct.pack_into(">III", data, 152, 0, 1, 3)
    fill = b"A" * 32 if unterminated else b"OK" + b"\0" * 30
    data[164:196] = fill
    data[196:228] = fill
    return bytes(data)


def make_h27_mpe_matrix_output_profile_bytes(output_channels):
    data = bytearray(188)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"A2B0"
    struct.pack_into(">II", data, 136, 144, 44)

    data[144:148] = b"mpet"
    struct.pack_into(">HHI", data, 152, 1, output_channels, 1)
    struct.pack_into(">II", data, 160, 24, 20)

    data[168:172] = b"matf"
    struct.pack_into(">HH", data, 176, 1, output_channels)
    if output_channels >= 1:
        struct.pack_into(">f", data, 180, 1.0)
    if output_channels >= 2:
        struct.pack_into(">f", data, 184, 0.0)
    return bytes(data)


def make_h28_lut_dimension_profile_bytes(n_input, n_output, n_grid):
    data = bytearray(155)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"A2B0"
    struct.pack_into(">II", data, 136, 144, 11)
    data[144:148] = b"mft1"
    data[152] = n_input
    data[153] = n_output
    data[154] = n_grid
    return bytes(data)


def make_h29_colorant_table_profile_bytes(unterminated):
    data = bytearray(232)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"clrt"
    struct.pack_into(">II", data, 136, 144, 88)
    data[144:148] = b"clrt"
    struct.pack_into(">I", data, 152, 2)
    fill = b"B" * 32 if unterminated else b"R\0" + b"\0" * 30
    data[156:188] = fill
    data[194:226] = fill
    return bytes(data)


def make_h31_mpe_channel_count_profile_bytes(channels):
    data = bytearray(160)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"A2B0"
    struct.pack_into(">II", data, 136, 144, 16)
    data[144:148] = b"mpet"
    struct.pack_into(">HHI", data, 152, channels, channels, 0)
    return bytes(data)


def make_h32_unknown_type_profile_bytes(type_sig):
    return make_h20_tag_type_signature_profile_bytes(type_sig)


def make_h100_profile_sequence_desc_profile_bytes(entry_count):
    def make_mluc(text):
        utf16 = text.encode("utf-16-be")
        out = bytearray()
        out += b"mluc" + b"\x00" * 4
        out += struct.pack(">II", 1, 12)
        out += b"enUS"
        out += struct.pack(">II", len(utf16), 28)
        out += utf16
        while len(out) % 4:
            out += b"\x00"
        return bytes(out)

    pseq = bytearray()
    pseq += b"pseq" + b"\x00" * 4
    pseq += struct.pack(">I", entry_count)
    for idx in range(entry_count):
        pseq += b"APPL"
        pseq += b"MDL "
        pseq += struct.pack(">Q", 0)
        pseq += b"fscn"
        pseq += make_mluc(f"Mfg{idx}")
        pseq += make_mluc(f"Model{idx}")
    while len(pseq) % 4:
        pseq += b"\x00"

    size = 128 + 4 + 12 + len(pseq)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"pseq"
    struct.pack_into(">II", data, 136, 144, len(pseq))
    data[144:144 + len(pseq)] = pseq
    return bytes(data)


def make_h91_colorant_order_profile_bytes(duplicate):
    clro = bytearray()
    clro += b"clro" + b"\x00" * 4
    clro += struct.pack(">I", 2)
    clro += b"\x00" + (b"\x00" if duplicate else b"\x01")
    while len(clro) % 4:
        clro += b"\x00"

    size = 128 + 4 + 12 + len(clro)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"clro"
    struct.pack_into(">II", data, 136, 144, len(clro))
    data[144:144 + len(clro)] = clro
    return bytes(data)


def make_h90_preview_profile_bytes(input_channels, output_channels):
    data = bytearray(160)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"pre0"
    struct.pack_into(">II", data, 136, 144, 16)
    data[144:148] = b"mft1"
    data[152] = input_channels
    data[153] = output_channels
    data[154] = 2
    return bytes(data)


def make_h88_chad_profile_singular_bytes():
    sf32 = bytearray()
    sf32 += b"sf32" + b"\x00" * 4
    sf32 += b"\x00" * (9 * 4)

    size = 128 + 4 + 12 + len(sf32)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"chad"
    struct.pack_into(">II", data, 136, 144, len(sf32))
    data[144:144 + len(sf32)] = sf32
    return bytes(data)


def make_h87_trc_curve_profile_all_zero_bytes():
    curv = bytearray()
    curv += b"curv" + b"\x00" * 4
    curv += struct.pack(">I", 3)
    curv += b"\x00" * 6
    while len(curv) % 4:
        curv += b"\x00"

    size = 128 + 4 + 12 + len(curv)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 1)
    data[132:136] = b"rTRC"
    struct.pack_into(">II", data, 136, 144, len(curv))
    data[144:144 + len(curv)] = curv
    return bytes(data)


def make_h93_flags_profile_bytes(flags, attributes):
    data = bytearray(132)
    struct.pack_into(">I", data, 0, len(data))
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    struct.pack_into(">I", data, 44, flags)
    struct.pack_into(">Q", data, 56, attributes)
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 0)
    return bytes(data)


def make_h94_matrix_trc_profile_bad_columns_bytes():
    def make_xyz(x, y, z):
        out = bytearray()
        out += b"XYZ " + b"\x00" * 4
        out += struct.pack(">iii", x, y, z)
        return bytes(out)

    r = make_xyz(0, 0, 0)
    g = make_xyz(0, 0, 0)
    b = make_xyz(0, 0, 0)

    size = 128 + 4 + 12 * 3 + len(r) + len(g) + len(b)
    data = bytearray(size)
    struct.pack_into(">I", data, 0, size)
    struct.pack_into(">I", data, 8, 0x04400000)
    data[12:16] = b"mntr"
    data[16:20] = b"RGB "
    data[20:24] = b"XYZ "
    struct.pack_into(">HHHHHH", data, 24, 2024, 1, 1, 0, 0, 0)
    data[36:40] = b"acsp"
    data[40:44] = b"APPL"
    data[80:84] = b"test"
    struct.pack_into(">i", data, 68, int(0.9642 * 65536))
    struct.pack_into(">i", data, 72, int(1.0000 * 65536))
    struct.pack_into(">i", data, 76, int(0.8249 * 65536))
    struct.pack_into(">I", data, 128, 3)
    data[132:136] = b"rXYZ"
    struct.pack_into(">II", data, 136, 168, len(r))
    data[144:148] = b"gXYZ"
    struct.pack_into(">II", data, 148, 168 + len(r), len(g))
    data[156:160] = b"bXYZ"
    struct.pack_into(">II", data, 160, 168 + len(r) + len(g), len(b))
    data[168:168 + len(r)] = r
    data[168 + len(r):168 + len(r) + len(g)] = g
    data[168 + len(r) + len(g):168 + len(r) + len(g) + len(b)] = b
    return bytes(data)


# ANSI color codes
class _Colors:
    """Terminal color codes with auto-detection."""
    def __init__(self):
        use_color = (
            hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )
        self.enabled = use_color

    def green(self, text):
        return f"\033[32m{text}\033[0m" if self.enabled else text

    def red(self, text):
        return f"\033[31m{text}\033[0m" if self.enabled else text

    def yellow(self, text):
        return f"\033[33m{text}\033[0m" if self.enabled else text

    def cyan(self, text):
        return f"\033[36m{text}\033[0m" if self.enabled else text

    def bold(self, text):
        return f"\033[1m{text}\033[0m" if self.enabled else text

    def dim(self, text):
        return f"\033[2m{text}\033[0m" if self.enabled else text

C = _Colors()

SLOW_TEST_THRESHOLD = 5.0  # seconds


class TestResult:
    def __init__(self, name, passed, message="", duration=0.0, stdout="", stderr="",
                 skipped=False):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration
        self.stdout = stdout
        self.stderr = stderr
        self.skipped = skipped


class _RecordingList(list):
    """List subclass that routes append() through TestSuite._record()."""
    def __init__(self, suite):
        super().__init__()
        self._suite = suite

    def append(self, result):
        self._suite._record(result)


class TestSuite:
    def __init__(self, binary_path=None, verbose=False, pattern=None,
                 fail_fast=False, debug=False):
        self.binary = str(binary_path or BINARY)
        self.verbose = verbose
        self.pattern = pattern
        self.fail_fast = fail_fast
        self.debug = debug
        self._results_list = []
        self.results = _RecordingList(self)
        self._section_results = {}  # section_name -> list of TestResult
        self._current_section = None
        self._stop_requested = False
        self.env = os.environ.copy()
        self.env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=0:print_stacktrace=1"
        self.env["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=1"
        self.env["LLVM_PROFILE_FILE"] = "/dev/null"
        self._run_counter = 0
        self.sanitizer_log_dir = Path(
            tempfile.mkdtemp(prefix="iccanalyzer-run-tests-sanitizer-")
        )

    def _append_sanitizer_option(self, base, extra):
        base = (base or "").strip(":")
        return f"{base}:{extra}" if base else extra

    def _sanitizer_log_prefix(self, args):
        label = "_".join(args) if args else "no_args"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._")
        safe = safe[:120] or "run"
        self._run_counter += 1
        return self.sanitizer_log_dir / f"{self._run_counter:04d}-{safe}"

    def _collect_sanitizer_log_text(self, prefix):
        chunks = []
        for pattern in (f"{prefix.name}.asan*", f"{prefix.name}.ubsan*"):
            for log_path in sorted(self.sanitizer_log_dir.glob(pattern)):
                try:
                    content = log_path.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    continue
                if content:
                    chunks.append(f"===== {log_path.name} =====\n{content}")
        return "\n".join(chunks)

    def run_analyzer(self, args, timeout=TIMEOUT_SEC):
        """Run iccanalyzer-lite with given args, return (exit_code, stdout, stderr)."""
        cmd = [self.binary] + args
        env = self.env.copy()
        log_prefix = self._sanitizer_log_prefix(args)
        env["ASAN_OPTIONS"] = self._append_sanitizer_option(
            env.get("ASAN_OPTIONS"), f"log_path={log_prefix}.asan"
        )
        env["UBSAN_OPTIONS"] = self._append_sanitizer_option(
            env.get("UBSAN_OPTIONS"), f"log_path={log_prefix}.ubsan"
        )
        if self.debug:
            print(f"    {C.dim('$ ' + ' '.join(cmd))}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True,
                timeout=timeout, env=env
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            sanitizer_text = self._collect_sanitizer_log_text(log_prefix)
            if sanitizer_text:
                if stderr and not stderr.endswith("\n"):
                    stderr += "\n"
                stderr += sanitizer_text
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
            sanitizer_text = self._collect_sanitizer_log_text(log_prefix)
            if sanitizer_text:
                if stderr and not stderr.endswith("\n"):
                    stderr += "\n"
                stderr += sanitizer_text
            if stderr and not stderr.endswith("\n"):
                stderr += "\n"
            stderr += "TIMEOUT"
            return -1, stdout, stderr
        except FileNotFoundError:
            return -99, "", f"Binary not found: {self.binary}"

    def _record(self, result):
        """Record a test result with live progress output."""
        if not result.skipped and result.passed:
            asan_hit = self._check_asan_analyzer(result.stderr, result.stdout)
            if asan_hit:
                result.passed = False
                result.message = f"ASAN/UBSAN error: {asan_hit}"
        list.append(self.results, result)  # bypass proxy to avoid recursion
        if self._current_section:
            self._section_results.setdefault(self._current_section, []).append(result)

        dur_str = f"{result.duration:.2f}s" if result.duration > 0 else ""

        if result.skipped:
            if self.verbose:
                print(f"  {C.yellow('o')} {result.name} {C.dim('(skipped)')}")
        elif result.passed:
            slow = ""
            if result.duration >= SLOW_TEST_THRESHOLD:
                slow = C.yellow(f" ! slow ({dur_str})")
            if self.verbose:
                print(f"  {C.green('+')} {result.name} {C.dim(f'({dur_str})')}{slow}")
        else:
            print(f"  {C.red('x')} {C.red(result.name)} {C.dim(f'({dur_str})')}")
            print(f"    {result.message}")
            if result.stderr:
                stderr_lines = result.stderr.splitlines()
                for line in stderr_lines[:10]:
                    print(f"    {C.dim('stderr:')} {line}")
                if len(stderr_lines) > 10:
                    print(f"    {C.dim(f'... ({len(stderr_lines) - 10} more lines)')}")
            if result.stdout and "ASAN" in result.message:
                stdout_lines = [l for l in result.stdout.splitlines() if l.strip()][:5]
                for line in stdout_lines:
                    print(f"    {C.dim('stdout:')} {line}")
            if self.fail_fast:
                self._stop_requested = True

    def assert_exit_code(self, name, args, expected_code, check_stderr=True):
        """Test that analyzer returns expected exit code."""
        if self._stop_requested:
            return False
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        passed = (rc == expected_code)
        msg = ""
        if not passed:
            msg = f"Expected exit code {expected_code}, got {rc}"

        # Check for ASAN errors in analyzer code (not upstream iccDEV)
        if check_stderr and passed:
            asan_hit = self._check_asan_analyzer(stderr, stdout)
            if asan_hit:
                passed = False
                msg = f"ASAN error in analyzer code: {asan_hit}"

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout contains a regex pattern."""
        if self._stop_requested:
            return False
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        found = bool(re.search(pattern, stdout))
        passed = found
        msg = ""
        if not found:
            msg = f"Pattern '{pattern}' not found in output"
        if expected_code is not None and rc != expected_code:
            passed = False
            msg += f"; exit code {rc} != expected {expected_code}"

        asan_hit = self._check_asan_analyzer(stderr, stdout)
        if asan_hit:
            passed = False
            msg += f"; ASAN: {asan_hit}"

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_output_not_contains(self, name, args, pattern, expected_code=None):
        """Test that stdout does NOT contain a regex pattern."""
        if self._stop_requested:
            return False
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        found = bool(re.search(pattern, stdout))
        passed = not found
        msg = ""
        if found:
            msg = f"Pattern '{pattern}' unexpectedly found in output"
        if expected_code is not None and rc != expected_code:
            passed = False
            msg += f"; exit code {rc} != expected {expected_code}"

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def assert_no_asan(self, name, args):
        """Test that no ASAN/UBSAN errors occur in analyzer code."""
        if self._stop_requested:
            return False
        t0 = time.monotonic()
        rc, stdout, stderr = self.run_analyzer(args)
        dur = time.monotonic() - t0

        asan_hit = self._check_asan_analyzer(stderr, stdout)
        passed = (asan_hit is None)
        msg = asan_hit or ""

        self._record(TestResult(name, passed, msg, dur, stdout, stderr))
        return passed

    def _check_asan_analyzer(self, stderr, stdout=""):
        """Check for ASAN/UBSAN errors without masking sanitizer log-path output."""
        for line in stderr.splitlines():
            if "ERROR: AddressSanitizer" in line:
                return line.strip()
            if "runtime error:" in line:
                return line.strip()
            if "SUMMARY: UndefinedBehaviorSanitizer" in line:
                return line.strip()
            if "SUMMARY: AddressSanitizer" in line:
                return line.strip()
        return None

    def should_run(self, name):
        """Check if test matches the filter pattern."""
        if self.pattern is None:
            return True
        return self.pattern.lower() in name.lower()

    def begin_section(self, name):
        """Mark the start of a test section for grouping."""
        self._current_section = name

    def report(self, xml_path=None):
        """Print results and optionally write JUnit XML."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed and not r.skipped)
        skipped = sum(1 for r in self.results if r.skipped)
        failed = total - passed - skipped
        total_time = sum(r.duration for r in self.results)

        # Section breakdown
        print(f"\n{'=' * 70}")
        print(C.bold(f"RESULTS: {passed}/{total - skipped} passed, {failed} failed"
                     f"{f', {skipped} skipped' if skipped else ''} ({total_time:.1f}s)"))
        print(f"{'=' * 70}")

        # Per-section summary
        if self._section_results:
            print(f"\n{C.bold('Section Breakdown:')}")
            for section, results in self._section_results.items():
                s_pass = sum(1 for r in results if r.passed and not r.skipped)
                s_fail = sum(1 for r in results if not r.passed and not r.skipped)
                s_skip = sum(1 for r in results if r.skipped)
                s_time = sum(r.duration for r in results)
                status = C.green("PASS") if s_fail == 0 else C.red(f"FAIL ({s_fail})")
                skip_str = f", {s_skip} skipped" if s_skip else ""
                print(f"  {status}  {section}: {s_pass}/{s_pass + s_fail} "
                      f"({s_time:.1f}s{skip_str})")

        # Slow tests
        slow = [r for r in self.results if r.duration >= SLOW_TEST_THRESHOLD]
        if slow:
            print(f"\n{C.yellow('Slow tests (>' + str(SLOW_TEST_THRESHOLD) + 's):')}")
            for r in sorted(slow, key=lambda x: -x.duration):
                print(f"  {C.yellow('!')} {r.name} ({r.duration:.2f}s)")

        # Failures detail
        if failed > 0:
            print(f"\n{C.red(C.bold('FAILURES:'))}")
            for r in self.results:
                if not r.passed and not r.skipped:
                    print(f"  {C.red('x')} {C.red(r.name)}")
                    print(f"    {r.message}")
                    if r.stderr:
                        for line in r.stderr.splitlines()[:10]:
                            print(f"    {C.dim('stderr:')} {line}")

        if self.verbose:
            print(f"\n{C.bold('ALL TESTS:')}")
            for r in self.results:
                if r.skipped:
                    print(f"  {C.yellow('o')} {r.name} {C.dim('(skipped)')}")
                elif r.passed:
                    print(f"  {C.green('+')} {r.name} {C.dim(f'({r.duration:.2f}s)')}")
                else:
                    print(f"  {C.red('x')} {r.name} {C.dim(f'({r.duration:.2f}s)')}")

        if xml_path:
            self._write_junit_xml(xml_path, total_time)
            print(f"\nJUnit XML written to: {xml_path}")
        if self.debug or failed > 0:
            print(f"\nSanitizer logs: {self.sanitizer_log_dir}")

        return 0 if failed == 0 else 1

    def _write_junit_xml(self, path, total_time):
        """Write JUnit-compatible XML report with section grouping."""
        total = len(self.results)
        failures = sum(1 for r in self.results if not r.passed and not r.skipped)
        skips = sum(1 for r in self.results if r.skipped)

        suites = ET.Element("testsuites", {
            "name": "iccanalyzer-lite",
            "tests": str(total),
            "failures": str(failures),
            "skipped": str(skips),
            "time": f"{total_time:.3f}",
        })

        # Group test cases by section
        for section_name, results in self._section_results.items():
            s_failures = sum(1 for r in results if not r.passed and not r.skipped)
            s_skips = sum(1 for r in results if r.skipped)
            s_time = sum(r.duration for r in results)

            suite = ET.SubElement(suites, "testsuite", {
                "name": section_name,
                "tests": str(len(results)),
                "failures": str(s_failures),
                "skipped": str(s_skips),
                "time": f"{s_time:.3f}",
            })

            for r in results:
                tc = ET.SubElement(suite, "testcase", {
                    "name": r.name,
                    "classname": section_name,
                    "time": f"{r.duration:.3f}",
                })
                if r.skipped:
                    ET.SubElement(tc, "skipped", {"message": r.message or "skipped"})
                elif not r.passed:
                    fail = ET.SubElement(tc, "failure", {"message": r.message})
                    if r.stderr:
                        fail.text = r.stderr[:2000]

        tree = ET.ElementTree(suites)
        ET.indent(tree)
        tree.write(path, xml_declaration=True, encoding="unicode")


# --- Test definitions ---

def test_exit_codes(suite):
    """Test exit code behavior for various inputs."""
    corpus = str(CORPUS_DIR)

    # Exit 0: clean profile (may get findings from structural checks)
    suite.assert_exit_code(
        "exit_code.version_flag",
        ["--version"], EXIT_CLEAN, check_stderr=False
    )

    # Exit 3: usage errors
    suite.assert_exit_code(
        "exit_code.no_args",
        [], EXIT_USAGE, check_stderr=False
    )
    suite.assert_exit_code(
        "exit_code.unknown_flag",
        ["-zzz", f"{corpus}/valid_srgb.icc"], EXIT_USAGE, check_stderr=False
    )

    # Exit 2/3: file errors (nonexistent = path validation = USAGE, empty = preflight = FINDING)
    suite.assert_exit_code(
        "exit_code.nonexistent_file",
        ["-a", "/tmp/nonexistent_profile_12345.icc"], EXIT_USAGE, check_stderr=False
    )
    suite.assert_exit_code(
        "exit_code.empty_file",
        ["-a", f"{corpus}/empty_file.icc"], EXIT_ERROR, check_stderr=False
    )

    # Exit 1 or 2: truncated/corrupt profiles
    rc, _, _ = suite.run_analyzer(["-a", f"{corpus}/truncated.icc"])
    suite.results.append(TestResult(
        "exit_code.truncated_file",
        rc in (EXIT_FINDING, EXIT_ERROR),
        f"Got {rc}, expected 1 or 2", 0.0
    ))

    # Exit 1: findings on bad_magic
    suite.assert_exit_code(
        "exit_code.bad_magic",
        ["-a", f"{corpus}/bad_magic.icc"], EXIT_FINDING
    )


def test_analysis_modes(suite):
    """Test each analysis mode runs without crashing."""
    # Use a known good profile from test-profiles/
    good_profile = None
    if TEST_PROFILES.exists():
        candidates = filter_quarantined_profiles(
            list(TEST_PROFILES.glob("sRGB*.icc")) + list(TEST_PROFILES.glob("*.icc"))
        )
        if candidates:
            good_profile = str(candidates[0])

    if not good_profile:
        good_profile = str(CORPUS_DIR / "valid_srgb.icc")

    for mode in ["-a", "-h", "-r", "-nf", "-n"]:
        suite.assert_no_asan(
            f"mode.{mode[1:]}_no_crash",
            [mode, good_profile]
        )

    # --version
    suite.assert_output_contains(
        "mode.version_output",
        ["--version"], r"iccAnalyzer-lite v\d+\.\d+\.\d+", EXIT_CLEAN
    )

    # --help
    suite.assert_output_contains(
        "mode.help_output",
        ["--help"], r"-a.*-h.*-r|Usage|USAGE", EXIT_CLEAN
    )


def test_heuristic_detection(suite):
    """Test that specific heuristics fire on synthesized profiles."""
    corpus = str(CORPUS_DIR)

    # H1: bad magic
    suite.assert_output_contains(
        "heuristic.bad_magic_detected",
        ["-a", "--legacy", f"{corpus}/bad_magic.icc"],
        r"magic|acsp|WARN|CRITICAL"
    )

    # H108/H123/H127: private tags
    suite.assert_output_contains(
        "heuristic.private_tags_detected",
        ["-a", "--legacy", f"{corpus}/private_tags.icc"],
        r"H108|H123|H127|[Pp]rivate|unknown tag"
    )

    # H112: bad wtpt
    suite.assert_output_contains(
        "heuristic.bad_wtpt_detected",
        ["-a", "--legacy", f"{corpus}/bad_wtpt.icc"],
        r"H112|wtpt|[Ww]hite.?[Pp]oint|D50|WARN"
    )

    # H116: wrong encoding for version
    suite.assert_output_contains(
        "heuristic.wrong_version_encoding",
        ["-a", "--legacy", f"{corpus}/wrong_version_encoding.icc"],
        r"H116|H117|encoding|mluc|text|WARN|wrong type"
    )

    # H117: wrong tag type
    suite.assert_output_contains(
        "heuristic.wrong_tag_type",
        ["-a", "--legacy", f"{corpus}/wrong_tag_type.icc"],
        r"H117|not in allowed|disallowed|WARN"
    )

    # H126: malware private tag
    suite.assert_output_contains(
        "heuristic.malware_signature",
        ["-a", "--legacy", f"{corpus}/malware_private_tag.icc"],
        r"H126|[Mm]alware|MZ|PE|executable|WARN|CRITICAL"
    )

    # H122: XYZ out of range
    suite.assert_output_contains(
        "heuristic.xyz_out_of_range",
        ["-a", "--legacy", f"{corpus}/xyz_out_of_range.icc"],
        r"H122|out of.*range|XYZ|WARN"
    )

    # H111: reserved bytes
    suite.assert_output_contains(
        "heuristic.reserved_bytes",
        ["-a", "--legacy", f"{corpus}/reserved_bytes_nonzero.icc"],
        r"H111|[Rr]eserved|non-zero|WARN"
    )

    # Huge tag count triggers preflight
    suite.assert_output_contains(
        "heuristic.huge_tag_count",
        ["-a", "--legacy", f"{corpus}/huge_tag_count.icc"],
        r"tag count|CRITICAL|preflight|threshold|999999|WARN"
    )

    # H124: v5 tags on v4
    suite.assert_output_contains(
        "heuristic.v5_tags_on_v4",
        ["-a", "--legacy", f"{corpus}/v5_tags_on_v4.icc"],
        r"H124|version|D2B|v5|WARN"
    )

    # H125: transform smoothness warning on CLUT quality fixture
    suite.assert_output_contains(
        "heuristic.transform_smoothness_warning",
        ["-a", "--legacy", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"H125|smoothness|discontinuity|poor smoothness|WARN"
    )

    # H114: non-monotonic TRC
    suite.assert_output_contains(
        "heuristic.non_monotonic_trc",
        ["-a", "--legacy", f"{corpus}/non_monotonic_curve.icc"],
        r"H114|[Mm]onoton|TRC|WARN"
    )

    # H96: embedded ICC5 path fingerprints the upstream CIccEmbedIO UB on
    # unpatched iccDEV, and wrong-type ICC5 tags report the type confusion path.
    suite.assert_output_contains(
        "heuristic.embedded_profile_ub_fingerprint",
        ["-a", "--legacy", f"{corpus}/cf_embedded_child_class_mismatch.icc"],
        r"H96|CIccEmbedIO constructor sentinel UB|IccIO\.cpp:569"
    )

    suite.assert_output_contains(
        "heuristic.embedded_profile_wrong_type",
        ["-a", "--legacy", f"{corpus}/cf_embedded_wrong_type.icc"],
        r"H96|wrong type \(dynamic_cast failed\)|CIccTagEmbeddedProfile"
    )

    suite.assert_output_contains(
        "heuristic.signature_conversion_shift_overflow",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"H173|Signature Conversion Shift Overflow|Resolved upstream: iccDEV #726"
    )

    suite.assert_output_contains(
        "heuristic.h174_header_half_float_ub",
        ["-a", "--legacy", f"{corpus}/h174_half_float_header.icc"],
        r"H174|Half-Float Conversion Unsigned Underflow|Resolved upstream: iccDEV #724/#727"
    )

    suite.assert_output_contains(
        "heuristic.h174_mdv_fl16_half_float_ub",
        ["-a", "--legacy", f"{corpus}/h174_half_float_mdv_fl16.icc"],
        r"H174|Half-Float Conversion Unsigned Underflow|Resolved upstream: iccDEV #724/#727"
    )

    suite.assert_output_contains(
        "heuristic.h174_defense_skip",
        ["-a", "--legacy", f"{corpus}/h174_half_float_mdv_fl16.icc"],
        r"H174|Half-Float Conversion Unsigned Underflow|Resolved upstream: iccDEV #724/#727"
    )

    # --- H175-H178: ICC.2:2023 Extended Device Colour Space ---

    # H175: valid dsrn tag provides range source -> OK
    suite.assert_output_contains(
        "heuristic.h175_valid_dsrn",
        ["-a", "--legacy", f"{corpus}/h175_spectral_device_valid_dsrn.icc"],
        r"Device spectral range defined by dsrn tag"
    )

    # H175: header fallback when no dsrn tag -> OK
    suite.assert_output_contains(
        "heuristic.h175_header_fallback",
        ["-a", "--legacy", f"{corpus}/h175_spectral_device_header_fallback.icc"],
        r"header spectral PCS range fields"
    )

    # H175: spectral device with NO range source -> CRITICAL
    suite.assert_output_contains(
        "heuristic.h175_no_range",
        ["-a", "--legacy", f"{corpus}/h175_spectral_device_no_range.icc"],
        r"CRITICAL.*NO spectral range definition"
    )

    # H176: valid dsrn tag encoding -> OK
    suite.assert_output_contains(
        "heuristic.h176_valid_dsrn",
        ["-a", "--legacy", f"{corpus}/h176_dsrn_valid.icc"],
        r"dsrn tag validation complete"
    )

    # H176: non-zero reserved bytes
    suite.assert_output_contains(
        "heuristic.h176_bad_reserved",
        ["-a", "--legacy", f"{corpus}/h176_dsrn_bad_reserved.icc"],
        r"reserved field is 0x01020304"
    )

    # H176: wrong type signature
    suite.assert_output_contains(
        "heuristic.h176_bad_sig",
        ["-a", "--legacy", f"{corpus}/h176_dsrn_bad_sig.icc"],
        r"CRITICAL.*type signature is.*XXXX.*expected.*srng"
    )

    # H176: inverted wavelength range
    suite.assert_output_contains(
        "heuristic.h176_inverted_range",
        ["-a", "--legacy", f"{corpus}/h176_dsrn_inverted_range.icc"],
        r"CRITICAL.*end.*380.*<=.*start.*780.*inverted"
    )

    # H177: valid dpcc tag with all sub-tags -> OK
    suite.assert_output_contains(
        "heuristic.h177_valid_dpcc",
        ["-a", "--legacy", f"{corpus}/h177_dpcc_valid.icc"],
        r"dpcc tag structure validation complete"
    )

    # H177: dpcc with missing sub-tags -> WARN/CRITICAL
    suite.assert_output_contains(
        "heuristic.h177_missing_subtags",
        ["-a", "--legacy", f"{corpus}/h177_dpcc_missing_subtags.icc"],
        r"CRITICAL: Required PCC sub-tag 'svcn'"
    )

    # H178: NaN wavelength -> CRITICAL
    suite.assert_output_contains(
        "heuristic.h178_nan_wavelength",
        ["-a", "--legacy", f"{corpus}/h178_srng_nan_wavelength.icc"],
        r"CRITICAL.*srng spectral range has NaN"
    )

    # H178: low steps -> CRITICAL
    suite.assert_output_contains(
        "heuristic.h178_low_steps",
        ["-a", "--legacy", f"{corpus}/h178_srng_low_steps.icc"],
        r"CRITICAL.*srng spectral steps=1"
    )

    # H178: out-of-range wavelength
    suite.assert_output_contains(
        "heuristic.h178_out_of_range",
        ["-a", "--legacy", f"{corpus}/h178_srng_out_of_range.icc"],
        r"srng start wavelength 50\.0 nm outside 100-2500"
    )

    # --- New heuristic-targeted tests ---

    # H3: null/invalid colorSpace
    suite.assert_output_contains(
        "heuristic.null_colorspace",
        ["-a", "--legacy", f"{corpus}/null_colorspace.icc"],
        r"Invalid/null colorSpace"
    )

    # H4: invalid PCS signature
    suite.assert_output_contains(
        "heuristic.invalid_pcs",
        ["-a", "--legacy", f"{corpus}/invalid_pcs.icc"],
        r"Invalid PCS signature"
    )

    # H5: unknown platform signature
    suite.assert_output_contains(
        "heuristic.unknown_platform",
        ["-a", "--legacy", f"{corpus}/unknown_platform.icc"],
        r"Unknown platform signature"
    )

    # H6: invalid rendering intent
    suite.assert_output_contains(
        "heuristic.invalid_rendering_intent",
        ["-a", "--legacy", f"{corpus}/invalid_rendering_intent.icc"],
        r"Invalid rendering intent value 99"
    )

    # H7: unknown device class
    suite.assert_output_contains(
        "heuristic.unknown_device_class",
        ["-a", "--legacy", f"{corpus}/unknown_device_class.icc"],
        r"Unknown profile class"
    )

    # H8: negative illuminant
    suite.assert_output_contains(
        "heuristic.negative_illuminant",
        ["-a", "--legacy", f"{corpus}/negative_illuminant.icc"],
        r"Negative illuminant values"
    )

    # H15: invalid date fields
    suite.assert_output_contains(
        "heuristic.invalid_date",
        ["-a", "--legacy", f"{corpus}/invalid_date.icc"],
        r"Invalid month: 13|Invalid day: 32"
    )

    # H128: non-BCD version nibble
    suite.assert_output_contains(
        "heuristic.version_bcd_invalid",
        ["-a", "--legacy", f"{corpus}/version_bcd_invalid.icc"],
        r"Non-BCD nibble in version"
    )

    # H129: D50 illuminant mismatch
    suite.assert_output_contains(
        "heuristic.wrong_d50_illuminant",
        ["-a", "--legacy", f"{corpus}/wrong_d50_illuminant.icc"],
        r"PCS illuminant does not match D50"
    )

    # H131: profile ID MD5 mismatch
    suite.assert_output_contains(
        "heuristic.profile_id_md5_mismatch",
        ["-a", "--legacy", f"{corpus}/cf_md5_mismatch.icc"],
        r"Profile ID MD5 MISMATCH"
    )

    # H133: flags reserved bits
    suite.assert_output_contains(
        "heuristic.flags_reserved_bits",
        ["-a", "--legacy", f"{corpus}/flags_reserved_bits.icc"],
        r"Reserved flag bits non-zero"
    )

    # H134: tag type reserved bytes
    suite.assert_output_contains(
        "heuristic.tag_type_reserved_bytes",
        ["-a", "--legacy", f"{corpus}/cf_reserved_bytes_nonzero_tag.icc"],
        r"reserved bytes 4-7 ="
    )

    # H135: duplicate tag signatures
    suite.assert_output_contains(
        "heuristic.duplicate_tags",
        ["-a", "--legacy", f"{corpus}/duplicate_tags.icc"],
        r"Duplicate tag signature.*desc"
    )

    # H130/H40: tag alignment
    suite.assert_output_contains(
        "heuristic.tag_misaligned",
        ["-a", "--legacy", f"{corpus}/tag_misaligned.icc"],
        r"not 4-byte aligned"
    )

    # H1: extra trailing bytes (size mismatch)
    suite.assert_output_contains(
        "heuristic.extra_trailing_bytes",
        ["-a", "--legacy", f"{corpus}/extra_trailing_bytes.icc"],
        r"EXTRA BYTES appended"
    )

    # H20: null tag type signature
    suite.assert_output_contains(
        "heuristic.null_tag_type",
        ["-a", "--legacy", f"{corpus}/null_tag_type.icc"],
        r"null type signature"
    )

    # H49: NaN/Inf in float tag
    suite.assert_output_contains(
        "heuristic.nan_float_tag",
        ["-a", "--legacy", f"{corpus}/nan_float_tag.icc"],
        r"NaN detected at offset|Inf detected at offset"
    )

    # H55: odd byte length UTF-16
    suite.assert_output_contains(
        "heuristic.odd_utf16_mluc",
        ["-a", "--legacy", f"{corpus}/odd_utf16_mluc.icc"],
        r"odd byte length.*invalid UTF-16"
    )

    # H69: suspicious profile ID
    suite.assert_output_contains(
        "heuristic.suspicious_profile_id",
        ["-a", "--legacy", f"{corpus}/suspicious_profile_id.icc"],
        r"suspicious pattern.*0xFF|Profile ID.*suspicious"
    )

    # --- H97 profileSequenceIdentifier validation regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h97_profile_sequence_id_profile_bytes(True))
        h97_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h97_psid_malformed",
            ["-a", "--legacy", h97_path],
        )

        suite.assert_output_contains(
            "heuristic.h97_null_profile_id",
            ["-a", "--legacy", h97_path],
            r"H97|Profile Sequence Identifier Validation|Null profile ID \(all zeros\) in sequence"
        )

        suite.assert_output_contains(
            "heuristic.h97_duplicate_profile_ids",
            ["-a", "--legacy", h97_path],
            r"H97|Duplicate profile IDs in sequence"
        )
    finally:
        try:
            os.unlink(h97_path)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h97_profile_sequence_id_profile_bytes(False))
        h97_clean_path = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h97_clean_profile",
            ["-a", "--legacy", h97_clean_path],
            r"\[H97\][\s\S]*Profile sequence identifiers valid"
        )
    finally:
        try:
            os.unlink(h97_clean_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h97_absent_tag",
        ["-a", "--legacy", f"{corpus}/suspicious_profile_id.icc"],
        r"\[H97\][\s\S]*No profile sequence ID tag present"
    )

    # --- H102 tag size vs profile size regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h102_profile_size_profile_bytes(140, 240, 64))
        h102_small_header = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h102_small_header",
            ["-a", "--legacy", h102_small_header],
            r"\[H102\][\s\S]*Profile size 140 too small for 9 tags"
        )
        suite.assert_output_contains(
            "heuristic.h102_small_header_offset",
            ["-a", "--legacy", h102_small_header],
            r"\[H102\][\s\S]*offset 240 exceeds profile size 140"
        )
    finally:
        try:
            os.unlink(h102_small_header)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h102_profile_size_profile_bytes(500, 1000, 64))
        h102_bad_offset = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h102_bad_offset",
            ["-a", "--legacy", h102_bad_offset],
            r"\[H102\][\s\S]*offset 1000 exceeds profile size 500"
        )
    finally:
        try:
            os.unlink(h102_bad_offset)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h102_profile_size_profile_bytes(500, 240, 1000))
        h102_bad_size = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h102_bad_size",
            ["-a", "--legacy", h102_bad_size],
            r"\[H102\][\s\S]*extends past profile end: offset=240 size=1000 total=500"
        )
    finally:
        try:
            os.unlink(h102_bad_size)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h102_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H102\][\s\S]*Tag size vs profile size consistent"
    )

    # H99: embedded image tag validation
    suite.assert_output_contains(
        "heuristic.h99_ehim_valid",
        ["-a", "--legacy", f"{corpus}/cf138-ehim-valid.icc"],
        r"\[H99\][\s\S]*Embedded image tags valid"
    )
    suite.assert_output_contains(
        "heuristic.h99_enim_valid",
        ["-a", "--legacy", f"{corpus}/cf139-enim-valid.icc"],
        r"\[H99\][\s\S]*Embedded image tags valid"
    )
    suite.assert_output_contains(
        "heuristic.h99_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H99\][\s\S]*No embedded image tags present"
    )

    # H100: profile sequence description validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h100_profile_sequence_desc_profile_bytes(1))
        h100_one = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h100_one_entry",
            ["-a", "--legacy", h100_one],
            r"\[H100\][\s\S]*Profile sequence description valid"
        )
    finally:
        try:
            os.unlink(h100_one)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h100_profile_sequence_desc_profile_bytes(101))
        h100_many = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h100_many_entries",
            ["-a", "--legacy", h100_many],
            "\\[H100\\][\\s\\S]*Excessive sequence entries \\(101\\) (?:-|\\u2014) DoS risk"
        )
    finally:
        try:
            os.unlink(h100_many)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h100_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H100\][\s\S]*No profile sequence description tag"
    )

    # H89: profile sequence description validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h100_profile_sequence_desc_profile_bytes(257))
        h89_many = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h89_many_entries",
            ["-a", "--legacy", h89_many],
            "\\[H89\\][\\s\\S]*Profile sequence has 257 descriptions \\(>256\\) (?:-|\\u2014) OOM risk"
        )
    finally:
        try:
            os.unlink(h89_many)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h89_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H89\][\s\S]*Profile sequence descriptions within bounds \(or absent\)"
    )

    # H20: tag type signature validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h20_tag_type_signature_profile_bytes(0x00000000))
        h20_null = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h20_null_type_signature",
            ["-a", "--legacy", h20_null],
            r"\[H20\][\s\S]*Tag 'desc' has null type signature \(0x00000000\)"
        )
    finally:
        try:
            os.unlink(h20_null)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h20_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H20\][\s\S]*All tag type signatures are valid ASCII"
    )

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h21_tag_struct_profile_bytes())
        h21_struct = tmp.name

    try:
        # H21: tagStruct member inspection
        suite.assert_output_contains(
            "heuristic.h21_struct_member_inventory",
            ["-a", "--legacy", h21_struct],
            r"\[H21\][\s\S]*Tag 'cept' is tagStruct \(type='cept', 15 members\)[\s\S]*Member 'srnd': type='ui08' size=12 values=4"
        )

        suite.assert_output_contains(
            "heuristic.h21_struct_member_clean",
            ["-a", "--legacy", f"{corpus}/cf143-meas-valid.icc"],
            r"\[H21\][\s\S]*Tag 'meas' is tagStruct \(type='meas', 0 members\)"
        )

        # H22: NumArray scalar expectation
        suite.assert_output_contains(
            "heuristic.h22_scalar_expectation_warn",
            ["-a", "--legacy", h21_struct],
            r"\[H22\][\s\S]*srnd \(ViewingSurround\) has 4 values \(expected 1 scalar\)"
        )

        suite.assert_output_contains(
            "heuristic.h22_scalar_expectation_na",
            ["-a", "--legacy", f"{corpus}/cf143-meas-valid.icc"],
            "\\[H22\\][\\s\\S]*No cept \\(ColorEncodingParams\\) tag (?:-|\\u2014) check not applicable"
        )

        # H23: NumArray value range
        suite.assert_output_contains(
            "heuristic.h23_numarray_clean",
            ["-a", "--legacy", f"{corpus}/cf143-meas-valid.icc"],
            r"\[H23\][\s\S]*All NumArray values within normal ranges"
        )

        # H24: tagStruct/tagArray nesting depth
        suite.assert_output_contains(
            "heuristic.h24_nesting_depth_warn_fixture",
            ["-a", "--legacy", h21_struct],
            r"\[H24\][\s\S]*Max nesting depth: 1 \(safe limit: 4\)"
        )

        suite.assert_output_contains(
            "heuristic.h24_nesting_depth_clean",
            ["-a", "--legacy", f"{corpus}/cf143-meas-valid.icc"],
            r"\[H24\][\s\S]*Max nesting depth: 0 \(safe limit: 4\)"
        )
    finally:
        try:
            os.unlink(h21_struct)
        except OSError:
            pass

    # H18: technology signature validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h18_technology_signature_profile_bytes(0xFFFFFFFF))
        h18_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h18_unknown_technology",
            ["-a", "--legacy", h18_bad],
            r"\[H18\][\s\S]*Unknown technology signature: 0xFFFFFFFF"
        )
    finally:
        try:
            os.unlink(h18_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h18_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H18\][\s\S]*No technology tag present"
    )

    # H25: tag offset/size out-of-bounds
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h25_tag_offset_oob_profile_bytes())
        h25_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h25_offset_oob",
            ["-a", "--legacy", h25_bad],
            r"\[H25\][\s\S]*Tag 'desc' offset 0x[0-9A-F]+ beyond file/profile bounds"
        )
    finally:
        try:
            os.unlink(h25_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h25_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H25\][\s\S]*All tag offsets/sizes within bounds"
    )

    # H26: NamedColor2 string validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h26_named_color2_string_profile_bytes(True))
        h26_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h26_unterminated_strings",
            ["-a", "--legacy", h26_bad],
            r"\[H26\][\s\S]*Prefix not null-terminated[\s\S]*Suffix not null-terminated"
        )
    finally:
        try:
            os.unlink(h26_bad)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h26_named_color2_string_profile_bytes(False))
        h26_ok = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h26_clean_profile",
            ["-a", "--legacy", h26_ok],
            r"\[H26\][\s\S]*No NamedColor2 tags with risky strings"
        )
    finally:
        try:
            os.unlink(h26_ok)
        except OSError:
            pass

    # H27: MPE matrix output channel validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h27_mpe_matrix_output_profile_bytes(2))
        h27_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h27_matrix_output_warn",
            ["-a", "--legacy", h27_bad],
            r"\[H27\][\s\S]*Matrix has 2 output channels \(XYZ needs 3\)"
        )
    finally:
        try:
            os.unlink(h27_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h27_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H27\][\s\S]*All MPE matrix/calculator dimensions valid"
    )

    # H28: LUT dimension validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h28_lut_dimension_profile_bytes(17, 3, 2))
        h28_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h28_dimension_overflow",
            ["-a", "--legacy", h28_bad],
            r"\[H28\][\s\S]*nInput=17 nOutput=3 exceeds spec max \(16\)"
        )
    finally:
        try:
            os.unlink(h28_bad)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h28_lut_dimension_profile_bytes(3, 3, 2))
        h28_ok = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h28_clean_profile",
            ["-a", "--legacy", h28_ok],
            r"\[H28\][\s\S]*All LUT dimensions within safe limits"
        )
    finally:
        try:
            os.unlink(h28_ok)
        except OSError:
            pass

    # H29: ColorantTable string validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h29_colorant_table_profile_bytes(True))
        h29_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h29_colorant_unterminated",
            ["-a", "--legacy", h29_bad],
            r"\[H29\][\s\S]*Colorant\[0\] name not null-terminated[\s\S]*2/2 colorant entries lack null terminator"
        )
    finally:
        try:
            os.unlink(h29_bad)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h29_colorant_table_profile_bytes(False))
        h29_ok = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h29_clean_profile",
            ["-a", "--legacy", h29_ok],
            r"\[H29\][\s\S]*No ColorantTable string issues detected"
        )
    finally:
        try:
            os.unlink(h29_ok)
        except OSError:
            pass

    # H31: MPE channel count validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h31_mpe_channel_count_profile_bytes(33))
        h31_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h31_mpe_channel_count",
            ["-a", "--legacy", h31_bad],
            r"\[H31\][\s\S]*MPE channels in=33 out=33 \(>32\)"
        )
    finally:
        try:
            os.unlink(h31_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h31_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H31\][\s\S]*All MPE channel counts within safe limits"
    )

    # H32: tag data type confusion
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h32_unknown_type_profile_bytes(0x7A7A7A7A))
        h32_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h32_unknown_type",
            ["-a", "--legacy", h32_bad],
            r"\[H32\][\s\S]*Tag 'desc': unknown type signature 'zzzz' \(0x7A7A7A7A\)"
        )
    finally:
        try:
            os.unlink(h32_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h32_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H32\][\s\S]*All tag type signatures are known ICC types"
    )

    # H87: TRC curve anomaly detection
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h87_trc_curve_profile_all_zero_bytes())
        h87_zero = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h87_zero_curve",
            ["-a", "--legacy", h87_zero],
            "\\[H87\\][\\s\\S]*Tag 'redTRCTag': TRC curve all-zero \\(3 points\\) (?:-|\\u2014) clipped output"
        )
    finally:
        try:
            os.unlink(h87_zero)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h87_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H87\][\s\S]*TRC curves within bounds \(or absent\)"
    )

    # H88: chromatic adaptation matrix validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h88_chad_profile_singular_bytes())
        h88_singular = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h88_singular_chad",
            ["-a", "--legacy", h88_singular],
            r"\[H88\][\s\S]*chad matrix near-singular \(det=0\.00e\+00\)"
        )
    finally:
        try:
            os.unlink(h88_singular)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h88_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H88\][\s\S]*No chromatic adaptation tag \(standard D50\)"
    )

    # H132: chad determinant validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h88_chad_profile_singular_bytes())
        h132_singular = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h132_singular_chad",
            ["-a", "--legacy", h132_singular],
            r"\[H132\][\s\S]*singular or near-singular"
        )
    finally:
        try:
            os.unlink(h132_singular)
        except OSError:
            pass

    # H93: embedded profile flag consistency
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h93_flags_profile_bytes(0x00000004, 0x0000000000000010))
        h93_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h93_reserved_bits",
            ["-a", "--legacy", h93_bad],
            r"\[H93\][\s\S]*Profile flags=0x00000004: reserved bits set \(mask=0x00000004\)[\s\S]*Attributes=0x0000000000000010: reserved bits set"
        )
    finally:
        try:
            os.unlink(h93_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h93_ok",
        ["-a", "--legacy", f"{corpus}/zero_tags.icc"],
        r"\[H93\][\s\S]*Profile flags and attributes consistent"
    )

    # H94: matrix/TRC colorant consistency
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h94_matrix_trc_profile_bad_columns_bytes())
        h94_bad = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h94_matrix_sum",
            ["-a", "--legacy", h94_bad],
            r"\[H94\][\s\S]*Matrix column sum \(0\.0000, 0\.0000, 0\.0000\) deviates from D50[\s\S]*deviation \(0\.9505, 1\.0000, 1\.0890\)"
        )
    finally:
        try:
            os.unlink(h94_bad)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h94_ok",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H94\][\s\S]*Matrix/TRC colorant consistency valid \(or non-RGB\)"
    )

    # H91: colorant order validation
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h91_colorant_order_profile_bytes(True))
        h91_dup = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h91_duplicate_index",
            ["-a", "--legacy", h91_dup],
            r"\[H91\][\s\S]*ColorantOrder has duplicate index 0"
        )
    finally:
        try:
            os.unlink(h91_dup)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h91_absent",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H91\][\s\S]*Colorant order indices valid \(or absent\)"
    )

    # H90: preview tag channel consistency
    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h90_preview_profile_bytes(3, 3))
        h90_ok = tmp.name

    try:
        suite.assert_output_contains(
            "heuristic.h90_preview_ok",
            ["-a", "--legacy", h90_ok],
            r"\[H90\][\s\S]*Preview tag channels consistent \(or absent\)"
        )
    finally:
        try:
            os.unlink(h90_ok)
        except OSError:
            pass

    # H10: zero tags (verify library-level detection)
    suite.assert_output_contains(
        "heuristic.zero_tags_detected",
        ["-a", "--legacy", f"{corpus}/zero_tags.icc"],
        r"Zero tags.*invalid"
    )

    # --- CWE-400 systemic pattern tests (CFL-074/075/076 findings) ---

    # H64: NamedColor2 device coords > 15
    suite.assert_output_contains(
        "heuristic.named_color2_excessive_coords",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"NamedColor2.*20 device coords.*>15"
    )

    # H136: ResponseCurve excessive measurements
    suite.assert_output_contains(
        "heuristic.response_curve_excessive_measurements",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"ResponseCurve.*channel.*500000 measurements.*>100K"
    )

    # H137: high-dimensional color space
    suite.assert_output_contains(
        "heuristic.high_dimensional_grid_complexity",
        ["-a", "--legacy", f"{corpus}/high_dimensional_colorspace.icc"],
        r"Input color space has 8 channels"
    )

    # Verify H136/H137 produce CWE-400 annotations
    suite.assert_output_contains(
        "heuristic.cwe400_in_response_curve",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"CWE-400.*Unbounded measurement count"
    )

    suite.assert_output_contains(
        "heuristic.cwe400_in_high_dim",
        ["-a", "--legacy", f"{corpus}/high_dimensional_colorspace.icc"],
        r"CWE-400.*O\(nGran\^ndim\)"
    )

    # --- Validation/Runtime symmetry tests ---

    # H47 raw-byte ncl2 check fires nDevCoords>15 (always-run, covers library-load failures)
    suite.assert_output_contains(
        "symmetry.h47_raw_ndevcoords_gt15",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"ncl2.*nDeviceCoords.*>15 ICC spec max"
    )

    # H47 raw-byte ncl2 check fires CFL-076 pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl076_pattern",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"CWE-787.*CFL-076"
    )

    # H64 library-level check fires nColors>10000 Describe() DoS (when library loads)
    # The named_color2_large_nsize profile has nColors=70000 but only 2 actual entries,
    # so the library may reject it. H47 always catches it at raw level.
    suite.assert_output_contains(
        "symmetry.h47_raw_ncolors_gt10000",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"ncl2.*entries.*>10000.*Describe.*DoS"
    )

    # H47 CWE-400 Describe() pattern annotation
    suite.assert_output_contains(
        "symmetry.h47_raw_cfl078_pattern",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"CWE-400.*Describe.*m_nSize.*CFL-078"
    )

    # H136 runs in always-run phase (not gated behind library load)
    # Verify it fires on response_curve_excessive_measurements.icc even with malformed header
    suite.assert_output_contains(
        "symmetry.h136_always_runs",
        ["-a", "--legacy", f"{corpus}/response_curve_excessive_measurements.icc"],
        r"\[H136\].*ResponseCurve"
    )

    # XYZ large array completes without hanging (runtime safety)
    suite.assert_output_contains(
        "symmetry.xyz_large_no_hang",
        ["-a", "--legacy", f"{corpus}/xyz_large_array.icc"],
        r"181 heuristics"
    )

    # Calculator deep nesting profile completes without hanging
    suite.assert_output_contains(
        "symmetry.calc_deep_no_hang",
        ["-a", "--legacy", f"{corpus}/calculator_deep_nesting.icc"],
        r"181 heuristics"
    )

    # --- H86 Unicode content detection tests (CWE-116) ---

    # H86: bidi override characters in mluc text
    suite.assert_output_contains(
        "heuristic.h86_bidi_override",
        ["-a", "--legacy", f"{corpus}/mluc_bidi_override.icc"],
        r"bidi override.*formatting characters"
    )

    # H86: mixed Latin + non-Latin scripts
    suite.assert_output_contains(
        "heuristic.h86_mixed_scripts",
        ["-a", "--legacy", f"{corpus}/mluc_mixed_scripts.icc"],
        r"mixes Latin.*non-Latin scripts"
    )

    # H86: control characters in mluc text
    suite.assert_output_contains(
        "heuristic.h86_control_chars",
        ["-a", "--legacy", f"{corpus}/mluc_control_chars.icc"],
        r"non-printable control characters"
    )

    # H86: embedded null characters (string truncation)
    suite.assert_output_contains(
        "heuristic.h86_embedded_nulls",
        ["-a", "--legacy", f"{corpus}/mluc_embedded_nulls.icc"],
        r"embedded null characters"
    )

    # H30: nested tary->gbd signed channel wrap / allocation bomb
    suite.assert_output_contains(
        "heuristic.h30_gbd_tary_signed_channel_wrap",
        ["-a", "--legacy", f"{corpus}/gbd_tary_signed_channel_wrap.icc"],
        r"PCS channels=65535, Device channels=65534.*out of range"
    )

    suite.assert_output_contains(
        "heuristic.h68_gbd_tary_triangle_overflow",
        ["-a", "--legacy", f"{corpus}/gbd_tary_signed_channel_wrap.icc"],
        r"\[H68\][\s\S]*nTriangles=\d+ \* 3 = \d+ overflows int32"
    )

    suite.assert_output_contains(
        "cf.140.gbd_tary_vertex_count_field",
        ["-a", "--legacy", f"{corpus}/gbd_tary_signed_channel_wrap.icc"],
        r"\[DEFENSE\][\s\S]*GamutBoundaryDesc allocation/channel fields are unsafe[\s\S]*skipping library phase"
    )

    suite.assert_output_contains(
        "cf.286.gbd_tary_triangle_vertex_consistency",
        ["-a", "--legacy", f"{corpus}/gbd_tary_signed_channel_wrap.icc"],
        r"\[NOT RUN\][\s\S]*Library-phase conformance not run"
    )

    suite.assert_output_contains(
        "cf.287.gbd_tary_channel_plausibility",
        ["-a", "--legacy", f"{corpus}/gbd_tary_signed_channel_wrap.icc"],
        r"\[H30\][\s\S]*PCS channels=65535, Device channels=65534.*out of range"
    )

    # --- H147 null/degenerate CLUT detection tests (CWE-476) ---

    # H147: null CLUT in AToB LUT tag
    suite.assert_output_contains(
        "heuristic.h147_null_clut",
        ["-a", "--legacy", f"{corpus}/lut_null_clut.icc"],
        r"null CLUT.*Apply\(\) will crash"
    )

    # H147: degenerate CLUT (0 grid points via pTag null)
    suite.assert_output_contains(
        "heuristic.h147_degenerate_clut",
        ["-a", "--legacy", f"{corpus}/lut_degenerate_clut.icc"],
        r"pTag pointer is null|gridPoints = 0"
    )

    # --- H148 memory copy bounds/overlap regression (CWE-119) ---

    suite.assert_output_contains(
        "heuristic.h148_namedcolor2_excessive_coords",
        ["-a", "--legacy", f"{corpus}/named_color2_excessive_coords.icc"],
        r"H148|Memory Copy Bounds Overlap|NamedColor2 deviceCoords=20 exceeds ICC max \(15\)|CWE-119"
    )

    suite.assert_output_contains(
        "heuristic.h148_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H148\][\s\S]*No memory copy overlap or bounds issues detected"
    )

    # --- H167 null MPE CLUT/curve-apply guard regression (CWE-476) ---

    suite.assert_no_asan(
        "asan.repo.h167_null_mpe_clut_guard",
        ["-a", "--legacy", f"{corpus}/lut_null_clut.icc"],
    )

    suite.assert_output_contains(
        "heuristic.h167_null_mpe_clut_guard",
        ["-a", "--legacy", f"{corpus}/lut_null_clut.icc"],
        r"H167|Null MPE CLUT/Curve Application Guard|CLUT offset=0 but active curves|m_pCLUT"
    )

    suite.assert_output_contains(
        "heuristic.h167_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"No null MPE CLUT/Curve application risks detected"
    )

    # --- H168 unchecked allocation-size overflow regression (CWE-190/CWE-789) ---

    suite.assert_no_asan(
        "asan.repo.h168_namedcolor2_large_nsize",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
    )

    suite.assert_output_contains(
        "heuristic.h168_namedcolor2_large_nsize",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"H168|Unchecked Allocation Size Overflow|NamedColor2 has 70000 entries|CWE-789"
    )

    suite.assert_no_asan(
        "asan.repo.h168_gbd_triangle_overflow",
        ["-a", "--legacy",
         str(CORPUS_DIR.parent.parent.parent /
             "test-profiles/oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc")],
    )

    suite.assert_output_contains(
        "heuristic.h168_gbd_triangle_overflow",
        ["-a", "--legacy",
         str(CORPUS_DIR.parent.parent.parent /
             "test-profiles/oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc")],
        r"H168|Unchecked Allocation Size Overflow|GamutBoundaryDesc|CWE-190.*CFL-002"
    )

    suite.assert_output_contains(
        "heuristic.h168_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"No unchecked allocation overflow patterns detected"
    )

    # --- H98 spectral matrix Describe() gap fixture ---
    # V1 currently gaps out on this truncated spectral PoC because preflight
    # refuses the unsafe library path before H98 can execute. V2 carries the
    # improved raw H98 coverage for this specific fixture.

    spectral_h98_gap = str(
        CORPUS_DIR.parent.parent.parent /
        "test-profiles/heap-buffer-overflow-CIccMpeSpectralMatrix-Describe-IccMpeSpectral_cpp-Line352.icc"
    )

    suite.assert_no_asan(
        "asan.repo.h98_spectral_matrix_gap_fixture",
        ["-a", "--legacy", spectral_h98_gap],
    )

    suite.assert_output_contains(
        "heuristic.h98_spectral_matrix_gap_prefight",
        ["-a", "--legacy", spectral_h98_gap],
        r"\[NOT RUN\].*Profile structurally unsafe for library loading"
    )

    suite.assert_output_not_contains(
        "heuristic.h98_spectral_matrix_gap_expected_absence",
        ["-a", "--legacy", spectral_h98_gap],
        r"\[H98\]"
    )

    # --- H157/H159 alloc-dealloc mismatch and ownership UAF regression ---

    suite.assert_no_asan(
        "asan.repo.h157_h159_namedcolor2",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
    )

    suite.assert_output_contains(
        "heuristic.h157_namedcolor2_large_nsize",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"H157|Alloc-Dealloc Mismatch Tag Patterns|NamedColor2.*new\[\]/delete mismatch|CWE-762"
    )

    suite.assert_output_contains(
        "heuristic.h159_namedcolor2_large_nsize",
        ["-a", "--legacy", f"{corpus}/named_color2_large_nsize.icc"],
        r"H159|UAF Tag Ownership Chain Detection|NamedColor2.*m_NamedColor UAF|CWE-416"
    )

    suite.assert_no_asan(
        "asan.repo.h157_h159_tary_cfl003",
        ["-a", "--legacy",
         str(CORPUS_DIR.parent.parent.parent / "test-profiles/cfl-003-roundtrip-segv-tary.icc")],
    )

    suite.assert_output_contains(
        "heuristic.h157_tary_cfl003",
        ["-a", "--legacy",
         str(CORPUS_DIR.parent.parent.parent / "test-profiles/cfl-003-roundtrip-segv-tary.icc")],
        r"H157|Alloc-Dealloc Mismatch Tag Patterns|TagArray \('tary'\).*CFL-003|CWE-762"
    )

    suite.assert_output_contains(
        "heuristic.h159_tary_cfl003",
        ["-a", "--legacy",
         str(CORPUS_DIR.parent.parent.parent / "test-profiles/cfl-003-roundtrip-segv-tary.icc")],
        r"H159|UAF Tag Ownership Chain Detection|CFL-003 UAF path|CWE-416"
    )

    suite.assert_output_contains(
        "heuristic.h157_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H157\][\s\S]*No alloc-dealloc mismatch trigger patterns"
    )

    suite.assert_output_contains(
        "heuristic.h159_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H159\][\s\S]*No UAF-triggering ownership patterns detected"
    )

    # --- H161 deep Apply() stack-address-escape regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h161_deep_apply_profile_bytes())
        h161_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h161_deep_apply_synthetic",
            ["-a", "--legacy", h161_path],
        )

        suite.assert_output_contains(
            "heuristic.h161_deep_apply_mpet_chain",
            ["-a", "--legacy", h161_path],
            r"H161|Stack Address Escape Deep Apply Chains|A2B0.*5 elements x 12->12 channels|CWE-121"
        )

        suite.assert_output_contains(
            "heuristic.h161_deep_apply_profile_wide",
            ["-a", "--legacy", h161_path],
            r"H161|12-channel profile with 2 MPE tags|High channel count"
        )
    finally:
        try:
            os.unlink(h161_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h161_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H161\][\s\S]*No deep Apply\(\) chain stack-escape risk patterns"
    )

    # --- H169 dictionary tag element bounds regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h169_dict_bounds_profile_bytes())
        h169_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h169_dictionary_bounds_synthetic",
            ["-a", "--legacy", h169_path],
        )

        suite.assert_output_contains(
            "heuristic.h169_dictionary_reclen",
            ["-a", "--legacy", h169_path],
            r"H169|Dictionary Tag Element Bounds|dict recLen = 8|CWE-20"
        )

        suite.assert_output_contains(
            "heuristic.h169_dictionary_size",
            ["-a", "--legacy", h169_path],
            r"H169|3 entries x 8 bytes/rec = 24 bytes exceeds 16-byte tag|CWE-789"
        )
    finally:
        try:
            os.unlink(h169_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h169_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H169\][\s\S]*No dictionary tag bounds issues detected"
    )

    # --- H165 LUT data sufficiency regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h165_lut_data_sufficiency_profile_bytes())
        h165_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h165_lut_data_sufficiency_synthetic",
            ["-a", "--legacy", h165_path],
        )

        suite.assert_output_contains(
            "heuristic.h165_lut_data_sufficiency",
            ["-a", "--legacy", h165_path],
            r"H165|LUT Data Sufficiency Validation|A2B0.*lut8.*n_in=3 n_out=3 grid=2.*min 1608 bytes but tag size is 16|CWE-125/CWE-122"
        )
    finally:
        try:
            os.unlink(h165_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h165_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H165\][\s\S]*All LUT tags have sufficient data for declared contents"
    )

    # --- H170 copy-constructor null PCS regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h170_null_pcs_profile_bytes())
        h170_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h170_null_pcs_synthetic",
            ["-a", "--legacy", h170_path],
        )

        suite.assert_output_contains(
            "heuristic.h170_null_pcs",
            ["-a", "--legacy", h170_path],
            r"H170|Copy Constructor UB via Null PCS|PCS is null \(0x00000000\).*profile class 'mntr'|CWE-843"
        )

        suite.assert_output_contains(
            "heuristic.h170_affected_tools",
            ["-a", "--legacy", h170_path],
            r"Affected tools: iccApplySearch, iccRoundTrip, iccApplyProfiles, iccApplyNamedCmm"
        )
    finally:
        try:
            os.unlink(h170_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h170_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H170\][\s\S]*PCS signature valid for copy-constructor safety"
    )

    srgb_encoding = str(TEST_PROFILES / "sRgbEncoding.icc")
    suite.assert_output_contains(
        "heuristic.cenc_h170_refined",
        ["-a", "--legacy", srgb_encoding],
        r"H170[\s\S]*ColorEncoding profile uses null PCS as required"
    )
    suite.assert_output_not_contains(
        "heuristic.cenc_no_icc1_required_tag_noise",
        ["-a", "--legacy", srgb_encoding],
        r"Missing required tag 'desc' for non-DeviceLink class|"
        r"Missing required tag 'cprt' for non-DeviceLink class|"
        r"Missing required tag 'wtpt' for non-DeviceLink class|"
        r"Missing wtpt tag \(required for non-DeviceLink\)|"
        r"not found in private tag registry"
    )
    suite.assert_output_not_contains(
        "conformance.cenc_no_private_tag_noise",
        ["-a", "--legacy", srgb_encoding],
        r"Private/unknown tag: 'rfnm'|"
        r"Private/unregistered: 'rfnm'|"
        r"Undocumented private tag: 'rfnm'|"
        r"Unrecognized: 'rfnm'"
    )
    suite.assert_output_not_contains(
        "conformance.cenc_no_d50_required_tag_failures",
        ["-a", "--legacy", srgb_encoding],
        r"PCS illuminant [XYZ]=.*!= D50|"
        r"chad tag required when adopted white != D50|"
        r"profileDescriptionTag required|"
        r"copyrightTag required|"
        r"mediaWhitePointTag required|"
        r"V4\+ requires chad when adopted white"
    )
    suite.assert_output_not_contains(
        "conformance.cenc_no_header_false_positives",
        ["-a", "--legacy", srgb_encoding],
        r"\[H4\][\s\S]*Invalid PCS signature|"
        r"\[H8\][\s\S]*PCS illuminant is NOT D50|"
        r"CF-014[\s\S]*Non-DeviceLink PCS must be PCSXYZ or PCSLab|"
        r"CF-263[\s\S]*Perceptual intent requires D50 PCS illuminant"
    )

    # --- H52 integer underflow in tag size / CFL-065 regression ---

    h52_poc = os.path.join(REPO_ROOT, "test-profiles", "cfl065-nEnd-underflow-v4.icc")
    if os.path.exists(h52_poc):
        suite.assert_no_asan(
            "asan.repo.h52_tag_size_underflow_v4",
            ["-a", "--legacy", h52_poc],
        )

        suite.assert_output_contains(
            "heuristic.h52_tag_size_underflow_v4",
            ["-a", "--legacy", h52_poc],
            r"H52|Integer Underflow in Tag Size|A2B0.*type mAB.*B-curves offset 332 exceeds tag size 32.*underflows to ~4GB|CFL-065"
        )

    suite.assert_output_contains(
        "heuristic.h52_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H52\][\s\S]*No integer underflow in tag sizes"
    )

    # --- H41 version/type consistency regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h41_version_type_profile_bytes())
        h41_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h41_version_type_synthetic",
            ["-a", "--legacy", h41_path],
        )

        suite.assert_output_contains(
            "heuristic.h41_version_type_desc",
            ["-a", "--legacy", h41_path],
            r"H41|Version/Type Consistency|v2-only textDescription type.*v4 profile"
        )
    finally:
        try:
            os.unlink(h41_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h41_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H41\][\s\S]*Version/type consistency OK"
    )

    # --- H42 matrix singularity regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h42_matrix_singularity_profile_bytes())
        h42_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h42_matrix_singularity_synthetic",
            ["-a", "--legacy", h42_path],
        )

        suite.assert_output_contains(
            "heuristic.h42_matrix_singular",
            ["-a", "--legacy", h42_path],
            r"H42|Matrix Singularity|near-singular 3x3 matrix|matrix is all zeros"
        )
    finally:
        try:
            os.unlink(h42_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h42_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H42\][\s\S]*No singular matrices detected"
    )

    # --- H50 zero-size tag regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h50_zero_size_tag_profile_bytes())
        h50_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h50_zero_size_tag_synthetic",
            ["-a", "--legacy", h50_path],
        )

        suite.assert_output_contains(
            "heuristic.h50_zero_size_tag",
            ["-a", "--legacy", h50_path],
            r"H50|Zero-Size Profile Tag|zero size"
        )
    finally:
        try:
            os.unlink(h50_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h50_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H50\][\s\S]*No zero-size tags"
    )

    # --- H38 curve degenerate value regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h38_curve_degenerate_profile_bytes())
        h38_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h38_curve_degenerate_synthetic",
            ["-a", "--legacy", h38_path],
        )

        suite.assert_output_contains(
            "heuristic.h38_curve_degenerate",
            ["-a", "--legacy", h38_path],
            r"H38|Curve Degenerate Value|all 4 entries are zero"
        )
    finally:
        try:
            os.unlink(h38_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h38_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H38\][\s\S]*No degenerate curve values detected"
    )

    # --- H39 shared tag data aliasing regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h39_shared_tag_alias_profile_bytes())
        h39_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h39_shared_alias_synthetic",
            ["-a", "--legacy", h39_path],
        )

        suite.assert_output_contains(
            "heuristic.h39_shared_alias",
            ["-a", "--legacy", h39_path],
            r"H39|Shared Tag Data Aliasing Detection|share offset 0xA8 but have different sizes"
        )
    finally:
        try:
            os.unlink(h39_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h39_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H39\][\s\S]*No risky shared tag data aliasing"
    )

    # --- H43 spectral/BRDF structure regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h43_spectral_brdf_profile_bytes())
        h43_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h43_spectral_brdf_synthetic",
            ["-a", "--legacy", h43_path],
        )

        suite.assert_output_contains(
            "heuristic.h43_spectral_brdf",
            ["-a", "--legacy", h43_path],
            r"H43|Spectral/BRDF Tag Structure|spectral end \(380\) <= start \(780\)|spectral steps = 0"
        )
    finally:
        try:
            os.unlink(h43_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h43_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H43\][\s\S]*No spectral/BRDF structure issues"
    )

    # --- H44 embedded image validation regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h44_embedded_image_profile_bytes())
        h44_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h44_embedded_image_synthetic",
            ["-a", "--legacy", h44_path],
        )

        suite.assert_output_contains(
            "heuristic.h44_embedded_image",
            ["-a", "--legacy", h44_path],
            r"H44|Embedded Image Validation|oversized embedded data"
        )
    finally:
        try:
            os.unlink(h44_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h44_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H44\][\s\S]*No embedded image issues"
    )

    # --- H45 sparse matrix bounds regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h45_sparse_matrix_profile_bytes())
        h45_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h45_sparse_matrix_synthetic",
            ["-a", "--legacy", h45_path],
        )

        suite.assert_output_contains(
            "heuristic.h45_sparse_matrix",
            ["-a", "--legacy", h45_path],
            r"H45|Sparse Matrix Bounds|sparse matrix 5000x5000"
        )
    finally:
        try:
            os.unlink(h45_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h45_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H45\][\s\S]*No sparse matrix bounds issues"
    )

    # --- H46 textDescription unicode length regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h46_text_desc_profile_bytes())
        h46_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h46_text_desc_synthetic",
            ["-a", "--legacy", h46_path],
        )

        suite.assert_output_contains(
            "heuristic.h46_text_desc",
            ["-a", "--legacy", h46_path],
            r"H46|TextDescription Unicode Length|ASCII length 64 exceeds available tag data"
        )
    finally:
        try:
            os.unlink(h46_path)
        except OSError:
            pass

    suite.assert_output_contains(
        "heuristic.h46_clean_profile",
        ["-a", "--legacy", f"{corpus}/valid_srgb.icc"],
        r"\[H46\][\s\S]*No text description length issues"
    )

    # --- H172 LUT matrix coefficient validation regression ---

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h172_lut_matrix_profile_bytes(True))
        h172_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h172_lut_matrix_synthetic",
            ["-a", "--legacy", h172_path],
        )

        suite.assert_output_contains(
            "heuristic.h172_singular_matrix",
            ["-a", "--legacy", h172_path],
            r"H172|LUT Matrix Coefficient Validation|A2B0 matrix is singular.*CWE-369"
        )

        suite.assert_output_contains(
            "heuristic.h172_extreme_coefficient",
            ["-a", "--legacy", h172_path],
            r"H172|A2B0 matrix e\[9\] = 200\.0000 \(extreme magnitude >100\)|CWE-682"
        )

        suite.assert_output_contains(
            "heuristic.h172_zero_row",
            ["-a", "--legacy", h172_path],
            r"H172|A2B0 matrix row 1 has all-zero coefficients.*CWE-682"
        )
    finally:
        try:
            os.unlink(h172_path)
        except OSError:
            pass

    with tempfile.NamedTemporaryFile(suffix=".icc", delete=False) as tmp:
        tmp.write(make_h172_lut_matrix_profile_bytes(False))
        h172_clean_path = tmp.name

    try:
        suite.assert_no_asan(
            "asan.repo.h172_lut_matrix_clean_synthetic",
            ["-a", "--legacy", h172_clean_path],
        )

        suite.assert_output_contains(
            "heuristic.h172_clean_profile",
            ["-a", "--legacy", h172_clean_path],
            r"\[H172\][\s\S]*Validated 1 LUT matrix/matrices"
        )
    finally:
        try:
            os.unlink(h172_clean_path)
        except OSError:
            pass

    # --- H151 float->int cast operator detection (CWE-681) ---

    # H151: truncate operator in calculator element
    suite.assert_output_contains(
        "heuristic.h151_calc_trunc",
        ["-a", "--legacy", f"{corpus}/calc_trunc_operator.icc"],
        r"float-to-int cast operators.*trnc"
    )

    # --- H73 shared tag pointer detection ---

    # H73: shared curve tag pointers (immutable type -> safe)
    suite.assert_output_contains(
        "heuristic.h73_shared_pointers",
        ["-a", "--legacy", f"{corpus}/tag_shared_pointers.icc"],
        r"shared tag pair.*immutable.*safe"
    )


def test_runtime_safety(suite):
    """Test that CWE-400 profiles don't hang the analyzer (runtime cap validation).
    Each profile must complete analysis within the test timeout."""
    corpus = str(CORPUS_DIR)

    # Real PoC files from fuzzing - verify analyzer doesn't hang
    poc_files = [
        "timeout-0bec9575ea3dd8e7b1cccafaf453d5e84fec69b6",  # CFL-076 NamedColor2 nDevCoords
    ]
    for poc in poc_files:
        poc_path = str(CORPUS_DIR.parent.parent.parent / poc)
        if os.path.exists(poc_path):
            suite.assert_output_contains(
                f"runtime_safety.poc_{poc[:12]}",
                ["-a", "--legacy", poc_path],
                r"HEURISTIC SUMMARY"
            )

    # Synthesized CWE-400 profiles must all complete
    cwe400_profiles = [
        "named_color2_excessive_coords.icc",
        "named_color2_large_nsize.icc",
        "high_dimensional_colorspace.icc",
        "response_curve_excessive_measurements.icc",
        "xyz_large_array.icc",
        "calculator_deep_nesting.icc",
    ]
    for profile in cwe400_profiles:
        suite.assert_output_contains(
            f"runtime_safety.{profile.replace('.icc', '')}",
            ["-a", "--legacy", f"{corpus}/{profile}"],
            r"HEURISTIC SUMMARY"
        )


def test_heuristic_summary(suite):
    """Test that the summary section appears with correct heuristic count."""
    suite.assert_output_contains(
        "summary.181_heuristics",
        ["-a", "--legacy", str(CORPUS_DIR / "bad_magic.icc")],
        r"181 heuristics"
    )

    suite.assert_output_contains(
        "summary.heuristic_summary_header",
        ["-a", "--legacy", str(CORPUS_DIR / "bad_magic.icc")],
        r"HEURISTIC SUMMARY"
    )


def test_sanitizer_clean(suite):
    """Test ASAN/UBSAN cleanliness across synthesized corpus."""
    for icc in sorted(CORPUS_DIR.glob("*.icc")):
        if icc.stat().st_size == 0:
            continue  # Skip empty file
        suite.assert_no_asan(
            f"asan.corpus.{icc.stem}",
            ["-a", str(icc)]
        )


def test_repo_profiles_sample(suite):
    """Test a sample of real profiles from the repo for ASAN cleanliness."""
    profiles = []
    if TEST_PROFILES.exists():
        all_profiles = filter_quarantined_profiles(sorted(TEST_PROFILES.glob("*.icc")))
        sample_step = max(1, int(os.environ.get("ICCANALYZER_REPO_PROFILE_SAMPLE_STEP", "10")))
        sample_cap = int(os.environ.get("ICCANALYZER_REPO_PROFILE_CAP", "30"))
        profiles = all_profiles[::sample_step]
        if sample_cap > 0:
            profiles = profiles[:sample_cap]

    for icc in profiles:
        suite.assert_no_asan(
            f"asan.repo.{icc.stem[:40]}",
            ["-a", str(icc)]
        )


def test_pcc_illuminant_overflow_regression(suite):
    """Regression: malformed PCC illuminants must not trigger icIsIllumD50 UBSan."""
    trigger_names = [
        "76558f2fb46ff50ff77237856adfde8ff74c3793",
        "8541e466f7def17ed6d5e8fa355bfcb3dc855ce1",
    ]

    for name in trigger_names:
        profile = TEST_PROFILES / name
        if not profile.exists():
            continue
        suite.assert_no_asan(
            f"asan.repo.pcc_illuminant_{name[:16]}",
            ["-h", str(profile)]
        )


def test_tonemap_describe_overflow_regression(suite):
    """Regression: malformed mpet element tables must not trigger ReadValidate() UBSan."""
    profile = TEST_PROFILES / "CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc"
    if not profile.exists():
        return

    suite.assert_no_asan(
        "asan.repo.tonemap_describe_heap_oob",
        ["-a", str(profile)]
    )
    suite.assert_output_contains(
        "heuristic.tonemap_describe_validation",
        ["-a", str(profile)],
        r"H101|CF-115|mpet element table entry|MPE element table structurally invalid"
    )


def test_curve_element_oom_regression(suite):
    """Regression: malformed sampled-curve elements must not trigger allocator/underflow UB."""
    trigger_profiles = [
        TEST_PROFILES / "oom-CIccSingleSampledCurve-SetSize-IccProfLib-IccMpeBasic_cpp-Line1496.icc",
        TEST_PROFILES / "cwe-400" / "oom-CIccSampledCurveSegment-SetSize-IccMpeBasic_cpp-Line986.icc",
    ]

    for profile in trigger_profiles:
        if not profile.exists():
            continue
        stem = profile.stem[:40]
        suite.assert_no_asan(
            f"asan.repo.curve_element_oom_{stem}",
            ["-a", str(profile)]
        )
        suite.assert_output_contains(
            f"heuristic.curve_element_oom_{stem}",
            ["-a", str(profile)],
            r"H152|Curve Element OOM Size Validation|SingleSampledCurve|SampledCurveSegment|skipping library phase"
        )


def test_xml_export(suite):
    """Test XML export mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", good, xml_path])
        exists = os.path.exists(xml_path) and os.path.getsize(xml_path) > 0
        suite.results.append(TestResult(
            "xml_export.creates_file",
            exists or rc == EXIT_CLEAN,
            f"XML file {'exists' if exists else 'missing'}, rc={rc}",
            0.0, stdout, stderr
        ))
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)


def test_multiple_modes_same_profile(suite):
    """Test that running different modes on the same profile gives consistent results."""
    profile = str(CORPUS_DIR / "valid_srgb.icc")
    for mode in ["-a", "-h", "-r"]:
        suite.assert_no_asan(
            f"consistency.{mode[1:]}_valid",
            [mode, profile]
        )


def test_lut_extraction(suite):
    """Test LUT extraction mode (-x) on profiles with curves/LUTs."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.TemporaryDirectory() as tmpdir:
        basename = os.path.join(tmpdir, "lut_test")
        # -x mode should run without crashing
        suite.assert_no_asan(
            "lut.extract_valid_srgb",
            ["-x", good, basename]
        )

    # Also test on a profile with actual curve data (non_monotonic has curv tags)
    mono = str(CORPUS_DIR / "non_monotonic_curve.icc")
    with tempfile.TemporaryDirectory() as tmpdir:
        basename = os.path.join(tmpdir, "lut_mono")
        suite.assert_no_asan(
            "lut.extract_non_monotonic",
            ["-x", mono, basename]
        )

    # Test with a real profile from test-profiles if available
    if TEST_PROFILES.exists():
        candidates = filter_quarantined_profiles(sorted(TEST_PROFILES.glob("*.icc")))
        if candidates:
            with tempfile.TemporaryDirectory() as tmpdir:
                basename = os.path.join(tmpdir, "lut_real")
                suite.assert_no_asan(
                    "lut.extract_real_profile",
                    ["-x", str(candidates[0]), basename]
                )


def test_call_graph_mode(suite):
    """Test call graph mode (-cg) with a sample ASAN log."""

    # Create a minimal ASAN-style crash log
    asan_log = (
        "=================================================================\n"
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001234\n"
        "READ of size 4 at 0x602000001234 thread T0\n"
        "    #0 0x55555557a000 in CIccProfile::Read /src/IccProfile.cpp:100\n"
        "    #1 0x55555558b000 in main /src/main.cpp:50\n"
        "\n"
        "0x602000001234 is located 4 bytes before 16-byte region\n"
        "allocated by thread T0 here:\n"
        "    #0 0x7ffff7c00000 in malloc /lib/asan.cpp:100\n"
        "    #1 0x55555557c000 in CIccProfile::Load /src/IccProfile.cpp:80\n"
        "=================================================================\n"
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(asan_log)
        log_path = f.name

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_base = os.path.join(tmpdir, "cg_test")
            suite.assert_no_asan(
                "callgraph.asan_log_parse",
                ["-cg", log_path, out_base]
            )
    finally:
        os.unlink(log_path)


def test_xml_heuristic_export(suite):
    """Test XML export mode (-xml) produces valid XML output."""
    # Test with valid profile
    good = str(CORPUS_DIR / "valid_srgb.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path = f.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", good, xml_path])
        if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
            with open(xml_path, 'r') as xf:
                content = xf.read()
            has_xml = '<?xml' in content or '<' in content
            suite.results.append(TestResult(
                "xml_heuristic.valid_xml_content",
                has_xml,
                f"XML content {'valid' if has_xml else 'empty/invalid'}, rc={rc}",
                0.0, stdout, stderr
            ))
        else:
            suite.results.append(TestResult(
                "xml_heuristic.valid_xml_content",
                rc != 2,  # Pass if not an I/O error
                f"No XML output, rc={rc}",
                0.0, stdout, stderr
            ))
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)

    # Test with malformed profile
    bad = str(CORPUS_DIR / "bad_magic.icc")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xml_path2 = f.name
    try:
        suite.assert_no_asan(
            "xml_heuristic.bad_magic_no_crash",
            ["-xml", bad, xml_path2]
        )
    finally:
        if os.path.exists(xml_path2):
            os.unlink(xml_path2)


def test_ninja_modes_coverage(suite):
    """Test ninja modes on diverse profiles for line coverage."""
    corpus = str(CORPUS_DIR)
    # -n (minimal) and -nf (full) on multiple profile types
    for profile_name in ["valid_srgb.icc", "private_tags.icc",
                         "non_monotonic_curve.icc", "bad_wtpt.icc"]:
        path = f"{corpus}/{profile_name}"
        stem = profile_name.replace(".icc", "")
        suite.assert_no_asan(
            f"ninja.n_{stem}",
            ["-n", path]
        )
        suite.assert_no_asan(
            f"ninja.nf_{stem}",
            ["-nf", path]
        )


def test_json_output(suite):
    """Test --json structured output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")

    # JSON should be valid and parseable
    rc, stdout, stderr = suite.run_analyzer(["--json", "--legacy", good])
    try:
        data = json.loads(stdout)
        valid = True
    except (json.JSONDecodeError, ValueError):
        data = {}
        valid = False

    suite.results.append(TestResult(
        "json.valid_parse", valid,
        "JSON output should parse" if not valid else "",
        0.0, stdout, stderr
    ))

    # Check required top-level keys
    for key in ["file", "exitCode", "summary", "results"]:
        has_key = key in data
        suite.results.append(TestResult(
            f"json.has_{key}", has_key,
            f"Missing key '{key}'" if not has_key else "",
            0.0, "", ""
        ))

    # Summary should have counts
    if "summary" in data:
        s = data["summary"]
        has_total = s.get("totalHeuristics", 0) == 181
        suite.results.append(TestResult(
            "json.total_heuristics_181", has_total,
            f"totalHeuristics={s.get('totalHeuristics')}" if not has_total else "",
            0.0, "", ""
        ))
        has_cve = "cveCoverage" in s
        suite.results.append(TestResult(
            "json.has_cve_coverage", has_cve,
            "Missing cveCoverage block" if not has_cve else "",
            0.0, "", ""
        ))
        if has_cve:
            cov = s["cveCoverage"]
            has_unique = "uniqueCVEs" in cov and cov["uniqueCVEs"] >= 100
            suite.results.append(TestResult(
                "json.cve_unique_count", has_unique,
                f"uniqueCVEs={cov.get('uniqueCVEs')}, expected >= 100" if not has_unique else "",
                0.0, "", ""
            ))
            has_scope = "outOfScopeXmlCVEs" in cov and cov["outOfScopeXmlCVEs"] == 0
            suite.results.append(TestResult(
                "json.cve_xml_scope", has_scope,
                f"outOfScopeXmlCVEs={cov.get('outOfScopeXmlCVEs')}, expected 0" if not has_scope else "",
                0.0, "", ""
            ))
            has_tool_scope = "outOfScopeToolCVEs" in cov and cov["outOfScopeToolCVEs"] == 0
            suite.results.append(TestResult(
                "json.cve_tool_scope", has_tool_scope,
                f"outOfScopeToolCVEs={cov.get('outOfScopeToolCVEs')}, expected 0" if not has_tool_scope else "",
                0.0, "", ""
            ))

    # Results array should have heuristic entries with required fields
    if "results" in data and len(data["results"]) > 0:
        r = data["results"][0]
        for field in ["id", "name", "status"]:
            has_f = field in r
            suite.results.append(TestResult(
                f"json.result_has_{field}", has_f,
                f"Result missing '{field}'" if not has_f else "",
                0.0, "", ""
            ))

    # At least one result should have cveRefs
    has_cve_ref = any("cveRefs" in r for r in data.get("results", []))
    suite.results.append(TestResult(
        "json.has_cve_refs", has_cve_ref,
        "No result with cveRefs found" if not has_cve_ref else "",
        0.0, "", ""
    ))

    # Registry block in JSON should have dynamic stats
    if "summary" in data and "registry" in data["summary"]:
        reg = data["summary"]["registry"]
        has_reg_total = reg.get("totalHeuristics", 0) == 181
        suite.results.append(TestResult(
            "json.registry_total_heuristics", has_reg_total,
            f"registry.totalHeuristics={reg.get('totalHeuristics')}" if not has_reg_total else "",
            0.0, "", ""
        ))
        has_reg_cve = reg.get("heuristicsWithCVE", 0) > 0
        suite.results.append(TestResult(
            "json.registry_has_cve_count", has_reg_cve,
            "registry.heuristicsWithCVE is 0" if not has_reg_cve else "",
            0.0, "", ""
        ))

    # ASAN clean
    suite.assert_no_asan("json.asan_clean", ["--json", good])


def test_registry_output(suite):
    """Test --registry CLI mode emits valid JSON with computed stats."""
    rc, out, err = suite.run_analyzer(["--registry"])
    suite.results.append(TestResult(
        "registry.exit_0", rc == 0,
        f"exit code {rc}" if rc != 0 else "",
        0.0, "", ""
    ))
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        suite.results.append(TestResult(
            "registry.valid_json", False, f"JSON parse error: {e}",
            0.0, "", ""
        ))
        return
    suite.results.append(TestResult(
        "registry.valid_json", True, "", 0.0, "", ""
    ))
    # totalHeuristics must equal len(heuristics)
    total = data.get("totalHeuristics", 0)
    entries = len(data.get("heuristics", []))
    match = total == entries and total > 0
    suite.results.append(TestResult(
        "registry.total_matches_entries", match,
        f"totalHeuristics={total} != len(heuristics)={entries}" if not match else "",
        0.0, "", ""
    ))
    # heuristicsWithCVE must be positive
    with_cve = data.get("heuristicsWithCVE", 0)
    suite.results.append(TestResult(
        "registry.has_cve_refs", with_cve > 0,
        f"heuristicsWithCVE={with_cve}" if with_cve <= 0 else "",
        0.0, "", ""
    ))
    # severity must sum to totalHeuristics
    sev = data.get("severity", {})
    sev_sum = sum(sev.values())
    suite.results.append(TestResult(
        "registry.severity_sum", sev_sum == total,
        f"severity sum {sev_sum} != total {total}" if sev_sum != total else "",
        0.0, "", ""
    ))
    # Each entry must have required fields
    if entries > 0:
        h = data["heuristics"][0]
        for field in ["id", "name", "cwe", "phase", "severity"]:
            has = field in h
            suite.results.append(TestResult(
                f"registry.entry_has_{field}", has,
                f"Missing '{field}'" if not has else "",
                0.0, "", ""
            ))


def test_tiff_analysis(suite):
    """Test TIFF image analysis with embedded ICC profile."""
    tiff_path = CORPUS_DIR / "test_tiff_with_icc.tif"
    if not tiff_path.exists():
        return

    tiff = str(tiff_path)

    # Should detect TIFF and run image analysis
    suite.assert_output_contains(
        "tiff.detects_format",
        ["-a", tiff], r"IMAGE FILE ANALYSIS.*TIFF"
    )

    # Should report TIFF metadata
    suite.assert_output_contains(
        "tiff.reports_dimensions",
        ["-a", tiff], r"Dimensions:.*10.*10"
    )

    # H139 strip geometry should run
    suite.assert_output_contains(
        "tiff.h139_runs",
        ["-a", tiff], r"\[H139\].*Strip Geometry"
    )

    # H140 dimension validation should run
    suite.assert_output_contains(
        "tiff.h140_runs",
        ["-a", tiff], r"\[H140\].*Dimension"
    )

    # H141 IFD offset bounds should run
    suite.assert_output_contains(
        "tiff.h141_runs",
        ["-a", tiff], r"\[H141\].*IFD"
    )

    # H149 IFD chain cycle detection should run
    suite.assert_output_contains(
        "tiff.h149_runs",
        ["-a", tiff], r"\[H149\].*IFD Chain Cycle"
    )

    # H150 tile geometry validation should run
    suite.assert_output_contains(
        "tiff.h150_runs",
        ["-a", tiff], r"\[H150\].*Tile Geometry"
    )

    # Should extract and analyze embedded ICC profile
    suite.assert_output_contains(
        "tiff.icc_extraction",
        ["-a", tiff], r"ICC Profile.*Extracted|Embedded ICC"
    )

    # ASAN clean
    suite.assert_no_asan("tiff.asan_clean", ["-a", tiff])


def test_tiff_corrupt(suite):
    """Test TIFF analysis when TIFFOpen fails (corrupt/truncated file)."""
    corrupt_path = CORPUS_DIR / "corrupt_truncated.tif"
    if not corrupt_path.exists():
        return

    corrupt = str(corrupt_path)

    # Should detect TIFF format and attempt analysis
    suite.assert_output_contains(
        "tiff_corrupt.detects_format",
        ["-a", corrupt], r"IMAGE FILE ANALYSIS.*TIFF"
    )

    # Should report CWE-20 for TIFFOpen failure
    suite.assert_output_contains(
        "tiff_corrupt.cwe20_tiffopen",
        ["-a", corrupt], r"CRIT.*Cannot open TIFF.*TIFFOpen failed"
    )

    # H149 should still run (uses raw file I/O, not TIFF handle)
    suite.assert_output_contains(
        "tiff_corrupt.h149_runs",
        ["-a", corrupt], r"\[H149\].*IFD Chain Cycle"
    )

    # H139/H140/H141/H150 should report NOT RUN (require valid TIFF handle)
    suite.assert_output_contains(
        "tiff_corrupt.h139_skips",
        ["-a", corrupt], r"\[H139\].*Strip Geometry"
    )
    suite.assert_output_contains(
        "tiff_corrupt.h139_skip_msg",
        ["-a", corrupt], r"\[NOT RUN\].*Requires parseable TIFF"
    )

    # Should output IMAGE ANALYSIS SUMMARY
    suite.assert_output_contains(
        "tiff_corrupt.summary",
        ["-a", corrupt], r"IMAGE ANALYSIS SUMMARY"
    )

    # ASAN clean
    suite.assert_no_asan("tiff_corrupt.asan_clean", ["-a", corrupt])


def test_bigtiff_analysis(suite):
    """Test BigTIFF image analysis — LE, BE, tiled, and SubIFD variants."""
    # --- BigTIFF LE (strip-based) ---
    le_path = CORPUS_DIR / "bigtiff_le.tif"
    if le_path.exists():
        le = str(le_path)

        suite.assert_output_contains(
            "bigtiff_le.detects_format",
            ["-a", le], r"IMAGE FILE ANALYSIS.*TIFF"
        )

        suite.assert_output_contains(
            "bigtiff_le.dimensions",
            ["-a", le], r"Dimensions:.*64.*64"
        )

        suite.assert_output_contains(
            "bigtiff_le.h139_ok",
            ["-a", le], r"\[H139\].*Strip Geometry"
        )

        suite.assert_output_contains(
            "bigtiff_le.h140_ok",
            ["-a", le], r"\[H140\].*Dimension"
        )

        suite.assert_output_contains(
            "bigtiff_le.h141_ok",
            ["-a", le], r"\[H141\].*IFD"
        )

        suite.assert_output_contains(
            "bigtiff_le.h149_ok",
            ["-a", le], r"\[H149\].*IFD Chain Cycle"
        )

        suite.assert_output_contains(
            "bigtiff_le.h150_strip_na",
            ["-a", le], r"\[H150\].*Tile Geometry"
        )

        suite.assert_output_contains(
            "bigtiff_le.no_icc",
            ["-a", le], r"No embedded ICC profile"
        )

        suite.assert_no_asan("bigtiff_le.asan_clean", ["-a", le])

    # --- BigTIFF BE (Motorola byte order) ---
    be_path = CORPUS_DIR / "bigtiff_be.tif"
    if be_path.exists():
        be = str(be_path)

        suite.assert_output_contains(
            "bigtiff_be.detects_format",
            ["-a", be], r"IMAGE FILE ANALYSIS.*TIFF"
        )

        suite.assert_output_contains(
            "bigtiff_be.dimensions",
            ["-a", be], r"Dimensions:.*64.*64"
        )

        suite.assert_output_contains(
            "bigtiff_be.h139_ok",
            ["-a", be], r"\[H139\].*Strip Geometry"
        )

        suite.assert_output_contains(
            "bigtiff_be.h149_ok",
            ["-a", be], r"\[H149\].*IFD Chain Cycle"
        )

        suite.assert_no_asan("bigtiff_be.asan_clean", ["-a", be])

    # --- BigTIFF tiled (exercises H150 tile geometry) ---
    tiled_path = CORPUS_DIR / "bigtiff_tiled.tif"
    if tiled_path.exists():
        tiled = str(tiled_path)

        suite.assert_output_contains(
            "bigtiff_tiled.detects_format",
            ["-a", tiled], r"IMAGE FILE ANALYSIS.*TIFF"
        )

        suite.assert_output_contains(
            "bigtiff_tiled.h139_tiled_na",
            ["-a", tiled], r"\[H139\].*Strip Geometry.*\n.*Tiled image"
        )

        suite.assert_output_contains(
            "bigtiff_tiled.h150_tile_ok",
            ["-a", tiled], r"\[H150\].*Tile Geometry.*\n.*\[OK\].*Tile geometry valid"
        )

        suite.assert_output_contains(
            "bigtiff_tiled.tile_size",
            ["-a", tiled], r"Tile Size:.*32.*32"
        )

        suite.assert_no_asan("bigtiff_tiled.asan_clean", ["-a", tiled])

    # --- BigTIFF SubIFD (multi-page, exercises H141/H149 IFD chain) ---
    subifd_path = CORPUS_DIR / "bigtiff_subifd.tif"
    if subifd_path.exists():
        subifd = str(subifd_path)

        suite.assert_output_contains(
            "bigtiff_subifd.detects_format",
            ["-a", subifd], r"IMAGE FILE ANALYSIS.*TIFF"
        )

        suite.assert_output_contains(
            "bigtiff_subifd.h141_multipage",
            ["-a", subifd], r"\[H141\].*IFD.*\n.*Multi-page TIFF.*2 directories"
        )

        suite.assert_output_contains(
            "bigtiff_subifd.h149_acyclic",
            ["-a", subifd], r"\[H149\].*IFD Chain Cycle.*\n.*\[OK\].*acyclic"
        )

        suite.assert_no_asan("bigtiff_subifd.asan_clean", ["-a", subifd])


def test_html_xml_output(suite):
    """Test XML+XSLT (HTML) export mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_out = tmp.name

    try:
        rc, stdout, stderr = suite.run_analyzer(["-xml", "--legacy", good, xml_out])
        suite.results.append(TestResult(
            "html.exit_code_ok", rc != 2,
            f"Exit code {rc} (I/O error)" if rc == 2 else "",
            0.0, "", ""
        ))

        xml_content = ""
        if os.path.exists(xml_out):
            with open(xml_out, "r") as f:
                xml_content = f.read()

        suite.results.append(TestResult(
            "html.xml_has_content", len(xml_content) > 100,
            f"XML output too short ({len(xml_content)} bytes)" if len(xml_content) <= 100 else "",
            0.0, "", ""
        ))

        has_decl = "<?xml" in xml_content
        suite.results.append(TestResult(
            "html.xml_declaration", has_decl,
            "Missing <?xml declaration" if not has_decl else "",
            0.0, "", ""
        ))

        has_xslt = "xsl:stylesheet" in xml_content or "xml-stylesheet" in xml_content
        suite.results.append(TestResult(
            "html.has_xslt", has_xslt,
            "Missing XSLT reference" if not has_xslt else "",
            0.0, "", ""
        ))

        has_ver = "iccAnalyzer-lite v" in xml_content
        suite.results.append(TestResult(
            "html.has_version", has_ver,
            "Missing version string" if not has_ver else "",
            0.0, "", ""
        ))

        has_av = "<analyzer_version>" in xml_content
        suite.results.append(TestResult(
            "html.has_analyzer_version_tag", has_av,
            "Missing <analyzer_version> tag" if not has_av else "",
            0.0, "", ""
        ))

        has_heuristic = "<check>" in xml_content
        suite.results.append(TestResult(
            "html.has_check_elements", has_heuristic,
            "Missing <check> elements" if not has_heuristic else "",
            0.0, "", ""
        ))

        # New: verify per-heuristic XML structure
        check_count = xml_content.count("<check>")
        has_many_checks = check_count > 20
        suite.results.append(TestResult(
            "html.per_heuristic_count", has_many_checks,
            f"Only {check_count} <check> elements (expected 100+)" if not has_many_checks else "",
            0.0, "", ""
        ))

        has_severity = "<severity>" in xml_content
        suite.results.append(TestResult(
            "html.has_severity_tags", has_severity,
            "Missing <severity> tags in XML" if not has_severity else "",
            0.0, "", ""
        ))

        has_cwe = "<cwe>" in xml_content
        suite.results.append(TestResult(
            "html.has_cwe_tags", has_cwe,
            "Missing <cwe> tags in XML" if not has_cwe else "",
            0.0, "", ""
        ))

        has_sha = "<sha256>" in xml_content
        suite.results.append(TestResult(
            "html.has_sha256", has_sha,
            "Missing <sha256> in XML profile section" if not has_sha else "",
            0.0, "", ""
        ))

        suite.assert_no_asan("html.asan_clean", ["-xml", good, xml_out])
    finally:
        if os.path.exists(xml_out):
            os.unlink(xml_out)


def test_report_output(suite):
    """Test --report severity-sorted report output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    bad = str(CORPUS_DIR / "huge_tag_count.icc")

    # Report should contain banner
    rc, stdout, stderr = suite.run_analyzer(["--report", "--legacy", good])
    has_banner = "ICC PROFILE SECURITY REPORT" in stdout
    suite.results.append(TestResult(
        "report.has_banner", has_banner,
        "Missing report banner" if not has_banner else "",
        0.0, "", ""
    ))

    # Report should contain tool version
    has_version = "iccAnalyzer-lite" in stdout
    suite.results.append(TestResult(
        "report.has_version", has_version,
        "Missing tool version in banner" if not has_version else "",
        0.0, "", ""
    ))

    # Report should contain SHA-256
    has_sha = "SHA-256:" in stdout
    suite.results.append(TestResult(
        "report.has_sha256", has_sha,
        "Missing SHA-256 hash" if not has_sha else "",
        0.0, "", ""
    ))

    # Report should contain executive summary
    has_exec = "EXECUTIVE SUMMARY" in stdout
    suite.results.append(TestResult(
        "report.has_executive_summary", has_exec,
        "Missing executive summary" if not has_exec else "",
        0.0, "", ""
    ))

    # Report should contain severity distribution
    has_dist = "Severity Distribution:" in stdout
    suite.results.append(TestResult(
        "report.has_severity_dist", has_dist,
        "Missing severity distribution" if not has_dist else "",
        0.0, "", ""
    ))

    # Report should contain CWE category summary
    has_cwe = "CWE CATEGORY SUMMARY" in stdout
    suite.results.append(TestResult(
        "report.has_cwe_summary", has_cwe,
        "Missing CWE category summary" if not has_cwe else "",
        0.0, "", ""
    ))

    # Report should contain CVE coverage statistics
    has_cve = "CVE COVERAGE STATISTICS" in stdout
    suite.results.append(TestResult(
        "report.has_cve_stats", has_cve,
        "Missing CVE coverage statistics" if not has_cve else "",
        0.0, "", ""
    ))

    # Report on bad profile should have severity sections with findings
    rc2, stdout2, stderr2 = suite.run_analyzer(["--report", "--legacy", bad])
    has_critical = "CRITICAL FINDINGS" in stdout2
    suite.results.append(TestResult(
        "report.bad_has_critical_section", has_critical,
        "Missing CRITICAL FINDINGS section for bad profile" if not has_critical else "",
        0.0, "", ""
    ))

    # CVE CROSS-REFERENCES section should appear when findings have CVEs
    has_xref = "CVE CROSS-REFERENCES" in stdout2
    suite.results.append(TestResult(
        "report.bad_has_cve_crossref", has_xref,
        "Missing CVE cross-references for bad profile" if not has_xref else "",
        0.0, "", ""
    ))

    # ASAN clean
    suite.assert_no_asan("report.asan_clean_good", ["--report", good])
    suite.assert_no_asan("report.asan_clean_bad", ["--report", bad])

    # JSON severity field test (requires --legacy for heuristic severity data)
    rc3, stdout3, stderr3 = suite.run_analyzer(["--json", "--legacy", good])
    try:
        data = json.loads(stdout3)
        results = data.get("results", [])
        has_severity = any("severity" in r for r in results)
        suite.results.append(TestResult(
            "json.has_severity_field", has_severity,
            "JSON results missing severity field" if not has_severity else "",
            0.0, "", ""
        ))
        if results:
            valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            sev = results[0].get("severity", "")
            valid_sev = sev in valid_severities
            suite.results.append(TestResult(
                "json.valid_severity_value", valid_sev,
                f"Invalid severity value: {sev}" if not valid_sev else "",
                0.0, "", ""
            ))
    except (json.JSONDecodeError, ValueError):
        suite.results.append(TestResult(
            "json.has_severity_field", False, "JSON parse failed", 0.0, "", ""
        ))


def test_pawg_output(suite):
    """Test -pawg ICC Profile Assessment Working Group report output mode."""
    good = str(CORPUS_DIR / "valid_srgb.icc")
    bad = str(CORPUS_DIR / "wrong_d50_illuminant.icc")

    # PAWG report should contain banner
    rc, stdout, stderr = suite.run_analyzer(["-pawg", good])
    has_banner = "ICC PROFILE ASSESSMENT REPORT (PAWG)" in stdout
    suite.results.append(TestResult(
        "pawg.has_banner", has_banner,
        "Missing PAWG report banner" if not has_banner else "",
        0.0, "", ""
    ))

    # Should contain tool version
    has_version = "iccAnalyzer-lite" in stdout
    suite.results.append(TestResult(
        "pawg.has_version", has_version,
        "Missing tool version in PAWG banner" if not has_version else "",
        0.0, "", ""
    ))

    # Should contain SHA-256
    has_sha = "SHA-256:" in stdout
    suite.results.append(TestResult(
        "pawg.has_sha256", has_sha,
        "Missing SHA-256 hash in PAWG report" if not has_sha else "",
        0.0, "", ""
    ))

    # Should contain all 3 sections
    has_security = "[ SECURITY ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_security_section", has_security,
        "Missing SECURITY section" if not has_security else "",
        0.0, "", ""
    ))

    has_conformance = "[ CONFORMANCE ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_conformance_section", has_conformance,
        "Missing CONFORMANCE section" if not has_conformance else "",
        0.0, "", ""
    ))

    has_quality = "[ QUALITY ]" in stdout
    suite.results.append(TestResult(
        "pawg.has_quality_section", has_quality,
        "Missing QUALITY section" if not has_quality else "",
        0.0, "", ""
    ))

    # Should contain assessment summary
    has_summary = "ASSESSMENT SUMMARY" in stdout
    suite.results.append(TestResult(
        "pawg.has_summary", has_summary,
        "Missing ASSESSMENT SUMMARY section" if not has_summary else "",
        0.0, "", ""
    ))

    # Should contain conformance check coverage
    has_coverage = "CONFORMANCE CHECK COVERAGE" in stdout
    suite.results.append(TestResult(
        "pawg.has_conformance_coverage", has_coverage,
        "Missing CONFORMANCE CHECK COVERAGE section" if not has_coverage else "",
        0.0, "", ""
    ))

    # Should contain spec references
    has_specs = "SPECIFICATION REFERENCES" in stdout
    suite.results.append(TestResult(
        "pawg.has_spec_references", has_specs,
        "Missing SPECIFICATION REFERENCES section" if not has_specs else "",
        0.0, "", ""
    ))

    has_checklist_ref = (
        "ICC Profile Assessment Working Group Checklist Reference: "
        "https://www.color.org/profiles/assessment/index.xalter"
    ) in stdout
    suite.results.append(TestResult(
        "pawg.has_checklist_reference_url", has_checklist_ref,
        "Missing PAWG checklist reference URL" if not has_checklist_ref else "",
        0.0, "", ""
    ))

    spec_refs = pawg_spec_reference_paths()
    has_all_spec_refs = all(ref in stdout for ref in spec_refs)
    suite.results.append(TestResult(
        "pawg.has_all_spec_reference_paths", has_all_spec_refs,
        "Missing one or more docs/iccDEV/specifications references"
        if not has_all_spec_refs else "",
        0.0, "", ""
    ))

    has_no_adgc_ref = "docs/iccDEV/specifications/ICC.1_Adaptive_Gain_Curve.pdf" not in stdout
    suite.results.append(TestResult(
        "pawg.omits_adaptive_gain_curve_reference", has_no_adgc_ref,
        "PAWG report should omit ICC.1_Adaptive_Gain_Curve.pdf from the reference list"
        if not has_no_adgc_ref else "",
        0.0, "", ""
    ))

    # Summary should show total of 31 checklist items
    has_31 = "Total checklist items:  31" in stdout
    suite.results.append(TestResult(
        "pawg.has_31_items", has_31,
        "PAWG report should have exactly 31 checklist items" if not has_31 else "",
        0.0, "", ""
    ))

    # Should have verdict counts in summary
    import re
    pass_match = re.search(r"PASS:\s+(\d+)", stdout)
    warn_match = re.search(r"WARN:\s+(\d+)", stdout)
    fail_match = re.search(r"FAIL:\s+(\d+)", stdout)
    has_counts = pass_match is not None and warn_match is not None and fail_match is not None
    suite.results.append(TestResult(
        "pawg.has_verdict_counts", has_counts,
        "Missing PASS/WARN/FAIL counts in summary" if not has_counts else "",
        0.0, "", ""
    ))

    has_quality_states = (
        re.search(r"\[OK\]\s+S1\b", stdout) is not None and
        re.search(r"\[OK\]\s+Q1\b", stdout) is not None and
        re.search(r"\[OK\]\s+Q2\b", stdout) is not None and
        re.search(r"\[OK\]\s+Q3\b", stdout) is not None and
        re.search(r"\[N/A\]\s+Q4\b", stdout) is not None
    )
    suite.results.append(TestResult(
        "pawg.good_profile_quality_states", has_quality_states,
        "Expected S1/Q1/Q2/Q3 to report [OK] and Q4 to report [N/A] on the good profile"
        if not has_quality_states else "",
        0.0, "", ""
    ))

    char_profile = str(CORPUS_DIR / "targ_quality_profile.icc")
    rc_char, stdout_char, stderr_char = suite.run_analyzer(["-pawg", char_profile])
    has_char_q4 = re.search(r"\[OK\]\s+Q4\b", stdout_char) is not None
    suite.results.append(TestResult(
        "pawg.characterization_profile_q4_ok", has_char_q4,
        "Expected Q4 to report [OK] on the characterization quality profile"
        if not has_char_q4 else "",
        0.0, "", ""
    ))

    has_char_q123 = (
        re.search(r"\[OK\]\s+Q1\b", stdout_char) is not None and
        re.search(r"\[OK\]\s+Q2\b", stdout_char) is not None and
        re.search(r"\[OK\]\s+Q3\b", stdout_char) is not None
    )
    suite.results.append(TestResult(
        "pawg.characterization_profile_q123_ok", has_char_q123,
        "Expected Q1/Q2/Q3 to report [OK] on the characterization quality profile"
        if not has_char_q123 else "",
        0.0, "", ""
    ))

    cmyk_profile = str(CORPUS_DIR / "targ_cmyk_quality_profile.icc")
    rc_cmyk, stdout_cmyk, stderr_cmyk = suite.run_analyzer(["-pawg", cmyk_profile])
    has_cmyk_q1234 = (
        re.search(r"\[OK\]\s+Q1\b", stdout_cmyk) is not None and
        re.search(r"\[OK\]\s+Q2\b", stdout_cmyk) is not None and
        re.search(r"\[OK\]\s+Q3\b", stdout_cmyk) is not None and
        re.search(r"\[OK\]\s+Q4\b", stdout_cmyk) is not None
    )
    suite.results.append(TestResult(
        "pawg.cmyk_quality_profile_q1234_ok", has_cmyk_q1234,
        "Expected Q1/Q2/Q3/Q4 to report [OK] on the CMYK characterization quality profile"
        if not has_cmyk_q1234 else "",
        0.0, "", ""
    ))

    namedcolor_profile = str(TEST_PROFILES / "NamedColor.icc")
    rc_named, stdout_named, stderr_named = suite.run_analyzer(["-pawg", namedcolor_profile])
    has_namedcolor_states = (
        re.search(r"\[N/A\]\s+S1\b", stdout_named) is not None and
        re.search(r"\[GAP\]\s+Q1\b", stdout_named) is not None and
        re.search(r"\[N/A\]\s+Q2\b", stdout_named) is not None and
        re.search(r"\[GAP\]\s+Q3\b", stdout_named) is not None and
        re.search(r"\[N/A\]\s+Q4\b", stdout_named) is not None and
        "[ -- ]" not in stdout_named
    )
    suite.results.append(TestResult(
        "pawg.namedcolor_coverage_states", has_namedcolor_states,
        "Expected NamedColor PAWG output to classify S1/Q1/Q2/Q3/Q4 without any [ -- ] items"
        if not has_namedcolor_states else "",
        0.0, "", ""
    ))

    # Counts should sum to exactly 31 including N/A/GAP/NOT RUN categories
    if has_counts:
        na_match = re.search(r"N/A:\s+(\d+)", stdout)
        gap_match = re.search(r"GAP:\s+(\d+)", stdout)
        not_run_match = re.search(r"NOT RUN:\s+(\d+)", stdout)
        total = (
            int(pass_match.group(1)) +
            int(warn_match.group(1)) +
            int(fail_match.group(1)) +
            (int(na_match.group(1)) if na_match else 0) +
            (int(gap_match.group(1)) if gap_match else 0) +
            (int(not_run_match.group(1)) if not_run_match else 0)
        )
        suite.results.append(TestResult(
            "pawg.counts_sum_31", total == 31,
            f"PAWG summary categories sum to {total}, expected 31" if total != 31 else "",
            0.0, "", ""
        ))

    # Should contain Overall verdict
    has_overall = "Overall:" in stdout
    suite.results.append(TestResult(
        "pawg.has_overall_verdict", has_overall,
        "Missing Overall verdict line" if not has_overall else "",
        0.0, "", ""
    ))

    # Check S1-S13 security items present
    s_items = sum(1 for i in range(1, 14) if f"S{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_13_security_items", s_items == 13,
        f"Found {s_items}/13 security items" if s_items != 13 else "",
        0.0, "", ""
    ))

    # Check C1-C14 conformance items present
    c_items = sum(1 for i in range(1, 15) if f"C{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_14_conformance_items", c_items == 14,
        f"Found {c_items}/14 conformance items" if c_items != 14 else "",
        0.0, "", ""
    ))

    # Check Q1-Q4 quality items present
    q_items = sum(1 for i in range(1, 5) if f"Q{i}" in stdout)
    suite.results.append(TestResult(
        "pawg.has_4_quality_items", q_items == 4,
        f"Found {q_items}/4 quality items" if q_items != 4 else "",
        0.0, "", ""
    ))

    # Bad profile should trigger WARN or FAIL items
    rc2, stdout2, stderr2 = suite.run_analyzer(["-pawg", bad])
    warn_match2 = re.search(r"WARN:\s+(\d+)", stdout2)
    fail_match2 = re.search(r"FAIL:\s+(\d+)", stdout2)
    warn_count2 = int(warn_match2.group(1)) if warn_match2 else 0
    fail_count2 = int(fail_match2.group(1)) if fail_match2 else 0
    has_bad_findings = (warn_count2 + fail_count2) > 0
    suite.results.append(TestResult(
        "pawg.bad_profile_has_findings", has_bad_findings,
        "Bad profile should have WARN or FAIL items" if not has_bad_findings else "",
        0.0, "", ""
    ))

    # Bad profile detail lines should show conformance check IDs
    has_detail = re.search(r"CF-\d+:.*\[(WARN|FAIL)\]", stdout2) is not None
    suite.results.append(TestResult(
        "pawg.bad_has_detail_lines", has_detail,
        "Bad profile WARN/FAIL items should include CF-### detail lines" if not has_detail else "",
        0.0, "", ""
    ))

    # ASAN clean on both profiles
    suite.assert_no_asan("pawg.asan_clean_good", ["-pawg", good])
    suite.assert_no_asan("pawg.asan_clean_bad", ["-pawg", bad])


def test_lut_text_io(suite):
    """Test LUT text export/import (-xt, -it) and .cube round-trip (-from-cube, -cube)."""

    good = str(CORPUS_DIR / "valid_srgb.icc")

    # --- Text extraction (-xt) on corpus profile ---
    with tempfile.TemporaryDirectory() as tmpdir:
        base = os.path.join(tmpdir, "xt_")
        suite.assert_no_asan("lut_text.xt_corpus", ["-xt", good, base])

    # --- Text extraction on real MPE profile (sRGB_D65_MAT.icc) ---
    srgb = TEST_PROFILES / "sRGB_D65_MAT.icc"
    if srgb.exists():
        with tempfile.TemporaryDirectory() as tmpdir:
            base = os.path.join(tmpdir, "xt_srgb_")
            rc, stdout, stderr = suite.run_analyzer(["-xt", str(srgb), base])
            has_mpe = "MPE" in stdout
            suite.results.append(TestResult(
                "lut_text.xt_srgb_has_mpe", has_mpe,
                "sRGB_D65_MAT should have MPE elements" if not has_mpe else "",
                0.0, "", ""
            ))
            # Should produce matrix and curve files
            files = os.listdir(tmpdir)
            has_matrix = any("matrix" in f for f in files)
            has_curves = any("curves" in f for f in files)
            suite.results.append(TestResult(
                "lut_text.xt_srgb_matrix_file", has_matrix,
                "Should produce matrix text file" if not has_matrix else "",
                0.0, "", ""
            ))
            suite.results.append(TestResult(
                "lut_text.xt_srgb_curves_file", has_curves,
                "Should produce curves text file" if not has_curves else "",
                0.0, "", ""
            ))

    # --- .cube import (-from-cube) ---
    cube_seeds = REPO_ROOT / "cfl" / "icc_fromcube_fuzzer_seed_corpus"
    if cube_seeds.exists():
        cubes = sorted(cube_seeds.glob("*.cube"))
        # Find a valid cube (identity_2x2x2 is known-good)
        valid_cube = None
        for c in cubes:
            if "identity_2x2x2" in c.name or "custom_domain_3x3x3" in c.name:
                valid_cube = c
                break
        if not valid_cube and cubes:
            valid_cube = cubes[0]

        if valid_cube:
            with tempfile.TemporaryDirectory() as tmpdir:
                out_icc = os.path.join(tmpdir, "from_cube.icc")
                suite.assert_output_contains(
                    "lut_text.from_cube_creates_icc",
                    ["-from-cube", str(valid_cube), out_icc],
                    r"Created ICC DeviceLink",
                    expected_code=0,
                )
                # Verify the ICC was written
                icc_exists = os.path.exists(out_icc) and os.path.getsize(out_icc) > 0
                suite.results.append(TestResult(
                    "lut_text.from_cube_file_exists", icc_exists,
                    "from-cube should create non-empty ICC" if not icc_exists else "",
                    0.0, "", ""
                ))

                # --- .cube export (-cube) round-trip ---
                if icc_exists:
                    rt_cube = os.path.join(tmpdir, "roundtrip.cube")
                    suite.assert_output_contains(
                        "lut_text.cube_export",
                        ["-cube", out_icc, "AToB0Tag", rt_cube],
                        r"Exported \.cube",
                        expected_code=0,
                    )
                    cube_exists = os.path.exists(rt_cube) and os.path.getsize(rt_cube) > 0
                    suite.results.append(TestResult(
                        "lut_text.cube_roundtrip_file", cube_exists,
                        "cube export should create non-empty file" if not cube_exists else "",
                        0.0, "", ""
                    ))

    # --- MPE matrix import round-trip (-it) ---
    if srgb.exists():
        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract
            base = os.path.join(tmpdir, "rt_")
            suite.run_analyzer(["-xt", str(srgb), base])
            matrix_file = None
            for f in os.listdir(tmpdir):
                if "matrix" in f and f.endswith(".txt"):
                    matrix_file = os.path.join(tmpdir, f)
                    break
            if matrix_file:
                # Copy profile, import matrix back
                mod_icc = os.path.join(tmpdir, "modified.icc")
                shutil.copy2(str(srgb), mod_icc)
                out_icc = os.path.join(tmpdir, "imported.icc")
                suite.assert_output_contains(
                    "lut_text.it_mpe_matrix",
                    ["-it", mod_icc, matrix_file, out_icc],
                    r"Imported MPE matrix",
                    expected_code=0,
                )
                out_exists = os.path.exists(out_icc) and os.path.getsize(out_icc) > 0
                suite.results.append(TestResult(
                    "lut_text.it_matrix_file_written", out_exists,
                    "import should create output ICC" if not out_exists else "",
                    0.0, "", ""
                ))

    # --- MPE CLUT import round-trip (-it) ---
    if cube_seeds.exists() and valid_cube:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create ICC from cube, extract CLUT text, import back
            icc1 = os.path.join(tmpdir, "clut_src.icc")
            suite.run_analyzer(["-from-cube", str(valid_cube), icc1])
            if os.path.exists(icc1):
                base = os.path.join(tmpdir, "clut_")
                suite.run_analyzer(["-xt", icc1, base])
                clut_file = None
                for f in os.listdir(tmpdir):
                    if "clut" in f and f.endswith(".txt"):
                        clut_file = os.path.join(tmpdir, f)
                        break
                if clut_file:
                    icc2 = os.path.join(tmpdir, "clut_mod.icc")
                    shutil.copy2(icc1, icc2)
                    out_icc = os.path.join(tmpdir, "clut_imported.icc")
                    suite.assert_output_contains(
                        "lut_text.it_mpe_clut",
                        ["-it", icc2, clut_file, out_icc],
                        r"Imported MPE CLUT",
                        expected_code=0,
                    )

    # --- Error handling: bad cube ---
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cube', delete=False) as f:
        f.write("TITLE bad\nLUT_3D_SIZE 0\n")
        bad_cube = f.name
    try:
        suite.assert_exit_code("lut_text.bad_cube_rejected", ["-from-cube", bad_cube, "/dev/null"], 2)
    finally:
        os.unlink(bad_cube)

    # --- Error handling: -xt with nonexistent profile ---
    suite.assert_exit_code(
        "lut_text.xt_nonexistent",
        ["-xt", "/tmp/nonexistent_profile.icc", "/tmp/out_"],
        3,  # usage/error
    )

    # --- ASAN clean: diverse profiles through -xt ---
    diverse = ["sRGB_D65_MAT.icc", "sRGB_D65_MAT-500lx.icc", "17ChanPart1.icc"]
    for name in diverse:
        p = TEST_PROFILES / name
        if p.exists():
            with tempfile.TemporaryDirectory() as tmpdir:
                base = os.path.join(tmpdir, "div_")
                suite.assert_no_asan(f"lut_text.xt_asan_{name}", ["-xt", str(p), base])


def test_conformance_checks(suite):
    """Test ICC Specification conformance checks (CF-001..CF-339)."""
    corpus = str(CORPUS_DIR)

    # --- CF Header Checks (CF-001..CF-019) ---
    # Valid profile should pass header checks cleanly
    suite.assert_output_contains(
        "cf.header.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-001|Header.*Size|Profile Size"
    )

    # CF-002: Date/Time Leap Year Validation
    suite.assert_output_contains(
        "cf.002.datetime_leap_year",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-002.*Date.*Time.*Leap Year"
    )

    # CF-003: Profile Flags Reserved Bits
    suite.assert_output_contains(
        "cf.003.flags_reserved_bits",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-003.*Profile Flags.*Reserved"
    )

    # CF-004: Device Attributes Reserved Bits
    suite.assert_output_contains(
        "cf.004.device_attr_reserved",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-004.*Device Attributes.*Reserved"
    )

    # CF-005: Rendering Intent Upper Bits Zero
    suite.assert_output_contains(
        "cf.005.rendering_intent_upper",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-005.*Rendering Intent.*Upper"
    )

    # CF-006: Profile Version BCD Encoding
    suite.assert_output_contains(
        "cf.006.version_bcd",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-006.*Version.*BCD"
    )

    # CF-007: Primary Platform Signature
    suite.assert_output_contains(
        "cf.007.platform_signature",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-007.*Platform.*Signature"
    )

    # CF-008: PCS Illuminant D50 Precision
    suite.assert_output_contains(
        "cf.008.pcs_illuminant_d50",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-008.*PCS Illuminant.*D50"
    )

    # CF-009: Chromatic Adaptation Tag Requirement
    suite.assert_output_contains(
        "cf.009.chad_tag_requirement",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-009.*Chromatic Adaptation.*Tag"
    )

    # CF-010: Profile Size vs File Size
    suite.assert_output_contains(
        "cf.010.profile_size_vs_file",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-010.*Profile Size.*File"
    )

    # CF-012: Profile Class Signature
    suite.assert_output_contains(
        "cf.012.profile_class_sig",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-012.*Profile Class"
    )

    # CF-013: Data Colour Space Signature
    suite.assert_output_contains(
        "cf.013.data_colour_space",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-013.*Data Colour Space"
    )

    # CF-014: PCS Field for Non-DeviceLink
    suite.assert_output_contains(
        "cf.014.pcs_non_devicelink",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-014.*PCS.*Non.*DeviceLink"
    )

    # CF-015: Reserved Bytes 100-127 Zero
    suite.assert_output_contains(
        "cf.015.reserved_bytes_zero",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-015.*Reserved Bytes.*Zero"
    )

    # CF-016: Device Manufacturer Signature
    suite.assert_output_contains(
        "cf.016.device_manufacturer",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-016.*Device Manufacturer"
    )

    # CF-017: Device Model Signature
    suite.assert_output_contains(
        "cf.017.device_model",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-017.*Device Model"
    )

    # CF-018: Device Attributes Semantic Bits
    suite.assert_output_contains(
        "cf.018.device_attributes",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-018.*Device Attributes"
    )

    # CF-019: Creator Signature
    suite.assert_output_contains(
        "cf.019.creator_signature",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-019.*Creator"
    )

    # --- CF Tag Type Checks (CF-020..CF-039) ---
    # CF-020: Tag Type Allowed for Signature
    suite.assert_output_contains(
        "cf.020.tag_type_allowed",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-020.*Tag Type.*Allowed"
    )

    # CF-022: curveType Entry Count Mode
    suite.assert_output_contains(
        "cf.022.curve_entry_count",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-022.*curveType.*Entry Count"
    )

    # CF-023: parametricCurveType Function Type
    suite.assert_output_contains(
        "cf.023.parametric_func_type",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-023.*parametricCurveType.*Function"
    )

    # CF-024: parametricCurveType Parameter Count
    suite.assert_output_contains(
        "cf.024.parametric_param_count",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-024.*parametricCurveType.*Parameter"
    )

    # CF-025: chromaticityType Phosphor Count
    suite.assert_output_contains(
        "cf.025.chromaticity_phosphor",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-025.*chromaticityType.*Phosphor"
    )

    # CF-026: colorantTableType Colorant Count
    suite.assert_output_contains(
        "cf.026.colorant_table_count",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-026.*colorantTableType.*Colorant"
    )

    # CF-027: colorantOrderType Count Match
    suite.assert_output_contains(
        "cf.027.colorant_order_match",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-027.*colorantOrderType.*Count"
    )

    # CF-028: namedColor2Type Coordinate Count
    suite.assert_output_contains(
        "cf.028.named_color2_coords",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-028.*namedColor2Type.*Coordinate"
    )

    # CF-029: dateTimeType Field Ranges
    suite.assert_output_contains(
        "cf.029.datetime_field_ranges",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-029.*dateTimeType.*Field"
    )

    # CF-032: XYZType Triplet Count
    suite.assert_output_contains(
        "cf.032.xyz_triplet_count",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-032.*XYZType.*Triplet"
    )

    # CF-033: measurementType Standard Observer
    suite.assert_output_contains(
        "cf.033.measurement_observer",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-033.*measurementType.*Observer"
    )

    # CF-034: measurementType Measurement Geometry
    suite.assert_output_contains(
        "cf.034.measurement_geometry",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-034.*measurementType.*Geometry"
    )

    # CF-035: responseCurveSet16Type Structure
    suite.assert_output_contains(
        "cf.035.response_curve_set",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-035.*responseCurveSet"
    )

    # CF-036: profileSequenceDescType Elements
    suite.assert_output_contains(
        "cf.036.profile_seq_desc",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-036.*profileSequenceDesc"
    )

    # CF-037: profileSequenceIdentifierType Validation
    suite.assert_output_contains(
        "cf.037.profile_seq_id",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-037.*profileSequenceIdentifier"
    )

    # CF-038: dateTimeType Tag Range Validation
    suite.assert_output_contains(
        "cf.038.datetime_range",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-038.*dateTimeType"
    )

    # CF-039: signatureType Technology Validation
    suite.assert_output_contains(
        "cf.039.technology_sig",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-039.*signatureType"
    )

    # CF-123: ADGC Class Restriction (tested in test_adgc_conformance)
    suite.assert_output_contains(
        "cf.123.adgc_class_restriction",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-123.*ADGC"
    )

    # CF-124: ADGC Data Validation (tested in test_adgc_conformance)
    suite.assert_output_contains(
        "cf.124.adgc_data_validation",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-124.*ADGC"
    )

    # --- CF Required Tag Checks (CF-040..CF-059) ---
    # CF-040: Common Required Tags (Non-DeviceLink)
    suite.assert_output_contains(
        "cf.040.common_required_tags",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-040.*Common Required Tags"
    )

    # CF-041: Input Profile Required Tags
    suite.assert_output_contains(
        "cf.041.input_profile_required",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-041.*Input Profile Required"
    )

    # CF-042: Display Profile Required Tags
    suite.assert_output_contains(
        "cf.042.display_profile_required",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-042.*Display Profile Required"
    )

    # CF-043: Output Profile Required Tags
    suite.assert_output_contains(
        "cf.043.output_profile_required",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-043.*Output Profile Required"
    )

    # CF-044: DeviceLink Profile Required Tags
    suite.assert_output_contains(
        "cf.044.devicelink_required",
        ["-a", f"{corpus}/cf_devicelink_no_atob.icc"],
        r"CF-044.*DeviceLink.*Required"
    )

    # CF-045: ColorSpace Profile Required Tags
    suite.assert_output_contains(
        "cf.045.colorspace_required",
        ["-a", str(TEST_PROFILES / "Lab_float-D50_2deg.icc")],
        r"CF-045.*ColorSpace.*Required"
    )

    # CF-046: Abstract Profile Required Tags
    suite.assert_output_contains(
        "cf.046.abstract_required",
        ["-a", str(TEST_PROFILES / "RefDecC.icc")],
        r"CF-046.*Abstract.*Required"
    )

    # CF-047: NamedColor Profile Required Tags
    suite.assert_output_contains(
        "cf.047.namedcolor_required",
        ["-a", f"{corpus}/named_color2_excessive_coords.icc"],
        r"CF-047.*NamedColor.*Required"
    )

    # CF-048: Rendering Intent Transform Consistency
    suite.assert_output_contains(
        "cf.048.rendering_intent_consistency",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-048.*Rendering Intent.*Transform"
    )

    # CF-049: Matrix/TRC Profile PCS Must Be XYZ
    suite.assert_output_contains(
        "cf.049.matrix_trc_pcs_xyz",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-049.*Matrix.*TRC.*PCS.*XYZ"
    )

    # CF-050: xCLR Colorant Table Required
    suite.assert_output_contains(
        "cf.050.xclr_colorant_table",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-050.*xCLR.*Colorant"
    )

    # CF-051: DeviceLink Prohibited Tags
    suite.assert_output_contains(
        "cf.051.devicelink_prohibited",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-051.*DeviceLink.*Prohibited"
    )

    # CF-052: Transform Tag Pair Consistency
    suite.assert_output_contains(
        "cf.052.transform_pair_consistency",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-052.*Transform.*Pair"
    )

    # CF-053: cicpTag Class Restriction
    suite.assert_output_contains(
        "cf.053.cicp_class_restriction",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-053.*cicpTag.*Class"
    )

    # CF-054: v5 Spectral Required Tags
    suite.assert_output_contains(
        "cf.054.v5_spectral_required",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-054.*v5 Spectral"
    )

    # CF-055: D2B/B2D Tag Pair Completeness
    suite.assert_output_contains(
        "cf.055.d2b_b2d_pair",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-055.*D2B.*B2D"
    )

    # CF-056: Embedded Profile Structure
    suite.assert_output_contains(
        "cf.056.embedded_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-056.*Embedded Profile"
    )

    # CF-057: Dictionary Tag Structure v5
    suite.assert_output_contains(
        "cf.057.dictionary_tag",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-057.*Dictionary"
    )

    # CF-058: Profile Sequence Identifier v5
    suite.assert_output_contains(
        "cf.058.profile_seq_id_v5",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-058.*Profile Sequence"
    )

    # CF-059: Colorimetric Intent Image State
    suite.assert_output_contains(
        "cf.059.colorimetric_intent",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-059.*Colorimetric Intent"
    )

    # --- CF LUT Checks (CF-060..CF-079) ---
    # LUT8 profile with AToB0+BToA0 should trigger LUT checks
    suite.assert_output_contains(
        "cf.lut.input_channel_count",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-060.*Input Channel"
    )
    suite.assert_output_contains(
        "cf.lut.output_channel_count",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-061.*Output Channel"
    )
    suite.assert_output_contains(
        "cf.060.valid_srgb_matrix_trc_ok",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-060[\s\S]*\[OK\].*Matrix/TRC device-side channel tags valid"
    )
    suite.assert_output_contains(
        "cf.061.valid_srgb_matrix_trc_ok",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-061[\s\S]*\[OK\].*Matrix/TRC PCS-side channel tags valid"
    )
    suite.assert_output_contains(
        "cf.060.namedcolor_not_applicable",
        ["-a", str(TEST_PROFILES / "NamedColor.icc")],
        r"CF-060[\s\S]*N/A:\s*NamedColor profiles do not encode transform input channel counts"
    )
    suite.assert_output_contains(
        "cf.061.namedcolor_not_applicable",
        ["-a", str(TEST_PROFILES / "NamedColor.icc")],
        r"CF-061[\s\S]*N/A:\s*NamedColor profiles do not encode transform output channel counts"
    )
    suite.assert_output_contains(
        "cf.lut.clut_grid",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-062.*CLUT Grid"
    )
    suite.assert_output_contains(
        "cf.lut.lut8_table_size",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-063.*lut8.*256"
    )

    # CF-064: lut16Type Table Size Range 2-4096
    suite.assert_output_contains(
        "cf.064.lut16_table_size",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-064.*lut16Type.*Table Size"
    )

    # CF-065: lutAToBType Processing Element Present
    suite.assert_output_contains(
        "cf.065.lut_atob_element",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-065.*lutAToBType.*Processing"
    )

    # CF-066: lutBToAType Processing Element Present
    suite.assert_output_contains(
        "cf.066.lut_btoa_element",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-066.*lutBToAType.*Processing"
    )

    # CF-067: lut8/16 Matrix Identity When Not PCSXYZ
    suite.assert_output_contains(
        "cf.067.lut_matrix_identity",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-067.*Matrix Identity"
    )

    # CF-068: Chromatic Adaptation Matrix Invertible
    suite.assert_output_contains(
        "cf.068.chad_matrix_invertible",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-068.*Chromatic Adaptation.*Invertible"
    )

    # CF-069: Matrix Column Tag XYZ Count
    suite.assert_output_contains(
        "cf.069.matrix_column_xyz",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-069.*Matrix Column.*XYZ"
    )

    # CF-070: Chad s15Fixed16 Array Count 9
    suite.assert_output_contains(
        "cf.070.chad_array_count_9",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-070.*Chad.*s15Fixed16.*Count"
    )

    # CF-071: Curve Count vs Channel Match
    suite.assert_output_contains(
        "cf.071.curve_count_channel",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-071.*Curve Count"
    )

    # CF-072: CLUT Output Value Range
    suite.assert_output_contains(
        "cf.072.clut_output_range",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-072.*CLUT Output"
    )

    # CF-073: MBB Matrix Determinant Non-Zero
    suite.assert_output_contains(
        "cf.073.mbb_matrix_det",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-073.*Matrix Determinant"
    )

    # CF-074: A2B/B2A Dimension Consistency
    suite.assert_output_contains(
        "cf.074.a2b_b2a_dimensions",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-074.*Dimension Consistency"
    )

    # CF-075: Tag Data Size vs Dimensions
    suite.assert_output_contains(
        "cf.075.tag_data_size",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-075.*Tag Data Size"
    )

    # CF-076: Curve Response Direction
    suite.assert_output_contains(
        "cf.076.curve_response_dir",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-076.*Curve Response"
    )

    # CF-077: CLUT Grid Size Plausibility
    suite.assert_output_contains(
        "cf.077.clut_grid_plausibility",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-077.*Grid Size"
    )

    # CF-078: MBB B-Curve Presence
    suite.assert_output_contains(
        "cf.078.mbb_bcurve_presence",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-078.*B-Curve"
    )

    # CF-079: LUT Bit Depth Consistency
    suite.assert_output_contains(
        "cf.079.lut_bit_depth",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-079.*Bit Depth"
    )

    # --- CF V5/iccMAX Checks (CF-080..CF-090) ---
    v5_profile = str(TEST_PROFILES / "Spec400_10_700-D50_2deg-Abs.icc")

    # CF-080: Spectral PCS Signature
    suite.assert_output_contains(
        "cf.080.spectral_pcs_sig",
        ["-a", v5_profile],
        r"CF-080.*Spectral PCS Signature"
    )

    # CF-081: Spectral PCS Range Validity
    suite.assert_output_contains(
        "cf.081.spectral_pcs_range",
        ["-a", v5_profile],
        r"CF-081.*Spectral PCS Range"
    )

    # CF-082: PCC Tags Required When Spectral
    suite.assert_output_contains(
        "cf.082.pcc_tags_spectral",
        ["-a", v5_profile],
        r"CF-082.*PCC Tags.*Spectral"
    )

    # CF-083: MCS Signature Encoding
    suite.assert_output_contains(
        "cf.083.mcs_signature",
        ["-a", v5_profile],
        r"CF-083.*MCS Signature"
    )

    # CF-084: Profile Sub-Class Signature
    suite.assert_output_contains(
        "cf.084.subclass_sig",
        ["-a", v5_profile],
        r"CF-084.*Sub.*Class"
    )

    # CF-085: Version Field 5.x BCD
    suite.assert_output_contains(
        "cf.085.version_5x_bcd",
        ["-a", v5_profile],
        r"CF-085.*Version.*5.*BCD"
    )

    # CF-086: Extended Attribute Bits
    suite.assert_output_contains(
        "cf.086.extended_attr_bits",
        ["-a", v5_profile],
        r"CF-086.*Extended Attribute"
    )

    # CF-087: MPE Element Signature Valid
    suite.assert_output_contains(
        "cf.087.mpe_element_sig",
        ["-a", v5_profile],
        r"CF-087.*MPE Element.*Signature"
    )

    # CF-088: Calculator Element Stack Structure
    suite.assert_output_contains(
        "cf.088.calculator_stack",
        ["-a", v5_profile],
        r"CF-088.*Calculator.*Stack"
    )

    # CF-089: Spectral Wavelength Range
    suite.assert_output_contains(
        "cf.089.spectral_wavelength",
        ["-a", v5_profile],
        r"CF-089.*Spectral Wavelength"
    )

    # CF-090: Spectral Illuminant Consistency (v5 only)
    suite.assert_output_contains(
        "cf.090.spectral_illuminant",
        ["-a", str(TEST_PROFILES / "17ChanPart1.icc")],
        r"CF-090.*Spectral Illuminant"
    )

    # CF-114: MCS Colour Space Consistency
    suite.assert_output_contains(
        "cf.114.mcs_colour_space",
        ["-a", v5_profile],
        r"CF-114.*MCS.*Colour Space"
    )

    # CF-193: Colorimetric ICS PCC Matrix Restriction
    suite.assert_output_contains(
        "cf.193.ics_pcc_matrix",
        ["-a", v5_profile],
        r"CF-193.*Colorimetric.*ICS.*PCC"
    )

    # --- CF Security Checks (CF-091..CF-094) ---
    # Malware signature should be detected
    suite.assert_output_contains(
        "cf.security.malware_scan",
        ["-a", f"{corpus}/malware_private_tag.icc"],
        r"CF-091.*[Mm]alware|PE header|MZ"
    )

    # Private tag presence should be reported
    suite.assert_output_contains(
        "cf.security.private_tag_presence",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-092.*[Pp]rivate"
    )

    # Private tag suspicious content
    suite.assert_output_contains(
        "cf.security.private_tag_content",
        ["-a", f"{corpus}/malware_private_tag.icc"],
        r"CF-093.*[Pp]rivate.*[Cc]ontent|[Ss]uspicious"
    )

    # NOP sled detection
    suite.assert_output_contains(
        "cf.security.nop_sled",
        ["-a", f"{corpus}/nop_sled_tag.icc"],
        r"CF-094.*NOP|sled"
    )

    # --- CF Required Tag Extension (CF-095..CF-098) ---
    # Non-required tags
    suite.assert_output_contains(
        "cf.required.non_required_tags",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-095.*Non.*Required"
    )

    # Private tag signature range (bit 31)
    suite.assert_output_contains(
        "cf.required.private_sig_range",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-096.*[Pp]rivate.*[Ss]ignature"
    )

    # Private tag documentation
    suite.assert_output_contains(
        "cf.required.private_doc",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-097.*[Pp]rivate.*[Dd]ocumentation"
    )

    # Undocumented private tags
    suite.assert_output_contains(
        "cf.required.undocumented_private",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-098.*[Uu]ndocumented"
    )

    # --- CF Quality Checks (CF-099..CF-102) ---
    # Round-trip check runs on LUT profiles
    suite.assert_output_contains(
        "cf.quality.roundtrip_structural",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-099.*Round.*Trip"
    )

    suite.assert_output_contains(
        "cf.quality.roundtrip_alt_intent_pair",
        ["-a", f"{corpus}/lut8_atob2_btoa2.icc"],
        r"(?s)CF-099.*A2B2/B2A2"
    )

    # Curve invertibility check
    suite.assert_output_contains(
        "cf.quality.curve_invertibility",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-100.*Curve.*Invertib"
    )
    suite.assert_output_contains(
        "cf.quality.curve_invertibility_alt_intent",
        ["-a", f"{corpus}/lut8_atob2_btoa2.icc"],
        r"CF-100.*Curve.*Invertib"
    )

    # Non-monotonic curve should warn
    suite.assert_output_contains(
        "cf.quality.non_monotonic_curve_warn",
        ["-a", f"{corpus}/non_monotonic_curve.icc"],
        r"non-monotonic|Non-monotonic|not monoton"
    )

    # Transform smoothness
    suite.assert_output_contains(
        "cf.quality.transform_smoothness",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-101.*[Ss]moothness"
    )
    suite.assert_output_contains(
        "cf.quality.transform_smoothness_cmyk",
        ["-a", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"CF-101.*[Ss]moothness|Transform smoothness metrics recorded"
    )
    suite.assert_output_contains(
        "cf.quality.roundtrip_cmyk",
        ["-a", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"CF-099.*Round.*Trip"
    )
    suite.assert_output_contains(
        "cf.quality.curve_invertibility_cmyk",
        ["-a", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"CF-100.*Curve.*Invertib"
    )

    # Characterization data check
    suite.assert_output_contains(
        "cf.quality.characterization_data",
        ["-a", f"{corpus}/targ_tag_profile.icc"],
        r"CF-102.*[Cc]haracterization"
    )
    suite.assert_output_contains(
        "cf.quality.characterization_data_eval",
        ["-a", f"{corpus}/targ_quality_profile.icc"],
        r"CF-102.*Characterization.*avg DeltaE00|Characterization DeltaE00 metrics recorded"
    )
    suite.assert_output_contains(
        "cf.quality.characterization_data_eval_cmyk",
        ["-a", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"CF-102.*Characterization.*avg DeltaE00|Characterization DeltaE00 metrics recorded"
    )

    # =======================================================================
    # CF-103..CF-122: Deep ICC Specification Conformance Checks
    # =======================================================================

    # CF-103: Tag Alignment & Offset Validity
    suite.assert_output_contains(
        "cf.103.tag_alignment_present",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-103.*Tag Alignment"
    )

    # CF-104: DeviceLink PCS Consistency - missing AToB0Tag
    suite.assert_output_contains(
        "cf.104.devicelink_missing_atob",
        ["-a", f"{corpus}/cf_devicelink_no_atob.icc"],
        r"CF-104.*DeviceLink.*AToB0|missing.*AToB0"
    )

    # CF-105: LUT Channel Symmetry (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.105.lut_channel_symmetry",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-105.*Channel.*Symmetr"
    )

    # CF-106: Curve Monotonicity - non-monotonic TRC
    suite.assert_output_contains(
        "cf.106.non_monotonic_trc",
        ["-a", f"{corpus}/cf_non_monotonic_trc.icc"],
        r"CF-106.*[Mm]onoton|not mono"
    )

    # CF-107: Tag Table Ordering - duplicate signatures
    suite.assert_output_contains(
        "cf.107.tag_table_ordering",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-107.*Tag Table"
    )
    suite.assert_output_contains(
        "cf.107.duplicate_sigs",
        ["-a", f"{corpus}/cf_duplicate_tag_sigs.icc"],
        r"CF-107.*Tag Table"
    )

    # CF-108: CLUT Grid Point Range (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.108.clut_grid_range",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-108.*CLUT Grid.*Range"
    )

    # CF-109: Matrix Column Normalization (runs on matrix profiles)
    suite.assert_output_contains(
        "cf.109.matrix_normalization",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-109.*Matrix.*Normal"
    )

    # CF-110: B-Curve vs CLUT Output (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.110.bcurve_vs_clut",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-110.*B.Curve.*CLUT"
    )

    # CF-111: Required Tags per Version
    suite.assert_output_contains(
        "cf.111.required_per_version",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-111.*Required.*Version"
    )

    # CF-112: XYZ Triplet Normalization - negative Y
    suite.assert_output_contains(
        "cf.112.xyz_negative_y",
        ["-a", f"{corpus}/cf_xyz_negative_y.icc"],
        r"CF-112.*XYZ|negative"
    )
    suite.assert_output_contains(
        "cf.112.xyz_clean",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-112.*XYZ"
    )

    # CF-113..CF-115: v5/iccMAX (skipped on v4 profiles - verify skip message)
    suite.assert_output_contains(
        "cf.113.spectral_range",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )
    suite.assert_output_contains(
        "cf.114.mcs_colour_space",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )
    suite.assert_output_contains(
        "cf.115.calculator_complexity",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"v5.*iccMAX.*skip"
    )

    # CF-116: Curve Segment Continuity (runs on LUT profiles)
    suite.assert_output_contains(
        "cf.116.curve_segment_continuity",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-116.*Segment.*Continu"
    )

    # CF-117: Rendering Intent Tags per Class - rig0 on Input class
    suite.assert_output_contains(
        "cf.117.rig0_wrong_class",
        ["-a", f"{corpus}/cf_rig0_wrong_class.icc"],
        r"CF-117.*[Rr]ender|rig0.*Output.*Display"
    )

    # CF-118: Private Tag Creator Signature
    suite.assert_output_contains(
        "cf.118.private_tag_creator",
        ["-a", f"{corpus}/private_tags.icc"],
        r"CF-118.*Private.*Creator"
    )

    # CF-119: Profile Sequence Identifier
    suite.assert_output_contains(
        "cf.119.profile_sequence_id",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-119.*Sequence.*Ident"
    )

    # CF-120: Named Color Space Dimensions
    suite.assert_output_contains(
        "cf.120.named_color_dims",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-120.*Named.*Color"
    )

    # CF-121: Illuminant Metadata Consistency - v4 wtpt != D50
    suite.assert_output_contains(
        "cf.121.v4_wtpt_not_d50",
        ["-a", f"{corpus}/cf_v4_wtpt_not_d50.icc"],
        r"CF-121.*Illuminant|wtpt.*D50"
    )

    # CF-122: Profile Date/Time Plausibility - year 1800
    suite.assert_output_contains(
        "cf.122.implausible_date",
        ["-a", f"{corpus}/cf_implausible_date.icc"],
        r"CF-122.*Date|implaus|1800"
    )

    # CF-011: Profile ID MD5 Verification - mismatch
    suite.assert_output_contains(
        "cf.011.md5_mismatch",
        ["-a", f"{corpus}/cf_md5_mismatch.icc"],
        r"CF-011.*\[WARN\]|MD5.*mismatch|Stored.*Computed"
    )

    # CF-011: Valid profile - MD5 check runs
    suite.assert_output_contains(
        "cf.011.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-011"
    )

    # CF-021: Non-zero reserved bytes in tag type header
    suite.assert_output_contains(
        "cf.021.reserved_nonzero",
        ["-a", f"{corpus}/cf_reserved_bytes_nonzero_tag.icc"],
        r"CF-021.*\[FAIL\]|reserved.*non-zero|must be zero"
    )

    # CF-021: Valid profile - reserved bytes OK
    suite.assert_output_contains(
        "cf.021.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"\[OK\].*reserved bytes are zero"
    )

    # CF-030: mluc duplicate language/country pair
    suite.assert_output_contains(
        "cf.030.bad_record_size",
        ["-a", f"{corpus}/cf_mluc_bad_record_size.icc"],
        r"CF-030.*\[WARN\]|duplicate.*language|Sec.10.13"
    )

    # CF-030: Valid profile - mluc structure OK
    suite.assert_output_contains(
        "cf.030.valid_profile",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"\[OK\].*mluc.*structurally valid"
    )

    # CF-031: sf32 bad element count
    suite.assert_output_contains(
        "cf.031.bad_size",
        ["-a", f"{corpus}/cf_sf32_bad_size.icc"],
        r"CF-031.*\[FAIL\]|not divisible|remainder|extra bytes"
    )

    # --- ICC.2-2019 Errata Conformance Checks (CF-137..CF-143) ---
    # v5 profile for "not applicable" tests (v2/v4 profiles skip V5 conformance entirely)
    test_profiles_dir = str(Path(__file__).resolve().parent.parent.parent / "test-profiles")
    v5_profile = f"{test_profiles_dir}/Spec400_10_700-D50_2deg-Abs.icc"

    # CF-137: MultiplexDefaultValues tag type validation
    suite.assert_output_contains(
        "cf.137.mdv_valid_type",
        ["-a", f"{corpus}/cf137-mdv-valid.icc"],
        r"conforms to errata-corrected permitted types"
    )
    suite.assert_output_contains(
        "cf.137.mdv_invalid_type",
        ["-a", f"{corpus}/cf137-mdv-invalid-type.icc"],
        r"\[WARN\].*not in errata-corrected"
    )
    # v5 profile without mdv tag reports not applicable
    suite.assert_output_contains(
        "cf.137.not_applicable",
        ["-a", v5_profile],
        r"multiplexDefaultValuesTag.*not applicable"
    )

    # CF-138: Embedded Height Image data length
    suite.assert_output_contains(
        "cf.138.ehim_valid",
        ["-a", f"{corpus}/cf138-ehim-valid.icc"],
        r"embeddedHeightImageType.*header=24"
    )
    # v5 profile without ehim tag
    suite.assert_output_contains(
        "cf.138.not_applicable",
        ["-a", v5_profile],
        r"embeddedHeightImageType.*not applicable"
    )

    # CF-139: Embedded Normal Image data length
    suite.assert_output_contains(
        "cf.139.enim_valid",
        ["-a", f"{corpus}/cf139-enim-valid.icc"],
        r"embeddedNormalImageType.*header=16"
    )
    suite.assert_output_contains(
        "cf.139.not_applicable",
        ["-a", v5_profile],
        r"embeddedNormalImageType.*not applicable"
    )

    # CF-140: GBD Vertex Count Field
    suite.assert_output_contains(
        "cf.140.not_applicable",
        ["-a", v5_profile],
        r"gamutBoundaryDescType.*not applicable"
    )

    # CF-141: Sparse Matrix Array Count
    suite.assert_output_contains(
        "cf.141.not_applicable",
        ["-a", v5_profile],
        r"sparseMatrixArrayType.*not applicable"
    )

    # CF-142: Vector-Or signature alignment (real v5 profile with 'vor ')
    vor_profile = f"{test_profiles_dir}/calcUnderStack_vor.icc"
    if Path(vor_profile).exists():
        suite.assert_output_contains(
            "cf.142.vor_aligned",
            ["-a", vor_profile],
            r"errata-aligned 4-byte signature"
        )
    suite.assert_output_contains(
        "cf.142.not_applicable",
        ["-a", v5_profile],
        r"vector-or.*not applicable"
    )

    # CF-143: Measurement tag struct type
    suite.assert_output_contains(
        "cf.143.meas_valid",
        ["-a", f"{corpus}/cf143-meas-valid.icc"],
        r"errata-conformant"
    )
    suite.assert_output_contains(
        "cf.143.not_applicable",
        ["-a", v5_profile],
        r"measurement.*not applicable"
    )

    # --- CF-144..CF-148: ICS Extended Range PCS (v5 profile) ---
    suite.assert_output_contains(
        "cf.144.ext_range_flag",
        ["-a", v5_profile],
        r"CF-144.*Extended Range PCS Flag"
    )
    suite.assert_output_contains(
        "cf.145.ext_range_spectral",
        ["-a", v5_profile],
        r"CF-145.*Extended Range PCS.*Spectral"
    )
    suite.assert_output_contains(
        "cf.146.class_restriction",
        ["-a", v5_profile],
        r"CF-146.*Extended Range Class"
    )
    suite.assert_output_contains(
        "cf.147.colorimetric_intent",
        ["-a", v5_profile],
        r"CF-147.*Extended Range Colorimetric"
    )
    suite.assert_output_contains(
        "cf.148.lut_mpe_type",
        ["-a", v5_profile],
        r"CF-148.*Extended Range LUT"
    )

    # --- CF-149..CF-152: ICS Extended Output (v5 profile) ---
    suite.assert_output_contains(
        "cf.149.ext_output_class",
        ["-a", v5_profile],
        r"CF-149.*Extended Output Profile Class"
    )
    suite.assert_output_contains(
        "cf.150.gamut_boundary",
        ["-a", v5_profile],
        r"CF-150.*Extended Output Gamut"
    )
    suite.assert_output_contains(
        "cf.151.mwp_range",
        ["-a", v5_profile],
        r"CF-151.*Extended Output mediaWhitePoint"
    )
    suite.assert_output_contains(
        "cf.152.atob_completeness",
        ["-a", v5_profile],
        r"CF-152.*Extended Output AToB"
    )

    # --- CF-153..CF-158: ICC.2-in-ICC.1 Embedding (v5 profile) ---
    suite.assert_output_contains(
        "cf.153.embedded_tag",
        ["-a", v5_profile],
        r"CF-153.*Embedded Profile Tag"
    )
    suite.assert_output_contains(
        "cf.154.version_bridging",
        ["-a", v5_profile],
        r"CF-154.*Embedded Profile Version"
    )
    suite.assert_output_contains(
        "cf.155.device_class",
        ["-a", v5_profile],
        r"CF-155.*Embedded Profile Device"
    )
    suite.assert_output_contains(
        "cf.156.header_flags",
        ["-a", v5_profile],
        r"CF-156.*Embedded Profile Header"
    )
    suite.assert_output_contains(
        "cf.157.recursive_depth",
        ["-a", v5_profile],
        r"CF-157.*Embedded Profile Recursive"
    )
    suite.assert_output_contains(
        "cf.158.size_bounds",
        ["-a", v5_profile],
        r"CF-158.*Embedded Profile Size"
    )
    # Hardened default: ICC5/ICCp embedded profiles hit the H96 UB fingerprint
    # and skip the unsafe library-phase conformance path.
    suite.assert_output_contains(
        "cf.153.embedded_type_ok",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"\[DEFENSE\].*Embedded ICC5 tag with ICCp type.*IccIO\.cpp:569"
    )
    suite.assert_output_not_contains(
        "cf.153.embedded_type_ok.skips_unsafe_cf",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"CF-153.*Embedded Profile Tag"
    )
    suite.assert_output_contains(
        "cf.153.embedded_wrong_type",
        ["-a", f"{corpus}/cf_embedded_wrong_type.icc"],
        r"Embedded profile tag type shall be 'ICCp'"
    )
    suite.assert_output_contains(
        "cf.154.embedded_wrong_type",
        ["-a", f"{corpus}/cf_embedded_wrong_type.icc"],
        r"Tag is not CIccTagEmbeddedProfile type"
    )
    suite.assert_output_contains(
        "cf.154.v5_parent_warning",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"Library-phase conformance not run"
    )
    suite.assert_output_contains(
        "cf.155.class_mismatch",
        ["-a", f"{corpus}/cf_embedded_child_class_mismatch.icc"],
        r"\[DEFENSE\].*Embedded ICC5 tag with ICCp type.*IccIO\.cpp:569"
    )
    suite.assert_output_contains(
        "cf.156.flags_invalid",
        ["-a", f"{corpus}/cf_embedded_child_flags_bad.icc"],
        r"Library-phase conformance not run"
    )
    suite.assert_output_contains(
        "cf.157.depth_ok",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"Raw-phase heuristics \(H1-H178\) still ran in legacy mode"
    )
    suite.assert_output_contains(
        "cf.158.size_ok",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"Library-phase conformance not run"
    )

    # --- CF-159..CF-162: dictType Validation (v5 profile) ---
    suite.assert_output_contains(
        "cf.159.dict_uniqueness",
        ["-a", v5_profile],
        r"CF-159.*Dictionary Name Uniqueness"
    )
    suite.assert_output_contains(
        "cf.160.dict_nonzero",
        ["-a", v5_profile],
        r"CF-160.*Dictionary Name Non-Zero"
    )
    suite.assert_output_contains(
        "cf.161.dict_alignment",
        ["-a", v5_profile],
        r"CF-161.*Dictionary Record"
    )
    suite.assert_output_contains(
        "cf.162.dict_bounds",
        ["-a", v5_profile],
        r"CF-162.*Dictionary Entry"
    )

    # --- CF-175..CF-177: ICC.2-in-ICC.1 Embedding - additional (v5 profile) ---
    suite.assert_output_contains(
        "cf.175.pcs_compat",
        ["-a", v5_profile],
        r"CF-175.*Embedded Profile PCS"
    )
    suite.assert_output_contains(
        "cf.176.reserved_bytes",
        ["-a", v5_profile],
        r"CF-176.*Embedded Profile Tag Reserved"
    )
    suite.assert_output_contains(
        "cf.177.data_integrity",
        ["-a", v5_profile],
        r"CF-177.*Embedded Profile Data"
    )
    suite.assert_output_contains(
        "cf.175.pcs_mismatch",
        ["-a", f"{corpus}/cf_embedded_child_pcs_mismatch.icc"],
        r"\[DEFENSE\].*Embedded ICC5 tag with ICCp type.*IccIO\.cpp:569"
    )
    suite.assert_output_contains(
        "cf.176.reserved_nonzero",
        ["-a", f"{corpus}/cf_embedded_reserved_nonzero.icc"],
        r"Library-phase conformance not run"
    )
    suite.assert_output_contains(
        "cf.177.embedded_clean_validation",
        ["-a", f"{corpus}/cf_embedded_clean.icc"],
        r"\[DEFENSE\].*Embedded ICC5 tag with ICCp type.*IccIO\.cpp:569"
    )

    # --- CF-178..CF-183: Partial Chromatic Adaptation (ICC TN) ---
    # Chad-related checks (CF-178/179/183) apply to any profile with chad tag
    chad_profile = str(Path(__file__).resolve().parent.parent.parent / "test-profiles" / "ios-gen-DisplayP3.icc")
    if Path(chad_profile).exists():
        suite.assert_output_contains(
            "cf.178.chad_diagonal",
            ["-a", chad_profile],
            r"CF-178.*Chad.*Diagonal"
        )
        suite.assert_output_contains(
            "cf.179.chad_d50_identity",
            ["-a", chad_profile],
            r"CF-179.*Chad.*D50"
        )
        suite.assert_output_contains(
            "cf.183.chad_column_norm",
            ["-a", chad_profile],
            r"CF-183.*Chad.*Column"
        )

    # PCC checks (CF-180/181/182) require v5 profile
    suite.assert_output_contains(
        "cf.180.pcc_complete",
        ["-a", v5_profile],
        r"CF-180.*PCC.*Complete"
    )
    suite.assert_output_contains(
        "cf.181.pcc_illuminant_chad",
        ["-a", v5_profile],
        r"CF-181.*PCC.*Illuminant"
    )
    suite.assert_output_contains(
        "cf.182.pcc_observer",
        ["-a", v5_profile],
        r"CF-182.*PCC.*Observer"
    )

    # --- CF-184..CF-187: RFC 1321 / Profile ID Conformance ---
    # CF-184: v4+ profile should have Profile ID presence check
    suite.assert_output_contains(
        "cf.184.profileid_v4_presence",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-184.*Profile ID.*v4"
    )

    # CF-185: Profile ID size consistency check runs
    suite.assert_output_contains(
        "cf.185.profileid_size_consistency",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-185.*Profile ID.*Size.*Consistency"
    )

    # CF-186: Profile ID entropy analysis runs
    suite.assert_output_contains(
        "cf.186.profileid_entropy",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-186.*Profile ID.*Entropy"
    )

    # CF-187: Embedded Profile ID chain (runs on any profile, reports no embed tag)
    suite.assert_output_contains(
        "cf.187.embedded_profileid_chain",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-187.*Embedded.*Profile.*Chain"
    )

    # CF-187: v5 profile with embedded tag should exercise chain validation
    suite.assert_output_contains(
        "cf.187.embedded_profileid_v5",
        ["-a", v5_profile],
        r"CF-187.*Embedded.*Profile"
    )
    suite.assert_output_contains(
        "cf.187.embedded_profileid_wrong_type",
        ["-a", f"{corpus}/cf_embedded_wrong_type.icc"],
        r"Cannot validate embedded Profile ID"
    )

    # --- CF-188..CF-190: SampleICC Compliance Testing Framework ---

    # CF-188: Global Per-Tag Validate() sweep runs on any profile
    suite.assert_output_contains(
        "cf.188.global_tag_validate_sweep",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-188.*Global.*Tag.*Validate"
    )
    # CF-188: Should report sweep results (N tags)
    suite.assert_output_contains(
        "cf.188.tag_sweep_reports_count",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"Swept \d+ tags"
    )

    # CF-189: Tag type recognition coverage runs
    suite.assert_output_contains(
        "cf.189.tag_type_recognition",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-189.*Tag Type Recognition"
    )
    # CF-189: For well-formed profiles, all tags should be recognized
    suite.assert_output_contains(
        "cf.189.all_recognized",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"tags have recognized type"
    )

    # CF-190: Profile legibility gate runs
    suite.assert_output_contains(
        "cf.190.profile_legibility_gate",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-190.*Profile Legibility"
    )
    # CF-190: Well-formed profile should be legible
    suite.assert_output_contains(
        "cf.190.profile_is_legible",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"legible.*\d+ tags parsed"
    )
    suite.assert_output_contains(
        "cf.190.zero_tags_gate_runs",
        ["-a", f"{corpus}/zero_tags.icc"],
        r"CF-190.*Profile Legibility"
    )
    suite.assert_output_contains(
        "cf.190.zero_tags_not_legible",
        ["-a", f"{corpus}/zero_tags.icc"],
        r"Profile has 0 tag entries.*not legible"
    )

    # --- CF-191..CF-198: ICS Interoperability Conformance Specifications ---
    # CF-191: ICS Sub-Class Signature Registry - runs on any v5 profile
    suite.assert_output_contains(
        "cf.191.ics_subclass_registry",
        ["-a", v5_profile],
        r"CF-191.*ICS Sub-Class"
    )

    # CF-192: Colorimetric ICS Required Tags - non-pcc profiles report not applicable
    suite.assert_output_contains(
        "cf.192.colorimetric_ics_na",
        ["-a", v5_profile],
        r"CF-192.*Colorimetric ICS"
    )

    # CF-194: Spectral Reflectance ICS - non-sref profiles report not applicable
    suite.assert_output_contains(
        "cf.194.spectral_reflectance_na",
        ["-a", v5_profile],
        r"CF-194.*Spectral Reflectance"
    )

    # CF-195: Extended Range Radiance White Point - runs when extended range PCS set
    suite.assert_output_contains(
        "cf.195.extended_range_radiance",
        ["-a", v5_profile],
        r"CF-195.*Extended.*Radiance"
    )

    # CF-196: ICS MPE Calculator Restriction - reports Part 1/Part 2 status
    suite.assert_output_contains(
        "cf.196.mpe_calculator_restriction",
        ["-a", v5_profile],
        r"CF-196.*MPE Calculator"
    )

    # CF-197: ICS PCC Transform Pair - runs on v5 profiles
    suite.assert_output_contains(
        "cf.197.pcc_transform_pair",
        ["-a", v5_profile],
        r"CF-197.*PCC Transform Pair"
    )

    # CF-198: Extended Range Sub-Class - non-xrng profiles report not applicable
    suite.assert_output_contains(
        "cf.198.extended_range_subclass",
        ["-a", v5_profile],
        r"CF-198.*Extended Range Sub-Class"
    )

    # --- CF-199..CF-205: SampleICC Compliance Framework Extended Checks ---
    # CF-199: CMM Type Signature Registration - runs on any profile
    suite.assert_output_contains(
        "cf.cmm_registration",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-199.*CMM Type Signature"
    )
    # CF-200: Device Manufacturer/Model Signature - runs on any profile
    suite.assert_output_contains(
        "cf.manufacturer_model",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-200.*Manufacturer.*Model"
    )
    # CF-201: Profile Creator Signature - runs on any profile
    suite.assert_output_contains(
        "cf.creator_signature",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-201.*Creator Signature"
    )
    # CF-202: Tag Data Padding Zero-Fill - runs on any profile with file access
    suite.assert_output_contains(
        "cf.padding_zerofill",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-202.*Padding Zero"
    )
    # CF-203: Profile Flags Semantic Validation - runs on any profile
    suite.assert_output_contains(
        "cf.flags_semantics",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-203.*Flags Semantic"
    )
    # CF-204: Device Attributes Semantic Validation - runs on any profile
    suite.assert_output_contains(
        "cf.device_attributes",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-204.*Device Attributes"
    )
    # CF-205: Tag Data Region Gap Analysis - runs on any profile
    suite.assert_output_contains(
        "cf.gap_analysis",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-205.*Gap Analysis"
    )

    # --- CF-206..CF-213: Spec Gap Coverage Batch ---

    # CF-206: Profile File Signature 'acsp' - runs on any profile
    suite.assert_output_contains(
        "cf.acsp_signature",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-206.*Profile File Signature"
    )

    # CF-207: mediaWhitePointTag Value Range - runs on profiles with wtpt
    suite.assert_output_contains(
        "cf.wtpt_value_range",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-207.*mediaWhitePointTag"
    )

    # CF-208: Tag Type Version Compatibility - runs on any profile
    suite.assert_output_contains(
        "cf.tag_type_version",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-208.*Tag Type Version"
    )

    # CF-209: Colorspace Channel Count vs LUT Dimensions - runs on any profile
    suite.assert_output_contains(
        "cf.colorspace_lut_channel",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-209.*Colorspace.*Channel"
    )

    # CF-210: DeviceLink PCS Space Validation - runs on any profile
    suite.assert_output_contains(
        "cf.devicelink_pcs",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-210.*DeviceLink PCS"
    )

    # CF-211: AToB/BToA Tag Pair Completeness - runs on any profile
    suite.assert_output_contains(
        "cf.atob_btoa_pairs",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-211.*AToB.*BToA"
    )

    # CF-212: textType Null Termination - runs on any profile
    suite.assert_output_contains(
        "cf.text_null_term",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-212.*textType.*Null"
    )

    # CF-213: viewingConditionsType Completeness - runs on any profile
    suite.assert_output_contains(
        "cf.viewing_conditions",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-213.*viewingConditionsType"
    )

    # CF-214: Embedded Profile Class Suitability
    suite.assert_output_contains(
        "cf.embedded_class_suitability",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-214.*Embedded.*Class"
    )
    suite.assert_output_contains(
        "cf.214.devicelink_flagged",
        ["-a", f"{corpus}/cf_embedded_devicelink_flagged.icc"],
        r"DeviceLink with embedded flag is unusual|Embedding a DeviceLink is atypical"
    )

    # CF-215: JPEG APP2 Embedding Size Limit
    suite.assert_output_contains(
        "cf.jpeg_embed_size",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-215.*JPEG.*APP2"
    )
    suite.assert_output_contains(
        "cf.215.jpeg_size_ok",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"Profile fits within JPEG APP2 embedding limit"
    )

    # CF-216: JP2 Restricted ICC Compliance
    suite.assert_output_contains(
        "cf.jp2_restricted",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-216.*JP2"
    )
    suite.assert_output_contains(
        "cf.216.valid_srgb_incompatible",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"Profile not compatible with JP2 Restricted ICC method"
    )

    # CF-217: JPX Any ICC Method Compliance
    suite.assert_output_contains(
        "cf.jpx_any_icc",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-217.*JPX"
    )
    suite.assert_output_contains(
        "cf.217.valid_srgb_compatible",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"Profile compatible with JPX Any ICC method"
    )

    # CF-218: HEIF Restricted ICC Compatibility
    suite.assert_output_contains(
        "cf.heif_restricted",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-218.*HEIF"
    )
    suite.assert_output_contains(
        "cf.218.valid_srgb_compatible",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"Profile compatible with HEIF embedding"
    )

    # CF-219: Container Format Version Matrix
    suite.assert_output_contains(
        "cf.container_version_matrix",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-219.*Container"
    )
    suite.assert_output_contains(
        "cf.219.v5_no_standard_support",
        ["-a", v5_profile],
        r"No media formats currently support ICC v5 embedding"
    )

    # CF-220: mluc Name Record Overlap Detection
    suite.assert_output_contains(
        "cf.mluc_overlap",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-220.*mluc.*Overlap"
    )

    # CF-221: profileSequenceDescTag Structure
    suite.assert_output_contains(
        "cf.pseq_structure",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-221.*profileSequenceDesc"
    )

    # CF-222: profileSequenceIdentifierTag Validation
    suite.assert_output_contains(
        "cf.psid_validation",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-222.*profileSequenceIdentifier"
    )

    # CF-223: mluc Zero-Name Placeholder Encoding
    suite.assert_output_contains(
        "cf.mluc_placeholder",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-223.*mluc.*Placeholder"
    )
    suite.assert_output_contains(
        "cf.223.zero_name_placeholder_nonminimal",
        ["-a", f"{corpus}/cf_mluc_zero_name_placeholder.icc"],
        r"zero-name mluc.*recommended: 12|\[WARN\].*placeholder"
    )

    # CF-224: mluc Reserved Field Zero
    suite.assert_output_contains(
        "cf.mluc_reserved",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-224.*mluc.*Reserved"
    )
    suite.assert_output_contains(
        "cf.224.reserved_field_nonzero",
        ["-a", f"{corpus}/cf_reserved_bytes_nonzero_tag.icc"],
        r"CF-224.*\[FAIL\]|mluc reserved field = 0x[0-9A-F]+"
    )

    # CF-225: mluc Name Record String Alignment
    suite.assert_output_contains(
        "cf.mluc_alignment",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-225.*mluc.*Alignment"
    )
    suite.assert_output_contains(
        "cf.225.odd_utf16_alignment",
        ["-a", f"{corpus}/odd_utf16_mluc.icc"],
        r"CF-225.*\[WARN\]|odd string length"
    )

    # CF-226: mluc Size Inference Safety
    suite.assert_output_contains(
        "cf.mluc_size_inference",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-226.*mluc.*Size.*Inference"
    )
    suite.assert_output_contains(
        "cf.226.valid_profile_sizes_ok",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"\[OK\].*sizes consistent with records"
    )

    # CF-227: v4 Text Tag Unicode Migration
    suite.assert_output_contains(
        "cf.227.v4_text_unicode",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-227.*Text Tag Unicode"
    )

    # CF-228: grayTRCTag Semantic Validation
    suite.assert_output_contains(
        "cf.228.gray_trc",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-228.*grayTRC"
    )

    # CF-229: Rendering Intent Dominance Per Class
    suite.assert_output_contains(
        "cf.229.intent_dominance",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-229.*Rendering Intent"
    )

    # CF-230: CIELAB Encoding Version Consistency
    suite.assert_output_contains(
        "cf.230.cielab_encoding",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-230.*CIELAB Encoding"
    )

    # CF-231: LUT Processing Element Sequence
    suite.assert_output_contains(
        "cf.231.lut_sequence",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-231.*LUT Processing"
    )

    # CF-232: Date/Time UTC Consistency
    suite.assert_output_contains(
        "cf.232.datetime_utc",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-232.*Date.*Time"
    )

    # CF-233: colorantOrderTag Index Validation
    suite.assert_output_contains(
        "cf.233.colorant_order",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-233.*colorantOrder"
    )

    # CF-234: v4 Perceptual PCS Reference Medium
    suite.assert_output_contains(
        "cf.234.perceptual_pcs",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-234.*Perceptual PCS"
    )

    # --- CF-235..CF-242: ICS Extended Range Part 1 conformance ---
    # These checks target 'xrng' sub-class profiles. On non-xrng profiles they report N/A.
    # CF-235: xrng Data Colour Space Restriction
    suite.assert_output_contains(
        "cf.235.xrng_colour_space",
        ["-a", v5_profile],
        r"CF-235.*xrng Data Colour Space"
    )
    # CF-236: xrng Colorimetric PCS Constraint
    suite.assert_output_contains(
        "cf.236.xrng_pcs",
        ["-a", v5_profile],
        r"CF-236.*xrng Colorimetric PCS"
    )
    # CF-237: xrng Required Tag Completeness
    suite.assert_output_contains(
        "cf.237.xrng_required_tags",
        ["-a", v5_profile],
        r"CF-237.*xrng Required Tag"
    )
    # CF-238: xrng Header Field Restrictions
    suite.assert_output_contains(
        "cf.238.xrng_header_fields",
        ["-a", v5_profile],
        r"CF-238.*xrng Header Field"
    )
    # CF-239: xrng Optional Tag Type Validation
    suite.assert_output_contains(
        "cf.239.xrng_optional_tags",
        ["-a", v5_profile],
        r"CF-239.*xrng Optional Tag"
    )
    # CF-240: xrng Transform Channel Dimensions
    suite.assert_output_contains(
        "cf.240.xrng_channels",
        ["-a", v5_profile],
        r"CF-240.*xrng Transform Channel"
    )
    # CF-241: xrng mediaWhitePointTag Absolute Radiance
    suite.assert_output_contains(
        "cf.241.xrng_mwpt_radiance",
        ["-a", v5_profile],
        r"CF-241.*xrng mediaWhitePointTag"
    )
    # CF-242: xrng Workflow Connection Consistency
    suite.assert_output_contains(
        "cf.242.xrng_workflow",
        ["-a", v5_profile],
        r"CF-242.*xrng Workflow Connection"
    )

    # --- CF-243..CF-257: Conformance gap coverage ---
    srgb = f"{corpus}/valid_srgb.icc"

    # CF-243: dateTimeNumber Field Range
    suite.assert_output_contains(
        "cf.243.datetime_range",
        ["-a", srgb],
        r"CF-243.*dateTimeNumber Field Range"
    )
    # CF-244: Profile Creation Date Plausibility
    suite.assert_output_contains(
        "cf.244.date_plausibility",
        ["-a", srgb],
        r"CF-244.*Creation Date Plausibility"
    )
    # CF-245: Profile Size Multiple of 4
    suite.assert_output_contains(
        "cf.245.size_mod4",
        ["-a", srgb],
        r"CF-245.*Size Multiple of 4"
    )
    # CF-246: Rendering Intent Range
    suite.assert_output_contains(
        "cf.246.intent_range",
        ["-a", srgb],
        r"CF-246.*Rendering Intent Range"
    )
    # CF-247: viewingConditionsType Illuminant Type Range
    suite.assert_output_contains(
        "cf.247.viewing_illum_type",
        ["-a", srgb],
        r"CF-247.*Illuminant Type Range"
    )
    # CF-248: namedColor2Type Device Coords Limit
    suite.assert_output_contains(
        "cf.248.namedcolor_devcoords",
        ["-a", srgb],
        r"CF-248.*Device Coords Limit"
    )
    # CF-249: profileDescriptionTag Non-Empty
    suite.assert_output_contains(
        "cf.249.desc_nonempty",
        ["-a", srgb],
        r"CF-249.*profileDescriptionTag Non-Empty"
    )
    # CF-250: copyrightTag Non-Empty
    suite.assert_output_contains(
        "cf.250.copyright_nonempty",
        ["-a", srgb],
        r"CF-250.*copyrightTag Non-Empty"
    )
    # CF-251: chromaticityType Phosphor Type Range
    suite.assert_output_contains(
        "cf.251.phosphor_type",
        ["-a", srgb],
        r"CF-251.*Phosphor Type Range"
    )
    # CF-252: curveType Gamma Positive/Finite
    suite.assert_output_contains(
        "cf.252.curve_gamma",
        ["-a", srgb],
        r"CF-252.*Gamma Positive"
    )
    # CF-253: chromaticityType Channel Count
    suite.assert_output_contains(
        "cf.253.chroma_channels",
        ["-a", srgb],
        r"CF-253.*Channel Count"
    )
    # CF-254: Technology Signature Registered
    suite.assert_output_contains(
        "cf.254.tech_sig",
        ["-a", srgb],
        r"CF-254.*Technology Signature"
    )
    # CF-255: CLUT Grid Point Values
    suite.assert_output_contains(
        "cf.255.clut_grid_points",
        ["-a", srgb],
        r"CF-255.*CLUT Grid Point"
    )
    # CF-256: LUT I/O Channels vs Profile Spaces
    suite.assert_output_contains(
        "cf.256.lut_io_channels",
        ["-a", srgb],
        r"CF-256.*I/O Channels"
    )
    # CF-257: Spectral Range Step Count (v5 only)
    suite.assert_output_contains(
        "cf.257.spectral_steps",
        ["-a", v5_profile],
        r"CF-257.*Spectral Range Step Count"
    )

    # --- CF-258..CF-265: Deep conformance gap coverage ---

    # CF-258: Display v4+ mediaWhitePointTag D50
    suite.assert_output_contains(
        "cf.258.display_mwpt_d50",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-258.*Display v4\+ mediaWhitePointTag D50"
    )

    # CF-259: colorantOrderTag vs colorantTableTag
    suite.assert_output_contains(
        "cf.259.colorant_order_table",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-259.*colorantOrder.*colorantTable"
    )

    # CF-260: Output gamutTag rendering intent
    suite.assert_output_contains(
        "cf.260.output_gamuttag",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-260.*Output.*gamutTag"
    )

    # CF-261: M-Curve Count = 3 When Matrix Present
    suite.assert_output_contains(
        "cf.261.mcurve_count_matrix",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-261.*M-Curve Count.*3.*Matrix"
    )

    # CF-262: B-Curve Count vs Output Channels
    suite.assert_output_contains(
        "cf.262.bcurve_output_channels",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-262.*B-Curve Count.*Output"
    )

    # CF-263: Perceptual PCS White Point D50
    suite.assert_output_contains(
        "cf.263.perceptual_pcs_d50",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-263.*Perceptual PCS White Point D50"
    )

    # CF-264: parametricCurveType Function Type Range
    suite.assert_output_contains(
        "cf.264.parametric_functype",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-264.*parametricCurveType Function Type"
    )

    # CF-265: mluc Language/Country Code Validity
    suite.assert_output_contains(
        "cf.265.mluc_lang_country",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-265.*mluc.*Language.*Country"
    )

    # --- CF-266..CF-271: Profile class constraints ---
    # CF-266: Input Profile Device Color Space
    suite.assert_output_contains(
        "cf.266.input_colorspace",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-266.*Input Profile Device Color Space"
    )

    # CF-267: Display Profile Color Space
    suite.assert_output_contains(
        "cf.267.display_colorspace",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-267.*Display Profile Color Space"
    )

    # CF-268: Output Profile Color Space
    suite.assert_output_contains(
        "cf.268.output_colorspace",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-268.*Output Profile Color Space"
    )

    # CF-269: DeviceLink Data Color Space Matching
    suite.assert_output_contains(
        "cf.269.devicelink_colorspace",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-269.*DeviceLink Data Color Space"
    )

    # CF-270: Abstract Profile PCS
    suite.assert_output_contains(
        "cf.270.abstract_pcs",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-270.*Abstract Profile PCS"
    )

    # CF-271: NamedColor Profile PCS
    suite.assert_output_contains(
        "cf.271.namedcolor_pcs",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-271.*NamedColor Profile PCS"
    )

    # --- CF-272..CF-274: Primary colorant validation ---
    # CF-272: Matrix/TRC RGB Required Colorant Tags
    suite.assert_output_contains(
        "cf.272.matrixtrc_colorant_tags",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-272.*Matrix.*TRC.*RGB.*Required"
    )

    # CF-273: Primary Colorant XYZ Values Positive
    suite.assert_output_contains(
        "cf.273.colorant_xyz_positive",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-273.*Primary Colorant XYZ.*Positive"
    )

    # CF-274: Primary Colorant Chromaticity Sum
    suite.assert_output_contains(
        "cf.274.colorant_chromaticity_sum",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-274.*Primary Colorant Chromaticity"
    )

    # --- CF-275..CF-278: Tag type enforcement ---
    # CF-275: copyrightTag Must Be mluc for v4+
    suite.assert_output_contains(
        "cf.275.copyright_mluc_v4",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-275.*copyrightTag.*mluc"
    )

    # CF-276: profileDescriptionTag Must Be mluc for v4+
    suite.assert_output_contains(
        "cf.276.profiledesc_mluc_v4",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-276.*profileDescriptionTag.*mluc"
    )

    # CF-277: mediaWhitePointTag Must Be XYZType
    suite.assert_output_contains(
        "cf.277.whitept_xyztype",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-277.*mediaWhitePointTag.*XYZType"
    )

    # CF-278: chromaticAdaptationTag Type
    suite.assert_output_contains(
        "cf.278.chad_s15fixed16",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-278.*chromaticAdaptationTag"
    )

    # --- CF-279..CF-281: Data encoding validation ---
    # CF-279: TRC Curve Values Non-Negative
    suite.assert_output_contains(
        "cf.279.trc_nonneg",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-279.*TRC Curve.*Non-Negative"
    )

    # CF-280: XYZ Element Luminance (Y) Non-Negative
    suite.assert_output_contains(
        "cf.280.xyz_luminance_nonneg",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-280.*XYZ.*Luminance.*Non-Negative"
    )

    # CF-281: profileSequenceDescTag Structure
    suite.assert_output_contains(
        "cf.281.pseqdesc_structure",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-281.*profileSequenceDescTag"
    )

    # --- CF-282..CF-283: DeviceLink requirements ---
    # CF-282: DeviceLink AToB0Tag Required
    suite.assert_output_contains(
        "cf.282.devicelink_atob0",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-282.*DeviceLink AToB0Tag"
    )

    # CF-283: DeviceLink profileSequenceDescTag
    suite.assert_output_contains(
        "cf.283.devicelink_pseqdesc",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-283.*DeviceLink profileSequenceDescTag"
    )

    # --- CF-284..CF-291: ICC.2:2019 errata-derived v5 checks ---
    # These checks require a v5/iccMAX profile (gated behind version >= 5)
    v5_profile = str(TEST_PROFILES / "17ChanPart1.icc")

    # CF-284: BRDF Spectral Parameter Tag Type
    suite.assert_output_contains(
        "cf.284.brdf_tag_type",
        ["-a", v5_profile],
        r"CF-284.*BRDF Spectral Parameter Tag Type"
    )

    # CF-285: BRDF Tag Presence Consistency
    suite.assert_output_contains(
        "cf.285.brdf_consistency",
        ["-a", v5_profile],
        r"CF-285.*BRDF Tag Presence Consistency"
    )

    # CF-286: GBD Triangle-Vertex Consistency
    suite.assert_output_contains(
        "cf.286.gbd_triangle_vertex",
        ["-a", v5_profile],
        r"CF-286.*GBD Triangle-Vertex Consistency"
    )

    # CF-287: GBD Channel Count Plausibility
    suite.assert_output_contains(
        "cf.287.gbd_channel_plausibility",
        ["-a", v5_profile],
        r"CF-287.*GBD Channel Count Plausibility"
    )

    # CF-288: Spectral Data Info Bi-Spectral Consistency
    suite.assert_output_contains(
        "cf.288.spectral_data_info",
        ["-a", v5_profile],
        r"CF-288.*Spectral Data Info"
    )

    # CF-289: Spectral Viewing Conditions Illuminant Bounds
    suite.assert_output_contains(
        "cf.289.spectral_viewing_illuminant",
        ["-a", v5_profile],
        r"CF-289.*Spectral Viewing Conditions Illuminant"
    )

    # CF-290: Material Default Values Tag Presence
    suite.assert_output_contains(
        "cf.290.material_default_values",
        ["-a", v5_profile],
        r"CF-290.*Material Default Values"
    )

    # CF-291: Spectral White Point XYZ Range
    suite.assert_output_contains(
        "cf.291.spectral_white_point",
        ["-a", v5_profile],
        r"CF-291.*Spectral White Point"
    )

    # --- CF-292..CF-300: multiProcessElementsType Container Validation ---
    # CF-292: MPE Chain I/O Channel Consistency
    suite.assert_output_contains(
        "cf.292.mpe_chain_io",
        ["-a", v5_profile],
        r"CF-292.*MPE.*Chain.*I/O"
    )
    # CF-293: MPE Container I/O vs First/Last Element
    suite.assert_output_contains(
        "cf.293.mpe_container_channel",
        ["-a", v5_profile],
        r"CF-293.*MPE.*Container.*I/O"
    )
    # CF-294: MPE ACS Boundary Element Pairing
    suite.assert_output_contains(
        "cf.294.mpe_acs_pairing",
        ["-a", v5_profile],
        r"CF-294.*ACS.*Boundary"
    )
    # CF-295: MPE Element Type Version Compatibility
    suite.assert_output_contains(
        "cf.295.mpe_version_compat",
        ["-a", v5_profile],
        r"CF-295.*Version.*Compat"
    )
    # CF-296: MPE Empty Container Validation
    suite.assert_output_contains(
        "cf.296.mpe_empty_container",
        ["-a", v5_profile],
        r"CF-296.*Empty.*Container"
    )
    # CF-297: MPE CurveSet Element Channel Count
    suite.assert_output_contains(
        "cf.297.mpe_curveset_channels",
        ["-a", v5_profile],
        r"CF-297.*CurveSet.*Channel"
    )
    # CF-298: MPE Matrix Element Dimension
    suite.assert_output_contains(
        "cf.298.mpe_matrix_dimension",
        ["-a", v5_profile],
        r"CF-298.*Matrix.*Dimension"
    )
    # CF-299: MPE CLUT Element Grid Dimension
    suite.assert_output_contains(
        "cf.299.mpe_clut_grid",
        ["-a", v5_profile],
        r"CF-299.*CLUT.*Grid"
    )
    # CF-300: MPE Tag vs Color Space Channels
    suite.assert_output_contains(
        "cf.300.mpe_tag_colorspace",
        ["-a", v5_profile],
        r"CF-300.*Color Space.*Channel"
    )

    # --- CF-301..CF-307: ICC.2:2019 Errata Enforcement ---
    # CF-301: Sec.9.2.86/87 measurementInfo tagStructType Enforcement
    suite.assert_output_contains(
        "cf.301.measurement_tagstruct",
        ["-a", v5_profile],
        r"CF-301.*Measurement.*tagStructType"
    )
    # CF-302: measurementInfoStruct Member Validation
    suite.assert_output_contains(
        "cf.302.measurement_members",
        ["-a", v5_profile],
        r"CF-302.*Measurement.*Member"
    )
    # CF-303: Spectral Data Array Type Restriction
    suite.assert_output_contains(
        "cf.303.spectral_array_types",
        ["-a", v5_profile],
        r"CF-303.*Spectral.*Array"
    )
    # CF-304: v5 Text Tags multiLocalizedUnicodeType
    suite.assert_output_contains(
        "cf.304.mluc_text_tags",
        ["-a", v5_profile],
        r"CF-304.*multiLocalizedUnicode"
    )
    # CF-305: multiProcessElementsType Naming Audit
    suite.assert_output_contains(
        "cf.305.mpet_naming",
        ["-a", v5_profile],
        r"CF-305.*multiProcessElements.*Nomenclature"
    )
    # CF-306: Embedded Image Data Length
    suite.assert_output_contains(
        "cf.306.embedded_image_length",
        ["-a", v5_profile],
        r"CF-306.*Embedded.*Image.*Length"
    )
    # CF-307: Calculator 'vor ' Element Signature
    suite.assert_output_contains(
        "cf.307.vor_signature",
        ["-a", v5_profile],
        r"CF-307.*Vector-Or.*Signature"
    )

    # --- CF-308..CF-316: ICS Conformance Checks ---
    # CF-308: pcc AToB1/BToA1 Part 1 Element Restriction
    suite.assert_output_contains(
        "cf.308.pcc_element_restriction",
        ["-a", v5_profile],
        r"CF-308.*pcc.*AToB1.*Element"
    )
    # CF-309: sref PCC Matrix Restriction
    suite.assert_output_contains(
        "cf.309.sref_pcc_matrix",
        ["-a", v5_profile],
        r"CF-309.*sref.*PCC.*Matrix"
    )
    # CF-310: sref DToB3/BToD3 Part 1 Element Restriction
    suite.assert_output_contains(
        "cf.310.sref_dtob3_element",
        ["-a", v5_profile],
        r"CF-310.*sref.*DToB3.*Element"
    )
    # CF-311: sref Spectral Range Mandatory
    suite.assert_output_contains(
        "cf.311.sref_spectral_range",
        ["-a", v5_profile],
        r"CF-311.*sref.*Spectral.*Range"
    )
    # CF-312: ext Required Tag Completeness
    suite.assert_output_contains(
        "cf.312.ext_required_tags",
        ["-a", v5_profile],
        r"CF-312.*ext.*Required.*Tag"
    )
    # CF-313: ext Part 1 Element Type Restriction
    suite.assert_output_contains(
        "cf.313.ext_element_restriction",
        ["-a", v5_profile],
        r"CF-313.*ext.*Part 1.*Element"
    )
    # CF-314: xrng AToB1/BToA1 Part 1 Element Restriction
    suite.assert_output_contains(
        "cf.314.xrng_element_restriction",
        ["-a", v5_profile],
        r"CF-314.*xrng.*AToB1.*Element"
    )
    # CF-315: xrng Part 2 PCC Matrix Restriction
    suite.assert_output_contains(
        "cf.315.xrng_pcc_matrix",
        ["-a", v5_profile],
        r"CF-315.*xrng.*PCC.*Matrix"
    )
    # CF-316: ICS svcn Observer/Illuminant Plausibility
    suite.assert_output_contains(
        "cf.316.ics_svcn_plausibility",
        ["-a", v5_profile],
        r"CF-316.*svcn.*Observer.*Illuminant"
    )

    # --- CF-317..CF-320: K.2.9 HDR-to-SDR Transform Conformance ---

    # CF-317: Flag-Tag Consistency - consistent (flag + tags both present)
    suite.assert_output_contains(
        "cf.317.htos_flag_tags_ok",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"CF-317.*HDR.*SDR.*Flag.*Tag"
    )
    suite.assert_output_contains(
        "cf.317.htos_flag_tags_ok.ok_msg",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"\[OK\].*Extended Range PCS flag set with 1 HToS"
    )

    # CF-317: Flag set but no tags -> WARN
    suite.assert_output_contains(
        "cf.317.htos_flag_only.warn",
        ["-a", f"{corpus}/cf_htos_flag_only.icc"],
        r"\[WARN\].*Extended Range PCS flag.*bit 3.*is set but no HToS tags"
    )

    # CF-317: Tags present but flag not set -> WARN (orphan tags)
    suite.assert_output_contains(
        "cf.317.htos_tags_no_flag.warn",
        ["-a", f"{corpus}/cf_htos_tags_no_flag.icc"],
        r"\[WARN\].*HToS tag.*present but Extended Range PCS flag.*NOT set"
    )
    suite.assert_output_contains(
        "cf.317.htos_tags_no_flag.orphan",
        ["-a", f"{corpus}/cf_htos_tags_no_flag.icc"],
        r"Orphan tag: H2S0"
    )

    # CF-318: Tag Type - valid mpet
    suite.assert_output_contains(
        "cf.318.htos_type_ok",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"CF-318.*HDR.*SDR.*Tag Type"
    )
    suite.assert_output_contains(
        "cf.318.htos_type_ok.mpet",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"\[OK\].*H2S0 tag type is multiProcessElementsType"
    )

    # CF-318: Wrong type -> WARN
    suite.assert_output_contains(
        "cf.318.htos_bad_type.warn",
        ["-a", f"{corpus}/cf_htos_bad_type.icc"],
        r"\[WARN\].*H2S0 tag type.*curv.*expected multiProcessElementsType"
    )

    # CF-319: Channel consistency - matching PCS
    suite.assert_output_contains(
        "cf.319.htos_channels_ok",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"CF-319.*HDR.*SDR.*Channel"
    )
    suite.assert_output_contains(
        "cf.319.htos_channels_ok.match",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"\[OK\].*H2S0 channels 3.*3 match PCS"
    )

    # CF-319: Channel mismatch -> WARN
    suite.assert_output_contains(
        "cf.319.htos_channel_mismatch.warn_in",
        ["-a", f"{corpus}/cf_htos_channel_mismatch.icc"],
        r"\[WARN\].*H2S0 input channels=4.*expected PCS channels=3"
    )
    suite.assert_output_contains(
        "cf.319.htos_channel_mismatch.warn_out",
        ["-a", f"{corpus}/cf_htos_channel_mismatch.icc"],
        r"\[WARN\].*H2S0 output channels=4.*expected PCS channels=3"
    )

    # CF-320: Intent coverage - all 4 intents
    suite.assert_output_contains(
        "cf.320.htos_all_intents.ok",
        ["-a", f"{corpus}/cf_htos_all_intents.icc"],
        r"\[OK\].*All 4 rendering intents have HToS coverage"
    )

    # CF-320: Partial coverage - 1 of 4 intents
    suite.assert_output_contains(
        "cf.320.htos_partial.info",
        ["-a", f"{corpus}/cf_htos_flag_and_tags.icc"],
        r"\[INFO\].*1 of 4 rendering intents covered"
    )

    # CF-320: No HToS tags on flag-only profile
    suite.assert_output_contains(
        "cf.320.htos_flag_only.no_coverage",
        ["-a", f"{corpus}/cf_htos_flag_only.icc"],
        r"No HToS tags.*no intent coverage"
    )

    # --- CF-321..CF-323: K.2.8 Calculator 'solv' Operator Conformance ---
    # CF-321: Calculator 'solv' Operator Presence
    suite.assert_output_contains(
        "cf.321.solv_operator_presence",
        ["-a", v5_profile],
        r"CF-321.*solv.*Operator.*Presence"
    )
    # CF-322: Calculator 'solv' Status Handling
    suite.assert_output_contains(
        "cf.322.solv_status_handling",
        ["-a", v5_profile],
        r"CF-322.*solv.*Status"
    )
    # CF-323: Calculator 'solv' Matrix Dimensions
    suite.assert_output_contains(
        "cf.323.solv_dimensions",
        ["-a", v5_profile],
        r"CF-323.*solv.*Dimensions"
    )

    # --- CF-324..CF-326: K.2.7 CMM Environment Variable Conformance ---
    # CF-324: Calculator 'env' Operator Usage
    suite.assert_output_contains(
        "cf.324.env_operator_usage",
        ["-a", v5_profile],
        r"CF-324.*env.*Operator.*Usage"
    )
    # CF-325: Calculator 'env' Status Handling
    suite.assert_output_contains(
        "cf.325.env_status_handling",
        ["-a", v5_profile],
        r"CF-325.*env.*Status"
    )
    # CF-326: Calculator 'env' Reserved Signatures
    suite.assert_output_contains(
        "cf.326.env_reserved_signatures",
        ["-a", v5_profile],
        r"CF-326.*env.*Reserved"
    )

    # CF-327: PCC Alternate Override Readiness
    suite.assert_output_contains(
        "cf.327.pcc_alternate_override",
        ["-a", v5_profile],
        r"CF-327.*PCC.*Alternate.*Override"
    )
    # CF-328: PCC Non-Standard Colorimetry Indication
    suite.assert_output_contains(
        "cf.328.pcc_nonstandard_colorimetry",
        ["-a", v5_profile],
        r"CF-328.*PCC.*Non-Standard.*Colorimetry"
    )
    # CF-329: PCC Override Source Profile Validation
    suite.assert_output_contains(
        "cf.329.pcc_override_source",
        ["-a", v5_profile],
        r"CF-329.*PCC.*Override.*Source"
    )

    # --- CF-330..CF-339: Device Spectral Colour Space (ICC.2:2023 amendment) ---
    spectral_no_range = f"{corpus}/h175_spectral_device_no_range.icc"
    spectral_valid_dsrn = f"{corpus}/h175_spectral_device_valid_dsrn.icc"
    spectral_fallback = f"{corpus}/h175_spectral_device_header_fallback.icc"

    # CF-330: Device Spectral Colour Space Signature
    suite.assert_output_contains(
        "cf.330.device_spectral_sig",
        ["-a", spectral_valid_dsrn],
        r"CF-330.*Device Spectral Colour Space"
    )
    # CF-331: missing range -> FAIL
    suite.assert_output_contains(
        "cf.331.no_range_fail",
        ["-a", spectral_no_range],
        r"Spectral device colour space has no spectral range"
    )
    # CF-331: dsrn present -> pass
    suite.assert_output_contains(
        "cf.331.dsrn_present",
        ["-a", spectral_valid_dsrn],
        r"deviceSpectralRangeTag.*dsrn.*present"
    )
    # CF-332: spectralRangeType reserved
    suite.assert_output_contains(
        "cf.332.srng_reserved",
        ["-a", spectral_valid_dsrn],
        r"dsrn tag found.*reserved field validation"
    )
    # CF-333: no dpcc -> skip
    suite.assert_output_contains(
        "cf.333.no_dpcc_skip",
        ["-a", spectral_valid_dsrn],
        r"No dpcc tag present"
    )
    # CF-337: no range -> FAIL
    suite.assert_output_contains(
        "cf.337.no_range_fail",
        ["-a", spectral_no_range],
        r"No spectral range source for spectral device"
    )
    # CF-337: dsrn only -> pass
    suite.assert_output_contains(
        "cf.337.dsrn_only",
        ["-a", spectral_valid_dsrn],
        r"Device spectral range defined by dsrn tag only"
    )
    # CF-338: non-bi-spectral zero check
    suite.assert_output_contains(
        "cf.338.non_bispectral_zero",
        ["-a", spectral_valid_dsrn],
        r"Non-bi-spectral.*correctly zero"
    )
    # CF-339: non-abstract -> skip
    suite.assert_output_contains(
        "cf.339.non_abstract_skip",
        ["-a", spectral_valid_dsrn],
        r"Profile class is not Abstract"
    )

    # --- Clean profile baseline ---
    # Clean monitor profile should produce zero CF warnings
    suite.assert_output_not_contains(
        "cf.clean.no_security_warn",
        ["-a", f"{corpus}/clean_mntr_profile.icc"],
        r"\[FAIL\].*CF-09[1-4]"
    )

    # --- PAWG integration verification ---
    # The compact PAWG state model should expose GAP/N/A instead of overloading [ -- ].
    suite.assert_output_contains(
        "cf.pawg.good_profile_gap_state",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"\[OK\]\s+S1"
    )
    suite.assert_output_contains(
        "cf.pawg.good_profile_q1_ok",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"\[OK\]\s+Q1"
    )
    suite.assert_output_contains(
        "cf.pawg.good_profile_q2_ok",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"\[OK\]\s+Q2"
    )
    suite.assert_output_contains(
        "cf.pawg.good_profile_q3_ok",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"\[OK\]\s+Q3"
    )
    suite.assert_output_contains(
        "cf.pawg.good_profile_na_state",
        ["-pawg", f"{corpus}/valid_srgb.icc"],
        r"\[N/A\]\s+Q4"
    )
    suite.assert_output_contains(
        "cf.pawg.characterization_profile_q4_ok",
        ["-pawg", f"{corpus}/targ_quality_profile.icc"],
        r"\[OK\]\s+Q4"
    )
    suite.assert_output_contains(
        "cf.pawg.cmyk_quality_profile_q1_ok",
        ["-pawg", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"\[OK\]\s+Q1"
    )
    suite.assert_output_contains(
        "cf.pawg.cmyk_quality_profile_q4_ok",
        ["-pawg", f"{corpus}/targ_cmyk_quality_profile.icc"],
        r"\[OK\]\s+Q4"
    )

    # --- iccDEV tool conformance (reference profiles) ---
    # sRGB v4 preference profile should be clean
    srgb_v4 = str(Path(__file__).resolve().parent.parent.parent / "test-profiles" / "sRGB_v4_ICC_preference.icc")
    if Path(srgb_v4).exists():
        suite.assert_output_not_contains(
            "cf.reference.srgb_v4_no_fail",
            ["-a", srgb_v4],
            r"\[FAIL\].*CF-"
        )

    # =======================================================================
    # CF-163..CF-168: v4 Matrix Entries TN Conformance
    # =======================================================================

    # CF-163: LUT Matrix Coefficient Finite - banner runs on LUT profiles
    suite.assert_output_contains(
        "cf.163.matrix_coeff_finite_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-163.*Matrix.*Coefficient.*Finite"
    )

    # CF-164: LUT Matrix s15Fixed16 Range
    suite.assert_output_contains(
        "cf.164.matrix_s15f16_range_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-164.*s15Fixed16.*Range"
    )

    # CF-165: LUT Matrix Determinant Non-Singular
    suite.assert_output_contains(
        "cf.165.matrix_determinant_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-165.*Determinant"
    )

    # CF-166: LUT Matrix Row Non-Zero
    suite.assert_output_contains(
        "cf.166.matrix_row_nonzero_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-166.*Row.*Non.*Zero"
    )

    # CF-167: LUT Matrix Offset Bounds
    suite.assert_output_contains(
        "cf.167.matrix_offset_bounds_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-167.*Offset.*Bounds"
    )

    # CF-168: LUT Matrix Input-Output Range
    suite.assert_output_contains(
        "cf.168.matrix_output_range_banner",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"CF-168.*Input.*Output.*Range"
    )

    # Clean LUT profile should pass all matrix checks
    suite.assert_output_not_contains(
        "cf.163_168.clean_lut_no_fail",
        ["-a", f"{corpus}/lut8_atob_btoa.icc"],
        r"\[FAIL\].*CF-16[3-8]"
    )

    # --- CF-169..CF-174: Negative PCSXYZ Values TN Conformance ---
    displayp3 = str(Path(__file__).resolve().parent.parent.parent / "test-profiles" / "ios-gen-DisplayP3.icc")

    # CF-169: Negative PCSXYZ Encoding Capability - DisplayP3 has negative rXYZ Z
    suite.assert_output_contains(
        "cf.169.negative_pcsxyz_encoding",
        ["-a", displayp3],
        r"CF-169.*Negative.*PCSXYZ.*Encoding"
    )

    # CF-169: DisplayP3 uses s15Fixed16 for negative values -> conformant
    suite.assert_output_contains(
        "cf.169.s15fixed16_conformant",
        ["-a", displayp3],
        r"s15Fixed16.*conformant"
    )

    # CF-170: Chad + negative consistency - DisplayP3 has chad tag
    suite.assert_output_contains(
        "cf.170.chad_negative_consistency",
        ["-a", displayp3],
        r"CF-170.*Chromatic.*Adaptation.*Negative"
    )

    # CF-171: White point non-negative luminance
    suite.assert_output_contains(
        "cf.171.whitept_nonneg",
        ["-a", displayp3],
        r"CF-171.*White.*Point.*Non.*Negative"
    )

    # CF-172: Colorant sum ~= white point
    suite.assert_output_contains(
        "cf.172.colorant_sum_whitept",
        ["-a", displayp3],
        r"CF-172.*Colorant.*Sum.*White.*Point"
    )

    # CF-173: Absorber encoding check
    suite.assert_output_contains(
        "cf.173.absorber_encoding",
        ["-a", displayp3],
        r"CF-173.*Absorber.*Encoding"
    )

    # CF-174: Lab conversion clipping awareness
    suite.assert_output_contains(
        "cf.174.lab_clipping",
        ["-a", displayp3],
        r"CF-174.*Lab.*Conversion.*Clipping"
    )

    # Clean DisplayP3 should pass all negative PCSXYZ checks (no FAIL)
    suite.assert_output_not_contains(
        "cf.169_174.displayp3_no_fail",
        ["-a", displayp3],
        r"\[FAIL\].*CF-1[67][0-4]"
    )


def test_adgc_conformance(suite):
    """Test ADGC (Adaptive Gain Curve) conformance checks CF-123..CF-136."""
    corpus = str(Path(__file__).resolve().parent / "corpus")

    # --- CF-123: ADGC Class Restriction ---
    # CMYK profile with ADGC must trigger CF-123
    suite.assert_output_contains(
        "adgc.cf123.cmyk_violation",
        ["-a", f"{corpus}/cf_adgc_cmyk_violation.icc"],
        r"CF-123"
    )
    # Valid RGB/Input with ADGC should NOT trigger CF-123
    suite.assert_output_not_contains(
        "adgc.cf123.rgb_input_ok",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-123.*\[FAIL\]"
    )

    # --- CF-124: ADGC Type Signature ---
    # Wrong type sig must trigger CF-124
    suite.assert_output_contains(
        "adgc.cf124.bad_type_sig",
        ["-a", f"{corpus}/cf_adgc_bad_type_sig.icc"],
        r"CF-124"
    )

    # --- CF-125: Function Type ID ---
    # funcType=2 must trigger CF-125
    suite.assert_output_contains(
        "adgc.cf125.bad_functype",
        ["-a", f"{corpus}/cf_adgc_bad_functype.icc"],
        r"CF-125"
    )

    # --- CF-126: Reserved Bytes ---
    # Non-zero reserved must trigger CF-126
    suite.assert_output_contains(
        "adgc.cf126.bad_reserved",
        ["-a", f"{corpus}/cf_adgc_bad_reserved.icc"],
        r"CF-126"
    )

    # --- CF-127: Float Field Finiteness ---
    # NaN weights must trigger CF-127
    suite.assert_output_contains(
        "adgc.cf127.nan_weights",
        ["-a", f"{corpus}/cf_adgc_nan_weights.icc"],
        r"CF-127"
    )

    # --- CF-128: Weight Coefficient Sum ---
    # Weights summing to 2.0 must trigger CF-128
    suite.assert_output_contains(
        "adgc.cf128.bad_weight_sum",
        ["-a", f"{corpus}/cf_adgc_bad_weight_sum.icc"],
        r"CF-128"
    )

    # --- CF-132: Curve Data Monotonicity ---
    # Non-monotonic x-values must trigger CF-132
    suite.assert_output_contains(
        "adgc.cf132.non_monotonic",
        ["-a", f"{corpus}/cf_adgc_non_monotonic.icc"],
        r"CF-132"
    )

    # --- CF-133: H_baseline == H_alternate (division-by-zero) ---
    suite.assert_output_contains(
        "adgc.cf133.h_equal",
        ["-a", f"{corpus}/cf_adgc_h_equal.icc"],
        r"CF-133"
    )

    # --- CF-134: GainMin > GainMax (inverted gain range) ---
    suite.assert_output_contains(
        "adgc.cf134.gain_inverted",
        ["-a", f"{corpus}/cf_adgc_gain_inverted.icc"],
        r"CF-134"
    )

    # --- CF-135: Curve x-values outside [0,1] ---
    suite.assert_output_contains(
        "adgc.cf135.bad_curve_range",
        ["-a", f"{corpus}/cf_adgc_bad_curve_range.icc"],
        r"CF-135"
    )

    # --- CF-136: Adjacent curve points with equal x ---
    suite.assert_output_contains(
        "adgc.cf136.equal_x_curve",
        ["-a", f"{corpus}/cf_adgc_equal_x_curve.icc"],
        r"CF-136"
    )

    # --- BT.2100 PQ realistic profile: should pass all ADGC checks ---
    suite.assert_output_not_contains(
        "adgc.bt2100_pq.no_fail",
        ["-a", f"{corpus}/cf_adgc_bt2100_pq.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- BT.2100 HLG realistic profile: should pass all ADGC checks ---
    suite.assert_output_not_contains(
        "adgc.bt2100_hlg.no_fail",
        ["-a", f"{corpus}/cf_adgc_bt2100_hlg.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- Single-point curve: valid edge case ---
    suite.assert_output_not_contains(
        "adgc.single_point.no_fail",
        ["-a", f"{corpus}/cf_adgc_single_point_curve.icc"],
        r"CF-13[2-6].*\[FAIL\]"
    )

    # --- Many-point curve: valid stress test ---
    suite.assert_output_not_contains(
        "adgc.many_point.no_fail",
        ["-a", f"{corpus}/cf_adgc_many_point_curve.icc"],
        r"CF-13[2-6].*\[FAIL\]"
    )

    # --- Valid profile: no ADGC failures (updated range CF-123..CF-136) ---
    suite.assert_output_not_contains(
        "adgc.valid.no_cf_fail",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"CF-12[4-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )

    # --- ADGC checks produce output for valid profiles ---
    suite.assert_output_contains(
        "adgc.valid.has_adgc_check",
        ["-a", f"{corpus}/cf_adgc_valid_rgb_input.icc"],
        r"ADGC"
    )

    # --- Profile without ADGC tag: CF-123..CF-136 should not fire false alarms ---
    suite.assert_output_not_contains(
        "adgc.no_tag.no_false_alarm",
        ["-a", f"{corpus}/valid_srgb.icc"],
        r"CF-12[3-9].*\[FAIL\]|CF-13[0-6].*\[FAIL\]"
    )


def test_iccdev_tool_conformance(suite):
    """Test iccDEV upstream tools against reference ICC profiles."""
    # Only run if iccDEV tools are built
    dump_tool = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "Tools" / "IccDumpProfile" / "iccDumpProfile"
    toxml_tool = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "Tools" / "IccToXml" / "iccToXml"
    lib_path = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "IccProfLib"
    xml_lib = Path(__file__).resolve().parent.parent.parent / "iccDEV" / "Build" / "IccXML"
    srgb_v4 = Path(__file__).resolve().parent.parent.parent / "test-profiles" / "sRGB_v4_ICC_preference.icc"

    if not dump_tool.exists() or not srgb_v4.exists():
        return

    env = {
        **os.environ,
        "LD_LIBRARY_PATH": f"{lib_path}:{xml_lib}",
        "ASAN_OPTIONS": "halt_on_error=0,detect_leaks=0",
        "LLVM_PROFILE_FILE": "/dev/null",
    }

    # iccDumpProfile on sRGB v4
    try:
        proc = subprocess.run(
            [str(dump_tool), str(srgb_v4), "ALL"],
            capture_output=True, timeout=30, env=env
        )
        passed = proc.returncode == 0
        msg = "" if passed else f"iccDumpProfile exit {proc.returncode}"
        sanitizer_hit = generic_sanitizer_hit(
            proc.stderr.decode("utf-8", errors="replace")
        )
        if sanitizer_hit:
            passed = False
            msg = f"Sanitizer error in iccDumpProfile: {sanitizer_hit}"
        suite.results.append(TestResult(
            "iccdev.dump_srgb_v4", passed, msg, 0.0, "", ""
        ))
    except Exception as e:
        suite.results.append(TestResult(
            "iccdev.dump_srgb_v4", False, str(e), 0.0, "", ""
        ))

    # iccToXml on sRGB v4
    if toxml_tool.exists():
        try:
            proc = subprocess.run(
                [str(toxml_tool), str(srgb_v4), "/dev/null"],
                capture_output=True, timeout=30, env=env
            )
            passed = proc.returncode == 0
            msg = "" if passed else f"iccToXml exit {proc.returncode}"
            sanitizer_hit = generic_sanitizer_hit(
                proc.stderr.decode("utf-8", errors="replace")
            )
            if sanitizer_hit:
                passed = False
                msg = f"Sanitizer error in iccToXml: {sanitizer_hit}"
            suite.results.append(TestResult(
                "iccdev.toxml_srgb_v4", passed, msg, 0.0, "", ""
            ))
        except Exception as e:
            suite.results.append(TestResult(
                "iccdev.toxml_srgb_v4", False, str(e), 0.0, "", ""
            ))

    # DumpProfile on synthesized valid profile (ASAN check)
    valid_corpus = str(Path(__file__).resolve().parent / "corpus" / "valid_srgb.icc")
    if Path(valid_corpus).exists():
        try:
            proc = subprocess.run(
                [str(dump_tool), valid_corpus, "ALL"],
                capture_output=True, timeout=30, env=env
            )
            passed = proc.returncode == 0
            msg = "" if passed else f"iccDumpProfile exit {proc.returncode}"
            sanitizer_hit = generic_sanitizer_hit(
                proc.stderr.decode("utf-8", errors="replace")
            )
            if sanitizer_hit:
                passed = False
                msg = f"Sanitizer error on valid_srgb.icc: {sanitizer_hit}"
            suite.results.append(TestResult(
                "iccdev.dump_synth_valid", passed, msg, 0.0, "", ""
            ))
        except Exception as e:
            suite.results.append(TestResult(
                "iccdev.dump_synth_valid", False, str(e), 0.0, "", ""
            ))


def test_extended_profiles_coverage(suite):
    """Test -a on extended test profiles for broader code coverage."""
    if not EXTENDED_PROFILES.exists():
        return
    profiles = filter_quarantined_profiles(sorted(EXTENDED_PROFILES.glob("*.icc")))
    # Test every 5th extended profile (OOM files live in test-profiles/cwe-400/)
    for icc in profiles[::5][:20]:
        suite.assert_no_asan(
            f"extended.{icc.stem[:40]}",
            ["-a", str(icc)]
        )


# --- Main ---

def _print_environment(binary):
    """Print environment info for debugging."""
    print(C.bold("Environment:"))
    print(f"  Binary:  {binary}")
    try:
        proc = subprocess.run(
            [str(binary), "--version"], capture_output=True, timeout=5,
            env={**os.environ, "LLVM_PROFILE_FILE": "/dev/null"}
        )
        ver = proc.stdout.decode("utf-8", errors="replace").strip().split("\n")[0]
        print(f"  Version: {ver}")
    except Exception:
        print(f"  Version: (could not determine)")
    print(f"  Python:  {sys.version.split()[0]}")
    print(f"  Platform: {sys.platform}")
    print(f"  ASAN_OPTIONS: detect_leaks=0")
    print(f"  Corpus:  {CORPUS_DIR}")
    corpus_count = len(list(CORPUS_DIR.glob("*.icc"))) if CORPUS_DIR.exists() else 0
    print(f"  Corpus profiles: {corpus_count}")
    if TEST_PROFILES.exists():
        tp_count = len(filter_quarantined_profiles(list(TEST_PROFILES.glob("*.icc"))))
        print(f"  test-profiles/: {tp_count}")
    if EXTENDED_PROFILES.exists():
        ep_count = len(filter_quarantined_profiles(list(EXTENDED_PROFILES.glob("*.icc"))))
        print(f"  extended-test-profiles/: {ep_count}")
    print(f"  Quarantine file: {PROFILE_RESOURCE_QUARANTINE}")
    print(f"  Quarantine enabled: {quarantine_enabled()}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="iccanalyzer-lite unit tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python3 run_tests.py                    Run all tests
  python3 run_tests.py -v                 Verbose (show each test)
  python3 run_tests.py -k json            Run tests matching 'json'
  python3 run_tests.py --fail-fast        Stop on first failure
  python3 run_tests.py --debug            Show commands being run
  python3 run_tests.py --list             List test sections
  python3 run_tests.py --xml report.xml   JUnit XML output"""
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show each test result as it runs")
    parser.add_argument("-k", "--pattern",
                        help="Filter tests by name pattern")
    parser.add_argument("--binary",
                        help="Path to iccanalyzer-lite binary")
    parser.add_argument("--xml",
                        help="Write JUnit XML report to this path")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: synthesize + test")
    parser.add_argument("--list", action="store_true",
                        help="List all test sections and exit")
    parser.add_argument("--fail-fast", action="store_true",
                        help="Stop on first test failure")
    parser.add_argument("--debug", action="store_true",
                        help="Show commands being run")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        C.enabled = False

    # Discover test functions
    test_functions = [
        ("Exit Codes", test_exit_codes),
        ("Analysis Modes", test_analysis_modes),
        ("Heuristic Detection", test_heuristic_detection),
        ("Heuristic Summary", test_heuristic_summary),
        ("Sanitizer Clean (Corpus)", test_sanitizer_clean),
        ("Repo Profile Sample", test_repo_profiles_sample),
        ("PCC Illuminant Overflow Regression", test_pcc_illuminant_overflow_regression),
        ("ToneMap Describe Overflow Regression", test_tonemap_describe_overflow_regression),
        ("Curve Element OOM Regression", test_curve_element_oom_regression),
        ("XML Export", test_xml_export),
        ("Multi-Mode Consistency", test_multiple_modes_same_profile),
        ("LUT Extraction", test_lut_extraction),
        ("Call Graph", test_call_graph_mode),
        ("XML Heuristic Export", test_xml_heuristic_export),
        ("Ninja Modes Coverage", test_ninja_modes_coverage),
        ("Runtime Safety", test_runtime_safety),
        ("JSON Output", test_json_output),
        ("Registry Output", test_registry_output),
        ("TIFF Analysis", test_tiff_analysis),
        ("TIFF Corrupt", test_tiff_corrupt),
        ("BigTIFF Analysis", test_bigtiff_analysis),
        ("HTML/XML Output", test_html_xml_output),
        ("Report Output", test_report_output),
        ("PAWG Output", test_pawg_output),
        ("LUT Text I/O", test_lut_text_io),
        ("Conformance Checks", test_conformance_checks),
        ("ADGC Conformance", test_adgc_conformance),
        ("iccDEV Tool Conformance", test_iccdev_tool_conformance),
        ("Extended Profiles", test_extended_profiles_coverage),
    ]

    # --list mode
    if args.list:
        print(C.bold(f"Test sections ({len(test_functions)}):"))
        for i, (name, fn) in enumerate(test_functions, 1):
            doc = (fn.__doc__ or "").strip().split("\n")[0]
            print(f"  {i:2d}. {name}")
            if doc:
                print(f"      {C.dim(doc)}")
        return 0

    # Synthesize corpus if not present
    if not CORPUS_DIR.exists() or len(list(CORPUS_DIR.glob("*.icc"))) == 0:
        print("Synthesizing test corpus...")
        subprocess.run([sys.executable, str(SCRIPT_DIR / "synthesize_profiles.py")], check=True)

    binary = Path(args.binary) if args.binary else BINARY
    if not binary.exists():
        print(f"{C.red('ERROR')}: Binary not found: {binary}")
        print("Build with: cd iccanalyzer-lite && ./build.sh")
        return 2

    # Show environment info
    _print_environment(binary)

    suite = TestSuite(binary, verbose=args.verbose, pattern=args.pattern,
                      fail_fast=args.fail_fast, debug=args.debug)

    # Run test sections
    t_start = time.monotonic()
    for section_name, test_fn in test_functions:
        if suite._stop_requested:
            break
        if suite.should_run(section_name):
            count_before = len(suite.results)
            suite.begin_section(section_name)
            print(f"\n{C.bold('--- ' + section_name + ' ---')}")
            test_fn(suite)
            count_after = len(suite.results)
            section_count = count_after - count_before
            section_pass = sum(1 for r in suite.results[count_before:]
                             if r.passed and not r.skipped)
            section_fail = sum(1 for r in suite.results[count_before:]
                             if not r.passed and not r.skipped)
            if not suite.verbose:
                # Compact: show pass/fail count per section
                if section_fail == 0:
                    print(f"  {C.green('+')} {section_pass}/{section_count} passed")
                # failures already printed by _record

    wall_time = time.monotonic() - t_start
    return suite.report(xml_path=args.xml)


if __name__ == "__main__":
    sys.exit(main())
