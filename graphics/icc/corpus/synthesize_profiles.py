#!/usr/bin/env python3
"""Synthesize minimal ICC profiles for unit testing iccanalyzer-lite.

Each profile is designed to trigger (or not trigger) specific heuristics
and validate specific exit-code paths. Profiles are written to tests/corpus/.

ICC profile structure (minimum):
  Header:      128 bytes
  Tag table:   4 + N*12 bytes (count + entries)
  Tag data:    variable

Reference: ICC.1:2022, clause 7
"""

import struct
import os
import sys

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def write_icc_header(
    size,
    preferred_cmm=0,
    version=0x04400000,  # 4.4.0.0
    device_class=b"mntr",
    color_space=b"RGB ",
    pcs=b"XYZ ",
    rendering_intent=0,
    creator=b"test",
    profile_id=b"\x00" * 16,
    flags=0,
    spectral_pcs=0,
    spectral_range=(0, 0, 0),
    bi_spectral_range=(0, 0, 0),
    mcs=0,
    device_sub_class=0,
):
    """Build a 128-byte ICC header."""
    def _sig_to_u32(value):
        if isinstance(value, int):
            return value & 0xFFFFFFFF
        if isinstance(value, (bytes, bytearray)):
            if len(value) != 4:
                raise ValueError(f"Expected 4-byte signature, got {len(value)} bytes")
            return int.from_bytes(value, "big")
        raise TypeError(f"Unsupported signature type: {type(value)!r}")

    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, size)
    hdr[4:8] = _sig_to_u32(preferred_cmm).to_bytes(4, "big")
    struct.pack_into(">I", hdr, 8, version)
    hdr[12:16] = device_class
    hdr[16:20] = color_space
    hdr[20:24] = pcs
    # Date/time: 2024-01-01 00:00:00
    struct.pack_into(">HHH HHH", hdr, 24, 2024, 1, 1, 0, 0, 0)
    hdr[36:40] = b"acsp"  # magic
    hdr[40:44] = b"APPL"  # platform
    struct.pack_into(">I", hdr, 44, flags)
    hdr[48:52] = b"\x00" * 4  # device manufacturer
    hdr[52:56] = b"\x00" * 4  # device model
    hdr[56:64] = b"\x00" * 8  # device attributes
    struct.pack_into(">I", hdr, 64, rendering_intent)
    # PCS illuminant (D50): X=0.9642, Y=1.0000, Z=0.8249
    struct.pack_into(">i", hdr, 68, int(0.9642 * 65536))
    struct.pack_into(">i", hdr, 72, int(1.0000 * 65536))
    struct.pack_into(">i", hdr, 76, int(0.8249 * 65536))
    hdr[80:84] = creator
    hdr[84:100] = profile_id
    struct.pack_into(">I", hdr, 100, _sig_to_u32(spectral_pcs))
    struct.pack_into(">HHH", hdr, 104, *spectral_range)
    struct.pack_into(">HHH", hdr, 110, *bi_spectral_range)
    struct.pack_into(">I", hdr, 116, _sig_to_u32(mcs))
    struct.pack_into(">I", hdr, 120, _sig_to_u32(device_sub_class))
    return bytes(hdr)


def make_tag_entry(sig, offset, size):
    return struct.pack(">4sII", sig, offset, size)


def make_text_tag(text):
    """Create a textType tag (ICC v2)."""
    data = b"text" + b"\x00" * 4 + text.encode("ascii") + b"\x00"
    # Pad to 4-byte boundary
    while len(data) % 4:
        data += b"\x00"
    return data


def make_mluc_tag(text):
    """Create a multiLocalizedUnicodeType tag (ICC v4)."""
    utf16 = text.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    data = b"mluc" + b"\x00" * 4
    data += struct.pack(">II", 1, record_size)  # 1 record, 12 bytes each
    data += b"enUS"  # language + country
    data += struct.pack(">II", len(utf16), string_offset)
    data += utf16
    while len(data) % 4:
        data += b"\x00"
    return data


def make_xyz_tag(x, y, z):
    """Create an XYZType tag."""
    data = b"XYZ " + b"\x00" * 4
    data += struct.pack(">iii", int(x * 65536), int(y * 65536), int(z * 65536))
    return data


def make_curve_tag(values=None, gamma=None):
    """Create a curveType tag."""
    data = b"curv" + b"\x00" * 4
    if gamma is not None:
        data += struct.pack(">I", 1)
        data += struct.pack(">H", int(gamma * 256))
        data += b"\x00\x00"  # pad
    elif values:
        data += struct.pack(">I", len(values))
        for v in values:
            data += struct.pack(">H", min(65535, max(0, int(v * 65535))))
        if len(values) % 2:
            data += b"\x00\x00"
    else:
        data += struct.pack(">I", 0)  # identity
    return data


def make_float16_array_tag(raw_values):
    """Create a float16ArrayType tag with caller-supplied raw IEEE-754 half values."""
    data = b"fl16" + b"\x00" * 4
    for raw in raw_values:
        data += struct.pack(">H", raw & 0xFFFF)
    while len(data) % 4:
        data += b"\x00"
    return data


def make_lut8_tag(n_in, n_out, grid=2, clut_values=None, matrix_values=None):
    """Create a simple lut8Type tag with identity input/output tables."""
    if matrix_values is None:
        matrix_values = (
            (1.0, 0.0, 0.0),
            (0.0, 1.0, 0.0),
            (0.0, 0.0, 1.0),
        )

    matrix = b""
    for r in range(3):
        for c in range(3):
            matrix += struct.pack(">i", int(matrix_values[r][c] * 65536))

    input_table = bytes(range(256)) * n_in
    clut_size = (grid ** n_in) * n_out
    if clut_values is None:
        clut = bytes([int(255 * i / max(1, clut_size - 1)) for i in range(clut_size)])
    else:
        if len(clut_values) != clut_size:
            raise ValueError(f"Expected {clut_size} CLUT entries, got {len(clut_values)}")
        clut = bytes(max(0, min(255, int(round(v)))) for v in clut_values)
    output_table = bytes(range(256)) * n_out

    lut8 = b"mft1" + b"\x00" * 4
    lut8 += struct.pack("BBBB", n_in, n_out, grid, 0)
    lut8 += matrix + input_table + clut + output_table
    return lut8


def build_profile(tags_data, **header_kwargs):
    """Assemble a complete ICC profile from tag data list.

    tags_data: list of (signature_bytes, tag_data_bytes)
    """
    tag_count = len(tags_data)
    tag_table_size = 4 + tag_count * 12
    header_size = 128

    # Calculate offsets
    data_offset = header_size + tag_table_size
    # Align to 4 bytes
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    offsets = []
    current = data_offset
    for sig, data in tags_data:
        offsets.append(current)
        current += len(data)
        if current % 4:
            current += 4 - (current % 4)

    total_size = current
    header = write_icc_header(total_size, **header_kwargs)

    # Tag table
    table = struct.pack(">I", tag_count)
    for i, (sig, data) in enumerate(tags_data):
        table += make_tag_entry(sig, offsets[i], len(data))

    # Assemble
    profile = bytearray(header)
    profile += table
    # Pad to data_offset
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (sig, data) in enumerate(tags_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += data
        while len(profile) % 4:
            profile += b"\x00"

    # Fix size
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def build_rgb_matrix_profile(
    description,
    *,
    version=0x04400000,
    device_class=b"mntr",
    pcs=b"XYZ ",
    flags=0,
):
    """Build a small RGB matrix/TRC profile with predictable validation behavior."""
    tags = [
        (b"desc", make_mluc_tag(description)),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(
        tags,
        version=version,
        device_class=device_class,
        color_space=b"RGB ",
        pcs=pcs,
        flags=flags,
    )


def make_embedded_profile_tag(child_profile, *, reserved=0, type_sig=b"ICCp"):
    """Create an embeddedProfileType payload for the ICC5 tag."""
    data = bytearray()
    data += type_sig
    data += struct.pack(">I", reserved)
    data += child_profile
    while len(data) % 4:
        data += b"\x00"
    return bytes(data)


def synth_valid_srgb():
    """Minimal valid v4 mntr/RGB profile with required tags."""
    tags = [
        (b"desc", make_mluc_tag("sRGB Test Profile")),
        (b"cprt", make_mluc_tag("Copyright 2024 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x04400000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_truncated():
    """Profile truncated mid-tag-table (triggers preflight/exit 2)."""
    valid = synth_valid_srgb()
    return valid[:80]  # Truncate before magic


def synth_bad_magic():
    """Profile with invalid 'acsp' magic (triggers H1)."""
    data = bytearray(synth_valid_srgb())
    data[36:40] = b"XXXX"
    return bytes(data)


def synth_zero_tags():
    """Profile with 0 tags (triggers preflight rejection)."""
    hdr = write_icc_header(132)
    return hdr + struct.pack(">I", 0)


def synth_oversized_tag():
    """Profile where tag size exceeds file size (triggers H3/H5)."""
    tags = [
        (b"desc", make_mluc_tag("Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    data = bytearray(build_profile(tags))
    # Corrupt: set first tag size to 999999
    struct.pack_into(">I", data, 128 + 4 + 8, 999999)
    return bytes(data)


def synth_wrong_version_encoding():
    """v2 profile using mluc for cprt (triggers H116)."""
    tags = [
        (b"desc", make_mluc_tag("Test")),
        (b"cprt", make_mluc_tag("Copyright")),  # Wrong: v2 should use textType
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags, version=0x02100000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_wrong_tag_type():
    """Profile with desc as XYZ type (triggers H117)."""
    tags = [
        (b"desc", make_xyz_tag(1.0, 1.0, 1.0)),  # Wrong type for desc
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags, version=0x04400000)


def synth_private_tags():
    """Profile with unknown private tags (triggers H108, H127)."""
    private_data = b"priv" + b"\x00" * 4 + b"PRIVATE DATA PAYLOAD" + b"\x00\x00"
    tags = [
        (b"desc", make_mluc_tag("Private Tag Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"zzzz", private_data),  # Private/unknown tag
        (b"xxxx", private_data),  # Another private tag
    ]
    return build_profile(tags)


def synth_malware_private_tag():
    """Profile with private tag containing PE header signature (triggers H126)."""
    # MZ header signature
    pe_payload = b"priv" + b"\x00" * 4 + b"MZ" + b"\x90" * 58 + b"PE\x00\x00" + b"\x00" * 60
    tags = [
        (b"desc", make_mluc_tag("Malware Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"zzzz", pe_payload),
    ]
    return build_profile(tags)


def synth_v5_tags_on_v4():
    """v4 profile with v5-only tags (triggers H124)."""
    d2b_data = b"mpet" + b"\x00" * 4 + struct.pack(">HH I", 3, 3, 0)
    tags = [
        (b"desc", make_mluc_tag("Version Mismatch")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"D2B0", d2b_data),  # v5-only tag on v4 profile
    ]
    return build_profile(tags, version=0x04400000)


def synth_cf_embedded_clean():
    """v5 parent with readable embedded v5 child and compliant ICC5 header."""
    child = build_rgb_matrix_profile(
        "Embedded Child Clean",
        version=0x05000000,
        device_class=b"mntr",
        pcs=b"XYZ ",
        flags=0x00000001,
    )
    tags = [
        (b"desc", make_mluc_tag("Embedded Parent Clean")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ICC5", make_embedded_profile_tag(child)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_wrong_type():
    """ICC5 tag present with wrong type signature instead of ICCp."""
    wrong_tag = bytearray()
    wrong_tag += b"text"
    wrong_tag += b"\x00" * 4
    wrong_tag += b"Not an embedded profile\x00"
    while len(wrong_tag) % 4:
        wrong_tag += b"\x00"

    tags = [
        (b"desc", make_mluc_tag("Embedded Wrong Type")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"ICC5", bytes(wrong_tag)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_child_flags_bad():
    """Embedded child violates bit-0/bit-1 header flag expectations."""
    child = build_rgb_matrix_profile(
        "Embedded Child Flags Bad",
        version=0x05000000,
        device_class=b"mntr",
        pcs=b"XYZ ",
        flags=0x00000002,
    )
    tags = [
        (b"desc", make_mluc_tag("Embedded Flags Bad")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ICC5", make_embedded_profile_tag(child)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_child_class_mismatch():
    """Embedded child uses a different profile class than the parent."""
    child = build_rgb_matrix_profile(
        "Embedded Child Class Mismatch",
        version=0x05000000,
        device_class=b"scnr",
        pcs=b"XYZ ",
        flags=0x00000001,
    )
    tags = [
        (b"desc", make_mluc_tag("Embedded Class Mismatch")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ICC5", make_embedded_profile_tag(child)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_child_pcs_mismatch():
    """Embedded child uses a different PCS than the parent."""
    child = build_rgb_matrix_profile(
        "Embedded Child PCS Mismatch",
        version=0x05000000,
        device_class=b"mntr",
        pcs=b"Lab ",
        flags=0x00000001,
    )
    tags = [
        (b"desc", make_mluc_tag("Embedded PCS Mismatch")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ICC5", make_embedded_profile_tag(child)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_reserved_nonzero():
    """Embedded profile tag with non-zero reserved bytes at bytes 4-7."""
    child = build_rgb_matrix_profile(
        "Embedded Reserved Nonzero",
        version=0x05000000,
        device_class=b"mntr",
        pcs=b"XYZ ",
        flags=0x00000001,
    )
    tags = [
        (b"desc", make_mluc_tag("Embedded Reserved Nonzero")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ICC5", make_embedded_profile_tag(child, reserved=1)),
    ]
    return build_profile(tags, version=0x05000000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_cf_embedded_devicelink_flagged():
    """DeviceLink profile marked embedded to exercise CF-214 atypical case."""
    tags = [
        (b"desc", make_mluc_tag("Embedded DeviceLink Flag")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
    ]
    return build_profile(tags, version=0x04400000, device_class=b"link",
                         color_space=b"RGB ", pcs=b"XYZ ", flags=0x00000001)


def synth_non_monotonic_curve():
    """Profile with non-monotonic TRC (triggers H114)."""
    # Non-monotonic: goes up, down, up
    values = [0.0, 0.2, 0.4, 0.6, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0]
    tags = [
        (b"desc", make_mluc_tag("Non-Monotonic TRC")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(values=values)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")


def synth_bad_wtpt():
    """Profile with wtpt far from D50 (triggers H112)."""
    tags = [
        (b"desc", make_mluc_tag("Bad White Point")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.5, 0.5, 0.5)),  # Not D50
    ]
    return build_profile(tags)


def synth_reserved_bytes_nonzero():
    """Profile with non-zero reserved header bytes (triggers H111)."""
    data = bytearray(synth_valid_srgb())
    # Reserved bytes at offset 44 (flags has reserved bits) and 100-127
    data[100:128] = b"\xFF" * 28
    return bytes(data)


def synth_empty_file():
    """Zero-byte file (triggers exit 2)."""
    return b""


def synth_just_header():
    """128-byte header only, no tag table (triggers preflight)."""
    return write_icc_header(128)


def synth_huge_tag_count():
    """Profile claiming 999999 tags (triggers preflight H4 tag count)."""
    hdr = write_icc_header(256)
    return hdr + struct.pack(">I", 999999) + b"\x00" * 124


def synth_xyz_out_of_range():
    """Profile with XYZ values outside [-5, 10] (triggers H122)."""
    tags = [
        (b"desc", make_mluc_tag("XYZ Out of Range")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(15.0, -8.0, 20.0)),  # Out of range
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")


# --- New heuristic-targeted profiles ---


def synth_null_colorspace():
    """Profile with null colorSpace (triggers H3)."""
    data = bytearray(synth_valid_srgb())
    data[16:20] = b"\x00\x00\x00\x00"
    return bytes(data)


def synth_invalid_pcs():
    """Profile with invalid PCS signature (triggers H4)."""
    data = bytearray(synth_valid_srgb())
    data[20:24] = b"XXXX"
    return bytes(data)


def synth_unknown_platform():
    """Profile with unknown platform signature (triggers H5)."""
    data = bytearray(synth_valid_srgb())
    data[40:44] = b"ZZZZ"
    return bytes(data)


def synth_invalid_rendering_intent():
    """Profile with invalid rendering intent value (triggers H6)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 64, 99)
    return bytes(data)


def synth_unknown_device_class():
    """Profile with unknown profile class (triggers H7)."""
    data = bytearray(synth_valid_srgb())
    data[12:16] = b"ZZZZ"
    return bytes(data)


def synth_negative_illuminant():
    """Profile with negative illuminant values (triggers H8)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">i", data, 68, int(-1.0 * 65536))
    return bytes(data)


def synth_invalid_date():
    """Profile with invalid date fields month=13, day=32 (triggers H15)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">HHH", data, 24, 2024, 13, 32)
    return bytes(data)


def synth_version_bcd_invalid():
    """Profile with non-BCD nibble in version byte (triggers H128)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 8, 0x044A0000)  # nibble A is non-BCD
    return bytes(data)


def synth_wrong_d50_illuminant():
    """Profile with PCS illuminant not matching D50 (triggers H129)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">i", data, 68, int(0.5 * 65536))
    struct.pack_into(">i", data, 72, int(0.5 * 65536))
    struct.pack_into(">i", data, 76, int(0.5 * 65536))
    return bytes(data)


def synth_flags_reserved_bits():
    """Profile with reserved flag bits set (triggers H133)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 44, 0xFFFFFFFC)
    return bytes(data)


def synth_duplicate_tags():
    """Profile with duplicate tag signatures (triggers H135)."""
    desc = make_mluc_tag("Duplicate Tags Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build manually to allow duplicate sigs
    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data = [
        (b"desc", desc),
        (b"desc", desc),  # duplicate!
        (b"cprt", cprt),
        (b"wtpt", wtpt),
    ]
    offsets = []
    current = data_offset
    for sig, d in tag_data:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    for i, (sig, d) in enumerate(tag_data):
        table += make_tag_entry(sig, offsets[i], len(d))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (sig, d) in enumerate(tag_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_tag_misaligned():
    """Profile with tag offsets not 4-byte aligned (triggers H130/H40)."""
    desc = make_mluc_tag("Misaligned Tags")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    # Force misaligned offsets by adding 1 byte
    offset1 = data_offset + 1  # NOT 4-byte aligned
    offset2 = offset1 + len(desc) + 1
    offset3 = offset2 + len(cprt) + 1

    total_size = offset3 + len(wtpt) + 4

    hdr = write_icc_header(total_size)
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offset1, len(desc))
    table += make_tag_entry(b"cprt", offset2, len(cprt))
    table += make_tag_entry(b"wtpt", offset3, len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < total_size:
        profile += b"\x00"
    profile[offset1:offset1 + len(desc)] = desc
    profile[offset2:offset2 + len(cprt)] = cprt
    profile[offset3:offset3 + len(wtpt)] = wtpt
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_extra_trailing_bytes():
    """Profile with extra bytes appended past declared size (triggers H1)."""
    data = bytearray(synth_valid_srgb())
    data += b"\xDE\xAD" * 50  # 100 extra bytes
    return bytes(data)


def synth_null_tag_type():
    """Profile with tag having null type signature (triggers H20)."""
    desc = make_mluc_tag("Null Type Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)
    # Tag with null type sig (first 4 bytes = 0x00000000)
    null_cprt = b"\x00\x00\x00\x00" + b"\x00" * 4 + b"fake data here!!"
    while len(null_cprt) % 4:
        null_cprt += b"\x00"

    tags = [
        (b"desc", desc),
        (b"cprt", null_cprt),
        (b"wtpt", wtpt),
    ]
    return build_profile(tags)


def synth_nan_float_tag():
    """Profile with fl32 tag containing NaN/Inf values (triggers H49)."""
    desc = make_mluc_tag("NaN Float Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)
    # fl32 tag with NaN and Inf values
    fl32_data = b"fl32" + b"\x00" * 4
    fl32_data += struct.pack(">I", 0x7FC00000)  # quiet NaN
    fl32_data += struct.pack(">I", 0x7F800000)  # +Inf
    fl32_data += struct.pack(">f", 1.0)          # normal
    while len(fl32_data) % 4:
        fl32_data += b"\x00"

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"fl32", fl32_data),
    ]
    return build_profile(tags)


def synth_odd_utf16_mluc():
    """Profile with mluc tag having odd-length UTF-16 string (triggers H55)."""
    data = bytearray(synth_valid_srgb())
    # Find cprt tag in the tag table and get its offset
    tag_count = struct.unpack_from(">I", data, 128)[0]
    for i in range(tag_count):
        entry_off = 132 + i * 12
        sig = data[entry_off:entry_off + 4]
        if sig == b"cprt":
            tag_offset = struct.unpack_from(">I", data, entry_off + 4)[0]
            # Verify it's mluc type
            if data[tag_offset:tag_offset + 4] == b"mluc":
                # strLen is at tag_offset + 20 (after type+reserved+numRec+recSz+lang)
                current_len = struct.unpack_from(">I", data, tag_offset + 20)[0]
                # Set to odd value
                struct.pack_into(">I", data, tag_offset + 20, current_len - 1)
            break
    return bytes(data)


def synth_suspicious_profile_id():
    """Profile with suspicious profile ID pattern (triggers H69)."""
    data = bytearray(synth_valid_srgb())
    data[84:100] = b"\xFF" * 16  # all 0xFF is suspicious
    return bytes(data)


def synth_tag_aliasing():
    """Profile where multiple tags share the same offset (tag aliasing)."""
    desc = make_mluc_tag("Tag Aliasing Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    offsets = []
    current = data_offset
    tag_data_list = [desc, cprt, wtpt]
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    # desc and cprt both point to same offset (aliasing)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[0], len(desc))  # same offset!
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_named_color2_excessive_coords():
    """NamedColor2 tag with nDeviceCoords=20 (>16 ICC spec max).
    Triggers H64 (CWE-787 device coord count exceeds ICC spec max).
    Based on CFL-076 finding: timeout-0bec9575 had nCoords=20734320."""
    desc = make_mluc_tag("NamedColor2 Excessive Coords")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build ncl2 tag with nDeviceCoords=20
    ncl2_sig = b"ncl2"
    n_device_coords = 20  # > 16
    n_colors = 2
    # ncl2 tag structure: type(4) + reserved(4) + vendorFlag(4) + nColors(4) +
    #   nDeviceCoords(4) + prefix(32) + suffix(32) +
    #   entries[nColors]: name(32) + PCS(6) + device(nDeviceCoords*2)
    entry_size = 32 + 6 + n_device_coords * 2
    ncl2_data = struct.pack(">4sI", b"ncl2", 0)  # type + reserved
    ncl2_data += struct.pack(">I", 0)  # vendor flag
    ncl2_data += struct.pack(">I", n_colors)
    ncl2_data += struct.pack(">I", n_device_coords)
    ncl2_data += b"\x00" * 32  # prefix
    ncl2_data += b"\x00" * 32  # suffix
    for i in range(n_colors):
        name = f"Color{i}".encode("ascii").ljust(32, b"\x00")
        ncl2_data += name
        ncl2_data += b"\x00" * 6  # PCS coords
        ncl2_data += b"\x00" * (n_device_coords * 2)  # device coords

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt, ncl2_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, color_space=b"RGB ", device_class=b"nmcl")
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    table += make_tag_entry(b"ncl2", offsets[3], len(ncl2_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_high_dimensional_colorspace():
    """Profile with 8-channel color space (icSig8colorData).
    Triggers H137 (CWE-400 high-dimensional grid complexity).
    33^8 = 1.41T iterations in EvaluateProfile."""
    desc = make_mluc_tag("8-Channel High Dimensional")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # icSig8colorData = '8CLR' = 0x38434C52
    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, color_space=b"8CLR", device_class=b"prtr")
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_response_curve_excessive_measurements():
    """ResponseCurveSet16 tag with nMeasurements=500000 per channel.
    Triggers H136 (CWE-400 unbounded measurement count)."""
    desc = make_mluc_tag("ResponseCurve Excessive Measurements")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build a minimal rcs2 (responseCurveSet16Type) tag
    # Structure: type(4) + reserved(4) + nChannels(2) + nMeasTypes(2) +
    #   offsets[nMeasTypes](4 each) + ResponseCurveStruct(s)
    n_channels = 3
    n_meas_types = 1
    rcs2_type = b"rcs2"
    rcs2_hdr = struct.pack(">4sI", rcs2_type, 0)  # type + reserved
    rcs2_hdr += struct.pack(">HH", n_channels, n_meas_types)
    # Offset to first curve struct (relative to start of tag)
    curve_struct_offset = 12 + n_meas_types * 4
    rcs2_hdr += struct.pack(">I", curve_struct_offset)
    # ResponseCurveStruct: measurementUnit(4) + nMeasurements[nChannels](4 each)
    meas_unit = 0x53746149  # 'StaI'
    excessive_count = 500000
    rcs2_curve = struct.pack(">I", meas_unit)
    for _ in range(n_channels):
        rcs2_curve += struct.pack(">I", excessive_count)
    # We don't need actual measurement data — the heuristic checks the count
    rcs2_data = rcs2_hdr + rcs2_curve

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    # Use signature 'rcs2' in tag table — actual tag sig doesn't matter,
    # H136 scans by type signature inside the tag data
    tag_data_list = [desc, cprt, wtpt, rcs2_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    # Use 'rTRC' as the tag sig (arbitrary — H136 scans by type sig in data)
    table += make_tag_entry(b"rTRC", offsets[3], len(rcs2_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_named_color2_large_nsize():
    """NamedColor2 tag with large m_nSize (50000 entries, nDevCoords=3).
    Triggers H64 CWE-400 warning for excessive named color entries (>65536).
    Tests Describe() iteration safety — should NOT hang the analyzer.
    Note: m_nSize=50000 is under 65536 but exercises the loop path.
    We set it to 70000 to trigger the H64 >65536 threshold."""
    desc = make_mluc_tag("NamedColor2 Large nSize")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    ncl2_sig = b"ncl2"
    n_device_coords = 3
    n_colors = 70000  # > 65536 threshold
    entry_size = 32 + 6 + n_device_coords * 2
    ncl2_data = struct.pack(">4sI", b"ncl2", 0)  # type + reserved
    ncl2_data += struct.pack(">I", 0)  # vendor flag
    ncl2_data += struct.pack(">I", n_colors)
    ncl2_data += struct.pack(">I", n_device_coords)
    ncl2_data += b"\x00" * 32  # prefix
    ncl2_data += b"\x00" * 32  # suffix
    # Only write 2 actual entries — the library will try to read n_colors
    # but the file is truncated. This tests Read() resilience.
    for i in range(2):
        name = f"C{i}".encode("ascii").ljust(32, b"\x00")
        ncl2_data += name
        ncl2_data += b"\x00" * 6
        ncl2_data += b"\x00" * (n_device_coords * 2)

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt, ncl2_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, color_space=b"RGB ", device_class=b"nmcl")
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    table += make_tag_entry(b"ncl2", offsets[3], len(ncl2_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_xyz_large_array():
    """XYZ tag with m_nSize=5000 entries to test Describe() output cap.
    The tag declares a large array — Describe() should not produce
    unbounded output. Tests CFL-080 pattern detection."""
    desc = make_mluc_tag("XYZ Large Array")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9642, 1.0, 0.8249)

    # Build a large XYZ tag: type(4) + reserved(4) + nSize * 12 bytes
    n_entries = 5000
    xyz_data = struct.pack(">4sI", b"XYZ ", 0)  # type + reserved
    for i in range(n_entries):
        # s15Fixed16Number: X, Y, Z
        xyz_data += struct.pack(">iii",
                                int(0.5 * 65536),  # X=0.5
                                int(0.5 * 65536),  # Y=0.5
                                int(0.5 * 65536))  # Z=0.5

    tag_count = 4
    # Use a non-standard sig to avoid wtpt confusion
    custom_sig = b"tst1"
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt, xyz_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    table += make_tag_entry(custom_sig, offsets[3], len(xyz_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_calculator_deep_nesting():
    """Profile with MPE calculator element containing many sub-elements.
    The multiProcessElementsType tag uses 'mpet' type signature.
    This creates a minimal MPE with a calculator that has >16 sub-elements
    to trigger H138 CWE-674 detection.

    MPE structure: type(4) + reserved(4) + nInputChannels(2) +
    nOutputChannels(2) + nElements(4) + [element positions] + [element data]

    Calculator element structure: type(4) + reserved(4) + nInputChannels(2) +
    nOutputChannels(2) + nSubElements(4) + ...

    We construct a minimal but structurally plausible MPE tag."""
    desc = make_mluc_tag("Calculator Deep Nesting")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9642, 1.0, 0.8249)

    # Build a minimal multiProcessElementsType (mpet) tag
    # with a calculator element that has sub-elements.
    # For testing H138, we need the library to parse this as CIccMpeCalculator
    # with detectable sub-elements.
    #
    # Simpler approach: create a profile with enough structure that
    # H138's scan finds calculator elements. Since creating a fully valid
    # mpet/calc is complex, we'll create one that the library can at least
    # partially parse.

    nIn = 3
    nOut = 3
    nSubElements = 20  # > 16 threshold

    # 'calc' element: sig(4) + reserved(4) + nIn(2) + nOut(2) + nSubElements(4)
    calc_elem = struct.pack(">4sI", b"calc", 0)
    calc_elem += struct.pack(">HH", nIn, nOut)
    calc_elem += struct.pack(">I", nSubElements)
    # Sub-element position table: nSubElements * (offset(4) + size(4))
    sub_data_start = len(calc_elem) + nSubElements * 8
    for s in range(nSubElements):
        # Each sub-element is a minimal curv: type(4)+reserved(4)+nEntries(4)=12 bytes
        sub_offset = sub_data_start + s * 12
        calc_elem += struct.pack(">II", sub_offset, 12)
    # Sub-element data: minimal curve elements
    for s in range(nSubElements):
        calc_elem += struct.pack(">4sI", b"curv", 0)
        calc_elem += struct.pack(">I", 0)  # gamma=1.0

    # Main function: 'func' block
    # We'll add a simple function string: "in 0 1 2 out 0 1 2"
    func_data = b"\x00" * 4  # function signature placeholder

    # Complete calculator data
    calc_data = calc_elem + func_data

    # MPE tag: 'mpet' type
    # Structure: type(4) + reserved(4) + nInput(2) + nOutput(2) + nElements(4) +
    #   element positions table: nElements * (offset(4) + size(4)) + element data
    nElements = 1
    elem_table_size = nElements * 8
    elem_data_start = 16 + elem_table_size  # after header + position table

    mpet_data = struct.pack(">4sI", b"mpet", 0)
    mpet_data += struct.pack(">HH", nIn, nOut)
    mpet_data += struct.pack(">I", nElements)
    mpet_data += struct.pack(">II", elem_data_start, len(calc_data))
    mpet_data += calc_data

    # AToB0 tag uses this MPE
    atob0_sig = b"A2B0"

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt, mpet_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, version=0x05000000)  # v5 for MPE
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    table += make_tag_entry(atob0_sig, offsets[3], len(mpet_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_mluc_bidi_override():
    """mluc tag with Unicode bidi override characters (U+200B-U+206F).
    Triggers H86 bidi text injection detection (CWE-116)."""
    # Build mluc with U+202E (RIGHT-TO-LEFT OVERRIDE) embedded in text
    text_chars = "Test \u202Eprofile\u202C name"  # RLO ... PDF
    utf16 = text_chars.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    mluc = b"mluc" + b"\x00" * 4
    mluc += struct.pack(">II", 1, record_size)
    mluc += b"enUS"
    mluc += struct.pack(">II", len(utf16), string_offset)
    mluc += utf16
    while len(mluc) % 4:
        mluc += b"\x00"

    tags = [
        (b"desc", mluc),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags)


def synth_mluc_mixed_scripts():
    """mluc tag mixing Latin and CJK characters.
    Triggers H86 mixed-script detection (CWE-116)."""
    text_chars = "sRGB \u534F\u5B9A Profile"  # 协定 = Chinese chars
    utf16 = text_chars.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    mluc = b"mluc" + b"\x00" * 4
    mluc += struct.pack(">II", 1, record_size)
    mluc += b"enUS"
    mluc += struct.pack(">II", len(utf16), string_offset)
    mluc += utf16
    while len(mluc) % 4:
        mluc += b"\x00"

    tags = [
        (b"desc", mluc),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags)


def synth_mluc_control_chars():
    """mluc tag with C0 control characters in text.
    Triggers H86 control character injection detection (CWE-116)."""
    # Build mluc with control chars manually (U+0001, U+0007 BEL, U+001B ESC)
    text = "Test\x01Prof\x07ile\x1BName"
    utf16 = text.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    mluc = b"mluc" + b"\x00" * 4
    mluc += struct.pack(">II", 1, record_size)
    mluc += b"enUS"
    mluc += struct.pack(">II", len(utf16), string_offset)
    mluc += utf16
    while len(mluc) % 4:
        mluc += b"\x00"

    tags = [
        (b"desc", mluc),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags)


def synth_mluc_embedded_nulls():
    """mluc tag with embedded null characters (not just terminator).
    Triggers H86 embedded null / string truncation detection (CWE-170)."""
    # "Test\x00\x00Hidden\x00\x00Data" — nulls in middle, not just at end
    raw_utf16 = b"\x00T\x00e\x00s\x00t\x00\x00\x00\x00\x00H\x00i\x00d\x00d\x00e\x00n"
    record_size = 12
    string_offset = 16 + record_size
    mluc = b"mluc" + b"\x00" * 4
    mluc += struct.pack(">II", 1, record_size)
    mluc += b"enUS"
    mluc += struct.pack(">II", len(raw_utf16), string_offset)
    mluc += raw_utf16
    while len(mluc) % 4:
        mluc += b"\x00"

    tags = [
        (b"desc", mluc),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags)


def synth_lut_null_clut():
    """AToB0 LUT tag with curves but NO CLUT data.
    Triggers H147 null CLUT detection (CWE-476, IccTagLut.cpp:3181).
    mAB type: type sig + reserved + inputChans + outputChans + padding
    + offsets (B curves, matrix, M curves, CLUT, A curves).
    Set CLUT offset to 0 = absent."""
    # mAB tag: input=3, output=3, CLUT offset=0 (null CLUT)
    mab = bytearray()
    mab += b"mAB " + b"\x00" * 4  # type sig + reserved
    mab += struct.pack(">BB", 3, 3)  # inputChans, outputChans
    mab += b"\x00\x00"  # padding
    # Offsets: B curves, matrix, M curves, CLUT, A curves
    # B curves at offset 32 (right after header), all others 0
    b_offset = 32
    mab += struct.pack(">IIIII", b_offset, 0, 0, 0, 0)
    # B curves: 3 identity curves (curveType with 0 entries = identity)
    for _ in range(3):
        mab += b"curv" + b"\x00" * 4 + struct.pack(">I", 0)
    while len(mab) % 4:
        mab += b"\x00"

    tags = [
        (b"desc", make_mluc_tag("Null CLUT Test")),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"A2B0", bytes(mab)),
    ]
    return build_profile(tags)


def synth_lut_degenerate_clut():
    """AToB0 LUT tag with a CLUT that has 0 grid points.
    Triggers H147 degenerate CLUT detection (CWE-476).
    Uses mft2 (lut16Type) format for simpler construction."""
    # lut16Type: 'mft2' + reserved + inputChan + outputChan + clutGridPts + padding
    # + 3x3 matrix + inputTableEntries + outputTableEntries
    # + input tables + CLUT + output tables
    mft2 = bytearray()
    mft2 += b"mft2" + b"\x00" * 4  # type + reserved
    mft2 += struct.pack(">BBB", 3, 3, 0)  # in=3, out=3, gridPts=0 (degenerate!)
    mft2 += b"\x00"  # padding
    # 3x3 identity matrix (s15Fixed16Number)
    for r in range(3):
        for c in range(3):
            val = 1.0 if r == c else 0.0
            mft2 += struct.pack(">i", int(val * 65536))
    # Input/output table entries
    mft2 += struct.pack(">HH", 2, 2)  # 2 entries each
    # Input tables: 3 channels × 2 entries
    for _ in range(3):
        mft2 += struct.pack(">HH", 0, 65535)
    # CLUT: 0 grid points → 0^3 * 3 = 0 entries (empty)
    # Output tables: 3 channels × 2 entries
    for _ in range(3):
        mft2 += struct.pack(">HH", 0, 65535)
    while len(mft2) % 4:
        mft2 += b"\x00"

    tags = [
        (b"desc", make_mluc_tag("Degenerate CLUT Test")),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"A2B0", bytes(mft2)),
    ]
    return build_profile(tags)


def synth_calc_trunc_operator():
    """Profile with calculator element containing trnc (truncate) operator.
    Triggers H151 float→int cast operator detection (CWE-681).
    Raw bytes match scanner layout:
      calc(4) + reserved(4) + nInput(2) + nOutput(2) + nSubElem(4)
      position table: (nSubElem+1) entries × (offset(4) + size(4))
      channel function: sig('func',4) + reserved(4) + nOps(4) + ops[](sig(4)+data(4))
    """
    calc_elem = bytearray()
    calc_elem += b"calc"                          # +0: type sig
    calc_elem += b"\x00\x00\x00\x00"              # +4: reserved
    calc_elem += struct.pack(">HH", 1, 1)         # +8: nInput=1, nOutput=1
    calc_elem += struct.pack(">I", 0)             # +12: nSubElem=0
    # Position table: (0+1=1) entry starting at +16
    func_offset = 24  # relative to calc start: 16 (header) + 8 (1 pos entry) = 24
    func_size = 28     # func header(12) + 2 ops × 8 = 28
    calc_elem += struct.pack(">II", func_offset, func_size)  # +16: pos[0]
    # Channel function at +24:
    calc_elem += b"func"                          # +24: chanFuncSig = 'func'
    calc_elem += b"\x00\x00\x00\x00"              # +28: reserved
    calc_elem += struct.pack(">I", 2)             # +32: nOps=2
    calc_elem += b"data" + b"\x00\x00\x00\x00"    # +36: op[0] = data push
    calc_elem += b"trnc" + b"\x00\x00\x00\x00"    # +44: op[1] = TRUNCATE (dangerous!)
    while len(calc_elem) % 4:
        calc_elem += b"\x00"

    # mpet wrapper
    mpet = bytearray()
    mpet += b"mpet" + b"\x00" * 4  # type + reserved
    mpet += struct.pack(">HHI", 1, 1, 1)  # input=1, output=1, numElements=1
    elem_data_start = 16 + 8  # header(16) + 1 pos entry(8) = 24
    mpet += struct.pack(">II", elem_data_start, len(calc_elem))
    mpet += calc_elem
    while len(mpet) % 4:
        mpet += b"\x00"

    tags = [
        (b"desc", make_mluc_tag("Calc Trunc Test")),
        (b"cprt", make_mluc_tag("Copyright 2024")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"A2B0", bytes(mpet)),
    ]
    return build_profile(tags)


def synth_tag_shared_pointers():
    """Two different tag signatures pointing to the same data offset with mutable types.
    Triggers H73 shared tag pointer detection for risky (non-immutable) types.
    Uses raw profile construction to force shared offsets.
    rTRC and gTRC share the same curve data — this is safe for immutable curv,
    but we also share desc-like tags which are mutable → risky."""
    desc_data = make_mluc_tag("Shared Pointer Test")
    cprt_data = make_mluc_tag("Copyright 2024")
    wtpt_data = make_xyz_tag(0.9505, 1.0, 1.089)
    rXYZ_data = make_xyz_tag(0.4124, 0.2126, 0.0193)
    gXYZ_data = make_xyz_tag(0.3576, 0.7152, 0.1192)
    rTRC_data = make_curve_tag(gamma=2.2)

    tag_count = 7  # desc, cprt, wtpt, rXYZ, gXYZ, rTRC, gTRC (gTRC shares rTRC)
    header_size = 128
    tag_table_size = 4 + tag_count * 12
    data_start = header_size + tag_table_size
    if data_start % 4:
        data_start += 4 - (data_start % 4)

    off_desc = data_start
    off_cprt = off_desc + len(desc_data)
    while off_cprt % 4:
        off_cprt += 1
    off_wtpt = off_cprt + len(cprt_data)
    while off_wtpt % 4:
        off_wtpt += 1
    off_rXYZ = off_wtpt + len(wtpt_data)
    while off_rXYZ % 4:
        off_rXYZ += 1
    off_gXYZ = off_rXYZ + len(rXYZ_data)
    while off_gXYZ % 4:
        off_gXYZ += 1
    off_rTRC = off_gXYZ + len(gXYZ_data)
    while off_rTRC % 4:
        off_rTRC += 1
    # gTRC intentionally shares rTRC offset (shared pointer — safe for curve)
    off_gTRC = off_rTRC

    total_size = off_rTRC + len(rTRC_data)
    while total_size % 4:
        total_size += 1

    header = write_icc_header(total_size)
    profile = bytearray(header)
    # Tag table
    profile += struct.pack(">I", tag_count)
    profile += make_tag_entry(b"desc", off_desc, len(desc_data))
    profile += make_tag_entry(b"cprt", off_cprt, len(cprt_data))
    profile += make_tag_entry(b"wtpt", off_wtpt, len(wtpt_data))
    profile += make_tag_entry(b"rXYZ", off_rXYZ, len(rXYZ_data))
    profile += make_tag_entry(b"gXYZ", off_gXYZ, len(gXYZ_data))
    profile += make_tag_entry(b"rTRC", off_rTRC, len(rTRC_data))
    profile += make_tag_entry(b"gTRC", off_gTRC, len(rTRC_data))  # shared with rTRC!

    # Pad to data start
    while len(profile) < data_start:
        profile += b"\x00"
    # Write tag data in order
    for off, data in [(off_desc, desc_data), (off_cprt, cprt_data),
                       (off_wtpt, wtpt_data), (off_rXYZ, rXYZ_data),
                       (off_gXYZ, gXYZ_data), (off_rTRC, rTRC_data)]:
        while len(profile) < off:
            profile += b"\x00"
        profile += data
    while len(profile) % 4:
        profile += b"\x00"

    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_nop_sled_tag():
    """Profile with NOP sled pattern in tag data (triggers CF-094)."""
    # 256 bytes of x86 NOP (0x90) — classic shellcode sled
    nop_sled = b"priv" + b"\x00" * 4 + b"\x90" * 256
    tags = [
        (b"desc", make_mluc_tag("NOP Sled Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"zzzz", nop_sled),
    ]
    return build_profile(tags)


def synth_lut8_atob_btoa():
    """Profile with lut8Type AToB0 and BToA0 tags (tests CF-060..CF-067, CF-099).
    Minimal valid lut8Type: 3-in, 3-out, identity curves, 2x2x2 CLUT."""
    lut8 = make_lut8_tag(3, 3, grid=2)

    # Build as Output (prtr) with AToB0 and BToA0
    tags = [
        (b"desc", make_mluc_tag("LUT8 AToB/BToA Profile")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"A2B0", lut8),
        (b"B2A0", lut8),
    ]
    return build_profile(tags, device_class=b"prtr", color_space=b"RGB ",
                         pcs=b"Lab ")


def synth_lut8_atob2_btoa2():
    """Profile with lut8Type AToB2 and BToA2 tags for quality fallback coverage."""
    lut8 = make_lut8_tag(3, 3, grid=2)
    tags = [
        (b"desc", make_mluc_tag("LUT8 AToB2/BToA2 Profile")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"A2B2", lut8),
        (b"B2A2", lut8),
    ]
    return build_profile(tags, device_class=b"prtr", color_space=b"RGB ",
                         pcs=b"Lab ")


def synth_targ_tag_profile():
    """Profile with charTargetTag ('targ') for CF-102 characterization data check."""
    targ_text = b"text" + b"\x00" * 4 + b"BEGIN_DATA_FORMAT\nSAMPLE_ID\nEND_DATA_FORMAT\n\x00"
    tags = [
        (b"desc", make_mluc_tag("Characterization Profile")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"targ", targ_text),
    ]
    return build_profile(tags, device_class=b"prtr", color_space=b"RGB ",
                         pcs=b"Lab ")


def synth_targ_quality_profile():
    """Matrix/TRC profile with usable targ rows for Q4 / CF-102."""
    matrix = (
        (0.4124, 0.3576, 0.1805),
        (0.2126, 0.7152, 0.0722),
        (0.0193, 0.1192, 0.9505),
    )
    samples = (
        (0.0, 0.0, 0.0),
        (0.25, 0.25, 0.25),
        (0.5, 0.2, 0.7),
        (0.75, 0.6, 0.4),
        (1.0, 1.0, 1.0),
    )

    lines = [
        "BEGIN_DATA_FORMAT",
        "RGB_R RGB_G RGB_B XYZ_X XYZ_Y XYZ_Z",
        "END_DATA_FORMAT",
        "BEGIN_DATA",
    ]

    for r, g, b in samples:
        rl = r ** 2.2
        gl = g ** 2.2
        bl = b ** 2.2
        x = matrix[0][0] * rl + matrix[0][1] * gl + matrix[0][2] * bl
        y = matrix[1][0] * rl + matrix[1][1] * gl + matrix[1][2] * bl
        z = matrix[2][0] * rl + matrix[2][1] * gl + matrix[2][2] * bl
        lines.append(f"{r:.6f} {g:.6f} {b:.6f} {x:.6f} {y:.6f} {z:.6f}")
    lines.append("END_DATA")

    targ_text = b"text" + b"\x00" * 4 + ("\n".join(lines) + "\n").encode("ascii")
    tags = [
        (b"desc", make_mluc_tag("Characterization Quality Profile")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"targ", targ_text),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_targ_cmyk_quality_profile():
    """CMYK/XYZ profile with reversible AToB0/BToA0 LUTs and usable targ rows for broader Q1/Q4 coverage."""
    clut_values_a2b = []
    for c in (0.0, 1.0):
        for m in (0.0, 1.0):
            for y in (0.0, 1.0):
                for k in (0.0, 1.0):
                    gray = max(0.0, min(1.0, 0.75 - 0.125 * (c + m + y + k)))
                    byte = int(round(gray * 255.0))
                    clut_values_a2b.extend((byte, byte, byte))

    clut_values_b2a = []
    for x in (0.0, 0.25, 0.5, 0.75, 1.0):
        for y in (0.0, 0.25, 0.5, 0.75, 1.0):
            for z in (0.0, 0.25, 0.5, 0.75, 1.0):
                device = max(0.0, min(1.0, 1.5 - 2.0 * x))
                byte = int(round(device * 255.0))
                clut_values_b2a.extend((byte, byte, byte, byte))

    a2b_lut8 = make_lut8_tag(4, 3, grid=2, clut_values=clut_values_a2b)
    b2a_lut8 = make_lut8_tag(3, 4, grid=5, clut_values=clut_values_b2a)

    samples = (
        (0.0, 0.0, 0.0, 0.0),
        (0.2, 0.3, 0.1, 0.0),
        (0.4, 0.1, 0.6, 0.2),
        (0.7, 0.4, 0.2, 0.3),
        (1.0, 1.0, 1.0, 1.0),
    )

    lines = [
        "BEGIN_DATA_FORMAT",
        "CMYK_C CMYK_M CMYK_Y CMYK_K XYZ_X XYZ_Y XYZ_Z",
        "END_DATA_FORMAT",
        "BEGIN_DATA",
    ]
    for c, m, y, k in samples:
        gray = max(0.0, min(1.0, 0.75 - 0.125 * (c + m + y + k)))
        lines.append(f"{c:.6f} {m:.6f} {y:.6f} {k:.6f} {gray:.6f} {gray:.6f} {gray:.6f}")
    lines.append("END_DATA")

    targ_text = b"text" + b"\x00" * 4 + ("\n".join(lines) + "\n").encode("ascii")
    tags = [
        (b"desc", make_mluc_tag("CMYK Characterization Quality Profile")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"A2B0", a2b_lut8),
        (b"B2A0", b2a_lut8),
        (b"targ", targ_text),
    ]
    return build_profile(tags, device_class=b"prtr", color_space=b"CMYK",
                         pcs=b"XYZ ", version=0x04400000)


def synth_clean_mntr_profile():
    """Clean well-formed mntr/RGB/XYZ profile with all required tags.
    Should produce zero conformance warnings — baseline for CF clean tests."""
    # D50 illuminant
    tags = [
        (b"desc", make_mluc_tag("Clean Monitor Profile")),
        (b"cprt", make_mluc_tag("Copyright 2025")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4361, 0.2225, 0.0139)),
        (b"gXYZ", make_xyz_tag(0.3851, 0.7169, 0.0971)),
        (b"bXYZ", make_xyz_tag(0.1431, 0.0606, 0.7141)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


# ═══════════════════════════════════════════════════════════════════════════════
# CF-103..CF-122 Test Profiles
# ═══════════════════════════════════════════════════════════════════════════════

def synth_misaligned_tag():
    """Profile with tag at non-4-byte-aligned offset (triggers CF-103)."""
    desc = make_mluc_tag("Misaligned Tag")
    cprt = make_mluc_tag("Copyright Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    hdr = write_icc_header(512, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")
    tag_count = 3
    table = struct.pack(">I", tag_count)
    # Force cprt to offset 145 (not 4-byte aligned)
    table += make_tag_entry(b"desc", 180, len(desc))
    table += make_tag_entry(b"cprt", 145, len(cprt))
    table += make_tag_entry(b"wtpt", 260, len(wtpt))

    profile = bytearray(512)
    profile[:128] = hdr[:128]
    profile[128:128 + len(table)] = table
    if 180 + len(desc) <= 512:
        profile[180:180 + len(desc)] = desc
    if 145 + len(cprt) <= 512:
        profile[145:145 + len(cprt)] = cprt[:min(len(cprt), 512 - 145)]
    if 260 + len(wtpt) <= 512:
        profile[260:260 + len(wtpt)] = wtpt
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_devicelink_no_atob():
    """DeviceLink profile without AToB0Tag (triggers CF-104)."""
    tags = [
        (b"desc", make_mluc_tag("DeviceLink No AToB0")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags, device_class=b"link", color_space=b"RGB ",
                         pcs=b"RGB ")


def synth_non_monotonic_trc():
    """Profile with non-monotonic TRC curve (triggers CF-106).
    Values go up then back down."""
    curve_data = [0.0, 0.3, 0.6, 0.9, 0.7, 0.8, 1.0]
    tags = [
        (b"desc", make_mluc_tag("Non-monotonic TRC")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(values=curve_data)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ")


def synth_duplicate_tag_sigs():
    """Profile with duplicate tag signatures in tag table (triggers CF-107)."""
    desc1 = make_mluc_tag("Description 1")
    desc2 = make_mluc_tag("Description 2")
    cprt = make_mluc_tag("Copyright Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    hdr = write_icc_header(600, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")
    tag_count = 4
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", 180, len(desc1))
    table += make_tag_entry(b"cprt", 244, len(cprt))
    table += make_tag_entry(b"wtpt", 312, len(wtpt))
    table += make_tag_entry(b"desc", 340, len(desc2))  # DUPLICATE sig

    profile = bytearray(600)
    profile[:128] = hdr[:128]
    profile[128:128 + len(table)] = table
    for off, data in [(180, desc1), (244, cprt), (312, wtpt), (340, desc2)]:
        end = min(off + len(data), 600)
        profile[off:end] = data[:end - off]
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_xyz_negative_y():
    """Profile with negative Y in wtpt XYZ tag (triggers CF-112)."""
    tags = [
        (b"desc", make_mluc_tag("Negative Y wtpt")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9505, -1.0, 1.089)),  # Y negative!
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ")


def synth_rig0_wrong_class():
    """Input class profile with rig0 tag (triggers CF-117).
    rig0 only valid for Output/Display per §9.2.36."""
    rig0_data = b"sig " + b"\x00" * 4 + b"\x00\x00\x00\x00"
    tags = [
        (b"desc", make_mluc_tag("Input with rig0")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"rig0", rig0_data),
    ]
    return build_profile(tags, device_class=b"scnr", color_space=b"RGB ",
                         pcs=b"XYZ ")


def synth_implausible_date():
    """Profile with year 1800 in dateTime field (triggers CF-122)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">H", data, 24, 1800)  # year 1800
    return bytes(data)


def synth_v4_wtpt_not_d50():
    """v4 profile whose wtpt differs significantly from D50 (triggers CF-121)."""
    tags = [
        (b"desc", make_mluc_tag("v4 non-D50 wtpt")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.7500, 0.8000, 0.6000)),  # far from D50
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x04400000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


# ── ADGC (Adaptive Gain Curve) test profiles ────────────────────────────────

def _make_adgc_tag(
    type_sig=b"adgc",
    func_type=1,
    reserved=0,
    guid=b"\x00" * 16,
    h_baseline=3.0,
    h_alternate=6.0,
    r_gain_min=0.0, r_gain_max=6.0, k_red=0.2126,
    g_gain_min=0.0, g_gain_max=6.0, k_green=0.7152,
    b_gain_min=0.0, b_gain_max=6.0, k_blue=0.0722,
    k_max=0.0, k_min=0.0, k_component=0.0,
    pre_cicp=0, post_cicp=0,
    a2b0_headroom=3.0, a2b1_headroom=0.0, a2b2_headroom=0.0,
    curve_data=None,
    nan_weights=False,
):
    """Build an adaptiveGainCurveType tag (128-byte header + curve data).

    ADGC header layout (128 bytes):
      0-3:     type sig 'adgc' (4)
      4-7:     reserved (4)
      8-11:    funcTypeID (uInt32)
      12-27:   GUID (16)
      28-31:   H_baseline (float32)
      32-35:   H_alternate (float32)
      36-39:   Red GainMin (float32)
      40-43:   Red GainMax (float32)
      44-47:   kRed (float32)
      48-51:   Green GainMin (float32)
      52-55:   Green GainMax (float32)
      56-59:   kGreen (float32)
      60-63:   Blue GainMin (float32)
      64-67:   Blue GainMax (float32)
      68-71:   kBlue (float32)
      72-75:   kMax (float32)
      76-79:   kMin (float32)
      80-83:   kComponent (float32)
      84-87:   PreGainCICP (uInt32)
      88-91:   PostGainCICP (uInt32)
      92-95:   A2B0 target headroom (float32)
      96-99:   A2B1 target headroom (float32)
      100-103: A2B2 target headroom (float32)
      104-111: Red curve positionNumber (offset + size, 8 bytes)
      112-119: Green curve positionNumber (8 bytes)
      120-127: Blue curve positionNumber (8 bytes)
    """
    import math

    # Default curve: 3 triplets {x, y, slope} for each channel
    if curve_data is None:
        curve_data = [
            (0.0, 0.0, 1.0),
            (0.5, 0.5, 1.0),
            (1.0, 1.0, 1.0),
        ]

    # Build curve data: uInt32 count + triplets of float32
    curve_count = len(curve_data)
    curve_bytes = struct.pack(">I", curve_count)
    for x, y, slope in curve_data:
        curve_bytes += struct.pack(">fff", x, y, slope)
    # Pad to 4-byte boundary
    while len(curve_bytes) % 4:
        curve_bytes += b"\x00"

    curve_size = len(curve_bytes)

    # Curve positions: all 3 channels share the same curve data
    # Offset relative to start of tag data (after header)
    curve_offset = 128  # curves start right after 128-byte header

    # Build 128-byte header
    hdr = bytearray(128)
    hdr[0:4] = type_sig[:4] if len(type_sig) >= 4 else type_sig + b"\x00" * (4 - len(type_sig))
    struct.pack_into(">I", hdr, 4, reserved)
    struct.pack_into(">I", hdr, 8, func_type)
    hdr[12:28] = guid[:16]

    if nan_weights:
        nan_val = float('nan')
        struct.pack_into(">f", hdr, 28, h_baseline)
        struct.pack_into(">f", hdr, 32, h_alternate)
        struct.pack_into(">f", hdr, 36, r_gain_min)
        struct.pack_into(">f", hdr, 40, r_gain_max)
        struct.pack_into(">f", hdr, 44, nan_val)  # NaN weight
        struct.pack_into(">f", hdr, 48, g_gain_min)
        struct.pack_into(">f", hdr, 52, g_gain_max)
        struct.pack_into(">f", hdr, 56, nan_val)  # NaN weight
        struct.pack_into(">f", hdr, 60, b_gain_min)
        struct.pack_into(">f", hdr, 64, b_gain_max)
        struct.pack_into(">f", hdr, 68, nan_val)  # NaN weight
    else:
        struct.pack_into(">f", hdr, 28, h_baseline)
        struct.pack_into(">f", hdr, 32, h_alternate)
        struct.pack_into(">f", hdr, 36, r_gain_min)
        struct.pack_into(">f", hdr, 40, r_gain_max)
        struct.pack_into(">f", hdr, 44, k_red)
        struct.pack_into(">f", hdr, 48, g_gain_min)
        struct.pack_into(">f", hdr, 52, g_gain_max)
        struct.pack_into(">f", hdr, 56, k_green)
        struct.pack_into(">f", hdr, 60, b_gain_min)
        struct.pack_into(">f", hdr, 64, b_gain_max)
        struct.pack_into(">f", hdr, 68, k_blue)

    struct.pack_into(">f", hdr, 72, k_max)
    struct.pack_into(">f", hdr, 76, k_min)
    struct.pack_into(">f", hdr, 80, k_component)
    struct.pack_into(">I", hdr, 84, pre_cicp)
    struct.pack_into(">I", hdr, 88, post_cicp)
    struct.pack_into(">f", hdr, 92, a2b0_headroom)
    struct.pack_into(">f", hdr, 96, a2b1_headroom)
    struct.pack_into(">f", hdr, 100, a2b2_headroom)

    # positionNumber: offset (4 bytes) + size (4 bytes)
    struct.pack_into(">II", hdr, 104, curve_offset, curve_size)  # Red
    struct.pack_into(">II", hdr, 112, curve_offset, curve_size)  # Green (shared)
    struct.pack_into(">II", hdr, 120, curve_offset, curve_size)  # Blue (shared)

    return bytes(hdr) + curve_bytes


def synth_adgc_valid_rgb_input():
    """Valid RGB/Input profile with well-formed ADGC tag (CF-123 passes)."""
    adgc_data = _make_adgc_tag()
    tags = [
        (b"desc", make_mluc_tag("ADGC Valid RGB Input")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"scnr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_cmyk_violation():
    """CMYK profile with ADGC tag — violates CF-123 class restriction."""
    adgc_data = _make_adgc_tag()
    tags = [
        (b"desc", make_mluc_tag("ADGC CMYK Violation")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"prtr", color_space=b"CMYK",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bad_functype():
    """ADGC with funcTypeID=2 instead of required 1 (triggers CF-125)."""
    adgc_data = _make_adgc_tag(func_type=2)
    tags = [
        (b"desc", make_mluc_tag("ADGC Bad FuncType")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bad_reserved():
    """ADGC with non-zero reserved bytes (triggers CF-126)."""
    adgc_data = _make_adgc_tag(reserved=0xDEADBEEF)
    tags = [
        (b"desc", make_mluc_tag("ADGC Bad Reserved")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_nan_weights():
    """ADGC with NaN in weight coefficient fields (triggers CF-127)."""
    adgc_data = _make_adgc_tag(nan_weights=True)
    tags = [
        (b"desc", make_mluc_tag("ADGC NaN Weights")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bad_weight_sum():
    """ADGC with weight coefficients summing to 2.0 (triggers CF-128)."""
    adgc_data = _make_adgc_tag(
        k_red=0.5, k_green=0.5, k_blue=0.5,
        k_max=0.3, k_min=0.1, k_component=0.1,
    )
    tags = [
        (b"desc", make_mluc_tag("ADGC Bad Weight Sum")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_non_monotonic_curve():
    """ADGC with non-monotonic curve x-values (triggers CF-132)."""
    bad_curve = [
        (0.0, 0.0, 1.0),
        (0.8, 0.8, 1.0),  # x decreases: 0.8 → 0.3
        (0.3, 0.3, 1.0),
        (1.0, 1.0, 1.0),
    ]
    adgc_data = _make_adgc_tag(curve_data=bad_curve)
    tags = [
        (b"desc", make_mluc_tag("ADGC Non-Monotonic Curve")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bad_type_sig():
    """ADGC with wrong type signature (triggers CF-124)."""
    adgc_data = _make_adgc_tag(type_sig=b"XXXX")
    tags = [
        (b"desc", make_mluc_tag("ADGC Bad Type Sig")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_h_equal():
    """ADGC with H_baseline == H_alternate (CF-133: div-by-zero in Output Evaluator)."""
    adgc_data = _make_adgc_tag(h_baseline=3.0, h_alternate=3.0)
    tags = [
        (b"desc", make_mluc_tag("ADGC H Equal")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_gain_inverted():
    """ADGC with Red GainMin > GainMax (CF-134: inverted gain range)."""
    adgc_data = _make_adgc_tag(r_gain_min=6.0, r_gain_max=0.0)
    tags = [
        (b"desc", make_mluc_tag("ADGC Gain Inverted")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bad_curve_range():
    """ADGC with curve x-values outside [0,1] (CF-135: domain violation)."""
    bad_range_curve = [
        (-0.5, 0.0, 1.0),   # first x < 0
        (0.5, 0.5, 1.0),
        (1.5, 1.0, 1.0),    # last x > 1
    ]
    adgc_data = _make_adgc_tag(curve_data=bad_range_curve)
    tags = [
        (b"desc", make_mluc_tag("ADGC Bad Curve Range")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_equal_x_curve():
    """ADGC with adjacent curve points having equal x (CF-136: cubic div-by-zero)."""
    equal_x_curve = [
        (0.0, 0.0, 1.0),
        (0.5, 0.3, 1.0),
        (0.5, 0.7, 1.0),   # same x as previous → div-by-zero in C3
        (1.0, 1.0, 1.0),
    ]
    adgc_data = _make_adgc_tag(curve_data=equal_x_curve)
    tags = [
        (b"desc", make_mluc_tag("ADGC Equal X Curve")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bt2100_pq():
    """BT.2100 PQ-realistic ADGC (H_base=0, H_alt=4.0, Rec.2020 weights)."""
    # BT.2100 PQ: ~10000 cd/m² peak → log2(10000/100) ≈ 6.64 stops above SDR
    # Use H_base=0 (SDR baseline), H_alt=4.0 (4 stops of headroom)
    # Rec.2020 luminance weights: R=0.2627, G=0.6780, B=0.0593
    pq_curve = [
        (0.0, 0.0, 0.5),
        (0.1, 0.15, 0.8),
        (0.3, 0.35, 1.0),
        (0.5, 0.55, 1.2),
        (0.7, 0.75, 1.0),
        (0.9, 0.92, 0.8),
        (1.0, 1.0, 0.5),
    ]
    adgc_data = _make_adgc_tag(
        h_baseline=0.0, h_alternate=4.0,
        r_gain_min=0.0, r_gain_max=4.0,
        g_gain_min=0.0, g_gain_max=4.0,
        b_gain_min=0.0, b_gain_max=4.0,
        k_red=0.2627, k_green=0.6780, k_blue=0.0593,
        k_max=0.0, k_min=0.0, k_component=0.0,
        pre_cicp=16,   # BT.2100 PQ EOTF
        post_cicp=16,
        a2b0_headroom=4.0,
        curve_data=pq_curve,
    )
    tags = [
        (b"desc", make_mluc_tag("ADGC BT.2100 PQ")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.7080, 0.2920, 0.0)),
        (b"gXYZ", make_xyz_tag(0.1700, 0.7970, 0.0)),
        (b"bXYZ", make_xyz_tag(0.1310, 0.0460, 0.0)),
        (b"rTRC", make_curve_tag(gamma=2.4)),
        (b"gTRC", make_curve_tag(gamma=2.4)),
        (b"bTRC", make_curve_tag(gamma=2.4)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_bt2100_hlg():
    """BT.2100 HLG-realistic ADGC (H_base=0, H_alt=3.0, Rec.2020 weights)."""
    hlg_curve = [
        (0.0, 0.0, 0.3),
        (0.2, 0.25, 0.8),
        (0.5, 0.55, 1.0),
        (0.8, 0.85, 0.8),
        (1.0, 1.0, 0.3),
    ]
    adgc_data = _make_adgc_tag(
        h_baseline=0.0, h_alternate=3.0,
        r_gain_min=0.0, r_gain_max=3.0,
        g_gain_min=0.0, g_gain_max=3.0,
        b_gain_min=0.0, b_gain_max=3.0,
        k_red=0.2627, k_green=0.6780, k_blue=0.0593,
        k_max=0.0, k_min=0.0, k_component=0.0,
        pre_cicp=18,   # BT.2100 HLG OETF
        post_cicp=18,
        a2b0_headroom=3.0,
        curve_data=hlg_curve,
    )
    tags = [
        (b"desc", make_mluc_tag("ADGC BT.2100 HLG")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.7080, 0.2920, 0.0)),
        (b"gXYZ", make_xyz_tag(0.1700, 0.7970, 0.0)),
        (b"bXYZ", make_xyz_tag(0.1310, 0.0460, 0.0)),
        (b"rTRC", make_curve_tag(gamma=2.4)),
        (b"gTRC", make_curve_tag(gamma=2.4)),
        (b"bTRC", make_curve_tag(gamma=2.4)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_single_point_curve():
    """ADGC with minimal 1-triplet curve (edge case)."""
    single_curve = [(0.5, 0.5, 1.0)]
    adgc_data = _make_adgc_tag(curve_data=single_curve)
    tags = [
        (b"desc", make_mluc_tag("ADGC Single Point Curve")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_adgc_many_point_curve():
    """ADGC with 50-triplet curve (stress test)."""
    many_curve = [(i / 49.0, i / 49.0, 1.0) for i in range(50)]
    adgc_data = _make_adgc_tag(curve_data=many_curve)
    tags = [
        (b"desc", make_mluc_tag("ADGC Many Point Curve")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"ADGC", adgc_data),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ",
                         pcs=b"XYZ ", version=0x04400000)


def synth_cf_md5_mismatch():
    """CF-011: Profile with non-zero profile ID that won't match actual MD5."""
    tags = [
        (b"desc", make_mluc_tag("MD5 Mismatch Test")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    # Deliberately wrong profile ID — will not match the computed MD5
    return build_profile(tags, profile_id=b"\xAA\xBB\xCC\xDD" * 4)


def synth_cf_reserved_bytes_nonzero_tag():
    """CF-021: Tag with non-zero reserved bytes at offset+4..+7."""
    tags = [
        (b"desc", make_mluc_tag("Reserved Bytes Test")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    profile = bytearray(build_profile(tags))
    # Find the first tag's data offset from the tag table
    # Tag table starts at byte 128, first 4 bytes = tag count
    # First tag entry: bytes 132-143 (sig 4B + offset 4B + size 4B)
    first_tag_offset = struct.unpack_from(">I", profile, 136)[0]
    # Set reserved bytes (offset+4 through offset+7) to non-zero
    profile[first_tag_offset + 4] = 0xFF
    profile[first_tag_offset + 5] = 0xFF
    profile[first_tag_offset + 6] = 0xFF
    profile[first_tag_offset + 7] = 0xFF
    return bytes(profile)


def synth_cf_mluc_bad_record_size():
    """CF-030: mluc tag with duplicate language/country pairs (§10.13).
    Note: record_size != 12 can't be tested because iccDEV's Read() rejects it
    before deep conformance checks run. Duplicate lang/country is the CF-030
    failure mode that passes library Read() but triggers CF-030's raw check."""
    # Build an mluc tag with 2 records both using 'enUS' — duplicate pair
    text1 = "First".encode("utf-16-be")
    text2 = "Second".encode("utf-16-be")
    header_size = 16  # type(4) + reserved(4) + count(4) + recSize(4)
    records_size = 2 * 12  # 2 records × 12 bytes
    str1_offset = header_size + records_size  # relative to tag start
    str2_offset = str1_offset + len(text1)

    dup_mluc = b"mluc" + b"\x00" * 4
    dup_mluc += struct.pack(">II", 2, 12)  # 2 records, record_size=12
    # Record 1: enUS
    dup_mluc += b"enUS"
    dup_mluc += struct.pack(">II", len(text1), str1_offset)
    # Record 2: enUS again — DUPLICATE
    dup_mluc += b"enUS"
    dup_mluc += struct.pack(">II", len(text2), str2_offset)
    dup_mluc += text1
    dup_mluc += text2
    while len(dup_mluc) % 4:
        dup_mluc += b"\x00"

    tags = [
        (b"desc", make_mluc_tag("mluc Duplicate Lang")),  # valid desc
        (b"cprt", dup_mluc),  # cprt with duplicate lang/country
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags)


def synth_cf_mluc_zero_name_placeholder():
    """CF-223: zero-record mluc encoded as a non-minimal 16-byte placeholder.

    ICC TN PSD recommends a 12-byte encoding for zero-name placeholders, but
    SampleICC's mluc reader still expects the legacy 16-byte form. This keeps
    the profile readable while exercising the conformance warning path.
    """
    zero_record_mluc = b"mluc" + b"\x00" * 4 + struct.pack(">II", 0, 12)

    tags = [
        (b"desc", make_mluc_tag("mluc Zero-Name Placeholder")),
        (b"cprt", zero_record_mluc),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags)


def synth_cf_sf32_bad_size():
    """CF-031: sf32 tag where (tagSize-8) is not divisible by 4.
    Uses 'chad' tag signature (chromaticAdaptationTag) which uses sf32 type."""
    # sf32 type: 4B sig + 4B reserved + N×4B s15Fixed16 values
    # Make data size 14 bytes total → 14-8=6, 6%4=2 ≠ 0 (invalid)
    bad_sf32 = b"sf32" + b"\x00" * 4 + b"\x00" * 6  # 14 bytes, 6 data bytes
    tags = [
        (b"desc", make_mluc_tag("sf32 Bad Size Test")),
        (b"cprt", make_mluc_tag("Copyright Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
        (b"chad", bad_sf32),  # chromaticAdaptationTag with bad sf32 size
    ]
    return build_profile(tags)


def _make_mpet_tag(n_in=3, n_out=3):
    """Create a minimal valid multiProcessElementsType ('mpet') tag.

    Structure: type(4) + reserved(4) + nInput(2) + nOutput(2) + nElements(4)
    With nElements=0, this is a valid identity MPE (no processing elements).
    """
    data = b"mpet" + b"\x00" * 4
    data += struct.pack(">HH", n_in, n_out)
    data += struct.pack(">I", 0)  # nElements = 0 (identity)
    return data


def synth_cf_htos_flag_and_tags():
    """v5 profile with Extended Range PCS flag (bit 3) set AND H2S0 mpet tag.
    Tests CF-317 OK path (flag + tags consistent), CF-318 OK (type is mpet),
    CF-319 OK (3→3 channels match PCS), CF-320 partial (1 of 4 intents)."""
    desc = make_mluc_tag("HToS Test Profile")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)
    htos0 = _make_mpet_tag(3, 3)  # H2S0: 3 input → 3 output (matches XYZ PCS)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"H2S0", htos0),  # icSigHToS0Tag
    ]
    return build_profile(tags, version=0x05000000, flags=0x00000008)


def synth_cf_htos_flag_only():
    """v5 profile with Extended Range PCS flag (bit 3) set but NO HToS tags.
    Tests CF-317 WARN path (flag set, no tags)."""
    desc = make_mluc_tag("HToS Flag Only")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
    ]
    return build_profile(tags, version=0x05000000, flags=0x00000008)


def synth_cf_htos_tags_no_flag():
    """v5 profile with HToS tags present but Extended Range PCS flag NOT set.
    Tests CF-317 WARN path (orphan tags, flag not set)."""
    desc = make_mluc_tag("HToS Tags No Flag")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)
    htos0 = _make_mpet_tag(3, 3)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"H2S0", htos0),
    ]
    return build_profile(tags, version=0x05000000, flags=0)


def synth_cf_htos_bad_type():
    """v5 profile with HToS tag that has wrong type (not 'mpet').
    Tests CF-318 WARN path (type mismatch)."""
    desc = make_mluc_tag("HToS Bad Type")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)
    # Use a curveType tag instead of mpet — wrong type for HToS
    bad_htos = make_curve_tag(gamma=2.2)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"H2S0", bad_htos),
    ]
    return build_profile(tags, version=0x05000000, flags=0x00000008)


def synth_cf_htos_channel_mismatch():
    """v5 profile with HToS mpet tag that has wrong channel count (4→4 vs PCS=3).
    Tests CF-319 WARN path (channel count mismatch)."""
    desc = make_mluc_tag("HToS Channel Mismatch")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)
    htos0 = _make_mpet_tag(4, 4)  # 4→4 but PCS is XYZ (3 channels)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"H2S0", htos0),
    ]
    return build_profile(tags, version=0x05000000, flags=0x00000008)


def synth_cf_htos_all_intents():
    """v5 profile with all 4 HToS tags (H2S0-H2S3) and Extended Range PCS flag.
    Tests CF-320 OK path (all 4 intents covered)."""
    desc = make_mluc_tag("HToS All Intents")
    cprt = make_mluc_tag("Copyright test")
    wtpt = make_xyz_tag(0.9642, 1.0000, 0.8249)
    htos0 = _make_mpet_tag(3, 3)
    htos1 = _make_mpet_tag(3, 3)
    htos2 = _make_mpet_tag(3, 3)
    htos3 = _make_mpet_tag(3, 3)

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"H2S0", htos0),
        (b"H2S1", htos1),
        (b"H2S2", htos2),
        (b"H2S3", htos3),
    ]
    return build_profile(tags, version=0x05000000, flags=0x00000008)


def synth_h174_half_float_header():
    """v5 profile with spectral header half-float < 1.0.

    Triggers H174 on raw scan and exercises analyzer-owned safe half-float
    conversion when library hardening is explicitly overridden.
    """
    tags = [
        (b"desc", make_mluc_tag("H174 Header Half-Float UB")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        spectral_pcs=b"rs16",
        spectral_range=(0x3800, 0x3C00, 31),  # 0.5 .. 1.0
    )


def synth_h174_half_float_mdv_fl16():
    """v5 profile with mdv tag encoded as float16ArrayType containing 0.5.

    Targets the parse-time ReadFloat16Float()->icF16toF path in upstream
    iccDEV. Default analyzer execution should fingerprint H174 and skip the
    unsafe library phase before CIccProfile::Read() touches the payload.
    """
    tags = [
        (b"desc", make_mluc_tag("H174 mdv/fl16 Half-Float UB")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"mdv ", make_float16_array_tag([0x3800, 0x3C00])),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        spectral_pcs=b"rs16",
        spectral_range=(0x3C00, 0x4400, 31),
    )


# ---------------------------------------------------------------------------
# H175-H178: ICC.2:2023 Extended Device Colour Space Amendment
# ---------------------------------------------------------------------------

def _make_srng_tag(start_f16, end_f16, steps, bi_start=0, bi_end=0, bi_steps=0,
                   bad_reserved=False, bad_sig=False):
    """Build a spectralRangeType tag (20 bytes).

    Layout: 'srng'(4) + reserved(4) + spectralRange(6) + biSpectralRange(6)
    """
    sig = b"XXXX" if bad_sig else b"srng"
    reserved = b"\x01\x02\x03\x04" if bad_reserved else b"\x00\x00\x00\x00"
    return sig + reserved + struct.pack(">HHH", start_f16, end_f16, steps) + \
        struct.pack(">HHH", bi_start, bi_end, bi_steps)


def synth_h175_spectral_device_valid_dsrn():
    """Profile with spectral device colour space AND a valid dsrn tag.

    colorSpace = 'rs16' (reflectance spectral, 16 channels)
    dsrn tag present with valid srng data (380-780nm, 81 steps)
    Should pass H175 — spectral device with range source present.
    """
    # 380nm = 0x5DF0, 780nm = 0x6218 in half-float
    dsrn_data = _make_srng_tag(0x5DF0, 0x6218, 81)
    tags = [
        (b"desc", make_mluc_tag("H175 Spectral Device Valid dsrn")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h175_spectral_device_header_fallback():
    """Profile with spectral device colour space, NO dsrn, but header range set.

    colorSpace = 'ts10' (transmission spectral, 10 channels)
    No dsrn tag, but header spectralRange fields at offset 104-109 are non-zero.
    Should pass H175 — using header range as fallback.
    """
    tags = [
        (b"desc", make_mluc_tag("H175 Header Fallback")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"ts10",
        pcs=b"XYZ ",
        spectral_range=(0x5DF0, 0x6218, 81),  # 380-780nm, 81 steps
    )


def synth_h175_spectral_device_no_range():
    """Profile with spectral device colour space but NO range source.

    colorSpace = 'es08' (radiant spectral, 8 channels)
    No dsrn tag AND header spectralRange fields are all zeros.
    Should FAIL H175 — no spectral range source defined.
    """
    tags = [
        (b"desc", make_mluc_tag("H175 Missing Range")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"es08",
        pcs=b"XYZ ",
        # No spectral_range, no dsrn tag
    )


def synth_h176_dsrn_valid():
    """Profile with valid dsrn tag (spectralRangeType, 380-780nm, 81 steps).

    Should pass H176 — well-formed srng encoding.
    """
    dsrn_data = _make_srng_tag(0x5DF0, 0x6218, 81)
    tags = [
        (b"desc", make_mluc_tag("H176 Valid dsrn")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h176_dsrn_bad_reserved():
    """Profile with dsrn tag where reserved bytes are non-zero.

    Should trigger H176 warning for non-zero reserved bytes.
    """
    dsrn_data = _make_srng_tag(0x5DF0, 0x6218, 81, bad_reserved=True)
    tags = [
        (b"desc", make_mluc_tag("H176 Bad Reserved")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h176_dsrn_bad_sig():
    """Profile with dsrn tag where type signature is not 'srng'.

    Should trigger H176 critical for wrong type signature.
    """
    dsrn_data = _make_srng_tag(0x5DF0, 0x6218, 81, bad_sig=True)
    tags = [
        (b"desc", make_mluc_tag("H176 Wrong Sig")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h176_dsrn_inverted_range():
    """Profile with dsrn tag where start > end wavelength.

    start=780nm (0x6218), end=380nm (0x5DF0) — inverted.
    Should trigger H176 warning for inverted range.
    """
    dsrn_data = _make_srng_tag(0x6218, 0x5DF0, 81)  # start > end
    tags = [
        (b"desc", make_mluc_tag("H176 Inverted Range")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h177_dpcc_valid():
    """Profile with valid dpcc tag (tagStructType with 'pcc ' structure).

    Builds a minimal tagStructType: 'tstr'(4) + reserved(4) + 'pcc '(4) +
    tagCount(4) + sub-tag entries. Sub-tags: iXYZ, mwpt, swpt, svcn, c2sp, s2cp.
    """
    # tagStructType layout:
    #   0-3:  'tstr' type signature
    #   4-7:  reserved (0)
    #   8-11: 'pcc ' structure type ID
    #   12-15: sub-tag count (6)
    #   16+:  sub-tag entries (sig(4) + offset(4) + size(4) each)
    #   then sub-tag data
    sub_tags = [
        b"iXYZ", b"mwpt", b"swpt", b"svcn", b"c2sp", b"s2cp"
    ]
    # Minimal sub-tag data: 12-byte XYZ for each
    sub_data = struct.pack(">4sI", b"XYZ ", 0) + struct.pack(">iii",
        int(0.9642 * 65536), int(1.0 * 65536), int(0.8249 * 65536))
    sub_data_size = len(sub_data)  # 20 bytes

    # Build sub-tag table + data
    sub_table_size = len(sub_tags) * 12
    data_start = 16 + sub_table_size

    entries = b""
    datas = b""
    for i, sig in enumerate(sub_tags):
        offset = data_start + i * sub_data_size
        entries += struct.pack(">4sII", sig, offset, sub_data_size)
        datas += sub_data

    dpcc_tag = struct.pack(">4sI4sI", b"tstr", 0, b"pcc ", len(sub_tags))
    dpcc_tag += entries + datas

    tags = [
        (b"desc", make_mluc_tag("H177 Valid dpcc")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dpcc", dpcc_tag),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"abst",
        pcs=b"XYZ ",
    )


def synth_h177_dpcc_missing_subtags():
    """Profile with dpcc tag that is missing required sub-tags.

    Only includes iXYZ — missing mwpt, swpt, svcn, c2sp, s2cp.
    Should trigger H177 warnings for missing sub-tags.
    """
    sub_data = struct.pack(">4sI", b"XYZ ", 0) + struct.pack(">iii",
        int(0.9642 * 65536), int(1.0 * 65536), int(0.8249 * 65536))
    sub_data_size = len(sub_data)

    data_start = 16 + 12  # 1 sub-tag entry
    entries = struct.pack(">4sII", b"iXYZ", data_start, sub_data_size)

    dpcc_tag = struct.pack(">4sI4sI", b"tstr", 0, b"pcc ", 1)
    dpcc_tag += entries + sub_data

    tags = [
        (b"desc", make_mluc_tag("H177 Missing SubTags")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dpcc", dpcc_tag),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"abst",
        pcs=b"XYZ ",
    )


def synth_h178_srng_nan_wavelength():
    """Profile with dsrn tag where wavelength is NaN (0x7E00).

    start=NaN (0x7E00), end=780nm (0x6218), steps=81.
    Should trigger H178 critical for NaN wavelength.
    """
    dsrn_data = _make_srng_tag(0x7E00, 0x6218, 81)  # NaN start
    tags = [
        (b"desc", make_mluc_tag("H178 NaN Wavelength")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h178_srng_low_steps():
    """Profile with dsrn tag where steps < 2.

    380-780nm but steps=1 (must be >= 2).
    Should trigger H178 warning for insufficient steps.
    """
    dsrn_data = _make_srng_tag(0x5DF0, 0x6218, 1)  # steps=1
    tags = [
        (b"desc", make_mluc_tag("H178 Low Steps")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def synth_h178_srng_out_of_range():
    """Profile with dsrn tag where wavelength is outside 100-2500nm.

    start=50nm (0x5240), end=780nm (0x6218), steps=81.
    Should trigger H178 warning for out-of-range wavelength.
    """
    dsrn_data = _make_srng_tag(0x5240, 0x6218, 81)  # 50nm < 100nm
    tags = [
        (b"desc", make_mluc_tag("H178 Out of Range")),
        (b"cprt", make_mluc_tag("Copyright 2026 Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0, 0.8249)),
        (b"dsrn", dsrn_data),
    ]
    return build_profile(
        tags,
        version=0x05000000,
        device_class=b"spac",
        color_space=b"rs16",
        pcs=b"XYZ ",
    )


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)

    profiles = {
        "valid_srgb.icc": synth_valid_srgb(),
        "truncated.icc": synth_truncated(),
        "bad_magic.icc": synth_bad_magic(),
        "zero_tags.icc": synth_zero_tags(),
        "oversized_tag.icc": synth_oversized_tag(),
        "wrong_version_encoding.icc": synth_wrong_version_encoding(),
        "wrong_tag_type.icc": synth_wrong_tag_type(),
        "private_tags.icc": synth_private_tags(),
        "malware_private_tag.icc": synth_malware_private_tag(),
        "v5_tags_on_v4.icc": synth_v5_tags_on_v4(),
        "non_monotonic_curve.icc": synth_non_monotonic_curve(),
        "bad_wtpt.icc": synth_bad_wtpt(),
        "reserved_bytes_nonzero.icc": synth_reserved_bytes_nonzero(),
        "empty_file.icc": synth_empty_file(),
        "just_header.icc": synth_just_header(),
        "huge_tag_count.icc": synth_huge_tag_count(),
        "xyz_out_of_range.icc": synth_xyz_out_of_range(),
        # New heuristic-targeted profiles
        "null_colorspace.icc": synth_null_colorspace(),
        "invalid_pcs.icc": synth_invalid_pcs(),
        "unknown_platform.icc": synth_unknown_platform(),
        "invalid_rendering_intent.icc": synth_invalid_rendering_intent(),
        "unknown_device_class.icc": synth_unknown_device_class(),
        "negative_illuminant.icc": synth_negative_illuminant(),
        "invalid_date.icc": synth_invalid_date(),
        "version_bcd_invalid.icc": synth_version_bcd_invalid(),
        "wrong_d50_illuminant.icc": synth_wrong_d50_illuminant(),
        "flags_reserved_bits.icc": synth_flags_reserved_bits(),
        "duplicate_tags.icc": synth_duplicate_tags(),
        "tag_misaligned.icc": synth_tag_misaligned(),
        "extra_trailing_bytes.icc": synth_extra_trailing_bytes(),
        "null_tag_type.icc": synth_null_tag_type(),
        "nan_float_tag.icc": synth_nan_float_tag(),
        "odd_utf16_mluc.icc": synth_odd_utf16_mluc(),
        "suspicious_profile_id.icc": synth_suspicious_profile_id(),
        "tag_aliasing.icc": synth_tag_aliasing(),
        # CWE-400 systemic patterns (CFL-074/075/076 findings)
        "named_color2_excessive_coords.icc": synth_named_color2_excessive_coords(),
        "high_dimensional_colorspace.icc": synth_high_dimensional_colorspace(),
        "response_curve_excessive_measurements.icc": synth_response_curve_excessive_measurements(),
        # CWE-400 validation/runtime symmetry (CFL-077 through CFL-081)
        "named_color2_large_nsize.icc": synth_named_color2_large_nsize(),
        "xyz_large_array.icc": synth_xyz_large_array(),
        "calculator_deep_nesting.icc": synth_calculator_deep_nesting(),
        # H86 Unicode content detection (CWE-116)
        "mluc_bidi_override.icc": synth_mluc_bidi_override(),
        "mluc_mixed_scripts.icc": synth_mluc_mixed_scripts(),
        "mluc_control_chars.icc": synth_mluc_control_chars(),
        "mluc_embedded_nulls.icc": synth_mluc_embedded_nulls(),
        # H147 null/degenerate CLUT detection (CWE-476)
        "lut_null_clut.icc": synth_lut_null_clut(),
        "lut_degenerate_clut.icc": synth_lut_degenerate_clut(),
        # H151 float→int cast operator detection (CWE-681)
        "calc_trunc_operator.icc": synth_calc_trunc_operator(),
        # H73 shared tag pointer detection (CWE-416)
        "tag_shared_pointers.icc": synth_tag_shared_pointers(),
        # CF conformance check profiles
        "nop_sled_tag.icc": synth_nop_sled_tag(),
        "lut8_atob_btoa.icc": synth_lut8_atob_btoa(),
        "lut8_atob2_btoa2.icc": synth_lut8_atob2_btoa2(),
        "targ_tag_profile.icc": synth_targ_tag_profile(),
        "targ_quality_profile.icc": synth_targ_quality_profile(),
        "targ_cmyk_quality_profile.icc": synth_targ_cmyk_quality_profile(),
        "clean_mntr_profile.icc": synth_clean_mntr_profile(),
        # CF-103..CF-122 conformance test profiles
        "cf_misaligned_tag.icc": synth_misaligned_tag(),
        "cf_devicelink_no_atob.icc": synth_devicelink_no_atob(),
        "cf_non_monotonic_trc.icc": synth_non_monotonic_trc(),
        "cf_duplicate_tag_sigs.icc": synth_duplicate_tag_sigs(),
        "cf_xyz_negative_y.icc": synth_xyz_negative_y(),
        "cf_rig0_wrong_class.icc": synth_rig0_wrong_class(),
        "cf_implausible_date.icc": synth_implausible_date(),
        "cf_v4_wtpt_not_d50.icc": synth_v4_wtpt_not_d50(),
        # ADGC (Adaptive Gain Curve) test profiles
        "cf_adgc_valid_rgb_input.icc": synth_adgc_valid_rgb_input(),
        "cf_adgc_cmyk_violation.icc": synth_adgc_cmyk_violation(),
        "cf_adgc_bad_functype.icc": synth_adgc_bad_functype(),
        "cf_adgc_bad_reserved.icc": synth_adgc_bad_reserved(),
        "cf_adgc_nan_weights.icc": synth_adgc_nan_weights(),
        "cf_adgc_bad_weight_sum.icc": synth_adgc_bad_weight_sum(),
        "cf_adgc_non_monotonic.icc": synth_adgc_non_monotonic_curve(),
        "cf_adgc_bad_type_sig.icc": synth_adgc_bad_type_sig(),
        # ADGC formula-derived test profiles (CF-133..CF-136)
        "cf_adgc_h_equal.icc": synth_adgc_h_equal(),
        "cf_adgc_gain_inverted.icc": synth_adgc_gain_inverted(),
        "cf_adgc_bad_curve_range.icc": synth_adgc_bad_curve_range(),
        "cf_adgc_equal_x_curve.icc": synth_adgc_equal_x_curve(),
        "cf_adgc_bt2100_pq.icc": synth_adgc_bt2100_pq(),
        "cf_adgc_bt2100_hlg.icc": synth_adgc_bt2100_hlg(),
        "cf_adgc_single_point_curve.icc": synth_adgc_single_point_curve(),
        "cf_adgc_many_point_curve.icc": synth_adgc_many_point_curve(),
        # CF-011, CF-021, CF-030, CF-031 conformance test profiles
        "cf_md5_mismatch.icc": synth_cf_md5_mismatch(),
        "cf_reserved_bytes_nonzero_tag.icc": synth_cf_reserved_bytes_nonzero_tag(),
        "cf_mluc_bad_record_size.icc": synth_cf_mluc_bad_record_size(),
        "cf_mluc_zero_name_placeholder.icc": synth_cf_mluc_zero_name_placeholder(),
        "cf_sf32_bad_size.icc": synth_cf_sf32_bad_size(),
        "cf_embedded_clean.icc": synth_cf_embedded_clean(),
        "cf_embedded_wrong_type.icc": synth_cf_embedded_wrong_type(),
        "cf_embedded_child_flags_bad.icc": synth_cf_embedded_child_flags_bad(),
        "cf_embedded_child_class_mismatch.icc": synth_cf_embedded_child_class_mismatch(),
        "cf_embedded_child_pcs_mismatch.icc": synth_cf_embedded_child_pcs_mismatch(),
        "cf_embedded_reserved_nonzero.icc": synth_cf_embedded_reserved_nonzero(),
        "cf_embedded_devicelink_flagged.icc": synth_cf_embedded_devicelink_flagged(),
        # CF-317..CF-320 HDR-to-SDR (K.2.9) test profiles
        "cf_htos_flag_and_tags.icc": synth_cf_htos_flag_and_tags(),
        "cf_htos_flag_only.icc": synth_cf_htos_flag_only(),
        "cf_htos_tags_no_flag.icc": synth_cf_htos_tags_no_flag(),
        "cf_htos_bad_type.icc": synth_cf_htos_bad_type(),
        "cf_htos_channel_mismatch.icc": synth_cf_htos_channel_mismatch(),
        "cf_htos_all_intents.icc": synth_cf_htos_all_intents(),
        "h174_half_float_header.icc": synth_h174_half_float_header(),
        "h174_half_float_mdv_fl16.icc": synth_h174_half_float_mdv_fl16(),
        # H175-H178: ICC.2:2023 Extended Device Colour Space Amendment
        "h175_spectral_device_valid_dsrn.icc": synth_h175_spectral_device_valid_dsrn(),
        "h175_spectral_device_header_fallback.icc": synth_h175_spectral_device_header_fallback(),
        "h175_spectral_device_no_range.icc": synth_h175_spectral_device_no_range(),
        "h176_dsrn_valid.icc": synth_h176_dsrn_valid(),
        "h176_dsrn_bad_reserved.icc": synth_h176_dsrn_bad_reserved(),
        "h176_dsrn_bad_sig.icc": synth_h176_dsrn_bad_sig(),
        "h176_dsrn_inverted_range.icc": synth_h176_dsrn_inverted_range(),
        "h177_dpcc_valid.icc": synth_h177_dpcc_valid(),
        "h177_dpcc_missing_subtags.icc": synth_h177_dpcc_missing_subtags(),
        "h178_srng_nan_wavelength.icc": synth_h178_srng_nan_wavelength(),
        "h178_srng_low_steps.icc": synth_h178_srng_low_steps(),
        "h178_srng_out_of_range.icc": synth_h178_srng_out_of_range(),
    }

    for name, data in profiles.items():
        path = os.path.join(CORPUS_DIR, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {name:40s} {len(data):6d} bytes")

    print(f"\n{len(profiles)} profiles written to {CORPUS_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
