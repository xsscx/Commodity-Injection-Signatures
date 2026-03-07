# Fuzz Corpus — Commodity Injection Signatures & CVE PoCs

Curated corpus of 1,139 malicious input files (201 MB) for security testing.
Originally created as "Commodity-Injection-Signatures" by David Hoyt
([hoyt.net](https://hoyt.net), [srd.cx](https://srd.cx), [xss.cx](https://xss.cx)),
maintained since 2015.

## Contents

| Category | Files | Size | Description |
|----------|------:|-----:|-------------|
| `graphics/icc/` | 95 | 6 MB | ICC CVE PoCs (CVE-2022-26730, CVE-2023-46602, CVE-2024-38427) |
| `graphics/jpg/` | 208 | 42 MB | Malformed JPEG files |
| `graphics/png/` | 200 | 34 MB | Malformed PNG files |
| `graphics/tif/` | 267 | 45 MB | Malformed TIFF files |
| `graphics/gif/` | 35 | — | Malformed GIF files |
| `graphics/heic/` | 9 | — | Malformed HEIC files |
| `graphics/bmp/` | 10 | — | Malformed BMP files |
| `graphics/exr/` | 4 | — | Malformed OpenEXR files |
| `xml/icc/` | 42 | — | ICC XML crash PoCs |
| `xml/icc/minimized/` | 74 | — | AFL-minimized ICC XML crashes |
| `xml/xxe/` | 10+ | — | XXE entity injection PoCs |
| Web injection | 80+ | — | XSS, SQLi, SSI, LFI, SSRF, XSLT signatures |

## ICC Profile CVE Coverage

| CVE | Files | CWE | Affected Software |
|-----|------:|-----|-------------------|
| CVE-2022-26730 | 11 | CWE-787 | Apple ColorSync |
| CVE-2023-32443 | 2 | CWE-125 | Apple ColorSync |
| CVE-2023-46602 | 1 | CWE-122 | DemoIccMAX |
| CVE-2023-46867 | 1 | CWE-126 | ArgyllCMS |
| CVE-2024-38427 | 1 | CWE-122 | DemoIccMAX |

References:
- https://srd.cx/cve-2022-26730/
- https://srd.cx/cve-2023-32443/
- [DemoIccMAX](https://github.com/InternationalColorConsortium/DemoIccMAX)

## Integration with CFL Fuzzers

ICC profiles seed the [CFL LibFuzzer harnesses](../cfl/):

```bash
# Seed binary ICC fuzzers
cp fuzz/graphics/icc/*.icc cfl/corpus-icc_profile_fuzzer/

# Seed XML fuzzer
cp fuzz/xml/icc/*.xml cfl/corpus-icc_fromxml_fuzzer/
cp fuzz/xml/icc/minimized/* cfl/corpus-icc_fromxml_fuzzer/
```

See [CFL instructions](../.github/instructions/cfl.instructions.md) for full fuzzing workflow.

## Suggested Use

- **CFL fuzzer seeding** — Primary ICC PoC source for LibFuzzer harnesses
- **iccanalyzer-lite testing** — Security heuristic validation against known-bad profiles
- **Burp Intruder payloads** — Web injection signature files
- **Manual injection testing** — Well-known XSS/SQLi/XXE signatures
- **Image decoder fuzzing** — Malformed graphics files for ImageIO/Skia/WebKit
- **XNU/Windows/Linux testing** — Platform-specific crash vectors

## File Naming Convention

ICC PoCs: `{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc`
- Crash types: `hbo` (heap overflow), `sbo` (stack overflow), `segv` (SIGSEGV),
  `oom` (out-of-memory), `ub` (undefined behavior), `npd` (null deref)

CVE PoCs: `cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc`

## Recent Additions

- CFL-discovered crash samples (repo root `crash-*`, `oom-*`, `slow-unit-*`)
- CVE-2024-38427 ICC Color Profile PoCs
- AFL-minimized ICC XML crash corpus (74 samples)
- XNU Crash Helpers for Apple Security Research Device

## Contributing

Setup a PR. All malicious input accepted.

__Happy Hunting!!__
