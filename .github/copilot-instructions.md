# Copilot Instructions — fuzz/ Corpus Repository

## What This Repository Is

A curated corpus of 1,139 malicious input files (201 MB) for security testing.
Contains CVE proof-of-concept files, injection signatures, malformed media files,
and AFL-minimized crash samples. Originally "Commodity-Injection-Signatures"
by David Hoyt (xss.cx/srd.cx), maintained since 2015.

## Repository Structure

| Directory | Files | Description |
|-----------|------:|-------------|
| `graphics/icc/` | 95 | ICC CVE PoC profiles (primary research asset) |
| `graphics/jpg/` | 208 | Malformed JPEG files |
| `graphics/png/` | 200 | Malformed PNG files |
| `graphics/tif/` | 267 | Malformed TIFF files |
| `xml/icc/` | 42+74 | ICC XML crash PoCs + AFL-minimized corpus |
| `xml/xxe/` | 10+ | XXE entity injection |
| Web injection | 80+ | XSS, SQLi, SSI, LFI, SSRF signatures |

## CI Workflow

The `sanitizer-corpus-scan.yml` workflow:
1. Builds iccanalyzer-lite + colorbleed_tools from `xsscx/research` (ASAN+UBSAN)
2. Scans all ICC profiles with iccanalyzer-lite security analysis
3. Scans all ICC profiles with iccToXml_unsafe
4. Scans all ICC XML files with iccFromXml_unsafe
5. Performs round-trip validation (XML → ICC → XML)
6. Collects coverage data and sanitizer findings

## Relationship to xsscx/research

This corpus provides seed data for the CFL LibFuzzer harnesses in `xsscx/research/cfl/`.
The mapping is:
- `graphics/icc/*.icc` → `cfl/corpus-icc_{profile,toxml,dump,apply}_fuzzer/`
- `xml/icc/*.xml` → `cfl/corpus-icc_fromxml_fuzzer/`
- `graphics/tif/*.tif` → `cfl/corpus-icc_tiff_fuzzer/`

## File Naming Convention

ICC PoCs: `{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc`
CVE PoCs: `cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc`

Crash types: `hbo` (heap overflow), `sbo` (stack overflow), `segv` (SIGSEGV),
`oom` (out-of-memory), `ub` (undefined behavior), `npd` (null deref)

## Security Warning

All files in this repository are **intentionally malicious**.
Do NOT open in normal applications — use sanitizer-instrumented tools only.
