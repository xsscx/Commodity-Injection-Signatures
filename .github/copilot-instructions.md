# Copilot Instructions — fuzz/ Corpus Repository

## What This Repository Is

A curated corpus of 1,139 malicious input files (201 MB) organized into 34 categories
for security testing. Contains CVE proof-of-concept files, injection signatures,
malformed media files, and AFL-minimized crash samples. Originally created as
"Commodity-Injection-Signatures" by David Hoyt (xss.cx/srd.cx), maintained since 2015.

## Quick Reference

### Primary Research Assets
- `graphics/icc/` — **95 ICC CVE PoC profiles** (most valuable for ICC security research)
- `xml/icc/` — 42 ICC XML crash PoCs + 74 AFL-minimized crash samples
- `graphics/{jpg,png,tif}/` — 675 malformed image files for ImageIO/Skia fuzzing

### CI Workflow
The `sanitizer-corpus-scan.yml` workflow (3 jobs):
1. **build-tools** — Builds iccanalyzer-lite + IccToXml/IccFromXml from `xsscx/research` with ASAN+UBSAN
2. **scan-icc-profiles** — Runs all 95 ICC profiles through iccanalyzer-lite + IccToXml
3. **scan-icc-xml** — Runs all 116 XML files through IccFromXml + round-trip validation

Triggers: push to `graphics/icc/` or `xml/icc/`, `workflow_dispatch`

## Repository Structure

```
fuzz/
├── .github/
│   ├── workflows/sanitizer-corpus-scan.yml  # CI: ASAN+UBSAN scan
│   ├── copilot-instructions.md              # This file
│   ├── instructions/                        # Path-specific instructions
│   │   ├── icc-profiles.instructions.md     # ICC binary profile handling
│   │   ├── icc-xml.instructions.md          # ICC XML corpus handling
│   │   └── web-injection.instructions.md    # Web injection signature handling
│   └── prompts/                             # Reusable AI prompt templates
│       ├── analyze-corpus-coverage.prompt.md # Coverage gap analysis
│       ├── triage-new-poc.prompt.md          # New PoC triage workflow
│       └── seed-optimization.prompt.md       # Seed selection optimization
├── graphics/                                # 832 files, 124 MB
│   ├── icc/  (95 files)                     # ICC CVE PoCs + crash samples
│   ├── jpg/  (208 files)                    # Malformed JPEGs
│   ├── png/  (200 files)                    # Malformed PNGs
│   ├── tif/  (267 files)                    # Malformed TIFFs
│   ├── gif/  (35 files)                     # Malformed GIFs
│   ├── bmp/  (10 files)                     # Malformed BMPs
│   ├── heic/ (9 files)                      # Malformed HEICs
│   ├── exr/  (4 files)                      # Malformed OpenEXRs
│   ├── eps/  (1 file)                       # Malformed EPS
│   └── svg/  (1 file)                       # Malformed SVG
├── xml/                                     # 173 files, 36 MB
│   ├── icc/  (42+74 files)                  # ICC XML PoCs + AFL-minimized
│   ├── xxe/                                 # XXE entity injection
│   ├── morgan-poc/                          # Morgan XXE variants
│   ├── yunusov-poc/                          # Yunusov XML attacks
│   ├── ssrf/                                # SSRF via XML
│   └── dos/                                 # XML billion laughs
├── angular/, javascript/, sqlinjection/     # Web injection signatures
├── css/, ssi/, uri/, svg/                   # More injection categories
├── lfi-local-file-system-harvesting/        # Path traversal payloads
├── httpheader/, email/, json/, soap/        # Protocol injection
├── unix/, python/, java/, applescript/      # Command injection
├── random/, ascii/, calc/                   # Fuzzing tokens
└── full-unicode.txt                         # 5.3 MB Unicode table
```

## ICC Profile CVE Inventory

| CVE | Count | CWE | Affected Software | Files |
|-----|------:|-----|-------------------|-------|
| CVE-2022-26730 | 11 | CWE-787 (OOB Write) | Apple ColorSync | `cve-2022-26730-*.icc` |
| CVE-2023-32443 | 2 | CWE-125 (OOB Read) | Apple ColorSync | `cve-2023-32443*.icc` |
| CVE-2023-46602 | 1 | CWE-122 (Heap BOF) | DemoIccMAX | `cve-2023-46602.icc` |
| CVE-2023-46867 | 1 | CWE-126 (Buffer Over-read) | ArgyllCMS | `Argyll_V302_*.icc` |
| CVE-2024-38427 | 1 | CWE-122 (Heap BOF) | DemoIccMAX | `cve-2024-38427.icc` |

## ICC Profile Crash Type Taxonomy

| Prefix | CWE | Description | Count |
|--------|-----|-------------|------:|
| `hbo-` | CWE-122 | Heap-based buffer overflow | 5 |
| `sbo-` | CWE-121 | Stack-based buffer overflow | 4 |
| `segv-` | CWE-476 | NULL pointer dereference / SIGSEGV | 3 |
| `npd-` | CWE-476 | NULL pointer dereference | 3 |
| `oom-` | CWE-789 | Memory allocation with excessive size | 5 |
| `ub-` | CWE-190/191 | Undefined behavior (int overflow, type confusion) | 10 |
| `so-` | CWE-674 | Uncontrolled recursion / stack exhaustion | 3 |
| `cve-` | Various | CVE proof-of-concept | 16 |

## File Naming Conventions

### ICC Profile PoCs
```
{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
```
- **crash_type**: `hbo`, `sbo`, `segv`, `oom`, `ub`, `npd`, `so`
- **Class**: C++ class (e.g., `CIccCLUT`, `CIccMpeCalculator`)
- **Method**: Crashing method (e.g., `Interp3d`, `ApplySequence`)
- **File**: Source file without path (e.g., `IccTagLut`)
- **Line**: Source line number

### CVE PoCs
```
cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc
```

### AFL-Minimized (xml/icc/minimized/)
```
id_{NNNNNN}_sig_{NN}_src_{NNNNNN}_time_{N}_execs_{N}_op_{type}_pos_{N}
```

## Integration with xsscx/research

This corpus is the **seed data source** for the CFL LibFuzzer harnesses in `xsscx/research/cfl/`.

### Seed Pipeline
```
fuzz/graphics/icc/*.icc  →  cfl/corpus-icc_{profile,toxml,dump,apply}_fuzzer/
fuzz/xml/icc/*.xml       →  cfl/corpus-icc_fromxml_fuzzer/
fuzz/graphics/tif/*.tif  →  cfl/corpus-icc_tiff_fuzzer/
```

### Fuzzer-to-Corpus Mapping
| fuzz/ Path | CFL Fuzzer(s) | Notes |
|-----------|---------------|-------|
| `graphics/icc/*.icc` | profile, toxml, dump, deep_dump, io, apply, calculator | Primary binary seeds |
| `xml/icc/*.xml` | fromxml | XML → ICC parsing |
| `xml/icc/minimized/*` | fromxml | AFL-minimized XML crashes |
| `graphics/tif/*.tif` | tiff | TIFF tag reading |
| `graphics/jpg/*.jpg` | xnuimagefuzzer (xnuimagetools) | JPEG UTI fuzzing |
| `graphics/png/*.png` | xnuimagefuzzer (xnuimagetools) | PNG UTI fuzzing |

### Cross-Repo Relationship
| Direction | What Flows |
|-----------|-----------|
| fuzz/ → research/cfl/ | Seed corpus files for LibFuzzer |
| research/cfl/ → research/ root | New crash-*, oom-*, timeout-* files |
| research/ root → fuzz/ | Curated crashes promoted to PoC corpus |

## Analysis Tools (from xsscx/research)

### iccanalyzer-lite
135-heuristic security analyzer with ASAN+UBSAN. Run against ICC profiles:
```bash
iccanalyzer-lite -a <profile.icc>     # Full analysis (all heuristics)
iccanalyzer-lite -nf <profile.icc>    # Narrative format
iccanalyzer-lite -r <profile.icc>     # Round-trip validation
```

### colorbleed_tools
ICC ↔ XML conversion (deliberately unsafe — no sanitizer hardening):
```bash
IccToXml_unsafe input.icc output.xml   # ICC → XML
IccFromXml_unsafe input.xml output.icc # XML → ICC
```

## Security Warning

⚠️ **All files in this repository are intentionally malicious.**

- Do NOT open in normal applications
- Use sanitizer-instrumented tools only (ASAN, UBSAN, MSan)
- ICC profiles may trigger crashes in ColorSync, Skia, WebKit, Windows ICM
- XML files may trigger XXE, SSRF, or DoS in vulnerable parsers
- Image files may trigger buffer overflows in image decoders

## Adding New PoCs

1. Name using the conventions above
2. Place in the appropriate category directory
3. For ICC profiles: also seed into `xsscx/research/cfl/corpus-*` directories
4. Update `README.md` if adding a new CVE category
5. Commit: `fuzz: add {crash_type} PoC for {component}`

## Environment Detection

This repo is consumed in two contexts:

### Standalone (this repo)
- CI workflow builds tools from `xsscx/research` automatically
- Push to `graphics/icc/` or `xml/icc/` triggers sanitizer scan

### As subpath in xsscx/research
- Gitignored in research repo (ephemeral, synced from ramdisk)
- Seeds propagated via `ramdisk-seed.sh`
- Research repo has its own copy of the workflow: `fuzz-sanitizer-corpus-scan.yml`
