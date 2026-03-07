# ICC Binary Profiles — Path-Specific Instructions

## Applies To
`graphics/icc/**`

## What These Are

95 binary ICC color profiles that trigger crashes, memory corruption, or undefined
behavior in ICC profile parsers. Each file is a proof-of-concept for a specific
vulnerability class.

## Handling Rules

1. **Never open in normal applications** — these crash ColorSync, Skia, WebKit, ICM
2. **Always use sanitizer-instrumented tools** for analysis:
   ```bash
   # From xsscx/research
   iccanalyzer-lite/iccanalyzer-lite -a <profile.icc>
   colorbleed_tools/IccToXml_unsafe <profile.icc> /tmp/out.xml
   ```
3. **Classify by filename prefix** — the prefix encodes the vulnerability type:
   - `hbo-` → Heap buffer overflow (CWE-122)
   - `sbo-` → Stack buffer overflow (CWE-121)
   - `segv-` / `npd-` → NULL pointer deref (CWE-476)
   - `oom-` → Excessive allocation (CWE-789)
   - `ub-` → Undefined behavior (CWE-190/191)
   - `so-` → Stack exhaustion (CWE-674)
   - `cve-` → Known CVE proof-of-concept

## Adding New ICC PoCs

### Naming Convention
```
{crash_type}-{Class}-{Method}-{SourceFile}_cpp-Line{N}.icc
```
Example: `hbo-CIccCLUT-Interp3d-IccTagLut_cpp-Line2741.icc`

### For CVE PoCs
```
cve-{YYYY}-{NNNNN}-{short-description}-variant-{NNN}.icc
```

### Checklist
- [ ] File triggers the described crash with ASAN-instrumented tools
- [ ] Filename follows the naming convention
- [ ] Copy to relevant `xsscx/research/cfl/corpus-*` directories for fuzzing
- [ ] Update `README.md` if this is a new CVE

## CFL Fuzzer Seeding

These files seed 7+ CFL LibFuzzer harnesses in `xsscx/research/cfl/`:
```bash
cp graphics/icc/*.icc ../cfl/corpus-icc_profile_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_toxml_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_dump_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_deep_dump_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_io_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_apply_fuzzer/
cp graphics/icc/*.icc ../cfl/corpus-icc_calculator_fuzzer/
```

## Key Profiles by Category

### CVE PoCs (16 files)
- `cve-2022-26730-*` — 11 variants, Apple ColorSync OOB write
- `cve-2023-32443*` — 2 files, Apple ColorSync OOB read
- `cve-2023-46602.icc` — DemoIccMAX heap buffer overflow
- `cve-2024-38427.icc` — DemoIccMAX heap buffer overflow

### High-Value Crash Samples
- `oom-120Gb-CIccTagDict-Read-*` — 120GB allocation request (504 bytes input)
- `xsscx-infinite-recursion-*` — Infinite recursion via CIccTagFloatNum destructor
- `DoubleFree_IccUtil.cpp-L121.icc` — Double-free in utility function
- `memcpy-param-overlap-*` — Overlapping memcpy parameters

### Known-Good Profiles
- `sample.icc` — Valid sRGB profile for baseline testing
- `Cat8Lab-D65_2degMeta.icc` — Valid v4 profile with metadata
