# Triage New PoC File

## Purpose
When a new crash file is discovered (from CFL fuzzing, manual testing, or external
report), triage it and integrate into this corpus.

## When to Use
- After a CFL fuzzer discovers a new crash (`crash-*` file in research repo root)
- When receiving an externally reported ICC crash file
- When promoting a `slow-unit-*` or `oom-*` to the PoC corpus

## Workflow

### Step 1 — Classify the crash
Run with ASAN-instrumented tools to identify the vulnerability:
```bash
# From xsscx/research
ASAN_OPTIONS=detect_leaks=0 iccanalyzer-lite/iccanalyzer-lite -a <crash_file>
```

Determine:
- **Crash type**: ASAN (heap-buffer-overflow, stack-buffer-overflow, use-after-free)
  or UBSAN (runtime error) or signal (SIGSEGV, SIGABRT)
- **CWE classification**: Map to CWE-122, CWE-121, CWE-476, CWE-789, etc.
- **Crash location**: Class::Method at File.cpp:LineN
- **Affected component**: Which iccDEV library function

### Step 2 — Check for duplicates
```bash
# Compare crash stack trace against existing PoCs
for existing in graphics/icc/*.icc; do
  ASAN_OPTIONS=detect_leaks=0 iccanalyzer-lite/iccanalyzer-lite -a "$existing" 2>&1 \
    | grep -E 'ERROR:|runtime error:' | head -1
done | sort -u
```

### Step 3 — Name the file
Use the naming convention:
```
{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
```

Abbreviations:
| Crash Type | Prefix |
|-----------|--------|
| Heap buffer overflow | `hbo` |
| Stack buffer overflow | `sbo` |
| SIGSEGV / NULL deref | `segv` or `npd` |
| Out of memory | `oom` |
| Undefined behavior | `ub` |
| Stack overflow | `so` |

### Step 4 — Place and seed
```bash
# Add to corpus
cp <crash_file> graphics/icc/<new_name>.icc

# Seed CFL fuzzers
cp graphics/icc/<new_name>.icc ../cfl/corpus-icc_profile_fuzzer/
cp graphics/icc/<new_name>.icc ../cfl/corpus-icc_toxml_fuzzer/
```

### Step 5 — For multi-profile crash files
If the crash came from a multi-profile fuzzer (link, v5dspobs, applyprofiles),
extract individual profiles first:
```bash
# From xsscx/research
.github/scripts/unbundle-fuzzer-input.sh <fuzzer_type> <crash_file>
# Output: ./tmp/icc_<fuzzer>/ with individual profiles
```

### Step 6 — Verify with upstream tools
```bash
# Check if upstream tool also crashes (confirms it's a valid upstream bug)
iccDEV/Build/Tools/IccToXml/IccToXml <new_name>.icc /tmp/test.xml
```

### Step 7 — Commit
```bash
git add graphics/icc/<new_name>.icc
git commit -m "fuzz: add {crash_type} PoC for {Class}::{Method}

CWE-{N}: {description}
Crash site: {File}.cpp:{Line}
Found by: {fuzzer_name} / {tool}"
```

## Output
- Named PoC file in `graphics/icc/`
- CWE classification
- Whether upstream tool also crashes (valid upstream bug vs. fuzzer-only)
- CFL patch recommendation if applicable
