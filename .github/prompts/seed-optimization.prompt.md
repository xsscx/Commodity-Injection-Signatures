# Seed Optimization for CFL Fuzzers

## Purpose
Select the optimal subset of fuzz/ corpus files to seed a specific CFL fuzzer
for maximum code coverage with minimum corpus size.

## When to Use
- Setting up a new fuzzing campaign
- Fuzzer coverage has plateaued
- After adding new PoC files to the corpus
- When optimizing ramdisk storage usage

## Workflow

### Step 1 — Identify target fuzzer
Which CFL fuzzer are you optimizing seeds for?

| Fuzzer | Input Format | Best Seeds |
|--------|-------------|-----------|
| icc_profile_fuzzer | Raw ICC bytes | All `graphics/icc/*.icc` |
| icc_toxml_fuzzer | Raw ICC bytes | Same as profile_fuzzer |
| icc_fromxml_fuzzer | ICC XML text | `xml/icc/*.xml` + `minimized/*` |
| icc_dump_fuzzer | Raw ICC bytes | Diverse tag types |
| icc_deep_dump_fuzzer | Raw ICC bytes | Complex profiles (large tag count) |
| icc_io_fuzzer | Raw ICC bytes | Small files (fast I/O) |
| icc_apply_fuzzer | Raw ICC bytes | Profiles with AToB/BToA tags |
| icc_calculator_fuzzer | Raw ICC bytes | MPE/calculator profiles only |
| icc_link_fuzzer | Concatenated pair | Need display+output pairs |
| icc_v5dspobs_fuzzer | `[4B size][dsp][obs]` | v5 display + observer profiles |
| icc_tiff_fuzzer | TIFF file | `graphics/tif/*.tif` |
| icc_spectral_fuzzer | Raw ICC bytes | Spectral PCS profiles |

### Step 2 — Measure baseline coverage
```bash
# Short run with current seeds
FUZZER=icc_profile_fuzzer
LLVM_PROFILE_FILE=/tmp/profraw/${FUZZER}_%m_%p.profraw \
  cfl/bin/${FUZZER} -max_total_time=120 cfl/corpus-${FUZZER}/

llvm-profdata-18 merge -sparse /tmp/profraw/*.profraw -o /tmp/merged.profdata
llvm-cov-18 report cfl/bin/${FUZZER} -instr-profile=/tmp/merged.profdata
```

### Step 3 — Identify high-value seeds
Run each seed file individually and measure incremental coverage:
```bash
for seed in graphics/icc/*.icc; do
  LLVM_PROFILE_FILE=/tmp/prof_$(basename $seed).profraw \
    cfl/bin/${FUZZER} -runs=0 "$seed" 2>/dev/null
done
# Merge all and compare
```

### Step 4 — Prioritize by crash type
Priority order for seed selection:
1. **CVE PoCs** — Known exploitation paths, highest priority
2. **Heap/stack overflow** (`hbo-`, `sbo-`) — Active memory corruption
3. **Type confusion** (`ub-runtime-error-type-confusion-*`) — Complex control flow
4. **NULL deref** (`segv-`, `npd-`) — Error handling paths
5. **OOM** (`oom-`) — Resource exhaustion paths
6. **Known-good profiles** — Baseline valid parsing paths
7. **Infinite recursion** (`so-`) — Stack depth exercising

### Step 5 — Create synthetic seeds for gaps
For uncovered code paths, create minimal profiles:
```bash
# Use the synthesizer from xsscx/research
python3 iccanalyzer-lite/tests/synthesize_profiles.py

# Or create manually with specific tag combinations:
# - Rare tags: gamt, bfd, ncl2, psvm
# - Specific PCS: XYZ vs Lab
# - Profile classes: scnr, prtr, link, spac, abst, nmcl
# - Versions: v2.x, v4.x, v5.x
```

### Step 6 — Minimize corpus
After extended fuzzing, minimize the corpus:
```bash
# LibFuzzer merge (deduplication)
cfl/bin/${FUZZER} -merge=1 /tmp/minimized_corpus/ cfl/corpus-${FUZZER}/
# Replace seed corpus
rm -rf cfl/corpus-${FUZZER}/*
cp /tmp/minimized_corpus/* cfl/corpus-${FUZZER}/
```

## Multi-Profile Fuzzer Seeding

For fuzzers that take concatenated input, create seed pairs:
```bash
# v5dspobs: [4B BE display_size][display.icc][observer.icc]
python3 -c "
import struct
with open('display.icc','rb') as f: d = f.read()
with open('observer.icc','rb') as f: o = f.read()
with open('seed.bin','wb') as f:
    f.write(struct.pack('>I', len(d)))
    f.write(d)
    f.write(o)
"

# link: [50% profile1][50% profile2][4B control]
python3 -c "
with open('display.icc','rb') as f: p1 = f.read()
with open('output.icc','rb') as f: p2 = f.read()
with open('seed.bin','wb') as f:
    f.write(p1)
    f.write(p2)
    f.write(b'\\x00\\x00\\x00\\x00')
"
```

## Output
- Recommended seed file list per fuzzer
- Coverage delta (before/after optimization)
- List of synthetic seeds to create
