# Analyze Corpus Coverage Gaps

## Purpose
Identify which CFL fuzzers lack adequate seed coverage from this corpus
and recommend new PoC files to create or acquire.

## When to Use
- Before starting a new fuzzing campaign
- When a CFL fuzzer shows stagnant coverage metrics
- After upstream iccDEV code changes add new code paths

## Workflow

### Step 1 — Inventory current seeds
```bash
echo "=== ICC Binary Profiles ==="
for type in hbo sbo segv oom ub npd so cve; do
  count=$(ls graphics/icc/ 2>/dev/null | grep -ci "^${type}" || echo 0)
  echo "  $type: $count files"
done
echo "Total ICC: $(ls graphics/icc/*.icc 2>/dev/null | wc -l)"
echo ""
echo "=== ICC XML ==="
echo "  Named: $(ls xml/icc/*.xml 2>/dev/null | wc -l)"
echo "  Minimized: $(ls xml/icc/minimized/ 2>/dev/null | wc -l)"
echo ""
echo "=== Image Formats ==="
for fmt in jpg png tif gif bmp heic exr; do
  count=$(ls graphics/$fmt/ 2>/dev/null | wc -l)
  echo "  $fmt: $count files"
done
```

### Step 2 — Map seeds to fuzzers
For each of the 19 CFL fuzzers, identify coverage:

| Fuzzer | Seed Source | Gap? |
|--------|-----------|------|
| icc_profile_fuzzer | graphics/icc/*.icc | Check v5 profiles |
| icc_fromxml_fuzzer | xml/icc/*.xml + minimized/ | Check MPE XML |
| icc_toxml_fuzzer | graphics/icc/*.icc | Same as profile |
| icc_calculator_fuzzer | *Calculator*.icc only | Needs MPE-heavy profiles |
| icc_link_fuzzer | Needs profile PAIRS | Check display+output combos |
| icc_v5dspobs_fuzzer | Needs v5 display+observer | Very few v5 in corpus |
| icc_tiff_fuzzer | graphics/tif/*.tif | Check ICC-embedded TIFFs |
| icc_spectral_fuzzer | Needs spectral PCS profiles | Almost none in corpus |

### Step 3 — Identify missing profile classes
Check which ICC profile classes have PoC coverage:
- `scnr` (Input) — present?
- `mntr` (Display) — present?
- `prtr` (Output) — present?
- `link` (DeviceLink) — present?
- `spac` (ColorSpace) — present?
- `abst` (Abstract) — present?
- `nmcl` (NamedColor) — present?

### Step 4 — Check version coverage
- v2.x profiles?
- v4.x profiles?
- v5.x profiles (spectral PCS)?

### Step 5 — Recommend new seeds
For each gap, recommend either:
1. **Synthesize** — Create minimal profiles with `iccanalyzer-lite/tests/synthesize_profiles.py`
2. **Acquire** — Download from ICC profile registries or vendor sites
3. **Mutate** — Use existing profiles as mutation base for specific tag types

## Output
Produce a markdown table of gaps with priority ratings (Critical/High/Medium/Low).
