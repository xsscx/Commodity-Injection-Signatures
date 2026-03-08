# xnuimagefuzzer — Fuzzed Image Outputs

Fuzz-mutated images from the xnuimagefuzzer tool (`XNU Image Fuzzer`).
These are **fuzzed/mutated** images produced by applying 17 permutation strategies,
ICC profile injection, color space mismatch, and multi-format re-encoding.

## Source

- Tool: `xnuimagetools/XNU Image Fuzzer/`
- Build: `build-native.sh` (Mac Catalyst, ASAN+UBSAN+Coverage)
- Modes: default (all permutations), `--input-dir`, `--chain`, `--pipeline`

## Directory Structure

```
xnuimagefuzzer/
├── png/       # Fuzzed PNG outputs
├── jpg/       # Fuzzed JPEG outputs
├── tiff/      # Fuzzed TIFF outputs (may contain injected ICC profiles)
├── bmp/       # Fuzzed BMP outputs
├── gif/       # Fuzzed GIF outputs
├── heic/      # Fuzzed HEIC outputs
├── icc/       # ICC profiles extracted from fuzzed images
├── chained/   # Chained fuzzing outputs (multi-pass mutations)
├── pipeline/  # Pipeline fuzzing outputs (5 phases)
└── README.md
```

## Filename Convention

All filenames include a 6-character hex hash suffix for uniqueness:

```
xif-{source}-perm{N}[-{variant}].{ext}.{hash6}
```

Components:
- **xif**: prefix identifying xnuimagefuzzer origin
- **source**: input image basename or context type
- **perm{N}**: permutation number (1-17)
- **variant**: optional variant (`icc_{name}`, `no_icc`, `mismatch`, `mutated`)
- **hash6**: first 6 hex chars of SHA-256 of file content

For chained outputs:
```
xif-chain-{source}-pass{N}.{ext}.{hash6}
```

For pipeline outputs:
```
xif-pipe-{phase}-{source}[-perm{N}][-icc_{name}].{ext}.{hash6}
```
Phases: `clean`, `format`, `fuzzed`, `icc-clean`, `combo`, `chained`

## Permutation Types

| Perm | Mutation |
|------|----------|
| 1 | Pixel scramble |
| 2 | Color shift |
| 3 | Bit manipulation |
| 4 | Channel swap |
| 5 | Noise injection |
| 6 | Boundary values |
| 8 | Format-specific |
| 9 | Alpha manipulation |
| 10 | Gradient corruption |
| 11 | Metadata mutation |
| 12 | Dimension edge cases |
| 13 | Color space abuse |
| 14 | Compression artifacts |
| 15 | Steganographic markers |
| 16 | ICC profile injection |
| 17 | Wide gamut / BT.2020 |

## Integration with CFL Fuzzers

```bash
# Seed fuzzed TIFFs with injected ICC profiles to CFL TIFF fuzzer
cp xnuimagefuzzer/tiff/*.tiff ../cfl/corpus-icc_tiff_fuzzer/

# Extract and seed ICC profiles from fuzzed outputs
cp xnuimagefuzzer/icc/*.icc ../cfl/corpus-icc_profile_fuzzer/
```
