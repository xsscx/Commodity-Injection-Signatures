# xnuimagegenerator — iOS Image Generator Outputs

Seed corpus from the iOS Image Generator app (`cx.srd.imagegenerator-xnu-demo`).
These are **clean, non-fuzzed** images generated across 13 CGContext types,
5 dimension variants, 6 formats, and 3 ICC color spaces.

## Source

- App: `xnuimagetools/XNU Image Generator for iOS/`
- Version: v1.8.1+
- Platform: iOS 17+ (iPhone/iPad simulator or device)

## Directory Structure

```
xnuimagegenerator/
├── png/      # PNG images (all contexts × dimensions × ICC variants)
├── jpg/      # JPEG images
├── tiff/     # TIFF images (with embedded ICC profiles)
├── bmp/      # BMP images (no ICC support)
├── gif/      # GIF images (no ICC support)
├── heic/     # HEIC images (ICC supported)
├── icc/      # Extracted ICC profiles from generated images
└── README.md
```

## Filename Convention

All filenames include a 6-character hex hash suffix for uniqueness:

```
xig-{context}-{WxH}[-icc_{profile}].{ext}.{hash6}
```

Components:
- **xig**: prefix identifying xnuimagegenerator origin
- **context**: CGContext type (e.g., `stdrgb`, `gray`, `1bit`, `p3`, `adobergb`)
- **WxH**: pixel dimensions (e.g., `300x300`, `1x1`, `4096x1`)
- **icc_{profile}**: optional ICC profile variant (`sRGB`, `DisplayP3`, `AdobeRGB`)
- **hash6**: first 6 hex chars of SHA-256 of file content (collision-proof)

Examples:
```
xig-stdrgb-300x300.png.a1b2c3
xig-1bit-16x16.tiff.d4e5f6
xig-hdr-1024x1024-icc_DisplayP3.png.78abcd
xig-gray-4096x1.bmp.ef0123
```

## Context Types

| Short Name | CGContext Type |
|-----------|---------------|
| stdrgb | StandardRGB |
| premul | PremultipliedFirstAlpha |
| nonpremul | NonPremultipliedAlpha |
| 16bit | 16BitDepth |
| gray | Grayscale |
| hdr | HDRFloatComponents |
| bigend | BigEndian |
| litend | LittleEndian |
| float4 | 32BitFloat4Component |
| 1bit | 1BitMonochrome |
| p3 | DisplayP3 |
| srgb | sRGB |
| adobergb | AdobeRGB1998 |

## Integration with CFL Fuzzers

```bash
# Seed ICC profiles to CFL corpus
cp xnuimagegenerator/icc/*.icc ../cfl/corpus-icc_profile_fuzzer/
cp xnuimagegenerator/icc/*.icc ../cfl/corpus-icc_toxml_fuzzer/

# Seed TIFFs to CFL TIFF fuzzer
cp xnuimagegenerator/tiff/*.tiff ../cfl/corpus-icc_tiff_fuzzer/
```
