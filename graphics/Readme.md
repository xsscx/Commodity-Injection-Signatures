# Graphics Images & Fuzzing

Last Updated: 2026-03-14 14:04:09 UTC by David Hoyt

## Info

This Fuzz Repo is driven by a few primary Tools:

1. https://github.com/xsscx/xnuimagetools
2. https://github.com/xsscx/xnuimagefuzzer
3. https://github.com/InternationalColorConsortium/iccDEV
4. AFL++
5. ClusterFuzz Lite
6. libFuzzer

**All** the Files in this graphics directory link back to a Published Poc and/or CVE.

The workflow begin with generating clean images for the baseline sweep through a target.
- Generate Clean Inputs and measure the Application Response of Interest
- Generated baseline Fuzzed Images and measure the Application Response
- Generate a second set of Fuzzed Images and measure the Application Response
- Rinse, Lather & Repeat

Do you have Questions?
- Open an Issue
