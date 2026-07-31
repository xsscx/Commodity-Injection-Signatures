# Fuzz Corpus - Commodity Injection Signatures and CVE PoCs

Curated malicious-input corpus for security testing. The repository contains ICC
profiles, ICC XML, malformed graphics, web injection signatures, protocol
payloads, and platform-specific parser inputs.

All files should be treated as hostile test data.

## Start Here

- Agent guidance: `AGENTS.md`
- Contribution rules: `CONTRIBUTING.md`
- GitHub automation index: `.github/README.md`
- ICC binary profile rules: `.github/instructions/icc-profiles.instructions.md`
- ICC XML rules: `.github/instructions/icc-xml.instructions.md`
- Repository management rules: `.github/instructions/repository-management.instructions.md`
- Artifact policy: `.github/artifacts/README.md`

## Major Corpus Areas

| Path | Purpose |
|------|---------|
| `graphics/icc/` | ICC profiles, CVE PoCs, and crash repros |
| `graphics/cube/` | ICC cube seeds and converter inputs |
| `graphics/tif/` | TIFF parser and ICC-embedded image inputs |
| `graphics/{jpg,png,gif,bmp,heic,exr}/` | Malformed image inputs |
| `xml/icc/` | ICC XML parser repros |
| `xml/icc/minimized/` | AFL-minimized ICC XML inputs |
| `xml/xxe/`, `xml/ssrf/`, `xml/dos/` | XML injection and parser-abuse payloads |
| `angular/`, `javascript/`, `sqlinjection/`, `ssi/`, `uri/` | Web injection signatures |
| `unix/`, `python/`, `java/`, `applescript/` | Command/code injection payloads |
| `xnuimagegenerator/`, `xnuimagefuzzer/` | Apple image generation and mutation corpora |

## Current Inventory

Do not trust hardcoded counts in old notes. Generate a fresh inventory when
needed:

```bash
find . -path './.git' -prune -o -type f -printf '%p\n' | wc -l
find . -path './.git' -prune -o -type f -printf '%s\n' | awk '{s+=$1} END {print s}'
for d in graphics/icc graphics/cube graphics/tif graphics/jpg graphics/png xml/icc xml/icc/minimized; do
  printf '%s ' "$d"
  find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l
done
```

## ICC CVE Coverage

This corpus includes PoCs and variants for Apple ColorSync, iccDEV, and
ArgyllCMS issues, including:

- CVE-2022-26730
- CVE-2023-32443
- CVE-2023-46602
- CVE-2023-46867
- CVE-2024-38427

References:

- https://srd.cx/cve-2022-26730/
- https://srd.cx/cve-2023-32443/
- https://github.com/InternationalColorConsortium/iccDEV

## Integration With xsscx/research

The ICC and image inputs feed the `xsscx/research` analyzer and fuzzing
workflows.

```bash
# Seed binary ICC fuzzers from a sibling research checkout.
cp fuzz/graphics/icc/*.icc cfl/corpus-icc_profile_fuzzer/

# Seed XML fuzzer.
cp fuzz/xml/icc/*.xml cfl/corpus-icc_fromxml_fuzzer/
cp fuzz/xml/icc/minimized/* cfl/corpus-icc_fromxml_fuzzer/
```

Use sanitizer-instrumented tools for validation. Do not open corpus files in
normal desktop applications.

## File Naming

ICC PoCs:

```text
{crash_type}-{Class}-{Method}-{SourceFile}_cpp-Line{N}.icc
```

Common crash prefixes:

- `hbo` - heap buffer overflow
- `sbo` - stack buffer overflow
- `segv` or `npd` - signal or null pointer dereference
- `oom` - excessive allocation
- `ub` - undefined behavior
- `so` - stack exhaustion
- `cve` - known CVE proof-of-concept

ICC XML PoCs follow the same crash-site convention when known. AFL minimized
inputs may retain their queue-style names if the name carries useful triage
metadata.

## Repository Hygiene

- Commit durable input artifacts and documentation.
- Do not commit local logs, reports, coverage files, build products, or generated
  conversion outputs.
- Keep edited text files ASCII and LF-normalized.
- Use `.gitignore` for local output classes only; do not ignore source corpus
  file types.
