# Copilot Instructions - fuzz Corpus Repository

## Repository Role

This repository is a curated malicious-input corpus for security testing. It is
used by ICC, XML, image, and web-injection fuzzing workflows.

## Required Reading

- `AGENTS.md` for session rules and Git scope.
- `.github/instructions/repository-management.instructions.md` before changing
  repo hygiene, docs, prompts, workflows, or agent files.
- `.github/instructions/icc-profiles.instructions.md` before touching
  `graphics/icc/**`.
- `.github/instructions/icc-xml.instructions.md` before touching `xml/icc/**`.
- `.github/instructions/web-injection.instructions.md` before touching web,
  protocol, command-injection, or payload directories.

## Safety

- Treat all corpus files as malicious.
- Do not open inputs in normal desktop applications.
- Use sanitizer-instrumented tools for parser checks.
- Preserve payload bytes unless the task explicitly asks for normalization.
- Do not create standalone PoC programs; use existing tools and durable input
  artifacts.

## Git Hygiene

- Branch: `master`.
- Stage paths explicitly.
- Commit subjects should start with `fuzz:`.
- Keep generated or edited text files ASCII and verify with `file`.
- Run `git diff --cached --check` before committing.
- Do not commit logs, coverage files, sanitizer output, build directories,
  generated reports, or generated conversion outputs.

## Inventory

Do not rely on hardcoded corpus counts. Generate counts when needed:

```bash
find . -path './.git' -prune -o -type f -printf '%p\n' | wc -l
for d in graphics/icc graphics/cube graphics/tif graphics/jpg graphics/png xml/icc xml/icc/minimized; do
  printf '%s ' "$d"
  find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l
done
```

## Useful Workflows

- `.github/skills/corpus-management/SKILL.md` - cleanup and promotion workflow.
- `.github/prompts/triage-new-poc.prompt.md` - classify and add a new PoC.
- `.github/prompts/repository-cleanup.prompt.md` - recover from local output
  clutter.
- `.github/prompts/analyze-corpus-coverage.prompt.md` - identify seed gaps.

## CI

`.github/workflows/sanitizer-corpus-scan.yml` builds tools from
`xsscx/research` and scans ICC profiles plus ICC XML files with sanitizer
settings. CI artifacts are for review and should not be committed unless a file
is intentionally promoted to curated corpus input.
