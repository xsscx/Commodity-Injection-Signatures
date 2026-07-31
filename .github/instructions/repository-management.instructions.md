# Repository Management Instructions

## Applies To

`.gitignore`, `.gitattributes`, `AGENTS.md`, `README.md`, `CONTRIBUTING.md`,
and `.github/**`.

## Goals

- Keep corpus inputs easy to stage intentionally.
- Keep generated local output out of Git.
- Keep future-agent instructions discoverable.
- Avoid stale file counts in documentation.

## Inventory Commands

Use these commands when docs or prompts need current counts:

```bash
find . -path './.git' -prune -o -type f -printf '%p\n' | wc -l
find . -path './.git' -prune -o -type f -printf '%s\n' | awk '{s+=$1} END {print s}'
for d in graphics/icc graphics/cube graphics/tif graphics/jpg graphics/png xml/icc xml/icc/minimized; do
  printf '%s ' "$d"
  find "$d" -maxdepth 1 -type f 2>/dev/null | wc -l
done
```

## Review Checklist

1. Run `git status --short --branch`.
2. Check untracked files with `git ls-files -o --exclude-standard`.
3. Check ignored local output with `git ls-files -o --ignored --exclude-standard`.
4. Stage only durable corpus inputs and repo-management files.
5. Run `git diff --cached --check`.
6. Run format checks for touched text formats, such as `xmllint --noout`.
7. Verify edited text files with `file`.

## Do Not Hide Corpus Inputs

Do not add broad ignore rules for file types that can be source corpus material:
`.icc`, `.xml`, `.cube`, `.tif`, `.tiff`, `.png`, `.jpg`, `.jpeg`, `.gif`,
`.bmp`, `.heic`, `.exr`, `.pf`, `.txt`, `.html`, `.svg`, `.json`, or AFL
queue-style names.
