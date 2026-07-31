# Agent Instructions

## Repository Role

This repository is a malicious-input corpus. Treat files as durable test
artifacts unless they are clearly local build, CI, QA, sanitizer, coverage, or
conversion output.

## Safety Rules

1. Do not open corpus files in normal desktop applications.
2. Use sanitizer-instrumented tools for ICC, XML, and image parser checks.
3. Do not commit local logs, generated reports, coverage files, build products,
   or generated conversion outputs.
4. Keep generated or edited text files ASCII. Verify with `file`.
5. Preserve malicious payload bytes. Do not reformat binary or payload files
   unless the task is explicitly to normalize that artifact.

## Git Scope

- The active branch is `master`.
- Stage paths explicitly. Do not use broad `git add -A` in a mixed worktree.
- Commit subjects should use `fuzz:` for corpus and repository-management
  changes.
- Push directly to `origin master` when the user asks for local changes to be
  published.

## Corpus Promotion Checklist

Before adding a new file:

1. Confirm it is a durable input artifact, not a generated log or output file.
2. Place it in the nearest format/category directory.
3. Name ICC and ICC XML PoCs with the crash site when known.
4. Check for duplicates by path, size, and hash when the input came from fuzzing.
5. Run format-safe validation when available, such as `xmllint --noout` for XML.
6. Update docs only when adding a new category, workflow, or naming convention.

## Ignore Policy

Keep `.gitignore` focused on local outputs:

- build, dist, temp, run, coverage, and artifact directories
- CI, QA, and test result directories
- sanitizer/debugger byproducts
- generated logs and conversion outputs

Do not ignore source corpus extensions such as `.icc`, `.xml`, `.cube`, image
formats, payload text files, or AFL-minimized crash names.
