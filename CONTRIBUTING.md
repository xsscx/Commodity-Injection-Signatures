# Contributing

This repository accepts malicious inputs, crash repros, parser edge cases, and
security-testing payloads. Treat every file as hostile.

## Before Adding Files

1. Confirm the file is a durable input artifact, not a log or generated report.
2. Put it in the nearest category directory.
3. Use a stable descriptive filename when the crash site is known.
4. Check for duplicate content before adding large files.
5. Run format-safe validation when available.
6. Keep edited text files ASCII.

## Do Not Commit

- local CI, QA, or test reports
- `*.log`, `*.out`, `*.err`, temporary stderr captures
- coverage files and sanitizer byproducts
- build, dist, temp, run, and artifact directories
- generated converter outputs unless promoted as curated repro inputs

## Commit Messages

Use short imperative subjects:

- `fuzz: add ICC XML repro for CIccMpeXmlUnknown`
- `fuzz: clean generated corpus artifacts`
- `fuzz: document corpus management workflow`

## Validation

Run the nearest cheap check before committing:

```bash
git diff --cached --check
xmllint --noout path/to/file.xml
file path/to/edited-text-file
```

Use sanitizer-instrumented ICC/image tools when available.
