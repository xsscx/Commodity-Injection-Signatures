# GitHub Automation Index

This directory stores automation and future-agent reference material for the
fuzz corpus.

## Contents

- `workflows/` - sanitizer and corpus scan automation.
- `instructions/` - path-specific handling rules for ICC, ICC XML, web
  injection, and repository management.
- `prompts/` - reusable review and triage prompts.
- `skills/` - durable task workflows for agents.
- `artifacts/` - policy for generated reports and downloadable CI output.
- `copilot-instructions.md` - cross-cutting agent guidance for this repository.

## Maintenance Rules

- Keep automation output out of Git unless it is intentionally curated as corpus
  data.
- Prefer generated inventory commands over hardcoded corpus counts.
- Keep edited text files ASCII and LF-normalized.
- Use `.gitattributes` for binary/text classification instead of relying on
  Git heuristics for corpus files.
