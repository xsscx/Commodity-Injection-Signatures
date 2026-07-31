---
name: corpus-management
description: Manage the fuzz corpus lifecycle, including cleanup, promotion, duplicate checks, ignore policy, and safe publication.
---

# Corpus Management

Use this workflow when cleaning the repository, promoting local fuzzing output,
or deciding what belongs in Git.

## Steps

1. Inspect repository state:

   ```bash
   git status --short --branch
   git ls-files -o --exclude-standard
   git ls-files -o --ignored --exclude-standard
   ```

2. Classify local files:

   - Keep durable parser inputs with stable names.
   - Drop local logs, reports, build products, coverage data, and conversion
     outputs.
   - Move misplaced corpus files to the nearest format directory.
   - Check byte duplicates before deleting or promoting files.

3. Validate touched inputs:

   - XML: `xmllint --noout <file>`
   - Text/docs: `file <file>` and `git diff --check`
   - ICC/image inputs: use sanitizer-instrumented tools when available.

4. Update repository guidance:

   - `.gitignore` for generated local outputs only.
   - `.gitattributes` for text/binary classification.
   - `.github/README.md`, prompts, or instructions when workflows change.

5. Publish:

   ```bash
   git diff --cached --check
   git commit -m "fuzz: <short imperative summary>"
   git push origin master
   ```

## Output

Report the commit, pushed branch, files changed, and validation commands.
