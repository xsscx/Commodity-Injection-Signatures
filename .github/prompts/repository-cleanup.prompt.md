# Repository Cleanup Prompt

Use this prompt when local fuzzing or CI runs leave a noisy worktree.

## Objective

Clean the repository without losing durable repro inputs.

## Procedure

1. Show `git status --short --branch`.
2. List untracked files with `git ls-files -o --exclude-standard`.
3. List ignored files with `git ls-files -o --ignored --exclude-standard`.
4. Classify each candidate as:
   - `keep` - durable input artifact worth committing
   - `drop` - generated local output
   - `ignore` - repeatable output pattern to add to `.gitignore`
   - `move` - useful input in the wrong directory
5. Verify byte duplicates with `cmp` or hashes before deleting tracked corpus
   files.
6. Stage only the intended paths and run `git diff --cached --check`.
7. Run format checks for touched files.

## Deliverable

Create one focused commit on `master` and push it to `origin`.
