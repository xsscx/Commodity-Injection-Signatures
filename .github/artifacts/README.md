# Artifact Policy

CI and local analysis artifacts are useful for triage but should not be
committed by default.

## Do Not Commit

- `*.log`, `*.out`, `*.err`, and temporary stderr captures
- `results/`, `reports/`, `ci-results/`, `qa-results/`, and `test-results/`
- coverage outputs such as `*.profraw`, `*.profdata`, `*.gcda`, and `*.gcno`
- sanitizer/debugger byproducts such as `asan.*`, `ubsan.*`, `core.*`, and
  `vgcore.*`
- generated conversion outputs such as `graphics/cube/*.cube.cube.icc`

## Commit Only When Curated

Commit a generated file only after it becomes a durable repro input and has a
stable name, category, and replay command. Prefer input artifacts over logs.

## Where To Put Reports

Use GitHub Actions artifacts or local scratch directories for bulky reports.
If a report must be preserved, place a short ASCII markdown summary under docs
or `.github/artifacts/` and link to the external artifact location.
