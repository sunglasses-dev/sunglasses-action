# Changelog

## v1.1.0 — unreleased

**Why this release exists.** v1 inferred meaning from the scanner's exit code
alone (`if [ "$code" -ne 0 ]` → "injection detected"). That matched the CLI
contract it was written against, and stopped matching it when the scanner grew a
richer exit map. The result: files the scanner could not read were reported to
the user's pull request as attacks, and files it silently skipped were counted as
clean.

### Fixed

- **A file that was not scanned is never reported as an injection.** Operational
  failures (missing path, unreadable file, scanner crash, any unexpected exit
  code) now produce `::error … could not scan … It was NOT inspected`, and fail
  the job. Previously every one of them produced
  `Sunglasses detected an agent-targeted injection in <file>`.
  - Reachable in practice on the published 0.5.5: a markdown file over the
    scanner's 1 MB limit, and any path that disappears mid-run.
- **A file that was not fully inspected is never counted as clean.** Archives,
  oversized files, unsupported binaries and missing paths are reported per file
  with the scanner's own reason and are counted in their own bucket.
- **Directories in `paths` are walked instead of silently dropped.** The usage
  documented in this repo's own README — `paths: "README.md docs/ prompts/"` —
  previously scanned `README.md` only and still reported a green result.
- **Unmatched globs and missing explicit paths are reported.** An unmatched glob
  is noted as configuration; a named path that does not exist counts as
  not-inspected and fails by default.
- **The job summary counts four outcomes separately**: findings, not inspected,
  scan failed, inspected-and-nothing-found. There is no combined "clean" number
  to hide behind.
- **The scanner is invoked with stdin closed**, so it cannot consume the file
  list and leave later files silently unscanned.

### Added

- **`fail-on-incomplete` input, default `true`.** Set `false` to report without
  failing. Either way an uninspected file is never counted as clean.
- **`tests/`** — an acceptance harness that runs the real `entrypoint.sh` against
  real fixtures with a real scanner, for every outcome, both flags, a mixed
  batch and the SARIF output. Run it once per scanner version:
  `SUNGLASSES_BIN=/path/to/sunglasses tests/run_tests.sh`.

### Changed

- **The exit code is now a hint; the meaning comes from the scanner's JSON.**
  If a future scanner release changes the exit map again, the Action degrades to
  an honest "could not classify" — an operational failure — instead of a false
  accusation.
- **SARIF contains findings only.** Files that could not be inspected are carried
  by the annotations and the job summary, never as security-tab alerts. Filing an
  alert for a file we never read would be the same false accusation in a
  different place.
- The Action reads JSON with `--json`, not `--output json`: on the published
  0.5.5 `--output json` is silently ignored and prints the human screen.

### Notes for users

- If you relied on a green check meaning "this repository is safe", it never did
  and now says so: it means every file we were asked to read, we read, and
  nothing fired.
- Repos with large generated markdown may newly fail with "not inspected". That
  is the scanner's 1 MB limit becoming visible rather than a new limitation. Set
  `fail-on-incomplete: false` to report only.
- `@v1` tracks the latest v1.x. Pin a commit SHA if you need immutability.

## v1.0 — 2026-07-01

- Initial release: scan agent-readable files on pull requests, merged SARIF
  upload to code scanning, `fail-on-threat` gating.
