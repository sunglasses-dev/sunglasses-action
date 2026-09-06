# 😎 Sunglasses — Agent File Scan (GitHub Action)

Scan your repository's **agent-readable files** — READMEs, docs, prompts, MCP configs, `.cursor` / `.windsurf` / `.claude` rules — for **prompt injection** and **tool poisoning** on every pull request, *before* an AI agent (Claude Code, Cursor, Copilot, etc.) ever reads them.

Powered by [Sunglasses](https://sunglasses.dev), the open-source, 100% local trust boundary for AI agents.

> Your agent trusts what it reads. A poisoned README or MCP description can quietly hand it instructions you never wrote. This Action catches that in CI.

## Quick start

Create `.github/workflows/sunglasses.yml`:

```yaml
name: Sunglasses — agent file scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # lets findings appear in the PR's "Code scanning" tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sunglasses-dev/sunglasses-action@v1
```

That's it. On every PR, Sunglasses scans the sensible default set of agent-readable files and **fails the check** if it finds an injection — or if it could not actually read a file it was asked to scan.

[![Sunglasses scanned](https://img.shields.io/badge/Sunglasses-scanned-00E08A?style=flat-square&labelColor=0B0B0A)](https://sunglasses.dev)

## What it scans (defaults)

`README*`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, every `*.md`, and `docs/`, `prompts/`, `.cursor/`, `.windsurf/`, `.claude/`, plus `mcp.json` / `*.mcp.json`. Override with the `paths` input.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | *(default set)* | Space-separated files, directories or globs to scan instead of the defaults. Directories are walked. |
| `fail-on-threat` | `true` | Fail the check when a finding is reported. Set `false` to report-only. |
| `fail-on-incomplete` | `true` | Fail the check when a file could not be fully inspected (archive, oversized file, unsupported binary, missing path). Set `false` to report-only. Either way, a file that was not inspected is **never counted as clean**. |
| `upload-sarif` | `true` | Upload merged SARIF to GitHub code scanning (needs `security-events: write`). |
| `python-version` | `3.x` | Python used to install the `sunglasses` package. |
| `version` | *(latest)* | Pin a `sunglasses` version, e.g. `==0.5.6`. Empty installs the latest published release, so a new release reaches your workflow the hour it lands. |

## What the check means

The Action reports four separate outcomes, and never folds them together:

| Outcome | Annotation | Fails the job? |
|---|---|---|
| **Inspected, nothing found** | none | no |
| **Finding** | `::error … detected an agent-targeted injection` | yes, unless `fail-on-threat: false` |
| **Not inspected** (archive, file over the scanner's 1 MB limit, unsupported binary, path not found) | `::warning … not inspected: <reason>` | yes, unless `fail-on-incomplete: false` |
| **Scan failed** (the scanner errored or crashed) | `::error … could not scan … It was NOT inspected` | **always** |

A green check means *"every file we were asked to read, we read, and nothing fired"*. It does not mean "this repository is safe" — no scanner can promise that, and this one does not.

**The injection wording is reserved for actual findings.** A file we could not open, or one the scanner failed on, is never described as an attack. Before v1.1 it was: the Action treated any non-zero exit as a threat, so a 1.2 MB CHANGELOG or a permissions error produced `Sunglasses detected an agent-targeted injection in <file>` on the pull request.

## Report-only mode

```yaml
      - uses: sunglasses-dev/sunglasses-action@v1
        with:
          fail-on-threat: false
          fail-on-incomplete: false
          paths: "README.md docs/ prompts/"
```

Directories in `paths` are walked recursively. (In v1 they were silently dropped — `paths: "README.md docs/ prompts/"` scanned only `README.md` and still reported a green result, which is the kind of quiet under-coverage v1.1 exists to remove.)

## What it catches

Direct & indirect prompt injection · README / repo poisoning · MCP tool-metadata poisoning · credential-exfiltration prompts · encoded / obfuscated / multilingual evasions.

## Honest notes

- **False positives:** security content that *quotes* attacks (e.g. a blog post containing "ignore all previous instructions") can trip the scanner. Scope `paths`, or run in `fail-on-threat: false` mode on docs-heavy repos.
- **False negatives are reported, not hidden.** If a file cannot be inspected, the Action says so per file and fails by default, rather than counting it as clean.
- **100% local:** scanning runs entirely inside your runner. No payloads are sent anywhere — no account, no API key, no telemetry.
- The Action installs the published [`sunglasses`](https://pypi.org/project/sunglasses/) package from PyPI. With `version` empty it installs the **latest** release at run time, so package changes reach your workflow without you upgrading anything — pin `version` if you need lockstep.
- The Action reads the scanner's JSON document rather than inferring meaning from the exit code alone, so a future change to the scanner's exit map degrades into an honest "could not classify" instead of a false accusation.
- **Dogfooding:** this repo's own `tests/fixtures/` contains deliberate injection samples, so a scan of this repository will flag them. Scope `paths` to exclude `tests/fixtures` when running the Action against itself.
- `@v1` is a moving tag that tracks the latest v1.x. Pin a commit SHA if you need immutability; a pinned SHA does **not** move when we publish v1.1.

## License

MIT — see [LICENSE](LICENSE).
