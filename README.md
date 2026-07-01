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

That's it. On every PR, Sunglasses scans the sensible default set of agent-readable files and **fails the check** if it finds an injection. A stranger can protect a repo in under 5 minutes.

[![Sunglasses scanned](https://img.shields.io/badge/Sunglasses-scanned-00E08A?style=flat-square&labelColor=0B0B0A)](https://sunglasses.dev)

## What it scans (defaults)

`README*`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, every `*.md`, and `docs/`, `prompts/`, `.cursor/`, `.windsurf/`, `.claude/`, plus `mcp.json` / `*.mcp.json`. Override with the `paths` input.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | *(default set)* | Space-separated globs to scan instead of the defaults. |
| `fail-on-threat` | `true` | Fail the check when a threat is found. Set `false` to report-only. |
| `upload-sarif` | `true` | Upload merged SARIF to GitHub code scanning (needs `security-events: write`). |
| `python-version` | `3.x` | Python used to install the `sunglasses` package. |
| `version` | *(latest)* | Pin a `sunglasses` version, e.g. `==0.2.71`. |

## Report-only mode

```yaml
      - uses: sunglasses-dev/sunglasses-action@v1
        with:
          fail-on-threat: false
          paths: "README.md docs/ prompts/"
```

## What it catches

Direct & indirect prompt injection · README / repo poisoning · MCP tool-metadata poisoning · credential-exfiltration prompts · encoded / obfuscated / multilingual evasions.

## Honest notes

- **False positives:** security content that *quotes* attacks (e.g. a blog post containing "ignore all previous instructions") can trip the scanner. Scope `paths`, or run in `fail-on-threat: false` mode on docs-heavy repos.
- **100% local:** scanning runs entirely inside your runner. No payloads are sent anywhere — no account, no API key, no telemetry.
- The Action installs the published [`sunglasses`](https://pypi.org/project/sunglasses/) package from PyPI. Exit-code gating (`scan --file` returns non-zero on a threat) is the verified contract this Action relies on.

## License

MIT — see [LICENSE](LICENSE).
