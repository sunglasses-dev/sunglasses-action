#!/usr/bin/env bash
# Sunglasses GitHub Action — scan agent-readable files for prompt injection / tool poisoning.
#
# v1.1 exit contract (measured 2026-09-06 against sunglasses 0.5.5 from PyPI and
# the 0.5.6 build; the matrix lives in tests/):
#
#   0  inspected, nothing found      -> reported as inspected, NOT as "safe"
#   1  finding                       -> ::error, fails per fail-on-threat
#   2  usage / operational error     -> ::error saying the file was NOT scanned,
#                                       fails the job, never the injection wording
#   3  incomplete inspection         -> ::warning "not inspected: <reason>",
#                                       fails per fail-on-incomplete (default true)
#   anything else, or a crash        -> treated as 2
#
# The exit code is a hint. The meaning comes from the scanner's own JSON
# document (see lib/classify.py), because a scanner that crashes exits 1 -- the
# same code as a real threat -- and v1 turned that into
# "Sunglasses detected an agent-targeted injection in <file>" on a stranger's PR.
#
# Written to run on any POSIX-ish bash (3.2+), no associative arrays / globstar.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SG_BIN="${SUNGLASSES_BIN:-sunglasses}"
PY_BIN="${PYTHON_BIN:-python3}"

FAIL_ON_THREAT="${INPUT_FAIL_ON_THREAT:-true}"
FAIL_ON_INCOMPLETE="${INPUT_FAIL_ON_INCOMPLETE:-true}"

work="$(mktemp -d)"
list="$work/list"
: > "$list"
# One line per non-clean outcome, for the summary. Kept in files rather than
# arrays so the counts and the report can never drift apart.
: > "$work/threats"
: > "$work/incomplete"
: > "$work/errors"
: > "$work/notes"

cleanup() { rm -rf "$work"; }
trap cleanup EXIT

# ---------------------------------------------------------------- discovery --
# v1 dropped anything that was not a plain existing file, silently. A directory
# in `paths` (which our own README documents: paths: "README.md docs/ prompts/")
# matched nothing and vanished, so the job reported a green "1 clean, 1 scanned"
# for a repo where two whole directories were never opened. Directories are now
# walked, and a path that genuinely is not there is REPORTED rather than dropped.
add_path() {
  if [ -d "$1" ]; then
    find "$1" -type f 2>/dev/null | sed 's|^\./||' >> "$list"
  elif [ -f "$1" ]; then
    printf '%s\n' "$1" | sed 's|^\./||' >> "$list"
  fi
}

if [ -n "${INPUT_PATHS:-}" ]; then
  for g in $INPUT_PATHS; do
    matched=0
    for f in $g; do
      if [ -e "$f" ]; then
        add_path "$f"
        matched=1
      fi
    done
    if [ "$matched" -eq 0 ]; then
      case "$g" in
        *'*'*|*'?'*|*'['*)
          # An unmatched glob is ordinary configuration, not a missing file.
          printf 'no files matched `%s`\n' "$g" >> "$work/notes"
          ;;
        *)
          # An explicit path the user asked us to scan and we could not: that is
          # exactly the "asked for, never inspected" case this release exists to
          # make visible, so it counts as incomplete rather than disappearing.
          printf '%s\tnot found\n' "$g" >> "$work/incomplete"
          echo "::warning::Sunglasses could not scan '$g': not found. It was NOT inspected."
          ;;
      esac
    fi
  done
else
  {
    ls -1 README* readme* AGENTS.md AGENT.md CLAUDE.md GEMINI.md 2>/dev/null
    find . -type f \( \
         -name '*.md' \
      -o -path './docs/*' \
      -o -path './prompts/*' \
      -o -path './.prompts/*' \
      -o -path './.cursor/*' \
      -o -path './.windsurf/*' \
      -o -path './.claude/*' \
      -o -name 'mcp.json' \
      -o -name '*.mcp.json' \
    \) 2>/dev/null | sed 's|^\./||'
  } >> "$list"
fi

sort -u "$list" | sed '/^$/d' > "$list.u" && mv "$list.u" "$list"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
printf '## 😎 Sunglasses — agent file scan\n\n' >> "$summary"

count="$(wc -l < "$list" | tr -d ' ')"
skipped_pre="$(wc -l < "$work/incomplete" | tr -d ' ')"

if [ "$count" -eq 0 ] && [ "$skipped_pre" -eq 0 ]; then
  echo "Sunglasses: no agent-readable files matched. Nothing to scan."
  printf '_No agent-readable files matched the configured paths. **Nothing was inspected** — this is not a clean result._\n' >> "$summary"
  exit 0
fi

echo "Sunglasses: scanning $count agent-readable file(s)…"
sarif_dir="$work/sarif"
mkdir -p "$sarif_dir"

threats=0
incomplete="$skipped_pre"
errors=0
clean=0

while IFS= read -r f; do
  [ -n "$f" ] || continue

  # ONE scan per file. `--json` is deliberate: on the published 0.5.5,
  # `--output json` is silently ignored and prints the human screen, while
  # `--json` returns a real document on both builds. Do not change this to
  # `--output json` without re-running tests/ against 0.5.5.
  # `< /dev/null` matters: without it the scanner inherits this loop's stdin and
  # can swallow the rest of the file list, so later files are silently never
  # scanned -- under-coverage reported as a pass, the exact bug class v1.1 fixes.
  out="$("$SG_BIN" scan --file "$f" --json 2>"$work/stderr" < /dev/null)"
  code=$?

  verdict="$(printf '%s' "$out" | "$PY_BIN" "$HERE/lib/classify.py" "$code" "$f" 2>/dev/null)"
  if [ -z "$verdict" ]; then
    verdict='{"kind":"error","reasons":["the Action could not classify the scanner output"],"detail":"","findings_count":0}'
  fi

  kind="$(printf '%s' "$verdict" | "$PY_BIN" -c 'import json,sys;print(json.load(sys.stdin).get("kind","error"))' 2>/dev/null)"
  reason="$(printf '%s' "$verdict" | "$PY_BIN" -c 'import json,sys;print("; ".join(json.load(sys.stdin).get("reasons") or []))' 2>/dev/null)"
  detail="$(printf '%s' "$verdict" | "$PY_BIN" -c 'import json,sys;print(json.load(sys.stdin).get("detail",""))' 2>/dev/null)"
  [ -n "$kind" ] || kind="error"

  case "$kind" in
    threat)
      threats=$((threats + 1))
      printf '%s\t%s\n' "$f" "${reason:-finding}" >> "$work/threats"
      echo "::error file=$f::Sunglasses detected an agent-targeted injection in $f"
      # SARIF only for real findings. A file we could not inspect must never
      # arrive in the security tab as an alert -- see lib/merge_sarif.py.
      safe_name="$(printf '%s' "$f" | tr '/ ' '__')"
      "$SG_BIN" scan --file "$f" --output sarif > "$sarif_dir/$safe_name.sarif" 2>/dev/null < /dev/null || true
      {
        printf '<details><summary>⛔ <code>%s</code> — threat detected</summary>\n\n' "$f"
        printf '```\n'
        printf '%s\n' "$detail" | head -40
        printf '```\n</details>\n'
      } >> "$summary"
      ;;
    incomplete)
      incomplete=$((incomplete + 1))
      printf '%s\t%s\n' "$f" "${reason:-not fully inspected}" >> "$work/incomplete"
      echo "::warning file=$f::not inspected: ${reason:-the file was not fully inspected}"
      ;;
    clean)
      clean=$((clean + 1))
      echo "inspected, nothing found: $f"
      ;;
    *)
      errors=$((errors + 1))
      printf '%s\t%s\n' "$f" "${reason:-the scanner failed}" >> "$work/errors"
      # Deliberately NOT the injection wording. The scan did not happen.
      echo "::error file=$f::Sunglasses could not scan $f (${reason:-scanner error}). It was NOT inspected — this is not a clean result."
      ;;
  esac
done < "$list"

# A run with zero results (not an empty runs array) is what lets code scanning
# clear alerts we reported on a previous commit.
"$PY_BIN" "$HERE/lib/merge_sarif.py" "$sarif_dir" > sunglasses.sarif 2>/dev/null \
  || printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Sunglasses","rules":[]}},"results":[]}]}' > sunglasses.sarif

# ------------------------------------------------------------------ summary --
# Every bucket is counted separately. An incomplete or failed file is never
# folded into "clean" -- that fold is the bug this release exists to remove.
inspected=$((clean + threats))
{
  printf '\n| outcome | files |\n|---|---|\n'
  printf '| ⛔ threats found | %s |\n' "$threats"
  printf '| ⚠️ not inspected (incomplete) | %s |\n' "$incomplete"
  printf '| 🔴 scan failed (operational) | %s |\n' "$errors"
  printf '| ✅ inspected, nothing found | %s |\n' "$clean"
  printf '\n**%s inspected · %s with findings · %s not inspected · %s failed**\n' \
    "$inspected" "$threats" "$incomplete" "$errors"
} >> "$summary"

if [ -s "$work/incomplete" ]; then
  {
    printf '\n<details><summary>⚠️ Files NOT inspected (%s)</summary>\n\n' "$incomplete"
    while IFS="$(printf '\t')" read -r p r; do printf -- '- `%s` — %s\n' "$p" "$r"; done < "$work/incomplete"
    printf '\n</details>\n'
  } >> "$summary"
fi
if [ -s "$work/errors" ]; then
  {
    printf '\n<details><summary>🔴 Files that could not be scanned (%s)</summary>\n\n' "$errors"
    while IFS="$(printf '\t')" read -r p r; do printf -- '- `%s` — %s\n' "$p" "$r"; done < "$work/errors"
    printf '\n</details>\n'
  } >> "$summary"
fi
if [ -s "$work/notes" ]; then
  { printf '\n'; while IFS= read -r n; do printf -- '_%s_\n' "$n"; done < "$work/notes"; } >> "$summary"
fi

echo ""
echo "Sunglasses: $inspected inspected, $threats with findings, $incomplete not inspected, $errors failed."

# --------------------------------------------------------------------- gate --
fail=0
if [ "$threats" -gt 0 ] && [ "$FAIL_ON_THREAT" = "true" ]; then
  echo "Failing check: $threats agent-readable file(s) contain findings."
  fail=1
fi
if [ "$errors" -gt 0 ]; then
  # Not configurable: a scan that did not run cannot be reported as a pass.
  echo "Failing check: $errors file(s) could not be scanned."
  fail=1
fi
if [ "$incomplete" -gt 0 ] && [ "$FAIL_ON_INCOMPLETE" = "true" ]; then
  echo "Failing check: $incomplete file(s) were not fully inspected (set fail-on-incomplete: false to report only)."
  fail=1
fi
exit "$fail"
