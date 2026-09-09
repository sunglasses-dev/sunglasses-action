#!/usr/bin/env bash
# Sunglasses Action — acceptance harness.
#
# Runs the REAL entrypoint.sh against REAL fixtures with a REAL scanner. A mock
# would only prove that the Action agrees with our beliefs about the CLI; the
# whole v1 defect was that those beliefs went stale without anyone noticing.
#
# Usage:
#   tests/run_tests.sh                      # uses `sunglasses` on PATH
#   SUNGLASSES_BIN=/path/to/venv/bin/sunglasses tests/run_tests.sh
#
# Run it once per scanner build you care about. Both are expected to pass:
#   pip install sunglasses==0.5.5           (the version CI installs today)
#   pip install ./dist/sunglasses-*.whl     (the 0.5.6 build)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
export SUNGLASSES_BIN="${SUNGLASSES_BIN:-sunglasses}"

pass=0
fail=0

# git cannot carry mode 000, so the unreadable condition is created here and
# always restored -- otherwise a failed run leaves the checkout unreadable.
UNREADABLE="$HERE/fixtures/unreadable/secret.md $HERE/fixtures/mixed/unreadable.md"
restore_modes() {
  for m in $UNREADABLE; do [ -e "$m" ] && chmod 644 "$m" 2>/dev/null; done
  find "$HERE/fixtures" -name sunglasses.sarif -delete 2>/dev/null
  return 0
}
trap restore_modes EXIT
for m in $UNREADABLE; do [ -e "$m" ] && chmod 000 "$m" 2>/dev/null; done
scanner_version="$("$SUNGLASSES_BIN" --version 2>&1 | head -1)"

echo "=== Sunglasses Action acceptance ==="
echo "scanner: $SUNGLASSES_BIN ($scanner_version)"
echo

# Behaviour marker, not the version string: the 0.5.6 wheel still self-reports
# 0.5.5 until the release bumps it, so `--version` cannot tell the builds apart.
if "$SUNGLASSES_BIN" scan --file "$HERE/fixtures/clean/README.md" --json 2>/dev/null \
     | grep -q inspection_complete; then
  BUILD="0.5.6+"
else
  BUILD="0.5.5"
fi
echo "detected build family (by behaviour, not version string): $BUILD"
echo

# ---------------------------------------------------------------------------
# run <name> <workdir> <paths|-> <fail_on_threat> <fail_on_incomplete>
# Sets: RC, OUT (combined stdout), SUMMARY (job summary file)
run() {
  local name="$1" dir="$2" paths="$3" fot="$4" foi="$5"
  SUMMARY="$(mktemp)"
  local before; before="$(pwd)"
  cd "$dir" || return 1
  if [ "$paths" = "-" ]; then unset INPUT_PATHS; else export INPUT_PATHS="$paths"; fi
  OUT="$(GITHUB_STEP_SUMMARY="$SUMMARY" INPUT_FAIL_ON_THREAT="$fot" \
         INPUT_FAIL_ON_INCOMPLETE="$foi" bash "$ROOT/entrypoint.sh" 2>&1)"
  RC=$?
  cd "$before" || return 1
  unset INPUT_PATHS
}

check() { # check <label> <condition-description> <0|1 result>
  if [ "$3" -eq 0 ]; then
    printf '  ok   %s\n' "$1"; pass=$((pass + 1))
  else
    printf '  FAIL %s -- %s\n' "$1" "$2"; fail=$((fail + 1))
    printf '       rc=%s\n' "$RC"
    printf '%s\n' "$OUT" | sed 's/^/       | /' | head -25
  fi
}

contains() { printf '%s' "$1" | grep -qF -- "$2"; }

# ---------------------------------------------------------------------- 1 ---
echo "[1] clean repo -> exit 0, no accusation"
run clean "$HERE/fixtures/clean" - true true
check "rc is 0" "expected 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "no ::error" "must not accuse a clean repo" \
  "$(contains "$OUT" '::error' && echo 1 || echo 0)"
check "does not claim 'safe'" "we report what we inspected, never a safety verdict" \
  "$(contains "$OUT" 'safe' && echo 1 || echo 0)"

# ---------------------------------------------------------------------- 2 ---
echo "[2] injection -> exit 1, ::error, fail-on-threat=false reports only"
run threat "$HERE/fixtures/threat" - true true
check "rc is 1" "a finding must fail the check" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "::error names an injection" "the finding wording belongs here and only here" \
  "$(contains "$OUT" 'detected an agent-targeted injection' && echo 0 || echo 1)"
run threat_report "$HERE/fixtures/threat" - false true
check "fail-on-threat=false -> rc 0" "report-only must not fail" \
  "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "still annotates in report-only" "reporting must stay visible" \
  "$(contains "$OUT" '::error' && echo 0 || echo 1)"

# ---------------------------------------------------------------------- 3 ---
echo "[3] uninspectable file (ZIP named .md) -> incomplete, never 'clean'"
run incomplete "$HERE/fixtures/incomplete" - true true
if [ "$BUILD" = "0.5.5" ]; then
  # 0.5.5 reports extraction_complete:true for an uninspected archive -- the
  # defect 0.5.6 repairs. The Action cannot invent knowledge the scanner does
  # not have, so this file reads as inspected on the old build. Documented, not
  # asserted away: the guarantee we DO make on 0.5.5 is the truncation case (5).
  check "0.5.5: no false injection claim" "must never call it an attack" \
    "$(contains "$OUT" 'detected an agent-targeted injection' && echo 1 || echo 0)"
else
  check "rc is 1 (fails by default)" "not inspected must not pass" \
    "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
  check "::warning not inspected" "the reason must reach the PR" \
    "$(contains "$OUT" '::warning' && contains "$OUT" 'not inspected' && echo 0 || echo 1)"
  check "no injection wording" "incomplete is not an accusation" \
    "$(contains "$OUT" 'detected an agent-targeted injection' && echo 1 || echo 0)"
  check "summary counts it as not-inspected" "buckets must stay separate" \
    "$(grep -q 'not inspected' "$SUMMARY" && echo 0 || echo 1)"
  run incomplete_off "$HERE/fixtures/incomplete" - true false
  check "fail-on-incomplete=false -> rc 0" "report-only must not fail" \
    "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
  # The fixture is README.md (clean) + archive.md (uninspectable). The property
  # is that they land in DIFFERENT buckets -- 1 clean and 1 not-inspected -- not
  # that clean is zero.
  grep -qE '\| ⚠️ not inspected \(incomplete\) \| 1 \|' "$SUMMARY" \
    && grep -qE '\| ✅ inspected, nothing found \| 1 \|' "$SUMMARY"
  check "incomplete is counted apart from clean" "never fold incomplete into clean" "$?"
fi

# ---------------------------------------------------------------------- 4 ---
echo "[4] missing explicit path -> reported, not silently dropped"
run missing "$HERE/fixtures/clean" "README.md does-not-exist.md" true true
check "warns about the missing path" "v1 dropped it with no trace" \
  "$(contains "$OUT" 'does-not-exist.md' && echo 0 || echo 1)"
check "no injection wording" "a missing file is not an attack" \
  "$(contains "$OUT" 'detected an agent-targeted injection' && echo 1 || echo 0)"
check "rc is 1 by default" "asked-for-but-not-scanned must not pass" \
  "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"

# ---------------------------------------------------------------------- 5 ---
echo "[5] oversized file -> truncation is visible on BOTH builds"
run big "$HERE/fixtures/big" - true true
check "reported as not inspected" "0.5.5 exits 0 here; the JSON still says truncated" \
  "$(contains "$OUT" 'not inspected' && echo 0 || echo 1)"
check "no injection wording" "a long changelog is not an attack" \
  "$(contains "$OUT" 'detected an agent-targeted injection' && echo 1 || echo 0)"

# ---------------------------------------------------------------------- 6 ---
echo "[6] operational failure (unreadable file) -> error, never an accusation"
if [ "$(id -u)" = "0" ]; then
  echo "  skip (running as root: chmod 000 is not enforced)"
else
  run unreadable "$HERE/fixtures/unreadable" - true true
  check "no injection wording" "a permissions error must not read as an attack" \
    "$(contains "$OUT" 'detected an agent-targeted injection' && echo 1 || echo 0)"
  check "says it was NOT inspected" "the user must know nothing was read" \
    "$(contains "$OUT" 'NOT inspected' && echo 0 || echo 1)"
  check "rc is 1" "a scan that did not run cannot pass" \
    "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
fi

# ---------------------------------------------------------------------- 7 ---
echo "[7] directory in paths is walked, not dropped"
run dirs "$HERE/fixtures/dirs" "docs/ prompts/" true true
check "scanned files inside docs/" "our own README documents this usage" \
  "$(contains "$OUT" 'docs/guide.md' && echo 0 || echo 1)"
check "scanned files inside prompts/" "same" \
  "$(contains "$OUT" 'prompts/system.md' && echo 0 || echo 1)"

# ---------------------------------------------------------------------- 8 ---
echo "[8] mixed batch -> every bucket counted separately"
run mixed "$HERE/fixtures/mixed" - true true
check "rc is 1" "a mixed batch containing a finding must fail" \
  "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "summary has all four buckets" "no bucket may be folded away" \
  "$(grep -q 'threats found' "$SUMMARY" && grep -q 'not inspected' "$SUMMARY" \
     && grep -q 'scan failed' "$SUMMARY" && grep -q 'inspected, nothing found' "$SUMMARY" \
     && echo 0 || echo 1)"
check "threat count is 1" "exactly one fixture carries a finding" \
  "$(grep -qE '\| ⛔ threats found \| 1 \|' "$SUMMARY" && echo 0 || echo 1)"

# ---------------------------------------------------------------------- 9 ---
echo "[9] SARIF: valid document, and no non-finding files in it"
run sarif "$HERE/fixtures/mixed" - true true
if [ -f "$HERE/fixtures/mixed/sunglasses.sarif" ]; then
  check "SARIF parses" "must be one valid document" \
    "$(python3 -c 'import json,sys;json.load(open(sys.argv[1]))' \
        "$HERE/fixtures/mixed/sunglasses.sarif" 2>/dev/null && echo 0 || echo 1)"
  check "single run" "GitHub rejects same-category multi-run uploads" \
    "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if len(d.get("runs",[]))<=1 else 1)' \
        "$HERE/fixtures/mixed/sunglasses.sarif" 2>/dev/null && echo 0 || echo 1)"
  python3 "$HERE/sarif_guard.py" "$HERE/fixtures/mixed/sunglasses.sarif" \
    archive.md unreadable.md >/dev/null 2>&1
  check "no incomplete/error file appears as a result" "the security tab must not allege what we never read" "$?"
  rm -f "$HERE/fixtures/mixed/sunglasses.sarif"
else
  check "SARIF written" "the file must exist even when empty" 1
fi

# --------------------------------------------------------------------- 10 ---
echo "[10] clean repo still uploads a run with zero results (clears old alerts)"
run sarif_clean "$HERE/fixtures/clean" - true true
if [ -f "$HERE/fixtures/clean/sunglasses.sarif" ]; then
  python3 - "$HERE/fixtures/clean/sunglasses.sarif" >/dev/null 2>&1 <<'GUARD'
import json,sys
d=json.load(open(sys.argv[1]))
runs=d.get("runs",[])
# exactly one run, zero results: an empty runs[] would leave previously
# reported code-scanning alerts standing forever.
sys.exit(0 if len(runs)==1 and runs[0].get("results")==[] else 1)
GUARD
  check "one run, zero results" "runs:[] cannot clear stale alerts" "$?"
  rm -f "$HERE/fixtures/clean/sunglasses.sarif"
else
  check "SARIF written for a clean repo" "the upload step needs the file" 1
fi

echo
echo "=== $pass passed, $fail failed  (scanner: $scanner_version, build family $BUILD) ==="
[ "$fail" -eq 0 ]
