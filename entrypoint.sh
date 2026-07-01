#!/usr/bin/env bash
# Sunglasses GitHub Action — scan agent-readable files for prompt injection / tool poisoning.
# Verified CLI contract: `sunglasses scan --file <f>` exits non-zero on a threat, 0 when clean.
# Written to run on any POSIX-ish bash (3.2+), no associative arrays / globstar required.
set -uo pipefail

list="$(mktemp)"

if [ -n "${INPUT_PATHS:-}" ]; then
  # user-supplied space-separated paths/globs (let the shell expand them)
  for g in $INPUT_PATHS; do
    for f in $g; do [ -f "$f" ] && printf '%s\n' "$f"; done
  done > "$list"
else
  # default agent-readable target set (portable discovery via find + top-level files)
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
  } > "$list"
fi

# de-duplicate, drop blanks
sort -u "$list" | sed '/^$/d' > "$list.u" && mv "$list.u" "$list"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
printf '## 😎 Sunglasses — agent file scan\n\n' >> "$summary"

count="$(wc -l < "$list" | tr -d ' ')"
if [ "$count" -eq 0 ]; then
  echo "Sunglasses: no agent-readable files matched. Nothing to scan."
  printf '_No agent-readable files matched the configured paths._\n' >> "$summary"
  rm -f "$list"; exit 0
fi

echo "Sunglasses: scanning $count agent-readable file(s)…"
sarif_dir="${RUNNER_TEMP:-/tmp}/sg-sarif"
mkdir -p "$sarif_dir"

threats=0
clean=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  out="$(sunglasses scan --file "$f" 2>&1)"; code=$?
  safe_name="$(printf '%s' "$f" | tr '/ ' '__')"
  sunglasses scan --file "$f" --output sarif > "$sarif_dir/$safe_name.sarif" 2>/dev/null || true
  if [ "$code" -ne 0 ]; then
    threats=$((threats + 1))
    echo "::error file=$f::Sunglasses detected an agent-targeted injection in $f"
    {
      printf '<details><summary>⛔ <code>%s</code> — threat detected</summary>\n\n' "$f"
      printf '```\n'
      printf '%s\n' "$out" | sed -E 's/\x1b\[[0-9;]*m//g' | head -40
      printf '```\n</details>\n'
    } >> "$summary"
  else
    clean=$((clean + 1))
    echo "clean: $f"
    printf -- '- ✅ `%s` — clean\n' "$f" >> "$summary"
  fi
done < "$list"

# merge per-file SARIF into one upload artifact
# GitHub code scanning rejects multiple runs with the same category (changelog 2025-07-21),
# so fold every per-file run into ONE run: first run's tool + concatenated results + deduped rules.
python3 - "$sarif_dir" > sunglasses.sarif <<'PY' || printf '{"version":"2.1.0","runs":[]}' > sunglasses.sarif
import sys, os, glob, json
base, results, rules, seen, schema, version = None, [], [], set(), None, "2.1.0"
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.sarif"))):
    try:
        d = json.load(open(p))
    except Exception:
        continue
    schema = d.get("$schema", schema)
    version = d.get("version", version)
    for run in d.get("runs", []):
        if base is None:
            base = run
        results.extend(run.get("results", []))
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id")
            if rid not in seen:
                seen.add(rid)
                rules.append(rule)
if base is None:
    out = {"version": version, "runs": []}
else:
    base["results"] = results
    base.setdefault("tool", {}).setdefault("driver", {})["rules"] = rules
    out = {"version": version, "runs": [base]}
if schema:
    out["$schema"] = schema
json.dump(out, sys.stdout)
PY

echo ""
echo "Sunglasses: $clean clean, $threats with threats (of $count scanned)."
printf '\n**%s clean · %s with threats · %s scanned**\n' "$clean" "$threats" "$count" >> "$summary"
rm -f "$list"

if [ "$threats" -gt 0 ] && [ "${INPUT_FAIL_ON_THREAT:-true}" = "true" ]; then
  echo "Failing check: $threats agent-readable file(s) contain injections."
  exit 1
fi
exit 0
