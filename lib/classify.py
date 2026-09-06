#!/usr/bin/env python3
"""Normalise one `sunglasses scan --file` run into a verdict the Action can act on.

Why this exists
---------------
Before v1.1 the Action inferred meaning from the exit code alone:
`if [ "$code" -ne 0 ]` -> "injection detected". That was true against the CLI
contract of the day (0 = clean, non-zero = threat) and became false the moment
the scanner grew a richer exit map. It also meant a crashed scanner, a missing
file and a poisoned README were all reported to the user's PR with the same
sentence.

So we read the scanner's own JSON document and treat the exit code as a hint,
not as the meaning. Anything we cannot positively classify is an operational
failure, never a finding: the Action must be able to say "I did not look at
this" without saying "this is an attack".

Version compatibility (measured 2026-09-06 against both builds, see tests/)
--------------------------------------------------------------------------
* `--json` is the flag we use. On the published 0.5.5 `--output json` is
  silently ignored and prints the human screen; `--json` emits a real document
  on both builds. Do not "modernise" this to `--output json`.
* 0.5.5 documents: event_id, decision, severity, channel, truncated,
  bytes_scanned, extraction_complete, extraction_warnings, findings_count,
  patterns_fired, findings, latency_ms, source.
* 0.5.6 adds the explicit axes: threat_found, inspection_complete, is_clean,
  and an error document {error, hint, scanned, exit_code, ...}.
  We prefer the explicit axes and fall back to deriving them, so the Action
  works on the version CI installs today and on the one being published.
"""

from __future__ import annotations

import json
import sys

# The scanner's exit map (v0.5.6). Older builds use a subset; we never rely on
# these alone, they only break ties.
EXIT_CLEAN, EXIT_THREAT, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3

# Verdict kinds the Action understands.
CLEAN, THREAT, INCOMPLETE, ERROR = "clean", "threat", "incomplete", "error"


def _first_json_object(raw: str):
    """Return the scanner's JSON document, or None if it did not emit one.

    A crash prints a traceback to stderr and nothing to stdout; a build that
    ignores the format flag prints an ANSI human screen. Both land here as
    None, which the caller turns into an operational failure rather than a
    finding.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _reasons(doc: dict) -> list:
    """Human-readable reasons the scan was not complete, in the scanner's words."""
    out = []
    for warning in doc.get("extraction_warnings") or []:
        if isinstance(warning, str) and warning.strip():
            out.append(warning.strip())
    if doc.get("truncated"):
        scanned = doc.get("bytes_scanned")
        out.append(
            "only the first %s bytes were scanned" % scanned
            if isinstance(scanned, int)
            else "the file was truncated before the end was scanned"
        )
    err = doc.get("error")
    if isinstance(err, str) and err.strip():
        out.append(err.strip())
    hint = doc.get("hint")
    if isinstance(hint, str) and hint.strip():
        out.append(hint.strip())
    return out


def _threat_found(doc: dict) -> bool:
    """Prefer the explicit axis; derive it on builds that lack one."""
    if isinstance(doc.get("threat_found"), bool):
        return doc["threat_found"]
    count = doc.get("findings_count")
    if isinstance(count, int):
        return count > 0
    findings = doc.get("findings")
    if isinstance(findings, list):
        return len(findings) > 0
    return str(doc.get("decision", "")).lower() in ("block", "deny")


def _inspection_complete(doc: dict):
    """True / False, or None when this build cannot tell us.

    None matters: on 0.5.5 an uninspected ZIP reports extraction_complete=true,
    so we must not dress a guess up as knowledge.
    """
    if isinstance(doc.get("inspection_complete"), bool):
        return doc["inspection_complete"]
    parts = []
    if isinstance(doc.get("extraction_complete"), bool):
        parts.append(doc["extraction_complete"])
    if isinstance(doc.get("truncated"), bool):
        parts.append(not doc["truncated"])
    if not parts:
        return None
    return all(parts)


def classify(exit_code: int, stdout: str, path: str) -> dict:
    """Return {kind, reasons, detail, exit_code, path, findings_count}."""
    doc = _first_json_object(stdout)

    if doc is None:
        # No parseable document. Never a finding: we do not know what happened,
        # and "I could not read the scanner" must not become "this file attacks
        # your agent". This is the branch that catches an uncaught traceback,
        # which exits 1 -- the same code as a real threat.
        return {
            "kind": ERROR,
            "path": path,
            "exit_code": exit_code,
            "findings_count": 0,
            "reasons": [
                "the scanner produced no readable result (exit %d)" % exit_code
            ],
            "detail": "",
        }

    # An explicit error document, whatever the exit code says.
    if doc.get("error") or doc.get("scanned") is False:
        return {
            "kind": ERROR,
            "path": path,
            "exit_code": exit_code,
            "findings_count": 0,
            "reasons": _reasons(doc) or ["the scanner reported an error"],
            "detail": "",
        }

    if exit_code == EXIT_USAGE:
        return {
            "kind": ERROR,
            "path": path,
            "exit_code": exit_code,
            "findings_count": 0,
            "reasons": _reasons(doc) or ["usage or operational error"],
            "detail": "",
        }

    count = doc.get("findings_count")
    count = count if isinstance(count, int) else len(doc.get("findings") or [])

    # A threat outranks incompleteness: finding something is still finding it,
    # and the user needs to see it. The reasons list still carries the
    # incompleteness so the summary can say both.
    if _threat_found(doc):
        return {
            "kind": THREAT,
            "path": path,
            "exit_code": exit_code,
            "findings_count": count,
            "reasons": _reasons(doc),
            "detail": _describe_findings(doc),
        }

    complete = _inspection_complete(doc)
    if exit_code == EXIT_INCOMPLETE or complete is False:
        return {
            "kind": INCOMPLETE,
            "path": path,
            "exit_code": exit_code,
            "findings_count": 0,
            "reasons": _reasons(doc) or ["the file was not fully inspected"],
            "detail": "",
        }

    if exit_code != EXIT_CLEAN:
        # Non-zero we have no name for. Conservative by construction.
        return {
            "kind": ERROR,
            "path": path,
            "exit_code": exit_code,
            "findings_count": 0,
            "reasons": ["unexpected scanner exit code %d" % exit_code],
            "detail": "",
        }

    return {
        "kind": CLEAN,
        "path": path,
        "exit_code": exit_code,
        "findings_count": 0,
        "reasons": [],
        "detail": "",
    }


def _describe_findings(doc: dict) -> str:
    """A compact, plain-text finding list for the job summary."""
    lines = []
    for finding in (doc.get("findings") or [])[:20]:
        if not isinstance(finding, dict):
            continue
        pid = finding.get("id") or finding.get("pattern_id") or ""
        sev = str(finding.get("severity", "")).upper()
        name = finding.get("name") or finding.get("title") or finding.get("category") or ""
        bits = [b for b in ("[%s]" % sev if sev else "", name, "(%s)" % pid if pid else "") if b]
        if bits:
            lines.append(" ".join(bits))
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: classify.py <exit_code> <path>  (scanner stdout on stdin)\n")
        return 2
    try:
        code = int(sys.argv[1])
    except ValueError:
        code = -1
    verdict = classify(code, sys.stdin.read(), sys.argv[2])
    json.dump(verdict, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
