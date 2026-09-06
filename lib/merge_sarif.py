#!/usr/bin/env python3
"""Fold the per-file SARIF documents into one run.

GitHub code scanning rejects multiple runs sharing a category (changelog
2025-07-21), so every per-file run is folded into a single run: the first run's
tool, the concatenated results, and de-duplicated rules.

Only files the Action classified as THREAT get a SARIF document in the first
place (see entrypoint.sh). That is deliberate and is the v1.1 rule: a file we
could not inspect, or that made the scanner fail, must never arrive in the
security tab as a finding. "I did not read this" is a coverage fact about the
run and belongs in the annotations and the job summary; a SARIF result is a
security alert with a lifecycle (dismiss / fix), and filing one for a file we
never read makes the security tab lie in the other direction.

Usage: merge_sarif.py <dir-of-sarif-files>   -> merged document on stdout
"""

from __future__ import annotations

import glob
import json
import os
import sys

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# A run with zero results is NOT the same as no runs at all. Code scanning uses
# an empty run to mark previously-reported alerts as fixed; uploading `runs: []`
# leaves stale alerts standing forever. v1 never hit this because it generated a
# SARIF document for every file (a second full scan each); v1.1 only scans again
# for actual findings, so the empty case has to be synthesised here.
def _empty_run(version: str = "2.1.0") -> dict:
    return {
        "$schema": SCHEMA,
        "version": version,
        "runs": [
            {
                "tool": {"driver": {"name": "Sunglasses", "informationUri": "https://sunglasses.dev", "rules": []}},
                "results": [],
            }
        ],
    }


EMPTY = _empty_run()


def merge(directory: str) -> dict:
    base = None
    results = []
    rules = []
    seen = set()
    schema = None
    version = "2.1.0"

    for path in sorted(glob.glob(os.path.join(directory, "*.sarif"))):
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (ValueError, OSError):
            # A malformed or unreadable per-file document is dropped rather
            # than allowed to abort the merge; the file's verdict is already
            # carried by the annotations and the summary.
            continue
        if not isinstance(doc, dict):
            continue
        schema = doc.get("$schema", schema)
        version = doc.get("version", version)
        for run in doc.get("runs", []):
            if base is None:
                base = run
            results.extend(run.get("results", []))
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id")
                if rule_id not in seen:
                    seen.add(rule_id)
                    rules.append(rule)

    if base is None:
        return _empty_run(version)

    base["results"] = results
    base.setdefault("tool", {}).setdefault("driver", {})["rules"] = rules
    out = {"version": version, "runs": [base]}
    if schema:
        out["$schema"] = schema
    return out


def main() -> int:
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    try:
        json.dump(merge(directory), sys.stdout)
    except Exception:  # never let the merge fail the job on its own
        json.dump(_empty_run(), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
