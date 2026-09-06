#!/usr/bin/env python3
"""Assert the merged SARIF alleges nothing about files we did not inspect.

Exits 0 when the document is clean by that rule, 1 when a file named on the
command line (default: the mixed fixture's uninspectable and unreadable files)
shows up as a SARIF result.

This is the machine-checkable half of the v1.1 SARIF rule: findings go to the
security tab, coverage facts do not. A "not inspected" file appearing as an
alert would be the v1 false accusation wearing a different hat.
"""

import json
import sys

DEFAULT_FORBIDDEN = ("archive.md", "unreadable.md")


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: sarif_guard.py <sunglasses.sarif> [forbidden basename ...]\n")
        return 2
    forbidden = set(sys.argv[2:]) or set(DEFAULT_FORBIDDEN)
    try:
        with open(sys.argv[1]) as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("could not read SARIF: %s\n" % exc)
        return 1

    for run in doc.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                uri = (
                    location.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
                if uri.rsplit("/", 1)[-1] in forbidden:
                    sys.stderr.write("SARIF alleges a finding in an uninspected file: %s\n" % uri)
                    return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
