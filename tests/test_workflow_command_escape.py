"""Values written into a workflow-command line (`::error::...`) are escaped.

The runner reads a command from the start of any output line. A path or a scanner reason
that carries a newline can start a second command; a `%`, `,` or `:` in a `file=` value
changes which property it is. `lib/gh_escape.sh` is the one helper; this file checks
 1. the helper's output (unit),
 2. that no `::` emission in entrypoint.sh or action.yml carries an unescaped variable (static),
 3. that the real entrypoint, run with a stub scanner, never lets a path, a glob or a
    scanner reason start a command of its own (dynamic).
"""
import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "lib" / "gh_escape.sh"
ENTRYPOINT = ROOT / "entrypoint.sh"
ACTION = ROOT / "action.yml"
COMMAND = re.compile(r"::(?:error|warning|notice|debug|group|endgroup|add-mask|set-output|set-env|"
                     r"stop-commands|save-state|add-path|echo)\b")
ESCAPED = re.compile(r'\$\(gh_escape(?: -p)? "[^"]*"\)')


def gh_escape(value: str, prop: bool = False) -> str:
    flag = "-p " if prop else ""
    script = f'. "{LIB}"; gh_escape {flag}"$V"'
    out = subprocess.run(["bash", "-c", script], env={"V": value, "PATH": os.environ["PATH"]},
                         capture_output=True, text=True, check=True)
    return out.stdout


# ---------------------------------------------------------------- 1. the helper --
@pytest.mark.parametrize("value, message, prop", [
    ("plain.md", "plain.md", "plain.md"),
    ("", "", ""),
    ("100%", "100%25", "100%25"),
    ("a\nb", "a%0Ab", "a%0Ab"),
    ("a\rb", "a%0Db", "a%0Db"),
    ("a\r\nb", "a%0D%0Ab", "a%0D%0Ab"),
    ("a,b", "a,b", "a%2Cb"),
    ("a:b", "a:b", "a%3Ab"),
    ("%0A", "%250A", "%250A"),
    ("x\n::error::y", "x%0A::error::y", "x%0A%3A%3Aerror%3A%3Ay"),
    ("trailing\n", "trailing%0A", "trailing%0A"),
])
def test_helper_escapes_message_and_property_values(value, message, prop):
    assert gh_escape(value) == message
    assert gh_escape(value, prop=True) == prop


def test_helper_output_has_no_raw_newline_or_carriage_return():
    for v in ["a\nb", "\n\n", "a\r\n", "\r"]:
        for p in (False, True):
            out = gh_escape(v, prop=p)
            assert "\n" not in out and "\r" not in out


# ------------------------------------------------------------------- 2. static --
def _emission_lines(path: Path):
    for no, line in enumerate(path.read_text().splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if COMMAND.search(line):
            yield no, line


def unescaped_expansions(line: str):
    """`$` expansions left on a command line once the gh_escape calls are taken out."""
    return re.findall(r"\$[{(A-Za-z_0-9@*#?!-]", ESCAPED.sub("", line))


def test_every_command_line_escapes_every_variable():
    bad = []
    for path in (ENTRYPOINT, ACTION):
        for no, line in _emission_lines(path):
            if unescaped_expansions(line):
                bad.append(f"{path.name}:{no}: {line.strip()}")
    assert not bad, "unescaped expansion on a workflow-command line:\n" + "\n".join(bad)


def test_the_entrypoint_loads_the_helper_and_uses_it():
    text = ENTRYPOINT.read_text()
    assert '. "$HERE/lib/gh_escape.sh"' in text
    assert len([1 for _ in _emission_lines(ENTRYPOINT)]) == 4
    assert text.count("gh_escape") >= 7


@pytest.mark.parametrize("line", [
    'echo "::warning::could not scan $g"',
    'echo "::error file=$f::bad"',
    'echo "::error file=$(gh_escape -p "$f")::bad $f"',
    'echo "::warning::${reason:-x}"',
    'echo "::error::$(gh_escape "$a") and $(id)"',
])
def test_the_static_check_flags_an_unescaped_variable(line):
    assert unescaped_expansions(line), line


@pytest.mark.parametrize("line", [
    'echo "::warning::could not scan $(gh_escape "$g")"',
    'echo "::error file=$(gh_escape -p "$f")::bad $(gh_escape "${reason:-x}")"',
    'echo "::error::version must be a pip version specifier such as ==0.5.6; refusing the given value"',
])
def test_the_static_check_passes_an_escaped_line(line):
    assert not unescaped_expansions(line), line


# ------------------------------------------------------------------ 3. dynamic --
STUB = textwrap.dedent('''\
    #!/usr/bin/env bash
    # stub scanner: first arg `scan`, then --file F --json (or --output sarif)
    case "$STUB_MODE" in
      error)      printf '%s' '{"error":"bad\\n::warning::injected-by-reason 100%","scanned":false}'; exit 2 ;;
      incomplete) printf '%s' '{"threat_found":false,"inspection_complete":false,"extraction_warnings":["w\\n::error::injected-by-warning, 5%"]}'; exit 3 ;;
      threat)     printf '%s' '{"threat_found":true,"findings_count":1,"findings":[]}'; exit 1 ;;
      *)          printf '%s' '{"threat_found":false,"inspection_complete":true}'; exit 0 ;;
    esac
    ''')

NASTY_NAMES = [
    "pct%41.md",
    "comma,colon:name.md",
    "::notice::lead.md",
    "nl\n::error::injected-by-name.md",
    "cr\r::warning::injected-cr.md",
]


def _run_entrypoint(tmp: Path, mode: str, paths=None):
    stub = tmp / "stub-scanner"
    stub.write_text(STUB)
    stub.chmod(0o755)
    work = tmp / "repo"
    work.mkdir()
    for n in NASTY_NAMES:
        (work / n).write_text("hello\n")
    env = {
        "PATH": os.environ["PATH"], "HOME": str(tmp), "TMPDIR": str(tmp),
        "SUNGLASSES_BIN": str(stub), "STUB_MODE": mode,
        "GITHUB_STEP_SUMMARY": str(tmp / "summary.md"),
        "INPUT_FAIL_ON_THREAT": "true", "INPUT_FAIL_ON_INCOMPLETE": "true",
    }
    if paths is not None:
        env["INPUT_PATHS"] = paths
    proc = subprocess.run(["bash", str(ENTRYPOINT)], cwd=work, env=env,
                          capture_output=True, text=True, timeout=60)
    return proc


def _command_lines(stdout: str):
    return [l for l in stdout.split("\n") if l.startswith("::")]


def _assert_only_our_commands(stdout: str, expected_min: int):
    cmds = _command_lines(stdout)
    assert len(cmds) >= expected_min, stdout
    for l in cmds:
        m = re.match(r"^::(error|warning)(?: file=([^:,]*))?::(.*)$", l)
        assert m, f"unexpected command line: {l!r}"
    # nothing a value carried may start a command of its own
    for marker in ("injected-by-name", "injected-cr", "injected-by-reason", "injected-by-warning"):
        for l in stdout.replace("\r", "\n").split("\n"):
            assert not (l.startswith("::") and marker in l and not re.match(r"^::(error|warning) file=[^:,]*::", l) and not l.startswith("::error::Sunglasses") and not l.startswith("::warning::Sunglasses")), l
    assert "\n::notice::" not in "\n" + stdout.replace("\r", "\n")
    assert not re.search(r"(^|[\r\n])::(?:notice|set-output|add-mask|stop-commands)", stdout)


@pytest.mark.parametrize("mode", ["error", "incomplete", "threat"])
def test_a_path_or_reason_never_starts_a_command_of_its_own(tmp_path, mode):
    proc = _run_entrypoint(tmp_path, mode)
    out = proc.stdout
    # discovered names with a newline are split into separate list entries; each of
    # the (at least) five entries yields exactly one command line
    _assert_only_our_commands(out, expected_min=len(NASTY_NAMES))
    # a bare carriage return ends a line for the runner too: none may survive
    assert "\r" not in out
    # property values carry no raw ':' or ',' ; the escapes are present for the names
    props = [re.match(r"^::(?:error|warning) file=([^:]*)::", l).group(1) for l in _command_lines(out)]
    assert any("%2C" in p and "%3A" in p for p in props), props
    assert any(p.startswith("%3A%3Anotice%3A%3A") for p in props), props
    assert any("pct%2541.md" == p for p in props), props


def test_an_unfound_explicit_path_is_escaped(tmp_path):
    proc = _run_entrypoint(tmp_path, "clean", paths="no%0Asuch,x:y.md 100%.md")
    out = proc.stdout
    warn = [l for l in _command_lines(out) if "could not scan" in l]
    assert len(warn) == 2, out
    assert any("'no%250Asuch,x:y.md'" in l for l in warn), warn
    assert any("'100%25.md'" in l for l in warn), warn
    assert not re.search(r"(^|[\r\n])::(?!warning::Sunglasses could not scan)", out), out
    # the run still fails the check for the unscanned files (default fail-on-incomplete)
    assert proc.returncode == 1


def test_plain_names_are_unchanged(tmp_path):
    work = tmp_path / "repo"
    work.mkdir()
    (work / "README.md").write_text("hello\n")
    stub = tmp_path / "stub-scanner"
    stub.write_text(STUB)
    stub.chmod(0o755)
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
           "SUNGLASSES_BIN": str(stub), "STUB_MODE": "error",
           "GITHUB_STEP_SUMMARY": str(tmp_path / "s.md")}
    proc = subprocess.run(["bash", str(ENTRYPOINT)], cwd=work, env=env,
                          capture_output=True, text=True, timeout=60)
    lines = _command_lines(proc.stdout)
    assert len(lines) >= 1
    assert lines[0].startswith("::error file=README.md::Sunglasses could not scan README.md ("), lines[0]
