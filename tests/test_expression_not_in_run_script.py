"""Lab finding C3, static check: no caller-controlled expression is expanded inside a run script.

GitHub replaces `${{ ... }}` with the raw text before bash reads the script, so an input,
event field or branch name placed there becomes code. Inputs have to reach a script through
`env:` and be read as `$NAME`. `github.action_path` is set by the runner, not by a caller,
and stays allowed.
"""
import re
from pathlib import Path

import yaml

ACTION = Path(__file__).resolve().parent.parent / "action.yml"
EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
CALLER_CONTROLLED = ("inputs.", "github.event", "github.head_ref", "github.ref_name", "env.")


def _run_scripts():
    doc = yaml.safe_load(ACTION.read_text())
    for step in doc["runs"]["steps"]:
        if "run" in step:
            yield step.get("name", "<unnamed>"), step["run"]


def test_no_caller_controlled_expression_inside_a_run_script():
    found = [(name, expr) for name, script in _run_scripts()
             for expr in EXPRESSION.findall(script)
             if expr.startswith(CALLER_CONTROLLED)]
    assert not found, f"expressions expanded inside run scripts (shell injection sink): {found}"


def test_the_check_sees_an_expression_when_one_is_present():
    script = 'pip install "sunglasses${{ inputs.version }}"'
    assert [e for e in EXPRESSION.findall(script) if e.startswith(CALLER_CONTROLLED)] == ["inputs.version"]
