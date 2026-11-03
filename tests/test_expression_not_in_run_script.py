"""Static check: no expression other than the action path is expanded inside a run script.

GitHub replaces `${{ ... }}` with the raw text before bash reads the script, so an input,
event field, branch name or step output placed there becomes code. Everything caller-
controlled has to reach a script through `env:` and be read as `$NAME`. The one expression
allowed in a script is `github.action_path`, which the runner sets and a caller cannot.

The rule is an allowlist on the whole expression, not a prefix match, so nested and
bracketed forms such as `format('{0}', inputs.version)`, `inputs['version']`,
`toJSON(inputs)` or `fromJSON(inputs.x).y` are caught too.
"""
import re
from pathlib import Path

import pytest
import yaml

ACTION = Path(__file__).resolve().parent.parent / "action.yml"
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
ALLOWED_IN_SCRIPT = {"github.action_path"}


def unsafe_expressions(script: str):
    """Every expression in `script` other than the allowed runner-set ones."""
    return [e.strip() for e in EXPRESSION.findall(script) if e.strip() not in ALLOWED_IN_SCRIPT]


def _run_scripts():
    doc = yaml.safe_load(ACTION.read_text())
    for step in doc["runs"]["steps"]:
        if "run" in step:
            yield step.get("name", "<unnamed>"), step["run"]


def test_only_the_action_path_is_expanded_inside_a_run_script():
    found = [(name, e) for name, script in _run_scripts() for e in unsafe_expressions(script)]
    assert not found, f"expressions expanded inside run scripts (shell injection sink): {found}"


def test_there_is_at_least_one_run_script_to_check():
    assert [name for name, _ in _run_scripts()], "action.yml has no run steps: the check would pass on nothing"


@pytest.mark.parametrize("script", [
    'pip install "sunglasses${{ inputs.version }}"',
    "echo ${{ inputs['version'] }}",
    'echo ${{ inputs["version"] }}',
    "echo ${{ format('{0}', inputs.version) }}",
    "echo ${{ toJSON(inputs) }}",
    "echo ${{ fromJSON(inputs.x).y }}",
    "echo ${{ github.event.pull_request.title }}",
    "echo ${{ github.head_ref }}",
    "echo ${{ env.FOO }}",
    "echo ${{ steps.a.outputs.b }}",
    "echo ${{\n  inputs.version\n}}",
    "echo ${{ github.action_path }} ${{ inputs.version }}",
    "echo ${{ github.action_path || inputs.version }}",
])
def test_the_check_sees_a_caller_controlled_expression_in_any_shape(script):
    assert unsafe_expressions(script), script


def test_the_check_lets_the_action_path_through():
    assert unsafe_expressions('bash "${{ github.action_path }}/entrypoint.sh"') == []
