"""Lab findings G1, G2, G3 and G6: files the entrypoint skipped without saying so.

Each test builds a small repo in a temporary directory and runs the real entrypoint.sh
with the real scanner, the way the Action does after checkout. A file the scan could not
open has to land in a bucket (threat, not inspected or failed), and a run that could not
start has to fail instead of passing over an empty list.

G1  a symlinked agent file was never listed, so the scan passed over it
G2  a file name holding a newline split the list in two, so the file was never opened
G3  .cursorrules, .clinerules, .windsurfrules and llms.txt were not in the default set
G6  a failed mktemp left the work directory empty and the check passed with nothing scanned
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "entrypoint.sh"
THREAT = (ROOT / "tests/fixtures/threat/README.md").read_text()
CLEAN = (ROOT / "tests/fixtures/clean/README.md").read_text()
SCANNER = os.environ.get("SUNGLASSES_BIN") or shutil.which("sunglasses")

pytestmark = pytest.mark.skipif(SCANNER is None, reason="needs the sunglasses scanner on PATH")


def run(repo: Path, paths: str = "", extra_env=None, path_prefix=None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo),
        "SUNGLASSES_BIN": SCANNER,
        "GITHUB_STEP_SUMMARY": "/dev/null",
        "INPUT_PATHS": paths,
    }
    if path_prefix:
        env["PATH"] = f"{path_prefix}:{env['PATH']}"
    env.update(extra_env or {})
    proc = subprocess.run(["bash", str(ENTRYPOINT)], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=120)
    return proc, proc.stdout + proc.stderr


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "README.md").write_text(CLEAN)
    return tmp_path


def test_a_clean_repo_still_passes(repo):
    proc, out = run(repo)
    assert proc.returncode == 0, out
    assert "1 inspected, 0 with findings, 0 not inspected, 0 failed" in out


# ---- G1: symlinks ----------------------------------------------------------------
def _link_repo(repo):
    (repo / "docs").mkdir()
    (repo / "assets").mkdir()
    (repo / "assets/payload.bin").write_text(THREAT)
    (repo / "docs/guide.md").symlink_to("../assets/payload.bin")


def test_default_set_scans_a_symlinked_markdown_file(repo):
    _link_repo(repo)
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "docs/guide.md" in out and "2 inspected, 1 with findings" in out, out


def test_a_directory_in_paths_scans_a_symlinked_file(repo):
    _link_repo(repo)
    proc, out = run(repo, "docs/")
    assert proc.returncode == 1, out
    assert "docs/guide.md" in out, out


def test_an_explicit_symlink_path_is_scanned(repo):
    _link_repo(repo)
    proc, out = run(repo, "docs/guide.md")
    assert proc.returncode == 1, out


def test_a_broken_symlink_is_reported_not_inspected(repo):
    (repo / "docs").mkdir()
    (repo / "docs/guide.md").symlink_to("../assets/missing.md")
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "docs/guide.md" in out and "NOT inspected" in out and "1 not inspected" in out, out


def test_a_symlink_to_a_directory_is_reported_not_followed(repo):
    (repo / "real").mkdir()
    (repo / "real/note.md").write_text(CLEAN)
    (repo / "docs.md").symlink_to("real")
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "docs.md" in out and "1 not inspected" in out, out


def test_a_symlink_that_leaves_the_workspace_is_reported_not_inspected(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.md"
    outside.write_text(CLEAN)
    (repo / "docs").mkdir()
    (repo / "docs/guide.md").symlink_to(outside)
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "docs/guide.md" in out and "1 not inspected" in out, out


# ---- G2: newline in a file name ------------------------------------------------------
def test_a_file_name_holding_a_newline_is_still_scanned(repo):
    (repo / "x").write_text("plain\n")
    (repo / "x\nREADME.md").write_text(THREAT)
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "1 with findings" in out, out


def test_a_clean_file_with_a_newline_in_its_name_is_counted_once(repo):
    (repo / "a\nb.md").write_text(CLEAN)
    proc, out = run(repo)
    assert proc.returncode == 0, out
    assert "2 inspected, 0 with findings, 0 not inspected, 0 failed" in out, out


# ---- G3: default set ------------------------------------------------------------------
@pytest.mark.parametrize("name", [".cursorrules", ".clinerules", ".windsurfrules", "llms.txt"])
def test_default_set_covers_agent_rules_files(repo, name):
    (repo / name).write_text(THREAT)
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert name in out, out


# ---- G6: work directory ---------------------------------------------------------------
def _mktemp_shim(tmp_path, body):
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "mktemp"
    shim.write_text("#!/bin/sh\n" + body + "\n")
    shim.chmod(0o755)
    return str(shim_dir)


def test_a_failed_mktemp_does_not_produce_a_green_check(repo, tmp_path_factory):
    (repo / "README.md").write_text(THREAT)
    shim = _mktemp_shim(tmp_path_factory.mktemp("s"), "echo 'mktemp: failed' >&2; exit 1")
    proc, out = run(repo, path_prefix=shim)
    assert proc.returncode == 2, out
    assert "Nothing was scanned" in out, out


def test_a_work_directory_that_does_not_exist_does_not_produce_a_green_check(repo, tmp_path_factory):
    (repo / "README.md").write_text(THREAT)
    shim = _mktemp_shim(tmp_path_factory.mktemp("s"), "echo /nonexistent/work")
    proc, out = run(repo, path_prefix=shim)
    assert proc.returncode == 2, out


def test_a_broken_top_level_symlink_is_counted_once(repo):
    (repo / "README.md").unlink()
    (repo / "README.md").symlink_to("gone.md")
    proc, out = run(repo)
    assert proc.returncode == 1, out
    assert "0 inspected, 0 with findings, 1 not inspected" in out, out
