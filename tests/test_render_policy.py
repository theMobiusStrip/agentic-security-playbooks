"""Tests for scripts/render-policy.py — the generator that keeps
dist/agent-security-policy.md byte-identical to the playbook's *Installed block*.

The drift pre-commit hook proves `dist == block`; these tests prove the checker
itself can't silently rot (wrong span extracted, --check passing while drifted,
partial/crossed markers emitted). Plus a doc-consistency guard (P3b).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "render-policy.py"
PLAYBOOK = REPO / "agentic-security-playbook.md"
ARTIFACT = REPO / "dist" / "agent-security-policy.md"

# The script's filename has a hyphen, so import it by path.
_spec = importlib.util.spec_from_file_location("render_policy", SCRIPT)
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)


def _block(version: str = "v1", body: str = "# Agent security policy\nbody line\n") -> str:
    return (
        f"<!-- BEGIN agentic-security-playbooks {version} -->\n"
        f"{body}"
        f"<!-- END agentic-security-playbooks {version} -->"
    )


def _doc(block: str, *, with_example: bool = True) -> str:
    """Wrap a block in playbook-like prose, optionally including the INDENTED
    marker example the real Install steps carry (which must be ignored)."""
    example = (
        "       <!-- BEGIN agentic-security-playbooks v1 -->\n"
        "       ...\n"
        "       <!-- END agentic-security-playbooks v1 -->\n\n"
        if with_example
        else ""
    )
    return f"# Playbook\n\nintro\n\n{example}```markdown\n{block}\n```\n\npost\n"


def _write_doc(tmp_path: Path, block: str) -> Path:
    pb = tmp_path / "playbook.md"
    pb.write_text(_doc(block), encoding="utf-8")
    return pb


# --- extract_block: span selection + malformed-input refusal ---


def test_extract_ignores_indented_example():
    block = _block()
    out = rp.extract_block(_doc(block, with_example=True))
    assert out.strip() == block.strip()
    assert "..." not in out  # the indented example body was not captured


def test_extract_zero_blocks():
    with pytest.raises(rp.RenderError):
        rp.extract_block("# nothing here\n")


def test_extract_two_blocks():
    text = _doc(_block()) + "\n```markdown\n" + _block() + "\n```\n"
    with pytest.raises(rp.RenderError):
        rp.extract_block(text)


def test_extract_version_mismatch():
    text = (
        "<!-- BEGIN agentic-security-playbooks v1 -->\nbody\n"
        "<!-- END agentic-security-playbooks v2 -->\n"
    )
    with pytest.raises(rp.RenderError):
        rp.extract_block(text)


def test_extract_crossed_markers():
    text = (
        "<!-- END agentic-security-playbooks v1 -->\nbody\n"
        "<!-- BEGIN agentic-security-playbooks v1 -->\n"
    )
    with pytest.raises(rp.RenderError):
        rp.extract_block(text)


def test_extract_only_begin():
    with pytest.raises(rp.RenderError):
        rp.extract_block("<!-- BEGIN agentic-security-playbooks v1 -->\nbody no end\n")


def test_extract_single_trailing_newline():
    out = rp.extract_block(_doc(_block()))
    assert out.endswith("-->\n")
    assert not out.endswith("\n\n")


# --- render(): check / write modes on temp files ---


def test_render_check_in_sync(tmp_path):
    pb = _write_doc(tmp_path, _block())
    art = tmp_path / "dist" / "art.md"
    rp.render(check=False, playbook=pb, artifact=art)
    assert "in sync" in rp.render(check=True, playbook=pb, artifact=art)


def test_render_check_missing(tmp_path):
    pb = _write_doc(tmp_path, _block())
    art = tmp_path / "dist" / "art.md"
    with pytest.raises(rp.RenderError) as e:
        rp.render(check=True, playbook=pb, artifact=art)
    assert "missing" in str(e.value)


def test_render_check_drift(tmp_path):
    block = _block()
    pb = _write_doc(tmp_path, block)
    art = tmp_path / "dist" / "art.md"
    art.parent.mkdir(parents=True)
    art.write_text(rp.extract_block(_doc(block)) + "tampered", encoding="utf-8")
    with pytest.raises(rp.RenderError) as e:
        rp.render(check=True, playbook=pb, artifact=art)
    assert "out of sync" in str(e.value)


def test_render_write_idempotent(tmp_path):
    block = _block()
    pb = _write_doc(tmp_path, block)
    art = tmp_path / "dist" / "art.md"
    assert rp.render(check=False, playbook=pb, artifact=art).startswith("wrote")
    assert rp.render(check=False, playbook=pb, artifact=art).startswith("unchanged")
    assert art.read_text(encoding="utf-8") == rp.extract_block(_doc(block))


# --- integration against the committed repo ---


def test_committed_artifact_matches_block():
    block = rp.extract_block(PLAYBOOK.read_text(encoding="utf-8"), source=PLAYBOOK.name)
    assert ARTIFACT.read_text(encoding="utf-8") == block


def test_cli_check_clean():
    r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_cli_unknown_arg_fails():
    r = subprocess.run([sys.executable, str(SCRIPT), "--bogus"], capture_output=True, text=True)
    assert r.returncode != 0
    assert "unknown argument" in (r.stderr + r.stdout)


# --- doc consistency (P3b): docs reference the artifact path that exists ---


def test_docs_reference_existing_artifact():
    rel = "dist/agent-security-policy.md"
    assert ARTIFACT.exists()
    assert rel in (REPO / "README.md").read_text(encoding="utf-8")
    assert rel in PLAYBOOK.read_text(encoding="utf-8")
