#!/usr/bin/env python3
"""Render the canonical *Installed block* out of agentic-security-playbook.md
into the committed artifact dist/agent-security-policy.md.

Single canonical source = the column-zero `<!-- BEGIN agentic-security-playbooks
vN -->` ... `<!-- END ... vN -->` span inside the playbook (the same block the
Install section tells an agent to write into AGENTS.md / CLAUDE.md). Runtimes
that install policy from a file (e.g. `coble policy install ./dist/agent-security
-policy.md`) read the rendered artifact, so it must stay byte-identical to the
block embedded in the doc.

Modes:
  render-policy.py            Write dist/agent-security-policy.md (mkdir dist/).
  render-policy.py --check    Byte-compare the artifact to the embedded block;
                              nonzero exit on drift or a missing artifact.

The indented marker EXAMPLE in the Install steps is ignored: only column-zero
markers are the real block.

The extraction/compare logic is exposed as importable functions (`extract_block`,
`render`) that raise `RenderError` instead of exiting, so tests can exercise the
failure modes without driving the process. `main()` is the CLI wrapper.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLAYBOOK = REPO / "agentic-security-playbook.md"
ARTIFACT = REPO / "dist" / "agent-security-policy.md"

# Column-zero markers only (`^...$` with MULTILINE). The indented example in the
# Install steps has leading whitespace and is deliberately not matched.
BEGIN_RE = re.compile(r"^<!-- BEGIN agentic-security-playbooks (v\d+) -->$", re.MULTILINE)
END_RE = re.compile(r"^<!-- END agentic-security-playbooks (v\d+) -->$", re.MULTILINE)
BLOCK_RE = re.compile(
    r"^<!-- BEGIN agentic-security-playbooks (v\d+) -->$"
    r".*?"
    r"^<!-- END agentic-security-playbooks (v\d+) -->$",
    re.MULTILINE | re.DOTALL,
)


class RenderError(Exception):
    """Raised when the block can't be extracted or the artifact has drifted."""


def extract_block(text: str, *, source: str = "the playbook") -> str:
    """Return the single column-zero Installed block, markers included, with a
    single trailing newline. Raise RenderError unless exactly one well-formed
    block with matching BEGIN/END versions exists."""
    begins = BEGIN_RE.findall(text)
    ends = END_RE.findall(text)
    if len(begins) != 1 or len(ends) != 1:
        raise RenderError(
            f"expected exactly one column-zero BEGIN and END marker in {source}, "
            f"found {len(begins)} BEGIN / {len(ends)} END"
        )
    if begins[0] != ends[0]:
        raise RenderError(
            f"marker version mismatch in {source}: BEGIN {begins[0]!r} vs END {ends[0]!r}"
        )
    matches = list(BLOCK_RE.finditer(text))
    if len(matches) != 1:
        raise RenderError(
            f"expected exactly one BEGIN..END span in {source}, found {len(matches)} "
            f"(markers may be crossed or out of order)"
        )
    return matches[0].group(0).rstrip("\n") + "\n"


def _rel(path: Path) -> Path | str:
    try:
        return path.relative_to(REPO)
    except ValueError:
        return path


def render(*, check: bool, playbook: Path = PLAYBOOK, artifact: Path = ARTIFACT) -> str:
    """Render or verify the artifact. Return a status line; raise RenderError on
    failure (missing/drifted artifact, or an unextractable block)."""
    block = extract_block(playbook.read_text(encoding="utf-8"), source=playbook.name)
    version = BEGIN_RE.search(block).group(1)
    nlines = block.count("\n")
    rel = _rel(artifact)

    if check:
        if not artifact.exists():
            raise RenderError(f"{rel} is missing — run scripts/render-policy.py to generate it")
        if artifact.read_text(encoding="utf-8") != block:
            raise RenderError(
                f"{rel} is out of sync with the {version} Installed block in "
                f"{playbook.name} — run scripts/render-policy.py"
            )
        return f"{rel} in sync with {playbook.name} Installed block ({version}, {nlines} lines)"

    artifact.parent.mkdir(parents=True, exist_ok=True)
    unchanged = artifact.exists() and artifact.read_text(encoding="utf-8") == block
    artifact.write_text(block, encoding="utf-8")
    status = "unchanged" if unchanged else "wrote"
    return f"{status} {rel} from {playbook.name} Installed block ({version}, {nlines} lines)"


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    check = "--check" in argv
    unknown = [a for a in argv if a != "--check"]
    if unknown:
        sys.exit(f"error: unknown argument(s): {unknown} (use --check or no args)")
    try:
        print(render(check=check))
    except RenderError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
