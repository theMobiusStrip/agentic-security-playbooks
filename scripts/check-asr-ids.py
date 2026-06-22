#!/usr/bin/env python3
"""Assert every `rule_id:` in validation/cases.yml refers to an ASR-NNN that
exists in agentic-security-playbook.md. Catches silent breakage when a rule is
renamed or removed without updating cases.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:
    sys.exit("error: PyYAML required (pip install pyyaml)")

REPO = Path(__file__).resolve().parent.parent
PLAYBOOK = REPO / "agentic-security-playbook.md"
CASES = REPO / "validation" / "cases.yml"


def main() -> None:
    playbook_text = PLAYBOOK.read_text(encoding="utf-8")
    # ASR ids appear in the installed-block rule table — match the table form
    # `| ASR-NNN |` so we only count real rule-row entries, not prose mentions.
    declared = set(re.findall(r"^\|\s*(ASR-\d{3})\s*\|", playbook_text, re.MULTILINE))
    if not declared:
        sys.exit(f"error: no ASR ids found in {PLAYBOOK.name} rule table")

    cases = yaml.safe_load(CASES.read_text(encoding="utf-8")) or {}
    case_list = cases.get("cases", []) if isinstance(cases, dict) else cases
    if not isinstance(case_list, list):
        sys.exit(f"error: {CASES.relative_to(REPO)} top-level shape unexpected")

    referenced: dict[str, list[str]] = {}
    for c in case_list:
        if not isinstance(c, dict):
            continue
        rid = c.get("rule_id") or c.get("rule")
        if not rid:
            continue
        referenced.setdefault(rid, []).append(c.get("id", "<no-id>"))

    missing = {rid: ids for rid, ids in referenced.items() if rid not in declared}
    if missing:
        lines = [
            f"{rid} (used by: {', '.join(case_ids)})" for rid, case_ids in missing.items()
        ]
        sys.exit(
            "error: validation cases reference unknown ASR ids:\n  - "
            + "\n  - ".join(lines)
            + f"\nDeclared in {PLAYBOOK.name}: {sorted(declared)}"
        )
    print(f"{CASES.relative_to(REPO)} → {len(referenced)} distinct rule ids, all present in {PLAYBOOK.name}")


if __name__ == "__main__":
    main()
