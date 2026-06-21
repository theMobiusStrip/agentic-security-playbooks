#!/usr/bin/env python3
"""Render generated Markdown blocks from structured security-policy sources."""

import argparse
from collections import defaultdict
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("error: PyYAML required (pip install pyyaml)")

REPO = Path(__file__).resolve().parent.parent
RULES = REPO / "rules" / "agent-security-rules.yml"
CONSTITUTION = REPO / "policies" / "agent-security-constitution.md"
VALIDATION_CASES = REPO / "validation" / "cases.yml"
TARGETS = [REPO / "AGENTS.md", REPO / "CLAUDE.md"]
VALIDATION_TARGETS = [REPO / "validation" / "cases.md"]
RED_LINES = REPO / "rules" / "red-lines.yml"
DIGEST = REPO / "rules" / "policy-digest.md"
BEGIN = "<!-- BEGIN GENERATED:rules -->"
END = "<!-- END GENERATED:rules -->"
VALIDATION_BEGIN = "<!-- BEGIN GENERATED:validation-cases -->"
VALIDATION_END = "<!-- END GENERATED:validation-cases -->"

# --- red-lines.yml source data -----------------------------------------------
# Translation of the source pattern literals (ASR-002 red_line_patterns +
# ASR-003 yellow_line_patterns + ASR-005 risky_patterns) into anchored regexes.
# `value` is the verbatim source literal (provenance); `match` is the regex a
# runtime evaluates (re.search, case-insensitive — see the file header). The set
# of (source, value) pairs here is asserted equal to the union of the three
# source lists at render time, so adding a literal to the rules YAML without a
# translation fails loudly.
RED_LINE_PATTERNS = [
    # ASR-002 red_line_patterns
    {
        "id": "rm-rf-root",
        "source": "ASR-002",
        "value": "rm -rf /",
        "action": "deny",
        "match": r"\brm\s+(?=(?:-\S+\s+)*(?:-[a-z]*r[a-z]*|--recursive)\b)(?:-\S+\s+)+(?:/|/[*.]|/(?:etc|usr|var|bin|sbin|lib|lib64|boot|root|sys|proc|dev|opt|srv|home|Users|System|Library|Applications)(?:/\*?)?)(?:\s|$)",
        "note": "Recursive delete of the filesystem root, a root glob (/* or /.), or a whole top-level system directory (/etc, /usr, /var, /home, /Users, ...). Matches combined (-rf), split (-r -f), and long-form (--recursive --force) flag orderings; a deeper subpath (rm -rf /tmp/build, /var/log/app) does not fire.",
    },
    {
        "id": "rm-rf-home",
        "source": "ASR-002",
        "value": "rm -rf ~",
        "action": "deny",
        "match": r"\brm\s+(?=(?:-\S+\s+)*(?:-[a-z]*r[a-z]*|--recursive)\b)(?:-\S+\s+)+(?:~|\$HOME\b|\$\{HOME\})(?:/\S*)?(?:\s|$)",
        "note": "Recursive delete of the home tree (~, $HOME, ${HOME}, or a path beneath them). Same combined/split/long-form flag handling as rm-rf-root.",
    },
    {
        "id": "mkfs",
        "source": "ASR-002",
        "value": "mkfs",
        "action": "deny",
        "match": r"\bmkfs(?:\.\w+)?\b",
        "note": "Filesystem format (mkfs, mkfs.ext4, ...). Destroys all data on the target device.",
    },
    {
        "id": "dd-device",
        "source": "ASR-002",
        "value": "dd if=",
        "action": "deny",
        "match": r"\bdd\s+(?:[^\n|;&]*\s)?(?:if|of)=/dev/",
        "note": "Raw block-device read or write via dd. Refines the source dd if= to device-targeted forms, which also covers of=/dev/ (the irreversible write). File-to-file dd does not fire.",
    },
    {
        "id": "authorized-keys",
        "source": "ASR-002",
        "value": "authorized_keys",
        "action": "ask",
        "match": r"\bauthorized_keys\b",
        "note": "SSH authorized_keys touch. Adding a key grants persistent remote access.",
    },
    {
        "id": "launchctl",
        "source": "ASR-002",
        "value": "launchctl",
        "action": "ask",
        "match": r"\blaunchctl\s+(?!(?:list|print|blame|dumpstate|examine|procinfo|hostinfo|help|version)\b)\S",
        "note": "launchd persistence change. Read-only subcommands (list, print, ...) are excluded.",
    },
    {
        "id": "crontab",
        "source": "ASR-002",
        "value": "crontab",
        "action": "ask",
        "match": r"\bcrontab\s+(?!(?:.*\s)?-l(?:\s|$))\S+",
        "note": "cron persistence change. Read-only crontab -l is excluded in any flag position (e.g. crontab -u user -l).",
    },
    {
        "id": "curl-pipe-shell",
        "source": "ASR-002",
        "value": "curl | sh",
        "action": "ask",
        "match": r"\bcurl\b[^\n]*?\|\s*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S+\s+)*(?!ssh\b)[a-z]*sh\b",
        "note": "Pipe a downloaded payload into any sh-suffixed shell (sh, bash, zsh, ksh, mksh, dash, fish, ...), optionally via sudo/env or inline VAR=val assignments. Catches the curl ... | bash and env-prefixed forms the literal curl | sh missed; ssh is excluded.",
    },
    {
        "id": "wget-pipe-shell",
        "source": "ASR-002",
        "value": "wget | bash",
        "action": "ask",
        "match": r"\bwget\b[^\n]*?\|\s*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S+\s+)*(?!ssh\b)[a-z]*sh\b",
        "note": "Pipe a downloaded payload into any sh-suffixed shell, optionally via sudo/env or inline VAR=val assignments. Catches the wget ... | sh and env-prefixed forms the literal wget | bash missed; ssh is excluded.",
    },
    {
        "id": "eval",
        "source": "ASR-002",
        "value": "eval",
        "action": "ask",
        "match": r"\beval\b",
        "note": "Shell eval of dynamically constructed input. Common obfuscation and decode-and-execute primitive.",
    },
    # ASR-003 yellow_line_patterns
    {
        "id": "npm-install",
        "source": "ASR-003",
        "value": "npm install",
        "action": "ask",
        "match": r"\bnpm\s+(?:install|i|ci|add)\b",
        "note": "Package install via npm (install, i, ci, add). Pulls and may execute third-party code.",
    },
    {
        "id": "pip-install",
        "source": "ASR-003",
        "value": "pip install",
        "action": "ask",
        "match": r"\bpip[0-9]*\s+install\b",
        "note": "Package install via pip / pip3.",
    },
    {
        "id": "brew-install",
        "source": "ASR-003",
        "value": "brew install",
        "action": "ask",
        "match": r"\bbrew\s+(?:install|reinstall)\b",
        "note": "Package install via Homebrew.",
    },
    {
        "id": "docker-run",
        "source": "ASR-003",
        "value": "docker run",
        "action": "ask",
        "match": r"\bdocker\s+run\b",
        "note": "Run a container. May mount host paths or open network exposure.",
    },
    {
        "id": "sudo",
        "source": "ASR-003",
        "value": "sudo",
        "action": "ask",
        "match": r"\bsudo\b",
        "note": "Elevated privileges.",
    },
    {
        "id": "mcp-install",
        "source": "ASR-003",
        "value": "MCP install",
        "action": "ask",
        "match": r"\bmcp\s+install\b",
        "note": "Install or add an MCP server (an agent extension). Matched case-insensitively.",
    },
    {
        "id": "plugin-install",
        "source": "ASR-003",
        "value": "plugin install",
        "action": "ask",
        "match": r"\bplugin\s+install\b",
        "note": "Install or add a plugin (an agent extension).",
    },
    # ASR-005 risky_patterns
    {
        "id": "curl",
        "source": "ASR-005",
        "value": "curl",
        "action": "ask",
        "match": r"\bcurl\b",
        "note": "Network fetch via curl. Overlaps curl-pipe-shell by design (ASR-005 keeps the bare-tool surface).",
    },
    {
        "id": "wget",
        "source": "ASR-005",
        "value": "wget",
        "action": "ask",
        "match": r"\bwget\b",
        "note": "Network fetch via wget. Overlaps wget-pipe-shell by design.",
    },
    {
        "id": "fetch-call",
        "source": "ASR-005",
        "value": "fetch(",
        "action": "ask",
        "match": r"\bfetch\s*\(",
        "note": "Runtime fetch() call; a secondary download from inside reviewed code.",
    },
    {
        "id": "urllib-request",
        "source": "ASR-005",
        "value": "urllib.request",
        "action": "ask",
        "match": r"\burllib\.request\b",
        "note": "Python urllib.request; a secondary download from inside reviewed code.",
    },
    {
        "id": "git-clone",
        "source": "ASR-005",
        "value": "git clone",
        "action": "ask",
        "match": r"\bgit\s+clone\b",
        "note": "Clone external code; a secondary download.",
    },
    {
        "id": "npm-install-from-script",
        "source": "ASR-005",
        "value": "npm install from script",
        "action": "ask",
        "match": r"\bnpm\s+(?:install|i|ci|add)\b",
        "note": "ASR-005 variant: npm install reached from inside a fetched script. Same surface as npm-install, kept as a distinct provenance entry.",
    },
    {
        "id": "pip-install-from-script",
        "source": "ASR-005",
        "value": "pip install from script",
        "action": "ask",
        "match": r"\bpip[0-9]*\s+install\b",
        "note": "ASR-005 variant: pip install reached from inside a fetched script. Same surface as pip-install.",
    },
    {
        "id": "postinstall",
        "source": "ASR-005",
        "value": "postinstall",
        "action": "ask",
        "match": r"\bpostinstall\b",
        "note": "Package lifecycle postinstall hook; runs code on install.",
    },
    {
        "id": "base64-decode-exec",
        "source": "ASR-005",
        "value": "base64 decode and execute",
        "action": "ask",
        "match": r"\bbase64\s+(?:--decode|-d|-D)\b",
        "note": "base64 decode step of a decode-and-execute payload; typically piped into a shell.",
    },
]

# Metadata for the red-line category taxonomy, keyed by the leading text (before
# the first colon) of each constitution Red-Line Actions bullet. The bullet text
# itself is read verbatim from the constitution at render time so the category
# `value` tracks the source; this table only carries the stable id/action/note.
RED_LINE_CATEGORY_META = {
    "Destructive filesystem or disk operations": {
        "id": "cat-destructive-fs",
        "action": "ask",
        "note": "Executable forms under patterns: rm-rf-root, rm-rf-home, mkfs, dd-device.",
    },
    "Credential or auth changes": {
        "id": "cat-credential-auth",
        "action": "ask",
        "note": "Executable form under patterns: authorized-keys. See ASR-006.",
    },
    "Secret exposure": {
        "id": "cat-secret-exposure",
        "action": "ask",
        "note": "No safe executable signature; gate by review (ASR-006).",
    },
    "Persistence changes": {
        "id": "cat-persistence",
        "action": "ask",
        "note": "Executable forms under patterns: launchctl, crontab.",
    },
    "Remote-code execution patterns": {
        "id": "cat-rce",
        "action": "ask",
        "note": "Executable forms under patterns: curl-pipe-shell, wget-pipe-shell, eval, base64-decode-exec, postinstall.",
    },
    "Network/security boundary changes": {
        "id": "cat-network-boundary",
        "action": "ask",
        "note": "No single executable signature; covered by review (ASR-009) and docker-run.",
    },
    "Agent policy weakening": {
        "id": "cat-policy-weakening",
        "action": "ask",
        "note": "Edits that reduce protections; gate by policy review, not a command pattern.",
    },
}

# Tokens stripped from the portable digest so it carries no dangling reference to
# this repo's internal layout (acceptance for A5).
DIGEST_PATH_TOKENS = (
    "rules/",
    "playbooks/",
    "references/",
    "policies/",
    "AGENTS.md",
    "CLAUDE.md",
    "this repo",
)


def cell(items):
    return "; ".join(s.strip() for s in items)


def render_block(rules, begin=BEGIN, end=END):
    rows = ["| ID | Trigger | Required action |", "| --- | --- | --- |"]
    for r in sorted(rules, key=lambda r: r["id"]):
        rows.append(f"| {r['id']} | {cell(r['trigger'])} | {cell(r['required_action'])} |")
    table = "\n".join(rows)
    return (
        f"{begin}\n"
        "<!-- regenerated by scripts/render.sh from rules/agent-security-rules.yml; do not edit by hand -->\n\n"
        f"{table}\n\n"
        f"{end}"
    )


def bool_word(value):
    return "yes" if value else "no"


def display_tool_behavior(value):
    return value.replace("_", " ")


def indented_block(text):
    return text.rstrip().splitlines()


def bullet_section(lines, title, items):
    lines.append(f"#### {title}")
    lines.append("")
    for item in items:
        lines.append(f"- {item}")
    lines.append("")


def render_validation_block(catalog, rules=None, begin=VALIDATION_BEGIN, end=VALIDATION_END):
    if isinstance(catalog, dict):
        cases = catalog["cases"]
        safe_harness = catalog.get("safe_harness", [])
    else:
        cases = catalog
        safe_harness = []

    rule_names = {rule["id"]: rule.get("name", "") for rule in rules or []}
    grouped = defaultdict(list)
    for case in sorted(cases, key=lambda item: item["id"]):
        grouped[case["rule_id"]].append(case)

    lines = [
        begin,
        "<!-- regenerated by scripts/render.sh from validation/cases.yml; do not edit by hand -->",
        "",
    ]

    if safe_harness:
        lines.extend(["## Safe Harness", ""])
        for item in safe_harness:
            lines.append(f"- {item}")
        lines.append("")

    for rule_id in sorted(grouped):
        rule_name = rule_names.get(rule_id, "")
        title = f"{rule_id}: {rule_name}" if rule_name else rule_id
        lines.extend([f"## {title}", ""])

        for case in grouped[rule_id]:
            lines.extend(
                [
                    f"### {case['id']} - {case['name']}",
                    "",
                    f"- Rule: `{case['rule_id']}`",
                    f"- Severity: `{case['severity']}`",
                    f"- Category: `{case['category']}`",
                    f"- Must not execute: `{bool_word(case['must_not_execute'])}`",
                    f"- Allowed tool behavior: `{display_tool_behavior(case['allowed_tool_behavior'])}`",
                    "",
                ]
            )

            fixture_files = case.get("fixture_files", [])
            if fixture_files:
                lines.extend(["#### Fixture Files", ""])
                for fixture in fixture_files:
                    lines.append(f"- `{fixture['path']}`: {fixture['purpose']}")
                    lines.append("")
                    lines.append("```text")
                    lines.extend(indented_block(fixture["content"]))
                    lines.append("```")
                    lines.append("")

            lines.extend(["#### Prompt", "", "```text"])
            lines.extend(indented_block(case["prompt"]))
            lines.extend(["```", ""])

            bullet_section(lines, "Expected Behavior", case["expected_behavior"])
            bullet_section(lines, "Pass Criteria", case["pass_criteria"])
            bullet_section(lines, "Fail Indicators", case["fail_indicators"])

            notes = case.get("notes", "").strip()
            if notes:
                lines.extend(["#### Notes", "", notes, ""])

    lines.append(end)
    return "\n".join(lines)


def splice(text, block, target, begin=BEGIN, end=END):
    pat = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
    if not pat.search(text):
        sys.exit(f"error: markers not found in {target}")
    return pat.sub(block, text)


def load_yaml(path):
    return yaml.safe_load(path.read_text())


def _rule(rules, rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            return rule
    sys.exit(f"red-lines: rule {rule_id} not found in {RULES.name}")


def _squote(text):
    """YAML single-quoted scalar (backslashes stay literal — ideal for regex)."""
    return "'" + text.replace("'", "''") + "'"


def _source_pattern_index(rules):
    """(source, value) -> source-list order, from the three rule pattern lists."""
    lists = [
        ("ASR-002", _rule(rules, "ASR-002")["examples"]["red_line_patterns"]),
        ("ASR-003", _rule(rules, "ASR-003")["examples"]["yellow_line_patterns"]),
        ("ASR-005", _rule(rules, "ASR-005")["examples"]["risky_patterns"]),
    ]
    index = {}
    order = 0
    for source, values in lists:
        for value in values:
            index[(source, value)] = order
            order += 1
    return index


def parse_red_line_categories(constitution_text):
    """Verbatim bullets of the constitution 'Red-Line Actions' section, in order."""
    bullets = []
    in_section = False
    for line in constitution_text.splitlines():
        if line.startswith("## "):
            in_section = line.strip() == "## Red-Line Actions"
            continue
        if in_section and line.startswith("- "):
            bullets.append(line[2:].strip())
    return bullets


def render_red_lines(rules, constitution_text):
    source_index = _source_pattern_index(rules)
    table = {(p["source"], p["value"]) for p in RED_LINE_PATTERNS}
    missing = sorted(source_index.keys() - table)
    extra = sorted(table - source_index.keys())
    if missing or extra:
        sys.exit(
            "red-lines: pattern table out of sync with rules YAML; "
            f"missing translations={missing}; orphan translations={extra}"
        )

    patterns = sorted(
        RED_LINE_PATTERNS, key=lambda p: source_index[(p["source"], p["value"])]
    )

    bullets = parse_red_line_categories(constitution_text)
    known = set(RED_LINE_CATEGORY_META)
    seen = {b.split(":", 1)[0] for b in bullets}
    if seen != known:
        sys.exit(
            "red-lines: category metadata out of sync with constitution; "
            f"missing={sorted(known - seen)}; unknown={sorted(seen - known)}"
        )

    header = [
        "# red-lines.yml - vendor-neutral red-line / risky-action patterns plus the",
        "# red-line category taxonomy.",
        "#",
        "# GENERATED from rules/agent-security-rules.yml (ASR-002/003/005 pattern lists)",
        "# and policies/agent-security-constitution.md (Red-Line Actions) by",
        "# scripts/render.py. Do not edit by hand - run scripts/render.sh and commit.",
        "#",
        "# Two record kinds, never flattened together:",
        "#   patterns:   executable. Each carries `match`, an anchored regex a runtime",
        "#               evaluates against a candidate command string.",
        "#   categories: human-readable red-line taxonomy. No `match` - descriptive only.",
        "#",
        "# Regex dialect (for `match`):",
        "#   - Python re / POSIX ERE syntax.",
        "#   - Evaluated with re.search (substring search), case-insensitive.",
        "#   - Patterns carry their own anchors (\\b word boundaries and shell-token",
        "#     boundaries) so a literal like mkfs matches the mkfs command and mkfs.ext4",
        "#     but not a substring inside an unrelated identifier. This is why entries",
        "#     are regexes, not literal substrings: the source literals over- and",
        "#     under-fire (curl | sh never matches the real curl ... | bash; dd if=",
        "#     misses dd ... of=/dev/...).",
        "#",
        "# action:",
        "#   deny - irreversible, catastrophic, no legitimate agent use (disk/home wipe,",
        "#          format, raw block-device write); a runtime should hard-block.",
        "#   ask  - pause for explicit human confirmation before running.",
        "#   Categories are labelled ask; the stronger deny is expressed only in the",
        "#   precise executable patterns, never against a fuzzy category.",
        "#",
        "# Some patterns share a `match` across different `source` rules (e.g. curl and",
        "# curl-pipe-shell, npm-install and npm-install-from-script). The overlap is",
        "# intentional: each source rule's surface is preserved with its own provenance.",
    ]

    lines = list(header)
    lines += [
        "",
        "version: 1",
        "name: red-lines",
        "description: Vendor-neutral red-line and risky-action patterns plus the red-line category taxonomy.",
        "",
        "patterns:",
    ]
    for p in patterns:
        lines += [
            f"  - id: {p['id']}",
            f"    source: {p['source']}",
            "    kind: pattern",
            f"    match: {_squote(p['match'])}",
            f"    value: {_squote(p['value'])}",
            f"    action: {p['action']}",
            f"    note: {_squote(p['note'])}",
        ]

    lines += ["", "categories:"]
    for bullet in bullets:
        meta = RED_LINE_CATEGORY_META[bullet.split(":", 1)[0]]
        lines += [
            f"  - id: {meta['id']}",
            "    source: ASR-002",
            "    kind: category",
            f"    value: {_squote(bullet)}",
            f"    action: {meta['action']}",
            f"    note: {_squote(meta['note'])}",
        ]

    return "\n".join(lines) + "\n"


def strip_repo_paths(text):
    for token in DIGEST_PATH_TOKENS:
        text = text.replace(token, "")
    return " ".join(text.split())


def render_digest(rules):
    lines = [
        "# Agent security policy (portable digest)",
        "<!-- generated; do not edit by hand -->",
        "",
    ]
    for rule in sorted(rules, key=lambda r: r["id"]):
        trigger = strip_repo_paths(cell(rule["trigger"]))
        lines.append(f"- {rule['id']} ({rule['name']}): {trigger}")
    return "\n".join(lines) + "\n"


def render_jobs():
    rules_data = load_yaml(RULES)
    validation_data = load_yaml(VALIDATION_CASES)

    return [
        {
            "targets": TARGETS,
            "block": render_block(rules_data["rules"]),
            "begin": BEGIN,
            "end": END,
        },
        {
            "targets": VALIDATION_TARGETS,
            "block": render_validation_block(validation_data, rules_data["rules"]),
            "begin": VALIDATION_BEGIN,
            "end": VALIDATION_END,
        },
    ]


def whole_file_jobs():
    """Markerless generated files written whole (no BEGIN/END splice markers)."""
    rules_data = load_yaml(RULES)
    constitution_text = CONSTITUTION.read_text()
    return [
        {
            "target": RED_LINES,
            "content": render_red_lines(rules_data["rules"], constitution_text),
        },
        {
            "target": DIGEST,
            "content": render_digest(rules_data["rules"]),
        },
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any target is out of sync with the YAML",
    )
    args = ap.parse_args()

    out_of_sync = []
    for job in render_jobs():
        for target in job["targets"]:
            rel = target.relative_to(REPO)
            if not target.exists():
                sys.exit(f"error: {rel} not found")
            current = target.read_text()
            rendered = splice(current, job["block"], target, job["begin"], job["end"])

            if args.check:
                if current != rendered:
                    out_of_sync.append(str(rel))
                else:
                    print(f"{rel} in sync")
                continue

            if current != rendered:
                target.write_text(rendered)
                print(f"updated {rel}")
            else:
                print(f"{rel} unchanged")

    for job in whole_file_jobs():
        target = job["target"]
        rel = target.relative_to(REPO)
        rendered = job["content"]

        if not target.exists():
            if args.check:
                out_of_sync.append(str(rel))
            else:
                target.write_text(rendered)
                print(f"created {rel}")
            continue

        current = target.read_text()
        if args.check:
            if current != rendered:
                out_of_sync.append(str(rel))
            else:
                print(f"{rel} in sync")
            continue

        if current != rendered:
            target.write_text(rendered)
            print(f"updated {rel}")
        else:
            print(f"{rel} unchanged")

    if args.check and out_of_sync:
        sys.exit("out of sync with generated sources: " + ", ".join(out_of_sync))


if __name__ == "__main__":
    main()
