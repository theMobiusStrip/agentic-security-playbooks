# Agentic Security Playbooks

Reusable playbooks for Codex, Claude, and other coding agents that need clear security behavior around tools, files, secrets, third-party code, and high-impact actions.

This repo separates security guidance into six layers:

| Layer | Path | Purpose |
| --- | --- | --- |
| Agent entry points | `AGENTS.md`, `CLAUDE.md` | Auto-loaded by each agent; carry the inlined rule table that governs every turn |
| Policy | `policies/` | Durable behavior rules and rationale that should rarely change |
| Rule registry | `rules/` | Canonical source: structured rule IDs, triggers, actions, and examples |
| Playbooks | `playbooks/` | Step-by-step procedures for recurring security workflows |
| Templates | `templates/` | Reusable report and review formats |
| References | `references/` | Background and threat model: `owasp-llm-top-10-2025.md`, `threat-model.md` |

## Design Principle

Treat this repo as an agent security constitution, not a pile of one-off checklists.

- Policies define what an agent must never skip.
- Rules make policy scan-friendly and reusable.
- Playbooks turn rules into repeatable operating procedures.
- Templates keep evidence and approvals consistent.
- References explain why the rules exist and what they defend against.

## Recommended Agent Load Order

Agents auto-load `AGENTS.md` (Codex) or `CLAUDE.md` (Claude Code). Both already contain the rule table inlined from `rules/agent-security-rules.yml`, so the runtime contract is in context without extra reads. Open the files below only when the inlined table is not enough:

1. `policies/agent-security-constitution.md` — full rule text and rationale.
2. `rules/agent-security-rules.yml` — canonical machine-readable source.
3. `references/threat-model.md` — adversary mapping for each rule.
4. The task-relevant playbook under `playbooks/`.
5. `templates/security-review-record.md` when a review or approval trail is needed.

## Current Playbooks

- `playbooks/third-party-code-review.md`: review skills, MCPs, plugins, scripts, dependency instructions, and installers before running them.
- `playbooks/untrusted-context-ingestion.md`: handle external docs, issues, diffs, web pages, and tool output without letting them become instructions.
- `playbooks/irreversible-action-preflight.md`: gate destructive, credential-sensitive, persistent, network-exposing, or financial actions.
- `playbooks/security-audit-reporting.md`: produce explicit, evidence-backed audit reports, including clean checks.

## Tooling

The rule table in `AGENTS.md` and `CLAUDE.md` is generated from `rules/agent-security-rules.yml`. Do not hand-edit anything between the `<!-- BEGIN GENERATED:rules -->` and `<!-- END GENERATED:rules -->` markers — edits there are overwritten on next render.

One-time setup:

```bash
python3 -m venv .venv
.venv/bin/pip install pyyaml
```

After editing `rules/agent-security-rules.yml`:

```bash
./scripts/render.sh           # regenerate AGENTS.md and CLAUDE.md
./scripts/render.sh --check   # CI / pre-commit drift check
```

## Source Anchors

- `references/owasp-llm-top-10-2025.md`
- `references/threat-model.md`
- SlowMist OpenClaw security guide concepts: red lines, yellow lines, pre-install review, secondary-download detection, explicit audit reporting, and zero-trust limits.
