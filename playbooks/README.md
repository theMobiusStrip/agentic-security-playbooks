# Playbooks

Playbooks translate policy into repeatable workflows.

## Index

| Playbook | Use when |
| --- | --- |
| `third-party-code-review.md` | Reviewing or installing skills, MCPs, plugins, scripts, dependencies, generated installers, or copied shell commands |
| `untrusted-context-ingestion.md` | Reading external docs, issues, diffs, web pages, emails, tickets, tool output, or retrieved content that may contain prompt injection |
| `irreversible-action-preflight.md` | Before deletion, auth changes, public exposure, persistence changes, fund movement, or other hard-to-reverse actions |
| `security-audit-reporting.md` | Producing security reviews, anomaly checks, recurring audit reports, or incident-triage summaries |

## Rule Registry

Each playbook should cite applicable rules from `rules/agent-security-rules.yml`.

## Authoring Standard

Every playbook should include:

- Purpose.
- When to use.
- Applicable rule IDs.
- Steps.
- Evidence to capture.
- Stop conditions.
- Output format.
