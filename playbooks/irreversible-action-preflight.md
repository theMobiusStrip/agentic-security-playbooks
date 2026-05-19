# Irreversible Action Preflight Playbook

## Purpose

Make high-impact actions deliberate, explainable, and reversible where possible.

## When To Use

Use this playbook before actions that:

- Delete, overwrite, or move important data.
- Change authentication, authorization, keys, tokens, sessions, or secrets.
- Add persistence through cron, launchd, shell startup files, login items, services, or daemons.
- Expose local services to a network or public tunnel.
- Rewrite Git history or publish sensitive content.
- Move funds, sign transactions, submit irreversible external operations, or call production APIs.
- Weaken agent policy, approvals, sandboxing, or audit behavior.

## Applicable Rules

- ASR-002: Red-Line Human Confirmation
- ASR-003: Yellow-Line Disclosure
- ASR-006: Secret Isolation
- ASR-007: Irreversible Action Preflight
- ASR-009: Least-Privilege Tool Use

## Steps

1. Classify the action as red-line, yellow-line, or ordinary.
2. Identify affected assets:
   - Files and directories.
   - Credentials or sessions.
   - External services.
   - Network exposure.
   - Automation or persistence.
   - User data or money.
3. Check rollback:
   - Backup exists.
   - Git diff or commit exists.
   - Command is reversible.
   - External action is irreversible.
4. Choose the least-privilege path.
5. Present the planned action and wait for approval if red-line.
6. Execute only the approved scope.
7. Report result and verification.

## Approval Prompt Shape

```md
This is a red-line action because <reason>.

Planned change:
- <exact command or file edit>

Affected assets:
- <files, secrets, services, money, network, or data>

Rollback:
- <available rollback or "no reliable rollback">

Please confirm before I proceed.
```

## Stop Conditions

Stop if:

- The affected asset list is unclear.
- The command scope is broader than necessary.
- Rollback is missing for a destructive operation.
- A secret would be exposed.
- The user has not explicitly approved a red-line action.
