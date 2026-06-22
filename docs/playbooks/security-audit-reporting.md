# Security Audit Reporting Playbook

## Purpose

Produce security reports that are useful for humans and future agents, without hiding clean checks or leaking sensitive data.

## When To Use

Use this playbook for:

- Security reviews.
- Incident triage.
- Anomaly checks.
- Recurring audit reports.
- Agent/tool activity reviews.
- Configuration integrity checks.

## Applicable Rules

- ASR-006: Secret Isolation
- ASR-010: Explicit Audit Reporting
- ASR-011: Instructions Are Not A Security Boundary

## Steps

1. Define scope and time window.
2. List evidence sources before analyzing.
3. Collect bounded evidence. Prefer pre-filtered, relevant output over dumping full raw logs.
4. Redact secrets and sensitive values.
5. Classify findings:
   - Critical.
   - Warning.
   - Informational.
   - Clean check.
6. Include explicit clean checks.
7. State limitations and gaps.
8. Provide concrete follow-ups.

## Report Format

```md
# Security Audit Report

Time window: <start> to <end>
Scope: <systems, repo, files, logs, or tools>

## Summary

- Critical: <count>
- Warning: <count>
- Informational: <count>
- Clean checks: <count>

## Findings

### Critical

- <finding, evidence, impact, recommendation>

### Warning

- <finding, evidence, impact, recommendation>

### Informational

- <finding, evidence, impact, recommendation>

## Clean Checks

- <explicit check and result>

## Limitations

- <what was not checked or could be stale>

## Follow-Ups

- <next action>
```

## Reporting Rules

- Do not say "no issues" unless the checked scope is clear.
- Do not paste raw secrets, keys, tokens, cookies, mnemonics, or passwords.
- Do not rely on the LLM to remember false positives. Keep repeatable exclusions in deterministic logic or an explicit exclusion file.
- Prefer durable report paths over temporary files for recurring audits.
