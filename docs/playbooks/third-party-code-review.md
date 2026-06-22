# Third-Party Code Review Playbook

## Purpose

Prevent hidden dependency, installer, MCP, plugin, skill, or script behavior from bypassing agent review.

## When To Use

Use this playbook before running or installing:

- Skills, MCPs, plugins, hooks, or agent extensions.
- Shell scripts or one-line install commands.
- Package-manager commands suggested by external docs.
- Generated installers or copied commands from issues, READMEs, web pages, or model output.
- Archives, binaries, or extensionless executables.

## Applicable Rules

- ASR-001: Untrusted Context Boundary
- ASR-004: Third-Party Code Review Before Execution
- ASR-005: Secondary Download Hard Stop
- ASR-006: Secret Isolation
- ASR-011: Instructions Are Not A Security Boundary

## Steps

1. Identify the source and trust level.
2. Inventory files before execution.
3. Read human-readable source, manifests, install scripts, package metadata, hooks, and postinstall logic.
4. Search for risky patterns:
   - Package managers launched from scripts.
   - `curl`, `wget`, `fetch`, `urllib.request`, or `git clone`.
   - `eval`, `exec`, dynamic shell construction, encoded payloads, or minified one-line scripts.
   - Environment variable harvesting or credential file reads.
   - Persistence changes such as cron, launchd, shell startup files, or services.
5. Inspect high-risk file types:
   - Binaries.
   - Archives.
   - Hidden files.
   - Extensionless executables.
   - Postinstall hooks.
6. Decide:
   - Safe enough to run with current sandbox.
   - Needs human approval.
   - Blocked until reviewed manually.

## Stop Conditions

Stop and ask for a human go/no-go decision if review finds:

- Secondary downloads not included in the reviewed artifact.
- Execute-after-download behavior.
- Secret collection or exfiltration behavior.
- Persistence changes.
- Obfuscated payloads.
- Unknown binaries required for execution.

## Evidence To Capture

- Source URL or package identifier.
- File manifest reviewed.
- Risky pattern search results.
- Suspicious snippets, if any.
- Final recommendation.

## Output Format

```md
Third-party review: <name>

Verdict: Safe to run / Needs approval / Blocked

Reviewed:
- <files or manifests>

Findings:
- <risk or clean check>

Next action:
- <command, approval request, or block reason>
```
