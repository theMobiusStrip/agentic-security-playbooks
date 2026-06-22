# OWASP LLM Top 10 2025

Sources:

- [OWASP GenAI Security Project - LLM Top 10](https://genai.owasp.org/llm-top-10/)
- Style reference: [Context Guard - OWASP LLM Top 10 2025](https://ctx-guard.com/blog/owasp-llm-top-10)

The OWASP Top 10 for LLM Applications is a shared vocabulary for the most important risks in LLM and generative AI systems. Use this reference during design reviews, threat modeling, red-team planning, and playbook authoring.

## At A Glance

| ID | Risk | Primary surface |
| --- | --- | --- |
| LLM01 | Prompt Injection | User input, retrieved content, files, tool output |
| LLM02 | Sensitive Information Disclosure | Prompts, context, memory, responses, logs |
| LLM03 | Supply Chain | Models, datasets, dependencies, plugins, providers |
| LLM04 | Data and Model Poisoning | Training data, fine-tuning data, RAG indexes, embeddings |
| LLM05 | Improper Output Handling | HTML, SQL, shell, code execution, workflow/API handoffs |
| LLM06 | Excessive Agency | Agents, tools, plugins, service accounts, external actions |
| LLM07 | System Prompt Leakage | System prompts, hidden policies, tool schemas, internal instructions |
| LLM08 | Vector and Embedding Weaknesses | Vector DBs, embedding pipelines, retrieval ranking, tenant isolation |
| LLM09 | Misinformation | User decisions, automated workflows, high-stakes generated content |
| LLM10 | Unbounded Consumption | Tokens, requests, recursion, storage, tools, provider spend |

## LLM01: Prompt Injection

Prompt injection happens when untrusted text changes what the model does. It can be direct, where a user types malicious instructions, or indirect, where the instructions are hidden in retrieved content such as a web page, email, ticket, PDF, or tool result.

Common impact: instruction bypass, data exfiltration, unsafe tool calls, policy evasion, privilege escalation, or corrupted downstream decisions.

Mitigations:

- Treat every context source as untrusted, not only the user's message.
- Separate instructions from data as much as the architecture allows.
- Inspect retrieved content for instruction-like payloads before adding it to context.
- Gate privileged actions with deterministic authorization, not model judgment alone.
- Log prompts, retrieved chunks, tool calls, and blocked attempts for investigation.

## LLM02: Sensitive Information Disclosure

Sensitive information disclosure occurs when an LLM system exposes data it should not reveal. This can include secrets, credentials, PII, customer data, internal documents, memory from another user, or sensitive information memorized from training data.

Common impact: privacy breach, cross-tenant leakage, credential exposure, compliance failure, or internal data disclosure.

Mitigations:

- Keep secrets out of prompts, system messages, tool descriptions, and logs.
- Apply tenant isolation to context, cache, memory, retrieval, and logging layers.
- Scan inputs and outputs for credentials, PII, and regulated data.
- Redact or tokenize sensitive data before it enters model context.
- Use least-privilege data access for retrieval and tool calls.

## LLM03: Supply Chain

LLM supply chain risk comes from compromised or untrusted components in the AI stack. The vulnerable component may be a model, adapter, dataset, prompt package, plugin, agent tool, dependency, container, provider, or deployment pipeline.

Common impact: hidden backdoors, malicious behavior, dependency compromise, poisoned model behavior, data theft, or provider-side risk.

Mitigations:

- Track models, datasets, adapters, tools, and dependencies in an AI bill of materials.
- Pin versions and verify artifacts where possible.
- Review model and plugin provenance before production use.
- Scan dependencies, containers, and deployment assets.
- Monitor model and agent behavior for unexpected changes after updates.

## LLM04: Data and Model Poisoning

Data and model poisoning happens when attackers manipulate training, fine-tuning, embedding, or retrieval data so the system learns or retrieves attacker-controlled behavior. For RAG systems, poisoning can happen without retraining the base model.

Common impact: backdoored behavior, biased answers, malicious retrieved context, unsafe recommendations, or targeted misinformation.

Mitigations:

- Track provenance for training, fine-tuning, and retrieval data.
- Validate and moderate content before indexing or training on it.
- Separate trusted, semi-trusted, and untrusted retrieval sources.
- Monitor retrieval results for suspicious or instruction-like content.
- Test for trigger phrases and backdoor behavior after model or data updates.

## LLM05: Improper Output Handling

Improper output handling occurs when application code treats model output as trusted. The model may generate HTML, SQL, shell commands, code, URLs, API payloads, or workflow actions that are executed or rendered without validation.

Common impact: XSS, SQL injection, command execution, SSRF, unsafe API calls, corrupted records, or workflow abuse.

Mitigations:

- Treat model output like user input to the downstream system.
- Escape rendered content and parameterize database queries.
- Sandbox code and shell execution.
- Validate structured outputs against strict schemas.
- Require allowlists and authorization checks for generated URLs, tool calls, and API requests.

## LLM06: Excessive Agency

Excessive agency occurs when an LLM or agent has more autonomy, tools, permissions, or persistence than the task requires. Prompt injection becomes much more dangerous when the model can take real actions.

Common impact: unauthorized email, file, database, ticket, payment, cloud, or shell actions; privilege misuse; lateral movement through connected systems.

Mitigations:

- Scope tools and credentials to the specific task.
- Use per-tool and per-action authorization.
- Require human approval for irreversible or high-impact actions.
- Disable tools by default and enable only what is needed.
- Record full audit trails for agent plans, tool calls, arguments, and results.

## LLM07: System Prompt Leakage

System prompt leakage happens when hidden instructions, internal policies, tool definitions, guardrail logic, or sensitive implementation details are exposed. A leaked prompt should not be treated as catastrophic by itself, but it often gives attackers a better map of the system.

Common impact: easier jailbreaks, exposed internal logic, leaked tool schemas, policy bypass, or accidental credential disclosure if secrets were placed in prompts.

Mitigations:

- Never put credentials or durable secrets in system prompts.
- Assume system prompts may become visible to attackers.
- Keep security controls outside the prompt where possible.
- Detect requests that ask the model to reveal hidden instructions or policies.
- Minimize prompt content to what the model actually needs.

## LLM08: Vector and Embedding Weaknesses

Vector and embedding weaknesses affect RAG and semantic search systems. Attackers may poison indexed content, exploit weak tenant isolation, manipulate retrieval ranking, or craft inputs that retrieve attacker-preferred documents.

Common impact: malicious context injection, cross-tenant data exposure, retrieval manipulation, poisoned answers, or hidden prompt injection through indexed content.

Mitigations:

- Enforce tenant isolation in vector stores and retrieval filters.
- Inspect documents before indexing and chunks before prompt assembly.
- Track source, owner, timestamp, and trust level for retrieved chunks.
- Limit retrieval from untrusted sources for privileged workflows.
- Test retrieval behavior with adversarial documents and confusing near-match content.

## LLM09: Misinformation

Misinformation occurs when an LLM produces false, misleading, unsupported, or overconfident output that users or automated workflows rely on. This can be adversarial, but it can also happen naturally through hallucination or weak grounding.

Common impact: bad business decisions, unsafe guidance, fabricated citations, broken code, compliance errors, or loss of trust.

Mitigations:

- Ground answers in cited, retrievable sources for knowledge tasks.
- Add factuality checks for high-stakes domains.
- Require human review for consequential decisions.
- Label uncertainty and avoid unsupported claims.
- Test for hallucinated citations, invented APIs, and unsupported numeric claims.

## LLM10: Unbounded Consumption

Unbounded consumption is resource abuse against the LLM system. Attackers may trigger long prompts, expensive models, recursive tool loops, large file processing, repeated retries, or high-volume requests.

Common impact: denial of service, runaway provider bills, queue exhaustion, degraded latency, storage growth, or tool abuse.

Mitigations:

- Set token, request, file size, recursion, and tool-call limits.
- Enforce per-user, per-tenant, and per-key quotas.
- Add budget alerts and cost visibility for operators.
- Detect repeated failures, loops, and unusually expensive requests.
- Use cheaper models or deterministic code for tasks that do not need frontier-model reasoning.

## Prioritization Notes

- RAG apps should prioritize LLM01, LLM02, LLM04, LLM08, and LLM09.
- Agentic apps should prioritize LLM01, LLM05, LLM06, LLM07, and LLM10.
- Regulated-data apps should prioritize LLM02, LLM05, LLM07, and LLM09.
- Public-facing apps should prioritize LLM01, LLM05, LLM06, and LLM10.

## How To Use This Reference

- Use the list as a taxonomy, not as a complete test plan.
- For each LLM feature, identify which risks apply to its inputs, context, model, tools, outputs, memory, and logs.
- Convert applicable risks into abuse cases, test cases, controls, and detection signals.
- Revisit the mapping whenever adding a new model, tool, retrieval source, memory store, or external action.
