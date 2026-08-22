# Harness Core Selective OSS Release Scope

Issue #855 selects a narrow public release: open-source Harness Core as a portable policy, evidence, receipt, and readiness layer for agents built with any framework. Hosted Triptych OS (Agent OS), Router / Marketplace, settlement, private connectors, and Full ECF internals remain private.

## Positioning

Public positioning:

```text
A portable policy, evidence, receipt, and readiness layer for agents built with any framework.
```

Harness Core is not a replacement for LangChain, LangGraph, CrewAI, OpenAI Agents, AutoGen, PydanticAI, Mastra, MCP, Hermes, Codex, or local Rust agent runtimes. The model loop is not the moat. Harness Core wraps local frameworks with policy, receipts, Agent OS preview export, and marketplace-readiness checks.

## Public Scope

The public package may include:

- Harness Core CLI and package metadata.
- Harness JSON schemas and profiles.
- Local run ledger, event kernel, proof, receipt, status, owner-inbox, review-gate, worktree-session, and schedule-intent artifacts.
- Host evidence import adapters.
- The observer-only Microsoft AHP `0.8.0` adapter: loopback root/session/chat observation, fixed-redaction metadata, and bounded artifacts in the existing local run ledger.
- Framework-wrapping examples for LangGraph, CrewAI, MCP, Codex, Hermes, and the Rust reference runtime.
- Rust reference runtime examples for self-hosted, local-only proof/export checks.
- Tests proving local artifacts remain preview/readiness-only.

## Private Scope

Do not export:

- Hosted Agent OS runtime provisioning internals.
- Router / Marketplace ranking, fraud, trust, retry, or settlement internals.
- Wallet custody, payout orchestration, or funded canary secrets.
- Private connector broker internals.
- Full ECF private runtime, enterprise context graphs, customer evidence, or resident context.
- Production admin routes, operator prompts, live deployment automation, or private analytics.
- An AHP server facade, VS Code session hosting, AHP-to-ACP translation, agent-to-agent routing, write-capable AHP control, tool approvals, transport authentication, remote gateways, hosted AHP deployment, or Interchange integration.

## AHP Observer Boundary

The public AHP tranche is pinned to `@microsoft/agent-host-protocol` `0.8.0`, supports negotiated AHP `0.8.0` only, and preserves Node.js 18 compatibility with a dedicated `ws` transport rather than a global WebSocket patch. Live endpoints are loopback-only, and subscriptions are limited to explicitly allowed root, session, and chat channels.

It observes sanitized snapshots, actions, and permitted notifications. It cannot dispatch actions; create or dispose sessions; create chats; write, delete, or move resources; provide or approve tools; send or claim terminal input; authenticate; run or mutate automations; or grant provider, wallet, x402, marketplace, trust, or owner-bypass authority. Raw messages, reasoning, tool payloads, authentication material, resource/terminal content, filesystem paths, environment values, and telemetry bodies are not retained.

AHP sequence values are correlation evidence, not proof of delivery completeness or loss. OTLP and other telemetry observations are not an audit ledger. Harness Core's sanitized local receipt remains the durable evidence record, and an observed host or model-judge assessment does not become ECF authority. Governed AHP control requires a separate design and explicit approval.

## Example Inventory

The framework examples are recorded in `examples/frameworks/framework-wrapping-examples.json`.

Required example IDs:

- `langgraph`
- `crewai`
- `mcp`
- `codex`
- `hermes`
- `rust_reference_runtime`

Each example must set `framework_replacement:false`, `agent_os_preview_only:true`, and all authority boundary booleans to `false`.

## Rust Runtime Boundary

The Rust runtime is a self-hosted reference runtime only. It may show how a local runtime exposes an Agent Card, OpenAPI profile, `/health`, `/tools`, and Harness export packet. It must not be positioned as hosted Agent OS, the commercial live product, a marketplace executor, or a settlement runtime.

## Acceptance Checklist

- Public docs describe Harness Core as a portable governance/proof/readiness layer.
- Framework examples show wrapping, not framework replacement.
- Rust runtime is framed as a reference runtime only.
- Hosted Agent OS remains the commercial live product.
- Tests prove examples and adapters keep preview/readiness-only authority.
- Tests prove the AHP observer remains loopback-only, bounded, redacted, and incapable of write/control methods.
