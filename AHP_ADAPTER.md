# Agent Host Protocol observer adapter

Harness Core's Agent Host Protocol (AHP) adapter records a bounded, sanitized view of synchronized AHP session state as local Harness evidence. It is an **observer**, not an AHP controller, server, gateway, or authority layer.

The adapter uses `@microsoft/agent-host-protocol` `0.8.0` and intentionally supports negotiated AHP protocol version `0.8.0` only. An unsupported negotiated version fails closed. The package remains compatible with Node.js 18 and newer.

## What AHP is—and is not

AHP synchronizes shared host/client agent sessions through channels, snapshots, actions, and ephemeral notifications. Its role is distinct from:

- **MCP**, which exposes tools, resources, and context to models or agent hosts;
- **ACP**, a separate client-to-agent protocol used by coding-agent and editor integrations;
- **A2A**, which addresses agent-to-agent task communication and interoperability;
- **Agoragentic Interchange**, the separate Agoragentic transaction and evidence contract.

This adapter translates a narrow, non-authoritative observation of AHP state into Harness Core's existing local run-ledger conventions. It does not govern or execute an AHP action. It does not translate between these protocols and does not connect AHP to the Interchange.

## Public API

Import the dedicated adapter subpath:

```js
import {
  AHP_OBSERVER_AUTHORITY_FLAGS,
  AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS,
  observeAhp,
  validateAhpObservationConfig,
} from 'agoragentic-harness-core/adapters/ahp';
```

`validateAhpObservationConfig(config)` validates the endpoint or injected transport, exact channel allowlist, and duration, event-count, frame-size, artifact-size, and request-timeout bounds. Protocol support and redaction are fixed rather than caller-configurable. `observeAhp(config)` also verifies the local artifact root, performs one bounded observation, closes its transport, writes sanitized local evidence, and returns a structured summary. When a negotiated transport remains open at cleanup, the observer attempts to emit ID-less `unsubscribe` notifications for negotiated or attempted channels in reverse order and waits for their tracked transport sends only within a bounded portion of the existing cleanup deadline, reserving the rest for shutdown. This is a bounded cleanup attempt, not proof that the host accepted or completed the release. The observer does not return an AHP client or transport handle.

There is no AHP CLI command in this tranche. Observation remains an explicit programmatic call; there is no daemon, scheduler, background mode, retry loop, or automatic reconnect.

## Compatibility and transport

- Dependency: `@microsoft/agent-host-protocol` exactly `0.8.0`.
- Supported AHP protocol version: exactly `0.8.0`.
- Runtime: Node.js `>=18.0.0`.
- Deterministic tests: the official AHP in-memory transport.
- Live local observation: a dedicated `ws`-backed transport for Node 18.

The Node 18 transport is local to the adapter. It does not monkey-patch `globalThis.WebSocket` or otherwise change process-wide WebSocket behavior.

V1 is loopback-only. Configured WebSocket endpoints must use `ws://` or `wss://` and resolve directly to `localhost`, `127.0.0.1`, or `::1`. Remote hosts, embedded URL credentials, query strings, and fragments are rejected. Endpoint evidence stores a digest rather than the raw URL.

## Permitted observation

The adapter can initialize the AHP client and subscribe only to explicitly configured channels using these schemes:

- `ahp-root://`
- `ahp-session:/<single-segment-id>`
- `ahp-chat:/<single-segment-id>`

It can consume the resulting snapshots, action envelopes, and permitted ephemeral notifications. It normalizes only the metadata needed for evidence, including:

- channel scheme and a digest of the channel reference;
- action or notification classification;
- server sequence number;
- server/client origin and a pseudonymous client-origin digest;
- digests of session, chat, turn, or tool-call references when present;
- bounded lifecycle/status and size/count metadata;
- observation timestamp;
- SHA-256 digest of the already-redacted source envelope.

Resource, terminal, telemetry, authentication, automation, and extension channels are not permitted. The adapter never supplies a filesystem, resource, authentication, tool, or other request handler, so the official AHP client selects its safe `MethodNotFound` default. Evidence records that rejection policy selection, not confirmed network delivery of the response.

## Redaction boundary

Redaction is fixed and fail-closed. The adapter does not persist:

- user or assistant message text;
- reasoning content;
- tool input, output, or structured result content;
- bearer tokens, authentication payloads, or authorization-server details;
- file or resource contents;
- terminal output;
- telemetry payload bodies, including raw OTLP logs, traces, or metrics;
- local filesystem paths or environment values;
- secret-looking strings;
- raw client identifiers when a stable digest is sufficient.

The redaction policy is not a switch for retaining those fields. Unknown event shapes are reduced to bounded classification and shape metadata or rejected rather than copied into evidence.

## Bounded local artifacts

The adapter reuses the Harness run ledger instead of creating a parallel evidence system:

```text
.agoragentic/runs/<run_id>/
├── state.json
├── events.jsonl
├── summary.json
├── summary.md
├── local-receipt.json
└── manifest.json
```

Configuration enforces maximum observation duration, event count, inbound frame size, persisted artifact size, and permitted channel count/schemes. The Node 18 WebSocket transport also bounds queued frames and aggregate queued bytes, and treats abnormal peer closure as a failed observation. The official client keeps at most one raw envelope per subscription; actions arriving during snapshot synchronization are reduced immediately to sanitized metadata and bounded by the same effective event limit. Observation has an explicit timeout and clean cancellation. V1 has no unbounded retry, reconnect, multi-host fan-out, or remote gateway behavior.

An observation is `completed` only after protocol initialization and every requested subscription snapshot succeed. A deadline before initialization fails closed; a deadline during requested subscription setup is partial evidence. For each accepted channel snapshot, a later action at or below that snapshot's `fromSeq` watermark is rejected instead of being counted as fresh evidence.

The structured summary follows `agoragentic.harness.ahp-observation.v1`, published at `schema/ahp-observation.v1.json`. Manifests and summaries contain digests and bounded counts, not raw event payloads.

## Evidence truth boundary

AHP `serverSeq` values support correlation within what this observer received. A repeated value can identify an observed duplicate, and a discontinuity can be reported as an **observed sequence gap**. Neither proves delivery completeness or message loss: the server sequence is global, while this adapter sees only its allowed subscriptions and bounded observation window.

AHP snapshots and actions are observations, not proof that an external side effect occurred. AHP model-judge scores or other host assessments do not become ECF policy, trust, approval, or execution authority.

Telemetry observations are not a durable audit ledger. Harness Core's sanitized, hash-bound local receipt and run artifacts remain the durable evidence layer, and even those local receipts are not settlement receipts, certifications, endorsements, or marketplace verification.

## Forced-false authority

Every observation schema instance and local receipt keeps this authority matrix false:

| Authority | Value |
|---|---|
| `dispatch_action` | `false` |
| `create_session` | `false` |
| `dispose_session` | `false` |
| `create_chat` | `false` |
| `terminal_input` | `false` |
| `terminal_claim` | `false` |
| `resource_write` | `false` |
| `resource_delete` | `false` |
| `resource_move` | `false` |
| `authenticate` | `false` |
| `provide_client_tools` | `false` |
| `approve_tool_calls` | `false` |
| `run_automation` | `false` |
| `mutate_automation` | `false` |
| `provider_dispatch` | `false` |
| `wallet_mutation` | `false` |
| `x402_settlement` | `false` |
| `marketplace_publication` | `false` |
| `trust_mutation` | `false` |
| `owner_approval_bypass` | `false` |

The adapter's public API has no write/control method. Its internal transport firewall permits only initialization, subscription lifecycle, and required JSON-RPC responses. It rejects dispatch, session/chat/terminal/resource mutation, authentication, tool confirmation/completion, automation mutation/run, `MCP tools/call`, and mutating `x-` extension methods.

## Explicit non-goals

This tranche does not implement:

- an Agoragentic AHP server or VS Code session host;
- AHP-to-ACP translation or agent-to-agent routing;
- action dispatch or governed write/control;
- tool execution, client-provided tools, or tool approval control;
- resource or terminal control;
- transport authentication;
- a remote multi-tenant gateway or hosted deployment;
- Interchange, provider, wallet, x402, marketplace, trust, or owner-approval integration.

Any future governed-control adapter requires a separate design, security review, authority analysis, tests, and explicit owner approval. Observation evidence from this tranche must not be treated as pre-approval for that work.
