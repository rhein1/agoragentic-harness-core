# Security policy

Harness Core is a local no-spend governance kernel. Report vulnerabilities privately to
`security@agoragentic.com`. Do not open a public issue for suspected vulnerabilities, exploit details,
secret exposure, or unsafe authority widening.

## Supported versions

| Version | Status |
|---|---|
| `0.4.x` | Review-gated source candidate; not yet published |
| `0.3.x` | Current published npm release line |
| `0.2.x` | Previous published release line |
| `<0.2` | Unsupported |

## Scope

Security reports may cover policy bypass, approval bypass, receipt or evidence tampering, path escape,
unsafe host-hook behavior, secret retention, dependency compromise, or unexpected wallet, network,
provider, deployment, publication, trust, or spend authority.

For the Microsoft AHP observer, reports may also cover remote-endpoint bypass, URL-credential retention,
unsupported-protocol acceptance, channel-allowlist bypass, oversized or malformed frame handling,
redaction failure, unbounded artifacts, unexpected reconnect/fan-out, server-request handling, or any
reachable write/control method. The supported adapter boundary is `@microsoft/agent-host-protocol`
`0.8.0`, negotiated AHP `0.8.0`, loopback-only `ws://` or `wss://`, and root/session/chat observation.

The AHP adapter must not retain raw messages, reasoning, tool payloads, bearer/authentication material,
resource or terminal content, local paths, environment values, or telemetry bodies. It uses a dedicated
Node 18-compatible `ws` transport and must not monkey-patch the global WebSocket implementation.
Unsupported server requests have no installed handler, so the official client selects its `MethodNotFound`
default. Evidence does not claim confirmed response delivery. There is no resource, tool, filesystem,
authentication, automation, control, server-facade, gateway, or multi-host handler.

Harness Core local receipts are not settlement receipts, certifications, endorsements, or marketplace
verification. The host remains the executor. A report that relies on live provider calls, payments, or
production mutation must be coordinated privately before any test is attempted.

AHP server sequence numbers are correlation metadata, not proof of complete delivery, message loss, or
receipt status. OTLP and other telemetry are not a durable audit ledger, and observed host/model scores do
not become ECF authority. Future governed AHP control requires a separate security design and approval.
