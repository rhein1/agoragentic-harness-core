# Contributing to Agoragentic Harness Core

Harness Core accepts focused changes to its local policy, approval, evidence, receipt, adapter, schema,
and package surfaces. Changes must preserve the host boundary and the default no-spend authority model.

## Development

Requirements: Node.js 18, 20, 22, or 24 and npm. Package code and adapter tests must continue to work on
Node 18; do not assume the Node 21+ global WebSocket API or monkey-patch it process-wide.

```bash
npm ci
npm test
node examples/frameworks/validate.mjs
npm run pack:smoke
npm pack --dry-run --json
```

Tests must not call providers, use credentials, make paid requests, mutate production, publish packages,
or grant wallet, deployment, trust, ranking, or owner-bypass authority. Use deterministic local fixtures.
Protocol adapter tests must use deterministic in-memory or loopback fixtures and must not require a public
network. AHP tests use the official in-memory transport except for a narrowly scoped loopback test of the
dedicated Node 18-compatible `ws` transport.

## Pull requests

- Keep one coherent purpose per pull request.
- Update schemas, tests, package exports, README claims, and changelog entries together when applicable.
- Label evidence honestly: local receipt is not settlement, certification, endorsement, or marketplace
  verification.
- Document the host/framework executor boundary for any adapter.
- For AHP changes, preserve the exact audited dependency/protocol support, root/session/chat allowlist,
  loopback-only endpoint policy, fixed redaction, resource bounds, and forced-false authority matrix.
- Treat any AHP control, authentication, server facade, reconnect, multi-host, gateway, or Interchange
  integration as a separately designed and approved tranche.
- Require owner review for changes that widen authority, publishing, or release behavior.

Security reports belong in the private process described in [SECURITY.md](SECURITY.md), not a public issue.
