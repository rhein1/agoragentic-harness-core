# Changelog

## Unreleased

- Hardened trusted publishing so a version-matched release tag must belong to protected `main` and have successful exact-SHA Node.js 18, 20, 22, and 24 CI before npm publication.

## 0.4.1 - 2026-08-24

- Attempt to release negotiated or attempted AHP observer subscriptions in reverse order before transport close, with bounded send tracking and warning-only evidence when cleanup cannot complete.

## 0.4.0 - 2026-08-24

- Added an observer-only Microsoft Agent Host Protocol adapter using the exact `@microsoft/agent-host-protocol` `0.8.0` dependency and explicit AHP `0.8.0` negotiation support.
- Added a dedicated Node 18-compatible `ws` transport, deterministic in-memory tests, loopback-only endpoint validation, fixed redaction, bounded local run-ledger artifacts, and a forced-false authority schema.
- Documented that AHP sequence and telemetry observations are correlation evidence—not receipts, loss proof, an audit ledger, ECF authority, or permission to control an AHP host.

## 0.3.1 - 2026-08-21

- Repaired npm CLI mappings so all four installed commands survive npm manifest normalization.
- Added packed-manifest and installed-shim checks to the clean-room package smoke gate.
- Published the standalone package through the repository's trusted-publisher workflow with npm provenance.
- Completed the canonical-source cutover and replaced the integrations-repository implementation with a thin pointer.

## 0.3.0 - 2026-08-20

- Added the packaged Harness Core hero and installed-package README link verification.
- Narrowed receipt and adapter claims to the configuration/proposal evidence emitted by the package.
- Added a review-gated Agoragentic Memory to SkillOpt task-draft bridge and bounded SkillOpt report adapter.

## 0.2.0 - 2026-07-23

- Added the local middleware kernel, lifecycle events, append-only run ledger, profiles, approvals, review gates, runtime metadata probes, context-reference imports, owner inbox, schedule intent, and worktree-session evidence.
- Added package exports for every shipped schema and retained the original proof, receipt, readiness, and Agent OS Harness schemas.
- Added an out-of-repository package install smoke test and explicit npm source metadata.
- Preserved the local no-spend boundary: no provider execution, hosted provisioning, wallet or x402 action, marketplace publication, trust mutation, hosted memory write, SSH, tunnel, or process-control authority.

## 0.1.0

- Initial local proof, receipt, Agent OS preview export, listing-readiness, and adapter scaffold release.
