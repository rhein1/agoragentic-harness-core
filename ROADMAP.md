# Roadmap

## Current release gate

- Require an owner-approved GitHub release tag that exactly matches `v<package.json version>`.
- Require the release-event SHA and live tag ref to match, belong to `main` while it is protected, and have successful exact-SHA CI on Node.js 18, 20, 22, and 24.
- Publish only from the release-tag workflow through npm trusted publishing with provenance; never add a local or token-based publish path.
- Independently verify the npm version, `latest` tag, tarball integrity, source commit, and provenance after publication.

## Completed foundations

- Published and independently verified the standalone `0.3.1` CLI-manifest recovery release.
- Replaced the integrations-repository implementation with a thin compatibility pointer to this canonical repository.
- Released the bounded, observer-only AHP `0.8.0` adapter in `0.4.0` and its best-effort subscription cleanup in `0.4.1`.
- Preserved Node.js 18 compatibility, loopback-only live transport, fixed redaction, bounded artifacts, and forced-false authority.

## Near term

- Keep local policy, approval, host-hook evidence, and receipt schemas stable.
- Expand deterministic adapter conformance without executing third-party hosts.
- Expand deterministic AHP conformance and real-host qualification evidence without adding host-control authority.
- Preserve exact source and revision evidence for optional Memory and SkillOpt bridges.
- Improve Windows, Linux, and macOS package smoke coverage.
- Narrow the owner-level tagged-workflow boundary with a reviewed tag ruleset or protected publishing environment.

Any governed AHP action or write/control support is a separate future tranche. It requires a new design, threat model, authority review, tests, and explicit approval; observer evidence does not pre-authorize it.

## Non-goals

Harness Core does not become an agent runtime, marketplace, wallet, settlement rail, trust authority,
provider dispatcher, deployment control plane, automatic owner-approval substitute, AHP server facade,
remote AHP gateway, transport-authentication broker, protocol translator, or write-capable AHP controller.
