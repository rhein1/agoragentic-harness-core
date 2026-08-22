# Roadmap

## Current release gate

- Verify the standalone filtered history and package at an exact source commit.
- Establish required GitHub CI and release-only npm provenance.
- Publish and independently verify the `0.3.1` CLI-manifest recovery release.
- Replace the integrations-repository implementation with a thin compatibility pointer after release.

## Near term

- Keep local policy, approval, host-hook evidence, and receipt schemas stable.
- Expand deterministic adapter conformance without executing third-party hosts.
- Independently review and release the bounded AHP `0.8.0` observer while preserving Node.js 18, loopback-only transport, fixed redaction, and forced-false authority.
- Preserve exact source and revision evidence for optional Memory and SkillOpt bridges.
- Improve Windows, Linux, and macOS package smoke coverage.

Any governed AHP action or write/control support is a separate future tranche. It requires a new design, threat model, authority review, tests, and explicit approval; observer evidence does not pre-authorize it.

## Non-goals

Harness Core does not become an agent runtime, marketplace, wallet, settlement rail, trust authority,
provider dispatcher, deployment control plane, automatic owner-approval substitute, AHP server facade,
remote AHP gateway, transport-authentication broker, protocol translator, or write-capable AHP controller.
