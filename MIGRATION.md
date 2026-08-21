# Migration from agoragentic-integrations

The npm package name and supported CLI/schema imports remain `agoragentic-harness-core`. Existing package
consumers do not need to change imports now that the standalone repository is canonical.

## Source consumers

The canonical source is:

`https://github.com/rhein1/agoragentic-harness-core`

Framework mapping examples move from `examples/harness-core-frameworks/` in the integrations repository
to `examples/frameworks/` here. The integrations repository now preserves historical links through a thin
pointer and a machine-readable standalone-release evidence record. The duplicate canonical implementation
was removed in [agoragentic-integrations PR #345](https://github.com/rhein1/agoragentic-integrations/pull/345).

## Release compatibility

- Package name: unchanged.
- CLI bins: unchanged.
- Exported kernel, adapter, evaluation, Memory-SkillOpt, and schema subpaths: unchanged.
- License: Apache-2.0, unchanged.
- Repository, homepage, issue tracker, releases, and trusted publisher: moved to the standalone repository.
- Verified standalone release: [`v0.3.1`](https://github.com/rhein1/agoragentic-harness-core/releases/tag/v0.3.1).
- Verified npm package: [`agoragentic-harness-core@0.3.1`](https://www.npmjs.com/package/agoragentic-harness-core/v/0.3.1).

Do not interpret repository extraction as new runtime, provider, wallet, payment, deployment, publication,
trust, or owner-bypass authority.
