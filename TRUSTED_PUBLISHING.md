# npm trusted publishing

`agoragentic-harness-core` must publish from GitHub Actions through npm trusted publishing. Do not add an
`NPM_TOKEN`, automation token, or local publish path.

Configure npm with:

- Package: `agoragentic-harness-core`
- GitHub owner: `rhein1`
- Repository: `agoragentic-harness-core`
- Workflow: `.github/workflows/publish.yml`
- Environment: none unless a later reviewed release policy adds one

The workflow accepts only a published GitHub release whose tag exactly equals `v<package.json version>`.
Its read-only verification job checks out the immutable release-event SHA, requires the live lightweight or
annotated tag to resolve to that SHA, confirms that `main` is the protected default branch at verification
time, and proves the tag commit is an ancestor of the frozen branch head. It then requires a successful
exact-SHA `push` run of the active `.github/workflows/ci.yml` workflow with one passing job for each supported
Node.js version: 18, 20, 22, and 24. Missing, duplicate, incomplete, failed, PR-only, branch-only, moved-tag,
or wrong-SHA evidence fails closed.

Only after that job passes does a separate job receive OIDC permission, check out the validated commit SHA,
recheck its version and identity, and run `npm ci`, package tests, framework-example validation, pack smoke,
an npm dry run, and `npm publish --access public --provenance`. Checkout credentials are not persisted.

This is an in-workflow guard for owner-reviewed tags and releases. GitHub executes a release workflow from
the release tag's associated ref, so this check is not an external control against a repository principal who
can substitute that tagged workflow itself. Tag/release authority remains an owner boundary; narrowing it
further requires a separately reviewed tag ruleset or protected publishing environment.

Repository extraction and green CI do not authorize publication. The owner must separately approve the
release, configure the trusted publisher, and verify npm package source metadata after publication.
