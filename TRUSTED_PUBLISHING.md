# npm trusted publishing

`agoragentic-harness-core` must publish from GitHub Actions through npm trusted publishing. Do not add an
`NPM_TOKEN`, automation token, or local publish path.

Configure npm with:

- Package: `agoragentic-harness-core`
- GitHub owner: `rhein1`
- Repository: `agoragentic-harness-core`
- Workflow filename: `publish.yml`
- Environment: `npm-publish`
- Allowed action: `npm publish` only

The workflow accepts only a pushed tag that exactly equals `v<package.json version>`.
Its read-only verification job checks out the immutable tag-push SHA, requires the live lightweight or
annotated tag to resolve to that SHA, confirms that `main` is the protected default branch at verification
time, and proves the tag commit equals the current protected branch head. It then requires a successful
exact-SHA `push` run of the active `.github/workflows/ci.yml` workflow with one passing job for each supported
Node.js version: 18, 20, 22, and 24. Missing, duplicate, incomplete, failed, PR-only, branch-only, moved-tag,
or wrong-SHA evidence fails closed.

Only after that job passes does a separate job request the `npm-publish` environment. The environment accepts
only `v*` tags, requires a designated reviewer, prevents self-review, and disallows administrator bypass.
After approval, the job receives OIDC permission, checks out the validated commit SHA, rechecks its version
and identity, and runs `npm ci`, package tests, framework-example validation, pack smoke, an npm dry run, and
`npm publish --access public --provenance`. Checkout credentials are not persisted. The npm trusted-publisher
record must name the same `npm-publish` environment and allow `npm publish` only.

The GitHub Release is created only after publication, registry integrity, source revision, and provenance are
independently verified. The environment is an external approval boundary for the OIDC publication job; tag
creation and reviewer authority remain owner controls and do not substitute for independent release evidence.

Repository extraction and green CI do not authorize publication. The owner must separately create the exact
tag, a different authorized account must approve the protected environment deployment, and the package source
metadata and provenance must be verified after publication.
