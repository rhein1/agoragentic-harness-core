import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import {
  CI_WORKFLOW_PATH,
  REQUIRED_CI_JOBS,
  requestGitHubJson,
  verifyReleaseTarget,
} from '../scripts/verify-release-target.mjs';

const TAG_COMMIT = 'a'.repeat(40);
const MAIN_COMMIT = 'b'.repeat(40);
const ANNOTATED_TAG_SHA = 'd'.repeat(40);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function validInput(overrides = {}) {
  return {
    repository: 'rhein1/agoragentic-harness-core',
    tagName: 'v0.4.1',
    tagCommit: TAG_COMMIT,
    eventCommit: TAG_COMMIT,
    packageVersion: '0.4.1',
    ...overrides,
  };
}

function passingJobs() {
  return REQUIRED_CI_JOBS.map((name, index) => ({
    id: 200 + index,
    name,
    head_sha: TAG_COMMIT,
    status: 'completed',
    conclusion: 'success',
  }));
}

function githubFixture(overrides = {}) {
  const calls = [];
  const tagRef = overrides.tagRef || {
    ref: 'refs/tags/v0.4.1',
    object: { type: 'commit', sha: TAG_COMMIT },
  };
  const annotatedTag = overrides.annotatedTag || {
    object: { type: 'commit', sha: TAG_COMMIT },
  };
  const publishedRelease = overrides.publishedRelease || {
    tag_name: 'v0.4.1',
    draft: false,
    prerelease: false,
    published_at: '2026-08-25T00:00:00Z',
  };
  const repository = overrides.repository || { default_branch: 'main' };
  const branch = overrides.branch || {
    name: 'main',
    protected: true,
    commit: { sha: MAIN_COMMIT },
  };
  const comparison = overrides.comparison || {
    status: 'ahead',
    base_commit: { sha: TAG_COMMIT },
    merge_base_commit: { sha: TAG_COMMIT },
  };
  const workflowRuns = overrides.workflowRuns || [{
    id: 101,
    run_attempt: 1,
    head_sha: TAG_COMMIT,
    head_branch: 'main',
    event: 'push',
    status: 'completed',
    conclusion: 'success',
    path: CI_WORKFLOW_PATH,
    html_url: 'https://github.example/actions/runs/101',
  }];
  const workflow = overrides.workflow || {
    name: 'Harness Core CI',
    path: CI_WORKFLOW_PATH,
    state: 'active',
  };
  const jobs = overrides.jobs || passingJobs();

  return {
    calls,
    requestJson: async (apiPath) => {
      calls.push(apiPath);
      const url = new URL(apiPath, 'https://api.github.test');
      if (url.pathname.includes('/git/ref/tags/')) return tagRef;
      if (url.pathname.includes('/git/tags/')) return annotatedTag;
      if (url.pathname.includes('/releases/tags/')) return publishedRelease;
      if (url.pathname === '/repos/rhein1/agoragentic-harness-core') return repository;
      if (url.pathname.endsWith('/branches/main')) return branch;
      if (url.pathname.includes('/compare/')) return comparison;
      if (url.pathname.endsWith('/actions/workflows/ci.yml/runs')) {
        return { total_count: workflowRuns.length, workflow_runs: workflowRuns };
      }
      if (url.pathname.endsWith('/actions/runs/101/jobs')) {
        return { total_count: jobs.length, jobs };
      }
      if (url.pathname.endsWith('/actions/workflows/ci.yml')) return workflow;
      throw new Error(`Unexpected fixture request: ${apiPath}`);
    },
  };
}

test('release verifier accepts a protected-main ancestor with exact successful matrix CI', async () => {
  const fixture = githubFixture();
  const result = await verifyReleaseTarget(validInput(), fixture);

  assert.equal(result.ok, true);
  assert.equal(result.tag_commit, TAG_COMMIT);
  assert.equal(result.protected_branch_commit, MAIN_COMMIT);
  assert.equal(result.ci_run_id, 101);
  assert.deepEqual(result.verified_jobs, REQUIRED_CI_JOBS);

  const runsCall = fixture.calls.find((entry) => entry.includes('/workflows/ci.yml/runs?'));
  const runsUrl = new URL(runsCall, 'https://api.github.test');
  assert.equal(runsUrl.searchParams.get('branch'), 'main');
  assert.equal(runsUrl.searchParams.get('event'), 'push');
  assert.equal(runsUrl.searchParams.get('status'), 'success');
  assert.equal(runsUrl.searchParams.get('head_sha'), TAG_COMMIT);
});

test('release verifier rejects a tag that does not exactly match package.json', async () => {
  let called = false;
  await assert.rejects(
    verifyReleaseTarget(validInput({ tagName: 'v0.4.2' }), {
      requestJson: async () => {
        called = true;
        return {};
      },
    }),
    /Release tag must equal v0\.4\.1/,
  );
  assert.equal(called, false);
});

test('release verifier rejects a checkout that differs from the release-event SHA', async () => {
  let called = false;
  await assert.rejects(
    verifyReleaseTarget(validInput({ eventCommit: MAIN_COMMIT }), {
      requestJson: async () => {
        called = true;
        return {};
      },
    }),
    /must equal the release-event GITHUB_SHA/,
  );
  assert.equal(called, false);
});

test('release verifier rejects a moved tag ref', async () => {
  const fixture = githubFixture({
    tagRef: {
      ref: 'refs/tags/v0.4.1',
      object: { type: 'commit', sha: MAIN_COMMIT },
    },
  });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /must resolve to the release-event commit/,
  );
});

test('release verifier peels an annotated tag to the release-event commit', async () => {
  const fixture = githubFixture({
    tagRef: {
      ref: 'refs/tags/v0.4.1',
      object: { type: 'tag', sha: ANNOTATED_TAG_SHA },
    },
  });
  const result = await verifyReleaseTarget(validInput(), fixture);
  assert.equal(result.tag_commit, TAG_COMMIT);
  assert.ok(
    fixture.calls.some((entry) => entry.endsWith(`/git/tags/${ANNOTATED_TAG_SHA}`)),
  );
});

test('release verifier rejects a draft release or non-main default branch', async () => {
  await assert.rejects(
    verifyReleaseTarget(validInput(), githubFixture({
      publishedRelease: {
        tag_name: 'v0.4.1',
        draft: true,
        published_at: null,
      },
    })),
    /must have a published, non-draft GitHub release/,
  );

  await assert.rejects(
    verifyReleaseTarget(validInput(), githubFixture({
      repository: { default_branch: 'trunk' },
    })),
    /default branch must be main/,
  );
});

test('release verifier rejects an unprotected main branch', async () => {
  const fixture = githubFixture({
    branch: { name: 'main', protected: false, commit: { sha: MAIN_COMMIT } },
  });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /main must be protected/,
  );
});

test('release verifier rejects a tag commit outside protected main history', async () => {
  const fixture = githubFixture({
    comparison: {
      status: 'diverged',
      base_commit: { sha: TAG_COMMIT },
      merge_base_commit: { sha: 'c'.repeat(40) },
    },
  });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /not an ancestor of protected main/,
  );
});

test('release verifier accepts a tag identical to the protected main head', async () => {
  const fixture = githubFixture({
    branch: { name: 'main', protected: true, commit: { sha: TAG_COMMIT } },
    comparison: {
      status: 'identical',
      base_commit: { sha: TAG_COMMIT },
      merge_base_commit: { sha: TAG_COMMIT },
    },
  });
  const result = await verifyReleaseTarget(validInput(), fixture);
  assert.equal(result.protected_branch_commit, TAG_COMMIT);
});

test('release verifier rejects an inactive or substituted CI workflow', async () => {
  const fixture = githubFixture({
    workflow: {
      name: 'Harness Core CI',
      path: CI_WORKFLOW_PATH,
      state: 'disabled_manually',
    },
  });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /Required workflow \.github\/workflows\/ci\.yml must be active/,
  );
});

test('release verifier rejects PR-only, branch, and wrong-SHA workflow runs', async () => {
  const fixture = githubFixture({
    workflowRuns: [
      {
        id: 101,
        head_sha: TAG_COMMIT,
        head_branch: 'feature',
        event: 'pull_request',
        status: 'completed',
        conclusion: 'success',
        path: CI_WORKFLOW_PATH,
      },
      {
        id: 102,
        head_sha: MAIN_COMMIT,
        head_branch: 'main',
        event: 'push',
        status: 'completed',
        conclusion: 'success',
        path: CI_WORKFLOW_PATH,
      },
    ],
  });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /No successful exact-SHA Harness Core CI push run/,
  );
});

for (const requiredName of REQUIRED_CI_JOBS) {
  test(`release verifier rejects a non-successful ${requiredName} job`, async () => {
    const jobs = passingJobs().map((job) => (
      job.name === requiredName ? { ...job, conclusion: 'failure' } : job
    ));
    const fixture = githubFixture({ jobs });
    await assert.rejects(
      verifyReleaseTarget(validInput(), fixture),
      new RegExp(`${requiredName.replace(/[()]/g, '\\$&')} did not complete successfully`),
    );
  });
}

test('release verifier rejects a missing required job', async () => {
  const jobs = passingJobs().filter((job) => job.name !== 'test (18)');
  const fixture = githubFixture({ jobs });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /must contain exactly one test \(18\) job/,
  );
});

test('release verifier rejects incomplete or wrong-SHA required jobs', async () => {
  const incomplete = passingJobs().map((job) => (
    job.name === 'test (20)'
      ? { ...job, status: 'in_progress', conclusion: null }
      : job
  ));
  await assert.rejects(
    verifyReleaseTarget(validInput(), githubFixture({ jobs: incomplete })),
    /test \(20\) did not complete successfully/,
  );

  const wrongSha = passingJobs().map((job) => (
    job.name === 'test (22)' ? { ...job, head_sha: MAIN_COMMIT } : job
  ));
  await assert.rejects(
    verifyReleaseTarget(validInput(), githubFixture({ jobs: wrongSha })),
    /test \(22\) did not complete successfully/,
  );
});

test('release verifier rejects duplicate required job names', async () => {
  const jobs = [...passingJobs(), { ...passingJobs()[0], id: 999 }];
  const fixture = githubFixture({ jobs });
  await assert.rejects(
    verifyReleaseTarget(validInput(), fixture),
    /must contain exactly one test \(18\) job/,
  );
});

test('GitHub API failures are fail-closed without reflecting response bodies', async () => {
  const secretBody = 'private diagnostic body';
  await assert.rejects(
    requestGitHubJson('/repos/rhein1/agoragentic-harness-core/branches/main', {
      token: 'fixture-token',
      fetchImpl: async () => ({
        ok: false,
        status: 403,
        json: async () => ({ message: secretBody }),
      }),
    }),
    (error) => {
      assert.match(error.message, /HTTP 403/);
      assert.doesNotMatch(error.message, new RegExp(secretBody));
      assert.doesNotMatch(error.message, /fixture-token/);
      return true;
    },
  );
});

test('publish workflow separates read-only verification from pinned-SHA OIDC publication', async () => {
  const workflowSource = await readFile(
    path.join(repositoryRoot, '.github', 'workflows', 'publish.yml'),
    'utf8',
  );
  const workflow = parseYaml(workflowSource);
  assert.deepEqual(workflow.on.release.types, ['published']);
  assert.deepEqual(workflow.permissions, {});

  const verifyJob = workflow.jobs.verify;
  const publishJob = workflow.jobs.publish;
  assert.equal(verifyJob.permissions.actions, 'read');
  assert.equal(verifyJob.permissions.contents, 'read');
  assert.equal(verifyJob.permissions['id-token'], undefined);
  assert.equal(publishJob.needs, 'verify');
  assert.equal(publishJob.permissions.contents, 'read');
  assert.equal(publishJob.permissions['id-token'], 'write');
  assert.equal(publishJob.permissions.actions, undefined);

  const verifyCheckout = verifyJob.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  assert.equal(verifyCheckout.with.ref, '${{ github.sha }}');
  assert.equal(verifyCheckout.with['persist-credentials'], false);
  const guard = verifyJob.steps.find(
    (step) => step.name === 'Verify protected-main release target and exact CI',
  );
  assert.ok(guard, 'release-target verification step must exist');
  assert.equal(guard.id, 'guard');
  assert.equal(guard.env.GITHUB_TOKEN, '${{ github.token }}');
  assert.equal(guard.env.RELEASE_TAG_NAME, '${{ github.event.release.tag_name }}');
  assert.match(guard.run, /node scripts\/verify-release-target\.mjs/);
  assert.equal(
    verifyJob.outputs.tag_commit,
    '${{ steps.guard.outputs.tag_commit }}',
  );

  const publishCheckout = publishJob.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  assert.equal(publishCheckout.with.ref, '${{ needs.verify.outputs.tag_commit }}');
  assert.equal(publishCheckout.with['persist-credentials'], false);
  const recheckIndex = publishJob.steps.findIndex(
    (step) => step.name === 'Recheck validated release commit',
  );
  const publishIndex = publishJob.steps.findIndex(
    (step) => step.run === 'npm publish --access public --provenance',
  );
  assert.ok(recheckIndex > -1, 'validated commit recheck must exist');
  assert.ok(publishIndex > recheckIndex, 'validated commit recheck must precede npm publish');
});
