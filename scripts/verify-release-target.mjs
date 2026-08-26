#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RELEASE_BRANCH = 'main';
export const CI_WORKFLOW_ID = 'ci.yml';
export const CI_WORKFLOW_PATH = '.github/workflows/ci.yml';
export const CI_WORKFLOW_NAME = 'Harness Core CI';
export const REQUIRED_CI_JOBS = Object.freeze([
  'test (18)',
  'test (20)',
  'test (22)',
  'test (24)',
]);

const SHA_PATTERN = /^[0-9a-f]{40}$/i;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_TAG_PEEL_DEPTH = 5;
const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = path.resolve(path.dirname(scriptPath), '..');

export function validateReleaseInputs({
  repository,
  tagName,
  tagCommit,
  eventCommit,
  packageVersion,
}) {
  if (!REPOSITORY_PATTERN.test(String(repository || ''))) {
    throw new Error('GITHUB_REPOSITORY must be an owner/repository pair.');
  }

  const normalizedVersion = String(packageVersion || '').trim();
  if (!normalizedVersion || /\s/.test(normalizedVersion)) {
    throw new Error('package.json must contain a non-empty version without whitespace.');
  }

  const expectedTag = `v${normalizedVersion}`;
  if (tagName !== expectedTag) {
    throw new Error(`Release tag must equal ${expectedTag}.`);
  }

  const normalizedCommit = String(tagCommit || '').toLowerCase();
  if (!SHA_PATTERN.test(normalizedCommit)) {
    throw new Error('Release tag must resolve to a full 40-character Git commit SHA.');
  }

  const normalizedEventCommit = String(eventCommit || '').toLowerCase();
  if (!SHA_PATTERN.test(normalizedEventCommit)) {
    throw new Error('GITHUB_SHA must be a full 40-character Git commit SHA.');
  }
  if (normalizedEventCommit !== normalizedCommit) {
    throw new Error('Checked-out release tag commit must equal the tag-push GITHUB_SHA.');
  }

  return {
    repository,
    tag_name: tagName,
    tag_commit: normalizedCommit,
    event_commit: normalizedEventCommit,
    package_version: normalizedVersion,
  };
}

export async function verifyReleaseTarget(input, options = {}) {
  const release = validateReleaseInputs(input);
  const requestJson = options.requestJson || ((apiPath) => requestGitHubJson(apiPath, {
    token: input.token,
    apiUrl: input.apiUrl,
    fetchImpl: options.fetchImpl,
  }));

  const encodedTag = encodeURIComponent(release.tag_name);
  const resolvedTagCommit = await resolveTagCommit({
    repository: release.repository,
    tagName: release.tag_name,
    requestJson,
  });
  if (resolvedTagCommit !== release.tag_commit) {
    throw new Error('Release tag ref must resolve to the tag-push commit.');
  }

  const repository = await requestJson(`/repos/${release.repository}`);
  if (repository?.default_branch !== RELEASE_BRANCH) {
    throw new Error(`Repository default branch must be ${RELEASE_BRANCH}.`);
  }

  const branch = await requestJson(
    `/repos/${release.repository}/branches/${RELEASE_BRANCH}`,
  );
  if (branch?.name !== RELEASE_BRANCH || branch?.protected !== true) {
    throw new Error(`Release branch ${RELEASE_BRANCH} must be protected.`);
  }

  const mainCommit = String(branch?.commit?.sha || '').toLowerCase();
  if (!SHA_PATTERN.test(mainCommit)) {
    throw new Error(`Protected branch ${RELEASE_BRANCH} did not return a full commit SHA.`);
  }

  if (mainCommit !== release.tag_commit) {
    throw new Error(`Release tag commit must equal the current protected ${RELEASE_BRANCH} head.`);
  }

  const workflow = await requestJson(
    `/repos/${release.repository}/actions/workflows/${CI_WORKFLOW_ID}`,
  );
  if (
    workflow?.name !== CI_WORKFLOW_NAME
    || workflow?.path !== CI_WORKFLOW_PATH
    || workflow?.state !== 'active'
  ) {
    throw new Error(`Required workflow ${CI_WORKFLOW_PATH} must be active.`);
  }

  const runQuery = new URLSearchParams({
    branch: RELEASE_BRANCH,
    event: 'push',
    status: 'success',
    head_sha: release.tag_commit,
    per_page: '100',
  });
  const runs = await requestJson(
    `/repos/${release.repository}/actions/workflows/${CI_WORKFLOW_ID}/runs?${runQuery}`,
  );
  const matchingRuns = Array.isArray(runs?.workflow_runs)
    ? runs.workflow_runs.filter((run) => (
      run?.head_sha === release.tag_commit
      && run?.head_branch === RELEASE_BRANCH
      && run?.event === 'push'
      && run?.status === 'completed'
      && run?.conclusion === 'success'
      && run?.path === CI_WORKFLOW_PATH
      && Number.isInteger(run?.id)
      && run.id > 0
    ))
    : [];

  if (matchingRuns.length === 0) {
    throw new Error('No successful exact-SHA Harness Core CI push run exists for the release tag commit.');
  }

  matchingRuns.sort((left, right) => (
    Number(right.run_attempt || 0) - Number(left.run_attempt || 0)
    || right.id - left.id
  ));
  const run = matchingRuns[0];
  const jobQuery = new URLSearchParams({ filter: 'latest', per_page: '100' });
  const jobs = await requestJson(
    `/repos/${release.repository}/actions/runs/${run.id}/jobs?${jobQuery}`,
  );
  const runJobs = Array.isArray(jobs?.jobs) ? jobs.jobs : [];
  const verifiedJobs = [];

  for (const requiredName of REQUIRED_CI_JOBS) {
    const matches = runJobs.filter((job) => job?.name === requiredName);
    if (matches.length !== 1) {
      throw new Error(`Exact-SHA CI must contain exactly one ${requiredName} job.`);
    }

    const job = matches[0];
    if (
      job.head_sha !== release.tag_commit
      || job.status !== 'completed'
      || job.conclusion !== 'success'
    ) {
      throw new Error(`Exact-SHA CI job ${requiredName} did not complete successfully.`);
    }
    verifiedJobs.push(requiredName);
  }

  return {
    ok: true,
    repository: release.repository,
    tag_name: release.tag_name,
    tag_commit: release.tag_commit,
    protected_branch: RELEASE_BRANCH,
    protected_branch_commit: mainCommit,
    ci_workflow: CI_WORKFLOW_PATH,
    ci_run_id: run.id,
    ci_run_url: run.html_url || null,
    verified_jobs: verifiedJobs,
  };
}

export async function resolveTagCommit({ repository, tagName, requestJson }) {
  const tagRef = await requestJson(
    `/repos/${repository}/git/ref/tags/${encodeURIComponent(tagName)}`,
  );
  if (tagRef?.ref !== `refs/tags/${tagName}`) {
    throw new Error('GitHub tag ref did not match the release tag name.');
  }

  let object = tagRef?.object;
  const seenTagObjects = new Set();
  for (let depth = 0; depth < MAX_TAG_PEEL_DEPTH; depth += 1) {
    const sha = String(object?.sha || '').toLowerCase();
    if (!SHA_PATTERN.test(sha)) {
      throw new Error('GitHub tag ref returned an invalid object SHA.');
    }
    if (object?.type === 'commit') return sha;
    if (object?.type !== 'tag' || seenTagObjects.has(sha)) {
      throw new Error('GitHub tag ref did not resolve to a commit.');
    }

    seenTagObjects.add(sha);
    const annotatedTag = await requestJson(`/repos/${repository}/git/tags/${sha}`);
    object = annotatedTag?.object;
  }

  throw new Error(`GitHub tag ref exceeded ${MAX_TAG_PEEL_DEPTH} annotated-tag levels.`);
}

export async function requestGitHubJson(apiPath, {
  token,
  apiUrl = 'https://api.github.com',
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!token) {
    throw new Error('GITHUB_TOKEN is required for release verification.');
  }
  if (typeof fetchImpl !== 'function') {
    throw new Error('A Fetch-compatible implementation is required for release verification.');
  }

  const normalizedApiUrl = String(apiUrl || '').replace(/\/+$/, '');
  const url = new URL(`${normalizedApiUrl}${apiPath}`);
  if (url.protocol !== 'https:') {
    throw new Error('GITHUB_API_URL must use HTTPS.');
  }

  const response = await fetchImpl(url, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'user-agent': 'agoragentic-harness-core-release-verifier',
      'x-github-api-version': '2022-11-28',
    },
  });
  if (!response?.ok) {
    throw new Error(`GitHub API request failed for ${url.pathname}: HTTP ${response?.status || 'unknown'}.`);
  }

  try {
    return await response.json();
  } catch {
    throw new Error(`GitHub API returned invalid JSON for ${url.pathname}.`);
  }
}

export function validateReleaseEnvironment(env = {}) {
  if (env.GITHUB_EVENT_NAME !== 'push') {
    throw new Error('Release verification must run from a GitHub tag-push event.');
  }
  if (env.GITHUB_REF_TYPE !== 'tag') {
    throw new Error('Release verification requires a tag ref.');
  }
  if (env.RELEASE_TAG_NAME !== env.GITHUB_REF_NAME) {
    throw new Error('Release tag name must equal GITHUB_REF_NAME.');
  }
  if (env.GITHUB_REF !== `refs/tags/${env.GITHUB_REF_NAME}`) {
    throw new Error('GITHUB_REF must exactly identify the release tag.');
  }

  return {
    tag_name: env.GITHUB_REF_NAME,
    ref: env.GITHUB_REF,
  };
}

export async function runReleaseVerificationFromEnvironment(env = process.env) {
  validateReleaseEnvironment(env);

  const packageJson = JSON.parse(
    readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'),
  );
  const tagCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();

  return verifyReleaseTarget({
    repository: env.GITHUB_REPOSITORY,
    tagName: env.RELEASE_TAG_NAME || env.GITHUB_REF_NAME,
    tagCommit,
    eventCommit: env.GITHUB_SHA,
    packageVersion: packageJson.version,
    token: env.GITHUB_TOKEN,
    apiUrl: env.GITHUB_API_URL,
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === path.resolve(scriptPath)) {
  try {
    const result = await runReleaseVerificationFromEnvironment();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Release target verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
