import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { observeToolProposal } from 'agoragentic-harness-core/adapters/tool-observe';

const fixture = JSON.parse(fs.readFileSync(new URL('../examples/frameworks/tool-observe/fixtures.json', import.meta.url), 'utf8'));

test('JavaScript and Python evaluate identical shadow evidence and golden hashes', async () => {
  const command = process.platform === 'win32' ? 'python' : 'python3';
  const python = execFileSync(command, ['-I', '-B', fileURLToPath(new URL('./tool-observe-python.py', import.meta.url))],
    { encoding: 'utf8', timeout: 10_000 });
  const js = [];
  for (const outcome of ['allow', 'ask', 'modify', 'deny']) {
    js.push(await observeToolProposal({
      mode: 'observe', context: fixture.context, arguments: fixture.vectors.unicode.value,
      assess(request, request_hash) {
        const decision = { outcome, request_hash };
        if (outcome === 'modify') decision.transformed_arguments = { label: 'suggested change' };
        return decision;
      },
    }));
  }
  assert.deepEqual(JSON.parse(python), js);
  assert.ok(js.every(record => record.status === 'observed'));
});
