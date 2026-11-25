import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import Ajv from 'ajv';
import { adapterCatalog } from 'agoragentic-harness-core/adapters';
import { controlValueHash, observeToolProposal } from 'agoragentic-harness-core/adapters/tool-observe';

const fixture = JSON.parse(fs.readFileSync(new URL('../examples/frameworks/tool-observe/fixtures.json', import.meta.url), 'utf8'));
const schema = JSON.parse(fs.readFileSync(new URL('../schema/control-observation.v1.json', import.meta.url), 'utf8'));
const validate = new Ajv().compile(schema);
const args = fixture.vectors.unicode.value;
const context = fixture.context;

function assertObservation(receipt) {
  assert.equal(validate(receipt), true, JSON.stringify(validate.errors));
  assert.equal(receipt.authoritative, false);
  assert.equal(receipt.execution_observed, false);
}

test('the public catalog advertises generic tool observation as observer-only', () => {
  const entry = adapterCatalog().find(row => row.id === 'tool_observe');
  assert.equal(entry?.entrypoint, 'agoragentic-harness-core/adapters/tool-observe');
  assert.equal(entry.status, 'observer');
  assert.equal(entry.authority, 'local_no_spend_observation_only');
});

test('portable value hashes match the shared vectors', () => {
  for (const [name, { value, hash }] of Object.entries(fixture.vectors)) {
    assert.equal(controlValueHash(value), hash, name);
  }
  assert.equal(controlValueHash(1), controlValueHash(1.0));
  assert.notEqual(controlValueHash(1), controlValueHash('1'));
  assert.notEqual(controlValueHash({ '2': 'two' }), controlValueHash([['2', 'two']]));
});

test('off is inert and enforce is unavailable', async () => {
  let calls = 0;
  assert.equal(await observeToolProposal({ assess: () => { calls += 1; } }), null);
  assert.equal(calls, 0);
  await assert.rejects(observeToolProposal({ mode: 'enforce' }), /Unsupported tool observation mode/);
});

test('shadow outcomes bind their request without authorizing or rewriting the host tool', async () => {
  for (const outcome of ['allow', 'ask', 'modify', 'deny']) {
    const raw = structuredClone(args);
    const receipt = await observeToolProposal({
      mode: 'observe', context, arguments: raw,
      assess(request, request_hash) {
        assert.equal(request_hash, controlValueHash(request));
        assert.equal(Object.hasOwn(request, 'arguments'), false);
        request.principal = 'caller cannot replace integrity-bound metadata';
        const assessment = { outcome, request_hash };
        if (outcome === 'modify') assessment.transformed_arguments = { label: 'suggested change' };
        return assessment;
      },
    });
    assertObservation(receipt);
    assert.equal(receipt.status, 'observed');
    assert.equal(receipt.request.principal, context.principal);
    assert.equal(receipt.decision.request_hash, receipt.request_hash);
    assert.equal(receipt.decision.outcome, outcome);
    assert.equal(receipt.decision.approval_proposal_ref, null);
    assert.equal(receipt.decision.transformation_hash,
      outcome === 'modify' ? controlValueHash({ label: 'suggested change' }) : null);
    const { decision_hash, ...decision } = receipt.decision;
    assert.equal(decision_hash, controlValueHash(decision));
    assert.deepEqual(raw, args);
    assert.equal(JSON.stringify(receipt).includes(raw.label), false);
    assert.equal(JSON.stringify(receipt).includes('suggested change'), false);
  }
});

test('stale and invalid assessments and thrown errors preserve only scoped request evidence', async () => {
  for (const assess of [
    () => ({ outcome: 'allow', request_hash: context.request_id }),
    async () => { throw new Error('secret error detail'); },
    (request, request_hash) => ({ outcome: 'allow', request_hash, authoritative: true }),
    (request, request_hash) => ({ outcome: 'modify', request_hash }),
  ]) {
    const receipt = await observeToolProposal({ mode: 'observe', context, arguments: args, assess });
    assertObservation(receipt);
    assert.equal(receipt.reason, 'assessment_unavailable');
    assert.equal(receipt.decision, null);
    assert.equal(JSON.stringify(receipt).includes('secret error detail'), false);
  }
});

test('invalid inputs do not invoke the assessor or retain payloads', async () => {
  let getterReads = 0;
  const accessor = { get value() { getterReads += 1; return 'private'; } };
  const proxy = new Proxy({}, { ownKeys() { getterReads += 1; throw new Error('unexpected reflection'); } });
  const cyclic = {};
  cyclic.self = cyclic;
  for (const payload of [
    accessor, proxy, cyclic, [1, , 3], Number.NaN, -0, 2 ** 53,
    '\ud800', 'x'.repeat(65_537), Object.create({ inherited: true }),
    Array.from({ length: 4096 }, () => null), undefined,
  ]) {
    let assessments = 0;
    const receipt = await observeToolProposal({
      mode: 'observe', context, arguments: payload, assess: () => { assessments += 1; },
    });
    assertObservation(receipt);
    assert.equal(receipt.reason, 'invalid_proposal');
    assert.equal(receipt.request, null);
    assert.equal(assessments, 0);
  }
  assert.equal(getterReads, 0);
});

test('context is closed, class lists are unique, timestamps and reference formats are strict', async () => {
  for (const invalid of [
    { ...context, approval_proposal_ref: context.policy },
    { ...context, expires_at: context.proposed_at },
    { ...context, proposed_at: '2030-02-30T00:00:00.000Z' },
    { ...context, principal: context.principal + '\n' },
    { ...context, framework: context.framework + '\n' },
    { ...context, economic_context: undefined },
    { ...context, data_classes: ['local', 'local'] },
  ]) {
    const receipt = await observeToolProposal({ mode: 'observe', context: invalid, arguments: args });
    assertObservation(receipt);
    assert.equal(receipt.reason, 'invalid_proposal');
  }
});

test('equivalent actions retain their action identity across framework metadata', async () => {
  const assess = (request, request_hash) => ({ outcome: 'deny', request_hash });
  const inspect = context => observeToolProposal({ mode: 'observe', context, arguments: args, assess });
  const a = await inspect(context);
  const b = await inspect({ ...context, framework: 'other-host' });
  assert.equal(a.request.action_hash, b.request.action_hash);
  assert.notEqual(a.request_hash, b.request_hash);
});

test('host dispatch and arguments are independent of an unfinished shadow assessment', async () => {
  const input = { directory: 'example' };
  let decide;
  const pending = observeToolProposal({
    mode: 'observe', context, arguments: input,
    assess: (request, request_hash) => new Promise(resolve => {
      decide = () => resolve({ outcome: 'deny', request_hash });
    }),
  });
  const invoked = [];
  const hostTool = args => { invoked.push(args); return 'completed'; };
  assert.equal(hostTool(input), 'completed');
  decide();
  const observation = await pending;
  assert.equal(observation.decision.outcome, 'deny');
  assert.equal(observation.execution_observed, false);
  assert.deepEqual(invoked, [{ directory: 'example' }]);
});
