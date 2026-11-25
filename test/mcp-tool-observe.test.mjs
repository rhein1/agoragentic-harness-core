import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { controlValueHash, observeMcpToolCall } from '../src/adapters/tool-observe.mjs';

const { context: fixture } = JSON.parse(readFileSync(
  new URL('../examples/frameworks/tool-observe/fixtures.json', import.meta.url), 'utf8',
));
const { tool, operation, framework, adapter_version: adapterVersion, ...context } = fixture;
const server = controlValueHash(['fixture-server', 1]);
const request = {
  method: 'tools/call',
  params: {
    name: 'fixture.echo',
    arguments: { note: 'fixture-input' },
    _meta: { progressToken: 'fixture-metadata' },
  },
};

test('uses the trusted server reference and MCP tool name for a shadow-only proposal', async () => {
  const seen = [];
  const assess = (value, requestHash) => {
    seen.push(value);
    return { outcome: 'deny', request_hash: requestHash };
  };
  const options = { mode: 'observe', request, server, context, assess };
  const first = await observeMcpToolCall(options);
  const second = await observeMcpToolCall({ ...options, server: controlValueHash(['fixture-server', 2]) });
  assert.equal(first.status, 'observed');
  assert.equal(first.decision.outcome, 'deny');
  assert.equal(first.authoritative, false);
  assert.equal(first.execution_observed, false);
  assert.equal(first.request.tool, controlValueHash(['agoragentic.mcp-tool.v1', server, 'fixture.echo']));
  assert.equal(first.request.operation, 'tools.call');
  assert.equal(first.request.framework, 'mcp');
  assert.equal(first.request.arguments_hash, controlValueHash(request.params.arguments));
  assert.notEqual(first.request.action_hash, second.request.action_hash);
  assert.doesNotMatch(JSON.stringify({ seen, first }), /fixture-input|fixture-metadata|fixture\.echo/);
});

test('default off is inert and malformed proposals cannot reach the assessor', async () => {
  let reads = 0;
  const accessor = {
    get method() {
      reads += 1;
      return 'tools/call';
    },
  };
  const assess = () => { assert.fail('invalid input reached assessor'); };
  assert.equal(await observeMcpToolCall({ request: accessor, assess }), null);
  await assert.rejects(observeMcpToolCall({ mode: 'enforce', request: accessor, assess }), RangeError);
  for (const [badRequest, badServer, badContext] of [
    [accessor, server, context],
    [{ method: 'resources/read', params: request.params }, server, context],
    [{ ...request, params: { name: 'fixture.echo\n' } }, server, context],
    [{ ...request, params: { name: 'fixture.echo', arguments: [] } }, server, context],
    [request, 'caller-supplied-server', context],
    [request, server, fixture],
  ]) {
    const result = await observeMcpToolCall({
      mode: 'observe', request: badRequest, server: badServer, context: badContext, assess,
    });
    assert.equal(result.reason, 'invalid_proposal');
    assert.equal(result.request, null);
    assert.equal(result.authoritative, false);
  }
  assert.equal(reads, 0);
});