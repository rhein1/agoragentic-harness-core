import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { controlValueHash, observeMcpToolCall } from '../../../src/adapters/tool-observe.mjs';

const { context: fixtureContext } = JSON.parse(readFileSync(
  new URL('../../../examples/frameworks/tool-observe/fixtures.json', import.meta.url), 'utf8',
));
const { tool, operation, framework, adapter_version, ...context } = fixtureContext;

test('official MCP client and server observe the same proposal without governing the SDK call', async (t) => {
  const server = new Server({ name: 'fixture-server', version: '1' }, { capabilities: { tools: {} } });
  const client = new Client({ name: 'fixture-client', version: '1' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => {
    await client.close();
    await server.close();
  });

  const serverRef = controlValueHash(['local-mcp-fixture', 'server']);
  const request = CallToolRequestSchema.parse({
    method: 'tools/call',
    params: {
      name: 'fixture.echo',
      arguments: { input: 'fixture-private-value' },
      _meta: { progressToken: 'fixture-metadata' },
    },
  });
  const hostResponse = { content: [{ type: 'text', text: 'host fixture result' }] };

  let resume;
  const parked = new Promise((resolve) => { resume = resolve; });
  t.after(resume);

  let serverEvidence;
  let delivered;
  let assessments = 0;
  server.setRequestHandler(CallToolRequestSchema, (received) => {
    delivered = received.params.arguments;
    serverEvidence = observeMcpToolCall({
      mode: 'observe', request: received, server: serverRef,
      context: { ...context, request_id: controlValueHash(['server', 1]) },
      assess: async (_proposal, requestHash) => {
        assessments += 1;
        await parked;
        return { outcome: 'deny', request_hash: requestHash };
      },
    });
    return hostResponse;
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const clientEvidence = observeMcpToolCall({
    mode: 'observe', request, server: serverRef,
    context: { ...context, request_id: controlValueHash(['client', 1]) },
    assess: async (_proposal, requestHash) => {
      assessments += 1;
      await parked;
      return {
        outcome: 'modify', request_hash: requestHash,
        transformed_arguments: { input: 'advisory-replacement' },
      };
    },
  });
  const result = await client.callTool(request.params, undefined, { timeout: 2000 });
  assert.equal(assessments, 2);
  assert.deepEqual(delivered, request.params.arguments);
  assert.deepEqual(result, hostResponse);
  resume();

  const [fromClient, fromServer] = await Promise.all([clientEvidence, serverEvidence]);
  assert.equal(fromClient.request.action_hash, fromServer.request.action_hash);
  assert.notEqual(fromClient.request_hash, fromServer.request_hash);
  assert.equal(fromClient.request.arguments_hash, controlValueHash(request.params.arguments));
  assert.equal(fromClient.request.tool, controlValueHash(['agoragentic.mcp-tool.v1', serverRef, 'fixture.echo']));
  assert.equal(fromClient.decision.outcome, 'modify');
  assert.equal(fromServer.decision.outcome, 'deny');
  for (const observation of [fromClient, fromServer]) {
    assert.equal(observation.status, 'observed');
    assert.equal(observation.authoritative, false);
    assert.equal(observation.execution_observed, false);
    assert.doesNotMatch(JSON.stringify(observation), /fixture-private-value|fixture-metadata|advisory-replacement|host fixture result/);
  }
});
