import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { ActionType, IS_CLIENT_DISPATCHABLE } from '@microsoft/agent-host-protocol';
import { InMemoryTransport } from '@microsoft/agent-host-protocol/client';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { WebSocket, WebSocketServer } from 'ws';

import * as ahpObserverModule from '../src/adapters/ahp-observer.mjs';
import {
  AHP_OBSERVER_ALLOWED_OUTBOUND_METHODS,
  AHP_OBSERVER_AUTHORITY_FLAGS,
  AHP_OBSERVER_LIMITS,
  AHP_OBSERVER_PROHIBITED_METHODS,
  AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS,
  observeAhp,
  validateAhpObservationConfig,
} from '../src/adapters/ahp-observer.mjs';
import {
  createHarnessEvent,
  sanitizeForPublicEvidence,
  sanitizeText,
  stableHash,
} from '../src/kernel/events.mjs';
import { probeRuntime } from '../src/kernel/runtime-probe.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXED_TIME = '2026-08-22T12:34:56.000Z';
const ROOT_CHANNEL = 'ahp-root://';
const SESSION_CHANNEL = 'ahp-session:/session-sensitive-id';
const CHAT_CHANNEL = 'ahp-chat:/chat-sensitive-id';

const AUTHORITY_KEYS = [
  'dispatch_action',
  'create_session',
  'dispose_session',
  'create_chat',
  'terminal_input',
  'terminal_claim',
  'resource_write',
  'resource_delete',
  'resource_move',
  'authenticate',
  'provide_client_tools',
  'approve_tool_calls',
  'run_automation',
  'mutate_automation',
  'provider_dispatch',
  'wallet_mutation',
  'x402_settlement',
  'marketplace_publication',
  'trust_mutation',
  'owner_approval_bypass',
];

const CANARIES = Object.freeze({
  message: 'MESSAGE-CANARY-49e25c',
  reasoning: 'REASONING-CANARY-75a6ac',
  toolInput: 'TOOL-INPUT-CANARY-e09537',
  toolOutput: 'TOOL-OUTPUT-CANARY-85a3dc',
  bearer: 'Bearer BEARER-CANARY-8bc3e5270d15',
  resource: 'file:///C:/private/RESOURCE-CANARY-ef33b8.txt',
  terminal: 'TERMINAL-CANARY-9f2a81 rm-never-run',
  otlp: 'OTLP-CANARY-41c5e7',
  rejection: 'REJECTION-CANARY-20f553',
  host: 'HOST-IDENTITY-CANARY-2f4a32',
  originClient: 'ORIGIN-CLIENT-CANARY-9bd3ff',
  reference: 'REFERENCE-ID-CANARY-f8dd82',
});

function assertObserverError(fn, code) {
  assert.throws(fn, (error) => error?.name === 'AhpObserverError' && error?.code === code);
}

function parseTransportFrame(frame) {
  if (frame?.kind === 'parsed') return frame.message;
  if (frame?.kind === 'text') return JSON.parse(frame.text);
  if (frame?.kind === 'binary') return JSON.parse(new TextDecoder().decode(frame.data));
  throw new Error('unexpected transport frame');
}

function snapshot(resource, fromSeq, state = {}) {
  return { resource, fromSeq, state };
}

function response(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function notification(method, params) {
  return { jsonrpc: '2.0', method, params };
}

function action(channel, serverSeq, type, payload = {}, extra = {}) {
  return notification('action', {
    channel,
    serverSeq,
    action: { type, ...payload },
    ...extra,
  });
}

function sensitiveShape() {
  return {
    message: CANARIES.message,
    reasoning: CANARIES.reasoning,
    toolInput: { value: CANARIES.toolInput },
    toolOutput: { value: CANARIES.toolOutput },
    authorization: CANARIES.bearer,
    filePath: CANARIES.resource,
    terminalOutput: CANARIES.terminal,
    otlpBody: CANARIES.otlp,
    metadata: { private: 'OPAQUE-CANARY-b91d9f' },
  };
}

test('public sanitizers fail closed for attacker-named digest fields, nesting, and arrays', () => {
  const literalPlaceholder = '__SAFE_SHA256_0__';
  const uppercaseDigest = `SHA256:${'ABCDEF0123456789'.repeat(4)}`;
  const lowercaseDigest = uppercaseDigest.toLowerCase();
  const redactedDigest = 'SHA256:[REDACTED_LONG_TOKEN]';
  const bearerSecret = 'Bearer SANITIZER-CANARY-123456789';
  const compositeDigest = `Authorization: Bearer ${lowercaseDigest}`;

  assert.equal(sanitizeText(literalPlaceholder), literalPlaceholder);
  assert.equal(sanitizeText(uppercaseDigest), redactedDigest);
  assert.equal(sanitizeText(bearerSecret), 'Bearer [REDACTED]');
  assert.equal(sanitizeText(compositeDigest), 'Authorization: Bearer sha256:[REDACTED_LONG_TOKEN]');

  const candidate = {
    literalPlaceholder,
    digest: uppercaseDigest,
    note: uppercaseDigest,
    reason: uppercaseDigest,
    task: uppercaseDigest,
    path: uppercaseDigest,
    event: uppercaseDigest,
    bearer_note: bearerSecret,
    attacker: {
      sha256: uppercaseDigest,
      source_event_digest: uppercaseDigest,
      origin_client_digest: uppercaseDigest,
      channel: { ref_digest: uppercaseDigest },
      references: { session_ref_digest: uppercaseDigest },
      source_event_digests: [
        uppercaseDigest,
        { source_event_digest: uppercaseDigest },
      ],
      forged_reference: { value: uppercaseDigest },
    },
  };
  const sanitized = sanitizeForPublicEvidence(candidate);
  assert.deepEqual(sanitized, {
    literalPlaceholder,
    digest: redactedDigest,
    note: redactedDigest,
    reason: redactedDigest,
    task: redactedDigest,
    path: redactedDigest,
    event: redactedDigest,
    bearer_note: 'Bearer [REDACTED]',
    attacker: {
      sha256: redactedDigest,
      source_event_digest: redactedDigest,
      origin_client_digest: redactedDigest,
      channel: { ref_digest: redactedDigest },
      references: { session_ref_digest: redactedDigest },
      source_event_digests: [
        redactedDigest,
        { source_event_digest: redactedDigest },
      ],
      forged_reference: { value: redactedDigest },
    },
  });
  assert.deepEqual(sanitizeForPublicEvidence(candidate), sanitized);
  const event = createHarnessEvent({
    run_id: 'run_untrusted_digest_regression',
    type: 'adapter_observation',
    summary: 'Untrusted digest regression',
    data: candidate,
    created_at: FIXED_TIME,
  });
  assert.deepEqual(event.data, sanitized);
});

test('runtime probe fetched JSON cannot forge trusted digest provenance', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'runtime-probe-digest-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const uppercaseDigest = `SHA256:${'ABCDEF0123456789'.repeat(4)}`;
  const redactedDigest = 'SHA256:[REDACTED_LONG_TOKEN]';
  const payload = {
    attacker: {
      sha256: uppercaseDigest,
      source_event_digest: uppercaseDigest,
      source_event_digests: [uppercaseDigest, { ref_digest: uppercaseDigest }],
    },
  };
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(payload),
  });
  const result = await probeRuntime({
    dir: temp,
    url: 'http://127.0.0.1:4319',
    fetchImpl,
  });
  assert.equal(result.artifact.status, 'passed');
  assert.equal(result.artifact.endpoints.length, 5);
  for (const endpoint of result.artifact.endpoints) {
    assert.match(endpoint.body_hash, /^sha256:[a-f0-9]{64}$/);
    assert.deepEqual(endpoint.body, {
      attacker: {
        sha256: redactedDigest,
        source_event_digest: redactedDigest,
        source_event_digests: [redactedDigest, { ref_digest: redactedDigest }],
      },
    });
  }
  assert.equal(JSON.stringify(result.artifact).includes(uppercaseDigest), false);
});

function scriptedServer(server, {
  channels = [ROOT_CHANNEL],
  initializeResult,
  subscribeSnapshots = {},
  messages = [],
  rawAfterInitialize,
  beforeInitializeResponse,
  beforeSubscribeResponse,
  closeAfterResponseId,
  keepOpen = false,
  onReady,
} = {}) {
  const outbound = [];
  let subscriptions = 0;
  let emitted = false;
  const expectedSubscriptions = Math.max(0, channels.length - 1);

  const emitWhenReady = async () => {
    if (emitted || subscriptions !== expectedSubscriptions) return;
    emitted = true;
    for (const message of messages) await server.send(message);
    await onReady?.({ server, outbound });
    if (!keepOpen && closeAfterResponseId === undefined) await server.close();
  };

  const done = (async () => {
    while (true) {
      const frame = await server.recv();
      if (frame === null) break;
      const message = parseTransportFrame(frame);
      outbound.push(message);

      if (message.method === 'initialize') {
        if (rawAfterInitialize !== undefined) {
          await server.send(rawAfterInitialize);
          continue;
        }
        await beforeInitializeResponse?.({ server, message, outbound });
        await server.send(response(message.id, initializeResult ?? {
          protocolVersion: '0.8.0',
          serverSeq: 0,
          snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
        }));
        await emitWhenReady();
        continue;
      }

      if (message.method === 'subscribe') {
        subscriptions += 1;
        await beforeSubscribeResponse?.({ server, message, outbound });
        const selected = subscribeSnapshots[message.params.channel];
        await server.send(response(message.id, selected ? { snapshot: selected } : {}));
        await emitWhenReady();
        continue;
      }

      if (!Object.hasOwn(message, 'method') && message.id === closeAfterResponseId) {
        await server.close();
      }
    }
    return outbound;
  })();

  return { outbound, done };
}

async function readRunArtifacts(temp, result) {
  const runRoot = path.join(temp, result.run_path);
  const names = await fs.readdir(runRoot);
  const raw = {};
  for (const name of names) raw[name] = await fs.readFile(path.join(runRoot, name), 'utf8');
  const events = raw['events.jsonl'].split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  return {
    runRoot,
    names,
    raw,
    allText: names.sort().map((name) => raw[name]).join('\n'),
    state: JSON.parse(raw['state.json']),
    events,
    summary: JSON.parse(raw['summary.json']),
    receipt: JSON.parse(raw['local-receipt.json']),
    manifest: JSON.parse(raw['manifest.json']),
  };
}

async function runScenario(t, scenario = {}, config = {}) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-observer-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const [client, server] = InMemoryTransport.pair();
  const channels = config.channels ?? scenario.channels ?? [ROOT_CHANNEL];
  const driver = scriptedServer(server, { ...scenario, channels });
  const result = await observeAhp({
    dir: temp,
    transport: client,
    channels,
    // Generic scenarios exercise protocol outcomes, not scheduler timing. Use
    // the production defaults; deadline-specific tests pass explicit limits.
    now: () => FIXED_TIME,
    ...config,
  });
  await driver.done;
  return {
    temp,
    result,
    outbound: driver.outbound,
    artifacts: await readRunArtifacts(temp, result),
  };
}

function eventEvidence(artifacts, kind) {
  return artifacts.events
    .filter((event) => event.data?.evidence?.observation_kind === kind)
    .map((event) => event.data.evidence);
}

test('configuration is loopback-only, credential-free, bounded, and hash-only', async (t) => {
  const transport = InMemoryTransport.pair()[0];
  const valid = validateAhpObservationConfig({
    endpoint: 'ws://127.0.0.1:4819/ahp',
    channels: [ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL],
    duration_ms: 25,
    request_timeout_ms: 25,
    max_events: 1,
    max_frame_bytes: 256,
    max_artifact_bytes: 81_920,
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.transport_kind, 'loopback_websocket');
  assert.equal(valid.endpoint_scheme, 'ws');
  assert.match(valid.endpoint_digest, /^sha256:[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(valid), /127\.0\.0\.1|4819|session-sensitive|chat-sensitive/);
  assert.deepEqual(valid.supported_protocol_versions, ['0.8.0']);
  assert.deepEqual(Object.keys(valid.authority).sort(), [...AUTHORITY_KEYS].sort());
  assert.ok(Object.values(valid.authority).every((value) => value === false));

  const injected = validateAhpObservationConfig({ transport });
  assert.equal(injected.transport_kind, 'injected');
  assert.equal(injected.endpoint_scheme, 'injected');
  assert.equal(Object.hasOwn(injected, 'transport'), false);

  const endpointCases = [
    ['http://127.0.0.1:1', 'unsupported_endpoint_scheme'],
    ['ws://example.com:4819', 'remote_endpoint_forbidden'],
    ['ws://127.0.0.1.evil.example:4819', 'remote_endpoint_forbidden'],
    ['ws://user:password@127.0.0.1:4819', 'endpoint_credentials_forbidden'],
    ['ws://127.0.0.1:4819/?token=secret', 'endpoint_query_or_fragment_forbidden'],
    ['ws://127.0.0.1:4819/#secret', 'endpoint_query_or_fragment_forbidden'],
    ['not a url', 'invalid_endpoint'],
  ];
  for (const [endpoint, code] of endpointCases) {
    await t.test(`reject endpoint: ${code}`, () => assertObserverError(
      () => validateAhpObservationConfig({ endpoint }),
      code,
    ));
  }

  const channelCases = [
    [[SESSION_CHANNEL, ROOT_CHANNEL], 'root_channel_required_first'],
    [[ROOT_CHANNEL, ROOT_CHANNEL], 'root_channel_required_first'],
    [[ROOT_CHANNEL, 'ahp-terminal:/terminal-id'], 'unsupported_channel'],
    [[ROOT_CHANNEL, 'ahp-resource-watch:/resource-id'], 'unsupported_channel'],
    [[ROOT_CHANNEL, 'ahp-session:/a%2Fb'], 'unsupported_channel'],
    [[ROOT_CHANNEL, 'ahp-chat:/a?token=secret'], 'unsupported_channel'],
    [[], 'invalid_channels'],
    [Array.from({ length: 17 }, (_, index) => index === 0 ? ROOT_CHANNEL : `ahp-session:/s${index}`), 'invalid_channels'],
  ];
  for (const [channels, code] of channelCases) {
    await t.test(`reject channels: ${code}`, () => assertObserverError(
      () => validateAhpObservationConfig({ transport, channels }),
      code,
    ));
  }

  const configCases = [
    [{}, 'endpoint_or_transport_required'],
    [{ transport, endpoint: 'ws://127.0.0.1:1' }, 'endpoint_transport_mutually_exclusive'],
    [{ transport: {} }, 'invalid_transport'],
    [{ transport, unknown: true }, 'unsupported_config_key'],
    [{ transport, duration_ms: 24 }, 'invalid_duration_limit'],
    [{ transport, duration_ms: 60_001 }, 'invalid_duration_limit'],
    [{ transport, max_events: 0 }, 'invalid_event_limit'],
    [{ transport, max_frame_bytes: 255 }, 'invalid_frame_limit'],
    [{ transport, max_artifact_bytes: 81_919 }, 'invalid_artifact_limit'],
    [{ transport, request_timeout_ms: 24 }, 'invalid_request_timeout'],
    [{ transport, duration_ms: 25, request_timeout_ms: 26 }, 'request_timeout_exceeds_duration'],
    [{ transport, signal: {} }, 'invalid_abort_signal'],
    [{ transport, now: 'not-a-clock' }, 'invalid_clock'],
    [{ transport, dir: '' }, 'invalid_output_directory'],
    [{ transport, dir: 123 }, 'invalid_output_directory'],
    [{ transport, dir: `bad${String.fromCharCode(0)}dir` }, 'invalid_output_directory'],
    [{ transport, dir: 'x'.repeat(4_097) }, 'invalid_output_directory'],
  ];
  for (const [config, code] of configCases) {
    await t.test(`reject config: ${code}`, () => assertObserverError(
      () => validateAhpObservationConfig(config),
      code,
    ));
  }
});

test('official in-memory transport observes root/session/chat snapshots and bounded action metadata', async (t) => {
  const channels = [ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL];
  const basePayload = {
    ...sensitiveShape(),
    sessionId: CANARIES.reference,
    status: 'running',
  };
  const first = action(ROOT_CHANNEL, 10, ActionType.RootConfigChanged, basePayload, {
    origin: { clientId: CANARIES.originClient, clientSeq: 7 },
    rejectionReason: CANARIES.rejection,
  });
  const duplicate = structuredClone(first);
  const messages = [
    first,
    duplicate,
    action(SESSION_CHANNEL, 12, ActionType.SessionMetaChanged, {
      ...sensitiveShape(),
      chatId: CANARIES.reference,
      status: 'ready',
    }),
    action(CHAT_CHANNEL, 12, ActionType.ChatReasoning, {
      ...sensitiveShape(),
      turnId: CANARIES.reference,
    }),
    action(CHAT_CHANNEL, 11, ActionType.ChatDelta, {
      ...sensitiveShape(),
      toolCallId: CANARIES.reference,
    }),
    notification('root/sessionAdded', {
      channel: ROOT_CHANNEL,
      sessionId: CANARIES.reference,
      ...sensitiveShape(),
    }),
    notification('auth/required', {
      channel: ROOT_CHANNEL,
      authorization: CANARIES.bearer,
      message: CANARIES.message,
    }),
    notification('otlp/exportLogs', {
      channel: 'ahp-otlp://logs',
      resourceLogs: [{ body: CANARIES.otlp, authorization: CANARIES.bearer }],
    }),
    notification('terminal/data', {
      channel: 'ahp-terminal:/terminal-sensitive-id',
      terminalOutput: CANARIES.terminal,
      filePath: CANARIES.resource,
    }),
    {
      jsonrpc: '2.0',
      id: 700,
      method: 'resourceRead',
      params: {
        channel: CHAT_CHANNEL,
        uri: CANARIES.resource,
        authorization: CANARIES.bearer,
      },
    },
  ];

  const run = await runScenario(t, {
    channels,
    initializeResult: {
      protocolVersion: '0.8.0',
      serverSeq: 9,
      serverInfo: { name: CANARIES.host, version: CANARIES.host },
      defaultDirectory: CANARIES.resource,
      snapshots: [snapshot(ROOT_CHANNEL, 9, sensitiveShape())],
    },
    subscribeSnapshots: {
      [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 9, sensitiveShape()),
      [CHAT_CHANNEL]: snapshot(CHAT_CHANNEL, 9, sensitiveShape()),
    },
    messages,
    closeAfterResponseId: 700,
  }, { channels });

  assert.equal(run.result.status, 'completed');
  assert.equal(run.result.termination_reason, 'transport_closed');
  const redactedDigest = 'sha256:[REDACTED_LONG_TOKEN]';
  assert.equal(run.artifacts.state.project_paths.endpoint_digest, redactedDigest);
  const startedLifecycle = run.artifacts.events.find((event) => (
    event.data?.observation_kind === 'lifecycle' && event.data?.phase === 'started'
  ));
  assert.equal(startedLifecycle.data.endpoint_digest, redactedDigest);
  assert.equal(run.artifacts.summary.protocol.negotiated_version, '0.8.0');
  assert.match(run.artifacts.summary.source.endpoint_digest, /^sha256:[a-f0-9]{64}$/);
  assert.ok(run.artifacts.summary.scope.channels.every((entry) => /^sha256:[a-f0-9]{64}$/.test(entry.ref_digest)));
  assert.equal(run.artifacts.summary.counts.snapshots, 3);
  assert.equal(run.artifacts.summary.counts.unique_actions, 4);
  assert.equal(run.artifacts.summary.counts.duplicates, 1);
  assert.equal(run.artifacts.summary.counts.sequence_gaps_observed, 1);
  assert.equal(run.artifacts.summary.counts.sequence_collisions_observed, 1);
  assert.equal(run.artifacts.summary.counts.out_of_order_observed, 1);
  assert.equal(run.artifacts.summary.counts.notifications, 4);
  assert.equal(run.artifacts.summary.counts.discarded_otlp_notifications, 1);
  assert.equal(run.artifacts.summary.counts.discarded_unknown_notifications, 1);
  assert.equal(run.artifacts.summary.counts.server_requests_default_rejection_selected, 1);
  assert.deepEqual(run.artifacts.summary.sequence.observed_discontinuities, [
    { after: 10, before: 12, observed_discontinuity: 1 },
  ]);
  assert.equal(run.artifacts.summary.sequence.loss_proven, false);
  assert.equal(run.artifacts.summary.sequence.receipt_claimed, false);
  assert.equal(run.artifacts.summary.claims.telemetry_is_audit_log, false);
  assert.equal(run.artifacts.summary.claims.governed_action_execution, false);

  const actionEvidence = eventEvidence(run.artifacts, 'action');
  assert.equal(actionEvidence.length, 5);
  assert.equal(actionEvidence[0].source_event_digest, redactedDigest);
  assert.equal(actionEvidence[1].source_event_digest, redactedDigest);
  assert.equal(actionEvidence[0].sequence_classification, 'accepted');
  assert.equal(actionEvidence[1].sequence_classification, 'duplicate');
  assert.deepEqual(actionEvidence.map((entry) => entry.sequence_classification), [
    'accepted', 'duplicate', 'gap_observed', 'collision', 'out_of_order',
  ]);
  assert.equal(actionEvidence[0].origin, 'client');
  assert.equal(actionEvidence[0].origin_client_digest, redactedDigest);
  assert.equal(actionEvidence[0].origin_client_seq, 7);
  assert.equal(actionEvidence[0].status, 'running');
  assert.equal(actionEvidence[0].rejection_reason_present, true);
  assert.ok(Object.values(actionEvidence[0].redactions).every((count) => count > 0));
  assert.ok(actionEvidence[0].redactions.tool_input > 0);
  assert.ok(actionEvidence[0].redactions.tool_result_content > 0);
  assert.equal(actionEvidence[0].references.session_ref_digest, redactedDigest);

  const notifications = eventEvidence(run.artifacts, 'notification');
  assert.deepEqual(notifications.map((entry) => entry.notification_type), [
    'root_session_added', 'auth_required', 'otlp_discarded', 'unknown_discarded',
  ]);
  assert.ok(notifications[1].redactions.bearer_or_secret > 0);
  assert.ok(notifications[2].redactions.telemetry_body > 0);
  assert.ok(notifications[3].redactions.terminal_content > 0);
  assert.ok(notifications[3].redactions.resource_or_path > 0);

  const rejected = eventEvidence(run.artifacts, 'server_request_default_rejection');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].method, 'resourceRead');
  assert.equal(rejected[0].response_policy, 'method_not_found');
  assert.ok(rejected[0].redactions.bearer_or_secret > 0);
  assert.ok(rejected[0].redactions.resource_or_path > 0);

  const methodNotFound = run.outbound.find((message) => message.id === 700 && message.error);
  assert.equal(methodNotFound.error.code, -32601);
  assert.equal(Object.hasOwn(methodNotFound, 'result'), false);
  const outboundMethods = run.outbound.filter((message) => message.method).map((message) => message.method);
  assert.deepEqual(outboundMethods, ['initialize', 'subscribe', 'subscribe']);
  assert.ok(outboundMethods.every((method) => AHP_OBSERVER_ALLOWED_OUTBOUND_METHODS.includes(method)));
  assert.ok(AHP_OBSERVER_PROHIBITED_METHODS.every((method) => !outboundMethods.includes(method)));
  const initialize = run.outbound.find((message) => message.method === 'initialize');
  assert.equal(initialize.params.channel, ROOT_CHANNEL);
  assert.deepEqual(initialize.params.protocolVersions, ['0.8.0']);
  assert.deepEqual(initialize.params.initialSubscriptions, [ROOT_CHANNEL]);
  assert.match(initialize.params.clientId, /^ahp_observer_[a-f0-9]{12}$/);
  assert.equal(Object.hasOwn(initialize.params, 'capabilities'), false);
  assert.equal(Object.hasOwn(initialize.params, 'locale'), false);

  assert.equal(run.artifacts.summary.counts.persisted_events, 13);
  assert.equal(run.artifacts.summary.source_event_digest_count, 13);
  assert.equal(run.artifacts.summary.source_event_digests.length, 12);
  assert.equal(run.artifacts.summary.source_event_digests_truncated, false);
  assert.ok(run.artifacts.summary.source_event_digests.every((digest) => /^sha256:[a-f0-9]{64}$/.test(digest)));
  assert.equal(run.artifacts.summary.counts.event_type_counts_truncated, false);
  assert.match(run.artifacts.summary.source_event_stream_digest, /^sha256:[a-f0-9]{64}$/);
  const perChannel = Object.fromEntries(run.artifacts.summary.counts.by_channel.map((entry) => [entry.scheme, entry]));
  assert.deepEqual(
    { ...perChannel['ahp-root'], ref_digest: '<digest>' },
    { scheme: 'ahp-root', ref_digest: '<digest>', snapshots: 1, actions: 2, notifications: 2, server_requests: 0, total: 5 },
  );
  assert.deepEqual(
    { ...perChannel['ahp-session'], ref_digest: '<digest>' },
    { scheme: 'ahp-session', ref_digest: '<digest>', snapshots: 1, actions: 1, notifications: 0, server_requests: 0, total: 2 },
  );
  assert.deepEqual(
    { ...perChannel['ahp-chat'], ref_digest: '<digest>' },
    { scheme: 'ahp-chat', ref_digest: '<digest>', snapshots: 1, actions: 2, notifications: 0, server_requests: 1, total: 4 },
  );
  const byType = Object.fromEntries(run.artifacts.summary.counts.by_event_type.map((entry) => (
    [`${entry.kind}:${entry.event_type}`, entry.count]
  )));
  assert.equal(byType['snapshot:snapshot'], 3);
  assert.equal(byType[`action:${ActionType.RootConfigChanged}`], 2);
  assert.equal(byType[`action:${ActionType.SessionMetaChanged}`], 1);
  assert.equal(byType[`action:${ActionType.ChatReasoning}`], 1);
  assert.equal(byType[`action:${ActionType.ChatDelta}`], 1);
  assert.equal(byType['notification:auth_required'], 1);
  assert.equal(byType['server_request:resourceRead'], 1);

  const persistedEvidence = run.artifacts.events
    .map((event) => event.data?.evidence)
    .filter((evidence) => evidence?.source_event_digest);
  assert.equal(persistedEvidence.length, 13);
  assert.ok(persistedEvidence.every((evidence) => evidence.source_event_digest === redactedDigest));
  assert.equal(run.artifacts.state.event_count, run.artifacts.events.length);
  assert.deepEqual(run.artifacts.events.map((event) => event.sequence), Array.from(
    { length: run.artifacts.events.length }, (_, index) => index + 1,
  ));
  assert.equal(new Set(run.artifacts.events.map((event) => event.event_id)).size, run.artifacts.events.length);

  for (const canary of Object.values(CANARIES)) assert.doesNotMatch(run.artifacts.allText, new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(run.artifacts.allText, /session-sensitive-id|chat-sensitive-id|terminal-sensitive-id/);
  assert.doesNotMatch(run.artifacts.allText, new RegExp(run.outbound[0].params.clientId));
  assert.doesNotMatch(run.artifacts.allText, new RegExp(run.temp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));

  assert.deepEqual(Object.keys(run.result), [
    'status', 'termination_reason', 'observation_id', 'output_digest', 'run_path', 'artifacts', 'authority',
  ]);
  assert.equal(Object.hasOwn(run.result, 'client'), false);
  assert.equal(Object.hasOwn(run.result, 'transport'), false);
});

test('observer exports no control-capable client API and every authority flag is forced false', () => {
  assert.deepEqual(AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS, ['0.8.0']);
  assert.deepEqual(AHP_OBSERVER_ALLOWED_OUTBOUND_METHODS, ['initialize', 'subscribe', 'unsubscribe']);
  assert.deepEqual(Object.keys(AHP_OBSERVER_AUTHORITY_FLAGS).sort(), [...AUTHORITY_KEYS].sort());
  assert.ok(AUTHORITY_KEYS.every((key) => AHP_OBSERVER_AUTHORITY_FLAGS[key] === false));
  for (const method of AHP_OBSERVER_PROHIBITED_METHODS) {
    assert.equal(Object.hasOwn(ahpObserverModule, method), false, `${method} must not be exported`);
  }
  assert.deepEqual(
    Object.keys(ahpObserverModule).filter((key) => typeof ahpObserverModule[key] === 'function').sort(),
    ['observeAhp', 'validateAhpObservationConfig'],
  );
});

test('exported hard-limit tuples are deeply immutable and retain their original maxima', () => {
  const transport = InMemoryTransport.pair()[0];
  assert.equal(Object.isFrozen(AHP_OBSERVER_LIMITS), true);
  assert.equal(Object.isFrozen(AHP_OBSERVER_LIMITS.duration_ms), true);
  assert.equal(Object.isFrozen(AHP_OBSERVER_LIMITS.max_frame_bytes), true);
  assert.throws(() => {
    AHP_OBSERVER_LIMITS.duration_ms[1] = 60_001;
  }, TypeError);
  assert.throws(() => {
    AHP_OBSERVER_LIMITS.max_frame_bytes[1] = 1_048_577;
  }, TypeError);
  assert.deepEqual(AHP_OBSERVER_LIMITS.duration_ms, [25, 60_000]);
  assert.deepEqual(AHP_OBSERVER_LIMITS.max_frame_bytes, [256, 1_048_576]);
  assertObserverError(
    () => validateAhpObservationConfig({ transport, duration_ms: 60_001 }),
    'invalid_duration_limit',
  );
  assertObserverError(
    () => validateAhpObservationConfig({ transport, max_frame_bytes: 1_048_577 }),
    'invalid_frame_limit',
  );
});

test('protocol negotiation and malformed state fail closed with bounded artifacts', async (t) => {
  const cases = [
    {
      name: 'unsupported protocol version',
      initializeResult: { protocolVersion: '0.7.0', serverSeq: 0, snapshots: [] },
      reason: 'unsupported_protocol_version',
    },
    {
      name: 'malformed initialize result',
      initializeResult: { protocolVersion: '0.8.0', serverSeq: 0 },
      reason: 'malformed_initialize_result',
    },
    {
      name: 'missing required root snapshot',
      initializeResult: { protocolVersion: '0.8.0', serverSeq: 0, snapshots: [] },
      reason: 'malformed_initialize_result',
    },
    {
      name: 'malformed initialize sequence',
      initializeResult: { protocolVersion: '0.8.0', serverSeq: -1, snapshots: [] },
      reason: 'malformed_initialize_result',
    },
    {
      name: 'snapshot for unconfigured channel',
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot('ahp-session:/not-configured', 0, {})],
      },
      reason: 'malformed_initialize_result',
    },
  ];
  for (const item of cases) {
    await t.test(item.name, async (subtest) => {
      const run = await runScenario(subtest, { initializeResult: item.initializeResult, keepOpen: true });
      assert.equal(run.result.status, 'blocked');
      assert.equal(run.result.termination_reason, item.reason);
      assert.equal(run.artifacts.summary.protocol.negotiated_version, null);
      assert.equal(run.artifacts.receipt.status, 'blocked');
      assert.equal(run.artifacts.state.status, 'blocked');
    });
  }

  await t.test('subscribe snapshot does not match the requested channel', async (subtest) => {
    const run = await runScenario(subtest, {
      channels: [ROOT_CHANNEL, SESSION_CHANNEL],
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(CHAT_CHANNEL, 0, {}),
      },
      keepOpen: true,
    }, { channels: [ROOT_CHANNEL, SESSION_CHANNEL] });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_snapshot');
    assert.equal(run.artifacts.summary.protocol.negotiated_version, '0.8.0');
  });

  const missingSubscribeSnapshotCases = [
    {
      name: 'missing required session snapshot without reconnect',
      channels: [ROOT_CHANNEL, SESSION_CHANNEL],
      subscribeSnapshots: {},
      methods: ['initialize', 'subscribe'],
    },
    {
      name: 'missing required chat snapshot without reconnect',
      channels: [ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL],
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      },
      methods: ['initialize', 'subscribe', 'subscribe'],
    },
  ];
  for (const item of missingSubscribeSnapshotCases) {
    await t.test(item.name, async (subtest) => {
      const run = await runScenario(subtest, {
        channels: item.channels,
        subscribeSnapshots: item.subscribeSnapshots,
        keepOpen: true,
      }, { channels: item.channels });
      assert.equal(run.result.status, 'blocked');
      assert.equal(run.result.termination_reason, 'malformed_snapshot');
      assert.equal(run.artifacts.summary.protocol.negotiated_version, '0.8.0');
      assert.deepEqual(
        run.outbound.map((message) => message.method),
        [...item.methods, ...item.channels.map(() => 'unsubscribe')],
      );
      assert.deepEqual(
        run.outbound.filter((message) => message.method === 'unsubscribe').map((message) => message.params.channel),
        [...item.channels].reverse(),
      );
      assert.equal(run.outbound.filter((message) => message.method === 'initialize').length, 1);
    });
  }

  await t.test('root snapshot cannot advance beyond initialize server sequence', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 5,
        snapshots: [snapshot(ROOT_CHANNEL, 6, {})],
      },
      keepOpen: true,
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_snapshot');
    assert.equal(run.artifacts.summary.counts.snapshots, 0);
    assert.equal(run.artifacts.summary.counts.persisted_events, 0);
  });

  for (const serverSeq of [5, 4]) {
    await t.test(`root action sequence ${serverSeq} cannot be at or below snapshot watermark 5`, async (subtest) => {
      const run = await runScenario(subtest, {
        initializeResult: {
          protocolVersion: '0.8.0',
          serverSeq: 5,
          snapshots: [snapshot(ROOT_CHANNEL, 5, {})],
        },
        messages: [action(ROOT_CHANNEL, serverSeq, ActionType.RootConfigChanged, {})],
      });
      assert.equal(run.result.status, 'blocked');
      assert.equal(run.result.termination_reason, 'malformed_action');
      assert.equal(run.artifacts.summary.counts.snapshots, 1);
      assert.equal(run.artifacts.summary.counts.unique_actions, 0);
      assert.equal(run.artifacts.summary.counts.persisted_events, 1);
      assert.equal(eventEvidence(run.artifacts, 'action').length, 0);
      assert.ok(run.artifacts.summary.warnings.includes('snapshot_watermark_violation'));
    });
  }

  await t.test('root action at the snapshot watermark before initialize response is rejected', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 5,
        snapshots: [snapshot(ROOT_CHANNEL, 5, {})],
      },
      beforeInitializeResponse: ({ server }) => server.send(action(
        ROOT_CHANNEL,
        5,
        ActionType.RootConfigChanged,
        { message: 'PRIVATE-PRE-INIT-ROOT-ACTION' },
      )),
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_action');
    assert.equal(run.artifacts.summary.counts.snapshots, 1);
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.equal(eventEvidence(run.artifacts, 'action').length, 0);
    assert.ok(run.artifacts.summary.warnings.includes('snapshot_watermark_violation'));
    assert.equal(run.artifacts.allText.includes('PRIVATE-PRE-INIT-ROOT-ACTION'), false);
  });

  await t.test('session action before subscribe is sent fails closed', async (subtest) => {
    const channels = [ROOT_CHANNEL, SESSION_CHANNEL];
    const run = await runScenario(subtest, {
      channels,
      beforeInitializeResponse: ({ server }) => server.send(action(
        SESSION_CHANNEL,
        1,
        ActionType.SessionMetaChanged,
        { message: 'PRIVATE-PRE-SUBSCRIBE-SESSION-ACTION' },
      )),
      keepOpen: true,
    }, { channels });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_action');
    assert.deepEqual(run.outbound.map((message) => message.method), ['initialize']);
    assert.equal(run.artifacts.summary.counts.snapshots, 0);
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.ok(run.artifacts.summary.warnings.includes('snapshot_required_before_action'));
    assert.equal(run.artifacts.allText.includes('PRIVATE-PRE-SUBSCRIBE-SESSION-ACTION'), false);
  });

  for (const item of [
    { serverSeq: 5, status: 'blocked', reason: 'malformed_action', actions: 0 },
    { serverSeq: 6, status: 'completed', reason: 'transport_closed', actions: 1 },
  ]) {
    await t.test(`session action ${item.serverSeq} during pending snapshot fromSeq 5`, async (subtest) => {
      const channels = [ROOT_CHANNEL, SESSION_CHANNEL];
      const canary = `PRIVATE-PENDING-SESSION-ACTION-${item.serverSeq}`;
      const run = await runScenario(subtest, {
        channels,
        subscribeSnapshots: {
          [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 5, {}),
        },
        beforeSubscribeResponse: ({ server }) => server.send(action(
          SESSION_CHANNEL,
          item.serverSeq,
          ActionType.SessionMetaChanged,
          { message: canary },
        )),
      }, { channels });
      assert.equal(run.result.status, item.status);
      assert.equal(run.result.termination_reason, item.reason);
      assert.equal(run.artifacts.summary.counts.snapshots, 2);
      assert.equal(run.artifacts.summary.counts.unique_actions, item.actions);
      assert.equal(eventEvidence(run.artifacts, 'action').length, item.actions);
      assert.equal(run.artifacts.allText.includes(canary), false);
      if (item.actions === 0) {
        assert.ok(run.artifacts.summary.warnings.includes('snapshot_watermark_violation'));
      } else {
        assert.equal(eventEvidence(run.artifacts, 'action')[0].server_seq, 6);
      }
    });
  }

  const malformedActionCases = [
    {
      name: 'server-only action carrying client origin',
      message: action(ROOT_CHANNEL, 1, ActionType.RootAgentsChanged, {}, {
        origin: { clientId: 'PRIVATE-ORIGIN-CLIENT', clientSeq: 1 },
      }),
      canary: 'PRIVATE-ORIGIN-CLIENT',
    },
    {
      name: 'non-string rejection reason',
      message: action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {}, {
        origin: { clientId: 'permitted-client', clientSeq: 1 },
        rejectionReason: { message: 'PRIVATE-NONSTRING-REJECTION' },
      }),
      canary: 'PRIVATE-NONSTRING-REJECTION',
    },
    {
      name: 'rejection reason without client origin',
      message: action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {}, {
        rejectionReason: 'PRIVATE-ORIGINLESS-REJECTION',
      }),
      canary: 'PRIVATE-ORIGINLESS-REJECTION',
    },
  ];
  for (const item of malformedActionCases) {
    await t.test(item.name, async (subtest) => {
      const run = await runScenario(subtest, { messages: [item.message] });
      assert.equal(run.result.status, 'blocked');
      assert.equal(run.result.termination_reason, 'malformed_action');
      assert.equal(run.artifacts.summary.counts.unique_actions, 0);
      assert.equal(eventEvidence(run.artifacts, 'action').length, 0);
      assert.ok(run.artifacts.summary.warnings.includes('malformed_action'));
      assert.equal(run.artifacts.allText.includes(item.canary), false);
    });
  }

  await t.test('initialize unsupported-protocol RPC error persists no error message or data', async (subtest) => {
    const messageCanary = 'PRIVATE-UNSUPPORTED-PROTOCOL-MESSAGE';
    const dataCanary = 'PRIVATE-UNSUPPORTED-PROTOCOL-DATA';
    const run = await runScenario(subtest, {
      rawAfterInitialize: {
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32005,
          message: messageCanary,
          data: { private: dataCanary },
        },
      },
      keepOpen: true,
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'unsupported_protocol_version');
    assert.equal(run.artifacts.summary.protocol.negotiated_version, null);
    assert.equal(run.artifacts.summary.counts.persisted_events, 0);
    assert.equal(run.artifacts.allText.includes(messageCanary), false);
    assert.equal(run.artifacts.allText.includes(dataCanary), false);
  });

  for (const type of ['chat/delta', 'root/notARealAction', 'root/ConfigChanged']) {
    await t.test(`malformed or noncanonical action: ${type}`, async (subtest) => {
      const run = await runScenario(subtest, {
        messages: [action(ROOT_CHANNEL, 1, type, sensitiveShape())],
      });
      assert.equal(run.result.status, 'blocked');
      assert.equal(run.result.termination_reason, 'malformed_action');
      assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    });
  }

  await t.test('root notification on a non-root channel fails closed', async (subtest) => {
    const channels = [ROOT_CHANNEL, SESSION_CHANNEL];
    const run = await runScenario(subtest, {
      channels,
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      },
      messages: [notification('root/progress', {
        channel: SESSION_CHANNEL,
        message: 'PRIVATE-WRONG-CHANNEL-ROOT-NOTIFICATION',
      })],
    }, { channels });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_frame');
    assert.equal(run.artifacts.summary.counts.notifications, 0);
    assert.ok(run.artifacts.summary.warnings.includes('malformed_notification'));
    assert.equal(run.artifacts.allText.includes('PRIVATE-WRONG-CHANNEL-ROOT-NOTIFICATION'), false);
  });

  await t.test('mixed JSON-RPC method and result frame fails closed', async (subtest) => {
    const run = await runScenario(subtest, {
      messages: [{
        jsonrpc: '2.0',
        method: 'root/progress',
        result: { private: 'PRIVATE-MIXED-RPC-RESULT' },
        params: { channel: ROOT_CHANNEL },
      }],
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_frame');
    assert.equal(run.artifacts.summary.counts.notifications, 0);
    assert.equal(run.artifacts.allText.includes('PRIVATE-MIXED-RPC-RESULT'), false);
  });
});

test('mutating the SDK dispatchability map after import cannot bypass the audited snapshot', async (t) => {
  const type = ActionType.RootAgentsChanged;
  const original = IS_CLIENT_DISPATCHABLE[type];
  assert.equal(original, false);
  IS_CLIENT_DISPATCHABLE[type] = true;
  assert.equal(IS_CLIENT_DISPATCHABLE[type], true);
  try {
    const run = await runScenario(t, {
      messages: [action(ROOT_CHANNEL, 1, type, {}, {
        origin: { clientId: 'PRIVATE-MUTATED-DISPATCH-CLIENT', clientSeq: 1 },
      })],
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_action');
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.equal(run.artifacts.allText.includes('PRIVATE-MUTATED-DISPATCH-CLIENT'), false);
  } finally {
    IS_CLIENT_DISPATCHABLE[type] = original;
  }
});

test('client sequence regression is warning-only and separately counted', async (t) => {
  const clientId = 'PRIVATE-CLIENT-SEQUENCE-IDENTITY';
  const run = await runScenario(t, {
    messages: [
      action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {}, {
        origin: { clientId, clientSeq: 10 },
      }),
      action(ROOT_CHANNEL, 2, ActionType.RootConfigChanged, {}, {
        origin: { clientId, clientSeq: 9 },
      }),
    ],
  });
  assert.equal(run.result.status, 'completed');
  assert.equal(run.artifacts.summary.counts.unique_actions, 2);
  assert.equal(run.artifacts.summary.counts.client_sequence_regressions_observed, 1);
  assert.ok(run.artifacts.summary.warnings.includes('client_sequence_regression_observed'));
  assert.deepEqual(
    eventEvidence(run.artifacts, 'action').map((entry) => entry.sequence_classification),
    ['accepted', 'accepted'],
  );
  assert.equal(run.artifacts.allText.includes(clientId), false);
});

test('duration, request timeout, cancellation, event, artifact, frame, and malformed bounds terminate deterministically', async (t) => {
  await t.test('duration bound', async (subtest) => {
    const run = await runScenario(subtest, { keepOpen: true }, { duration_ms: 30, request_timeout_ms: 25 });
    assert.equal(run.result.status, 'completed');
    assert.equal(run.result.termination_reason, 'duration_limit');
  });

  await t.test('request timeout', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-timeout-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [client, server] = InMemoryTransport.pair();
    const outbound = [];
    const serverDone = (async () => {
      while (true) {
        const frame = await server.recv();
        if (frame === null) return;
        outbound.push(parseTransportFrame(frame));
      }
    })();
    const result = await observeAhp({
      dir: temp,
      transport: client,
      duration_ms: 100,
      request_timeout_ms: 25,
      now: () => FIXED_TIME,
    });
    await serverDone;
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'request_timeout');
    assert.deepEqual(outbound.map((message) => message.method), ['initialize']);
  });

  await t.test('snapshot timestamp failure leaves no negotiated or aggregate evidence', async (subtest) => {
    let clockCalls = 0;
    const run = await runScenario(subtest, {}, {
      now() {
        clockCalls += 1;
        if (clockCalls === 2) throw new Error('PRIVATE-SNAPSHOT-CLOCK-FAILURE');
        return FIXED_TIME;
      },
    });

    assert.ok(clockCalls >= 3);
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'observer_runtime_error');
    assert.equal(run.artifacts.summary.protocol.negotiated_version, null);
    assert.equal(run.artifacts.summary.sequence.initialize_server_seq, null);
    assert.equal(run.artifacts.summary.counts.persisted_events, 0);
    assert.equal(run.artifacts.summary.counts.snapshots, 0);
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.equal(run.artifacts.summary.counts.notifications, 0);
    assert.equal(run.artifacts.summary.counts.server_requests_default_rejection_selected, 0);
    assert.deepEqual(run.artifacts.summary.source_event_digests, []);
    assert.equal(run.artifacts.summary.source_event_digest_count, 0);
    assert.equal(run.artifacts.summary.source_event_digests_truncated, false);
    assert.deepEqual(run.artifacts.summary.counts.by_event_type, []);
    for (const counts of run.artifacts.summary.counts.by_channel) {
      assert.deepEqual(
        {
          snapshots: counts.snapshots,
          actions: counts.actions,
          notifications: counts.notifications,
          server_requests: counts.server_requests,
          total: counts.total,
        },
        { snapshots: 0, actions: 0, notifications: 0, server_requests: 0, total: 0 },
      );
    }
    assert.deepEqual(
      run.artifacts.events.map((event) => event.data?.observation_kind),
      ['lifecycle', 'lifecycle'],
    );
    assert.equal(eventEvidence(run.artifacts, 'snapshot').length, 0);
    assert.equal(run.artifacts.allText.includes('PRIVATE-SNAPSHOT-CLOCK-FAILURE'), false);

    const schema = JSON.parse(await fs.readFile(path.join(root, 'schema', 'ahp-observation.v1.json'), 'utf8'));
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const validate = ajv.compile(schema);
    assert.equal(validate(run.artifacts.summary), true, JSON.stringify(validate.errors));
  });

  await t.test('late valid initialize response during cleanup cannot mutate sealed evidence', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-late-initialize-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    let queued = null;
    let waiter = null;
    let closeCalls = 0;
    let resolveClose;
    let resolveDelivered;
    const closePromise = new Promise((resolve) => { resolveClose = resolve; });
    const delivered = new Promise((resolve) => { resolveDelivered = resolve; });
    const transport = {
      send(value) {
        const message = typeof value === 'string' ? JSON.parse(value) : value;
        if (message.method !== 'initialize') return;
        setTimeout(() => {
          const frame = {
            kind: 'parsed',
            message: response(message.id, {
              protocolVersion: '0.8.0',
              serverSeq: 9,
              snapshots: [snapshot(ROOT_CHANNEL, 9, { message: 'PRIVATE-LATE-SNAPSHOT' })],
            }),
          };
          if (waiter) {
            const resolve = waiter;
            waiter = null;
            resolve(frame);
          } else {
            queued = frame;
          }
          resolveDelivered();
          resolveClose();
        }, 30);
      },
      recv() {
        if (queued) {
          const frame = queued;
          queued = null;
          return Promise.resolve(frame);
        }
        return new Promise((resolve) => { waiter = resolve; });
      },
      close() {
        closeCalls += 1;
        return closePromise;
      },
    };
    const result = await observeAhp({
      dir: temp,
      transport,
      duration_ms: 100,
      request_timeout_ms: 25,
      now: () => FIXED_TIME,
    });
    await delivered;
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'request_timeout');
    assert.equal(closeCalls, 1);
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.protocol.negotiated_version, null);
    assert.equal(artifacts.summary.sequence.initialize_server_seq, null);
    assert.equal(artifacts.summary.counts.snapshots, 0);
    assert.equal(artifacts.summary.counts.persisted_events, 0);
    assert.equal(artifacts.allText.includes('PRIVATE-LATE-SNAPSHOT'), false);
  });

  await t.test('validated negotiation releases root when artifact commit crosses the deadline', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-delayed-negotiation-write-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [client, server] = InMemoryTransport.pair();
    const driver = scriptedServer(server, { keepOpen: true });
    const originalAppendFile = fs.appendFile;
    let appendCalls = 0;
    fs.appendFile = async (...args) => {
      appendCalls += 1;
      if (appendCalls === 2) await new Promise((resolve) => setTimeout(resolve, 150));
      return originalAppendFile(...args);
    };

    let result;
    try {
      result = await observeAhp({
        dir: temp,
        transport: client,
        duration_ms: 100,
        request_timeout_ms: 100,
        now: () => FIXED_TIME,
      });
    } finally {
      fs.appendFile = originalAppendFile;
    }
    await driver.done;

    assert.equal(appendCalls >= 3, true);
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'initialize_failed');
    assert.deepEqual(driver.outbound.map((message) => message.method), ['initialize', 'unsubscribe']);
    const unsubscribe = driver.outbound.at(-1);
    assert.equal(Object.hasOwn(unsubscribe, 'id'), false);
    assert.deepEqual(unsubscribe.params, { channel: ROOT_CHANNEL });
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.protocol.negotiated_version, '0.8.0');
    assert.equal(artifacts.summary.counts.snapshots, 1);
    assert.equal(artifacts.summary.warnings.includes('unsubscribe_cleanup_incomplete'), false);
  });

  await t.test('pending root overflow before unanswered initialize normalizes to blocked', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-root-pending-overflow-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [client, server] = InMemoryTransport.pair();
    const serverDone = (async () => {
      while (true) {
        const frame = await server.recv();
        if (frame === null) return;
        const message = parseTransportFrame(frame);
        if (message.method === 'initialize') {
          await server.send(action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {
            message: 'PRIVATE-PENDING-ROOT-ONE',
          }));
          await server.send(action(ROOT_CHANNEL, 2, ActionType.RootConfigChanged, {
            message: 'PRIVATE-PENDING-ROOT-TWO',
          }));
        }
      }
    })();
    const result = await observeAhp({
      dir: temp,
      transport: client,
      max_events: 1,
      duration_ms: 500,
      request_timeout_ms: 100,
      now: () => FIXED_TIME,
    });
    await serverDone;
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'initialize_failed');
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.protocol.negotiated_version, null);
    assert.equal(artifacts.summary.sequence.initialize_server_seq, null);
    assert.equal(artifacts.summary.counts.snapshots, 0);
    assert.equal(artifacts.summary.counts.persisted_events, 0);
    assert.equal(eventEvidence(artifacts, 'action').length, 0);
    assert.ok(artifacts.summary.warnings.includes('pending_record_limit'));
    assert.equal(artifacts.allText.includes('PRIVATE-PENDING-ROOT-ONE'), false);
    assert.equal(artifacts.allText.includes('PRIVATE-PENDING-ROOT-TWO'), false);
  });

  await t.test('global duration during unanswered initialize cannot report completed', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-initialize-duration-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [client, server] = InMemoryTransport.pair();
    const outbound = [];
    const serverDone = (async () => {
      while (true) {
        const frame = await server.recv();
        if (frame === null) return;
        outbound.push(parseTransportFrame(frame));
      }
    })();
    const result = await observeAhp({
      dir: temp,
      transport: client,
      duration_ms: 25,
      request_timeout_ms: 25,
      now: () => FIXED_TIME,
    });
    await serverDone;
    assert.notEqual(result.status, 'completed');
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'initialize_failed');
    assert.deepEqual(outbound.map((message) => message.method), ['initialize']);
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.protocol.negotiated_version, null);
    assert.equal(artifacts.summary.status, 'blocked');
    assert.equal(artifacts.receipt.status, 'blocked');
  });

  await t.test('global duration during unanswered requested subscribe is partial', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-subscribe-duration-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [client, server] = InMemoryTransport.pair();
    const outbound = [];
    const serverDone = (async () => {
      while (true) {
        const frame = await server.recv();
        if (frame === null) return;
        const message = parseTransportFrame(frame);
        outbound.push(message);
        if (message.method === 'initialize') {
          await server.send(response(message.id, {
            protocolVersion: '0.8.0',
            serverSeq: 0,
            snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
          }));
        }
      }
    })();
    const result = await observeAhp({
      dir: temp,
      transport: client,
      channels: [ROOT_CHANNEL, SESSION_CHANNEL],
      duration_ms: 500,
      request_timeout_ms: 500,
      now: () => FIXED_TIME,
    });
    await serverDone;
    assert.equal(result.status, 'partial');
    assert.equal(result.termination_reason, 'subscribe_failed');
    assert.deepEqual(
      outbound.map((message) => message.method),
      ['initialize', 'subscribe', 'unsubscribe', 'unsubscribe'],
    );
    assert.deepEqual(
      outbound.filter((message) => message.method === 'unsubscribe').map((message) => message.params.channel),
      [SESSION_CHANNEL, ROOT_CHANNEL],
    );
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.protocol.negotiated_version, '0.8.0');
    assert.equal(artifacts.summary.counts.snapshots, 1);
    assert.equal(artifacts.summary.status, 'partial');
    assert.equal(artifacts.receipt.status, 'blocked');
  });

  await t.test('abort signal', async (subtest) => {
    const controller = new AbortController();
    const run = await runScenario(subtest, {
      keepOpen: true,
      onReady: () => setTimeout(() => controller.abort(), 5),
    }, { signal: controller.signal });
    assert.equal(run.result.status, 'cancelled');
    assert.equal(run.result.termination_reason, 'cancelled');
  });

  await t.test('event bound', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, sensitiveShape())],
      },
      keepOpen: true,
    }, { max_events: 1 });
    assert.equal(run.result.status, 'partial');
    assert.equal(run.result.termination_reason, 'event_limit');
    assert.equal(run.artifacts.summary.counts.persisted_events, 1);
  });

  await t.test('event-limit race accounts only the one persisted record', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, { message: 'LIMITED-SNAPSHOT-PRIVATE' })],
      },
      messages: [action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {
        message: 'DROPPED-ACTION-PRIVATE',
      })],
    }, { max_events: 1 });
    assert.equal(run.result.status, 'partial');
    assert.equal(run.result.termination_reason, 'event_limit');
    assert.equal(run.artifacts.summary.counts.persisted_events, 1);
    assert.equal(run.artifacts.summary.counts.snapshots, 1);
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.equal(run.artifacts.summary.counts.duplicates, 0);
    assert.equal(run.artifacts.summary.source_event_digest_count, 1);
    assert.equal(run.artifacts.summary.source_event_digests.length, 1);
    assert.equal(eventEvidence(run.artifacts, 'snapshot').length, 1);
    assert.equal(eventEvidence(run.artifacts, 'action').length, 0);
    assert.equal(run.artifacts.summary.counts.by_channel.reduce((sum, entry) => sum + entry.total, 0), 1);
    assert.equal(run.artifacts.summary.counts.by_event_type.reduce((sum, entry) => sum + entry.count, 0), 1);
    assert.doesNotMatch(run.artifacts.allText, /LIMITED-SNAPSHOT-PRIVATE|DROPPED-ACTION-PRIVATE/);
  });

  await t.test('artifact-derived event bound and total byte invariant', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
      },
      messages: [action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, {})],
      keepOpen: true,
    }, {
      max_events: 10,
      max_artifact_bytes: 81_920,
      duration_ms: 5_000,
      request_timeout_ms: 1_000,
    });
    assert.equal(run.result.status, 'partial');
    assert.equal(run.result.termination_reason, 'artifact_limit');
    const sizes = await Promise.all(run.artifacts.names.map(async (name) => (
      await fs.stat(path.join(run.artifacts.runRoot, name))
    ).size));
    assert.ok(sizes.reduce((sum, size) => sum + size, 0) <= 81_920);
  });

  await t.test('malformed JSON frame', async (subtest) => {
    const run = await runScenario(subtest, { rawAfterInitialize: '{not-json', keepOpen: true });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'malformed_frame');
  });

  await t.test('oversized frame', async (subtest) => {
    const oversized = JSON.stringify(notification('root/progress', {
      channel: ROOT_CHANNEL,
      message: 'x'.repeat(512),
    }));
    const run = await runScenario(subtest, { rawAfterInitialize: oversized, keepOpen: true }, { max_frame_bytes: 256 });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'frame_limit');
  });
});

test('invalid UTF-8 binary frame is distinguished from malformed JSON', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-utf8-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  let delivered = false;
  let waiter = null;
  let closed = false;
  const transport = {
    send(message) {
      const decoded = typeof message === 'string' ? JSON.parse(message) : message;
      if (decoded.method === 'initialize' && !delivered) {
        delivered = true;
        const frame = { kind: 'binary', data: Uint8Array.from([0xff, 0xfe, 0xfd]) };
        if (waiter) {
          const resolve = waiter;
          waiter = null;
          resolve(frame);
        } else {
          transport.pending = frame;
        }
      }
    },
    recv() {
      if (transport.pending) {
        const frame = transport.pending;
        transport.pending = null;
        return Promise.resolve(frame);
      }
      if (closed) return Promise.resolve(null);
      return new Promise((resolve) => { waiter = resolve; });
    },
    close() {
      closed = true;
      if (waiter) {
        const resolve = waiter;
        waiter = null;
        resolve(null);
      }
    },
  };
  const result = await observeAhp({
    dir: temp,
    transport,
    duration_ms: 100,
    request_timeout_ms: 25,
    now: () => FIXED_TIME,
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'invalid_utf8');
});

test('same-sequence actions with identical public shape but different private content are collisions, not duplicates', async (t) => {
  const firstCanary = 'PRIVATE-COLLISION-A-88e7';
  const secondCanary = 'PRIVATE-COLLISION-B-88e7';
  const run = await runScenario(t, {
    messages: [
      action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, { message: firstCanary }),
      action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, { message: secondCanary }),
    ],
  });
  assert.equal(run.artifacts.summary.counts.unique_actions, 2);
  assert.equal(run.artifacts.summary.counts.duplicates, 0);
  assert.equal(run.artifacts.summary.counts.sequence_collisions_observed, 1);
  assert.ok(run.artifacts.summary.warnings.includes('sequence_collision_observed'));
  const evidence = eventEvidence(run.artifacts, 'action');
  assert.deepEqual(evidence.map((entry) => entry.sequence_classification), ['accepted', 'collision']);
  assert.equal(evidence[0].source_event_digest, 'sha256:[REDACTED_LONG_TOKEN]');
  assert.equal(evidence[1].source_event_digest, 'sha256:[REDACTED_LONG_TOKEN]');
  assert.doesNotMatch(run.artifacts.allText, new RegExp(firstCanary));
  assert.doesNotMatch(run.artifacts.allText, new RegExp(secondCanary));
});

test('snapshot and receive-loop writes serialize into one contiguous append-only event stream', async (t) => {
  const channels = [ROOT_CHANNEL, SESSION_CHANNEL];
  const messages = Array.from({ length: 30 }, (_, index) => action(
    ROOT_CHANNEL,
    index + 1,
    ActionType.RootConfigChanged,
    { message: `CONCURRENT-PRIVATE-${String(index).padStart(2, '0')}` },
  ));
  const run = await runScenario(t, {
    channels,
    subscribeSnapshots: {
      [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, { message: 'SUBSCRIBE-SNAPSHOT-PRIVATE' }),
    },
    messages,
  }, {
    channels,
    max_events: 100,
    duration_ms: 5_000,
    request_timeout_ms: 500,
  });
  assert.equal(run.result.status, 'completed');
  assert.equal(run.artifacts.summary.counts.snapshots, 2);
  assert.equal(run.artifacts.summary.counts.unique_actions, 30);
  assert.equal(run.artifacts.summary.counts.persisted_events, 32);
  assert.equal(run.artifacts.summary.source_event_digest_count, 32);
  assert.equal(run.artifacts.state.event_count, 34);
  assert.equal(run.artifacts.events.length, 34);
  assert.deepEqual(
    run.artifacts.events.map((event) => event.sequence),
    Array.from({ length: 34 }, (_, index) => index + 1),
  );
  assert.equal(new Set(run.artifacts.events.map((event) => event.event_id)).size, 34);
  assert.doesNotMatch(run.artifacts.allText, /CONCURRENT-PRIVATE|SUBSCRIBE-SNAPSHOT-PRIVATE/);
});

test('pending-subscribe action bursts retain only bounded sanitized evidence', async (t) => {
  const source = await fs.readFile(path.join(root, 'src', 'adapters', 'ahp-observer.mjs'), 'utf8');
  assert.match(source, /subscriptionBuffer:\s*1/);
  const channels = [ROOT_CHANNEL, SESSION_CHANNEL];

  await t.test('known root and auth notifications are accepted in arrival order after pending snapshot', async (subtest) => {
    const run = await runScenario(subtest, {
      channels,
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      },
      beforeSubscribeResponse: async ({ server }) => {
        await server.send(notification('root/progress', {
          channel: ROOT_CHANNEL,
          message: 'PRIVATE-PENDING-ROOT-NOTIFICATION',
        }));
        await server.send(notification('auth/required', {
          channel: ROOT_CHANNEL,
          authorization: 'Bearer PRIVATE-PENDING-AUTH-NOTIFICATION',
        }));
      },
    }, {
      channels,
      duration_ms: 5_000,
      request_timeout_ms: 500,
    });
    assert.equal(run.result.status, 'completed');
    assert.equal(run.artifacts.summary.counts.snapshots, 2);
    assert.equal(run.artifacts.summary.counts.notifications, 2);
    assert.deepEqual(
      eventEvidence(run.artifacts, 'notification').map((entry) => entry.notification_type),
      ['root_progress', 'auth_required'],
    );
    assert.equal(run.artifacts.allText.includes('PRIVATE-PENDING-ROOT-NOTIFICATION'), false);
    assert.equal(run.artifacts.allText.includes('PRIVATE-PENDING-AUTH-NOTIFICATION'), false);
  });

  await t.test('interleaved pending session and ready-root actions flush in global arrival order', async (subtest) => {
    const run = await runScenario(subtest, {
      channels,
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 4, {}),
      },
      beforeSubscribeResponse: async ({ server }) => {
        await server.send(action(SESSION_CHANNEL, 5, ActionType.SessionMetaChanged, {
          message: 'PRIVATE-INTERLEAVED-SESSION',
        }));
        await server.send(action(ROOT_CHANNEL, 6, ActionType.RootConfigChanged, {
          message: 'PRIVATE-INTERLEAVED-ROOT',
        }));
      },
    }, {
      channels,
      duration_ms: 5_000,
      request_timeout_ms: 500,
    });
    assert.equal(run.result.status, 'completed');
    assert.equal(run.artifacts.summary.counts.unique_actions, 2);
    assert.equal(run.artifacts.summary.counts.out_of_order_observed, 0);
    assert.deepEqual(
      eventEvidence(run.artifacts, 'action').map((entry) => [entry.server_seq, entry.sequence_classification]),
      [[5, 'accepted'], [6, 'accepted']],
    );
    assert.equal(run.artifacts.allText.includes('PRIVATE-INTERLEAVED-SESSION'), false);
    assert.equal(run.artifacts.allText.includes('PRIVATE-INTERLEAVED-ROOT'), false);
  });

  await t.test('within the event bound, pending actions are accepted after the snapshot', async (subtest) => {
    const canaryPrefix = 'PRIVATE-PENDING-BURST-ACCEPTED-';
    const run = await runScenario(subtest, {
      channels,
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      },
      beforeSubscribeResponse: async ({ server }) => {
        for (let index = 1; index <= 8; index += 1) {
          await server.send(action(
            SESSION_CHANNEL,
            index,
            ActionType.SessionMetaChanged,
            { message: `${canaryPrefix}${index}` },
          ));
        }
      },
    }, {
      channels,
      max_events: 20,
      duration_ms: 5_000,
      request_timeout_ms: 500,
    });
    assert.equal(run.result.status, 'completed');
    assert.equal(run.result.termination_reason, 'transport_closed');
    assert.equal(run.artifacts.summary.counts.snapshots, 2);
    assert.equal(run.artifacts.summary.counts.unique_actions, 8);
    assert.equal(run.artifacts.summary.counts.persisted_events, 10);
    assert.deepEqual(
      eventEvidence(run.artifacts, 'action').map((entry) => entry.server_seq),
      [1, 2, 3, 4, 5, 6, 7, 8],
    );
    assert.equal(run.artifacts.allText.includes(canaryPrefix), false);
  });

  await t.test('pending actions stop at the configured event bound before a snapshot arrives', async (subtest) => {
    const canaryPrefix = 'PRIVATE-PENDING-BURST-BOUNDED-';
    const run = await runScenario(subtest, {
      channels,
      subscribeSnapshots: {
        [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      },
      beforeSubscribeResponse: async ({ server }) => {
        for (let index = 1; index <= 5; index += 1) {
          await server.send(action(
            SESSION_CHANNEL,
            index,
            ActionType.SessionMetaChanged,
            { message: `${canaryPrefix}${index}` },
          ));
        }
      },
    }, {
      channels,
      max_events: 4,
      duration_ms: 5_000,
      request_timeout_ms: 500,
    });
    assert.equal(run.result.status, 'partial');
    assert.equal(run.result.termination_reason, 'event_limit');
    assert.equal(run.artifacts.summary.counts.snapshots, 1);
    assert.equal(run.artifacts.summary.counts.unique_actions, 0);
    assert.equal(run.artifacts.summary.counts.persisted_events, 1);
    assert.equal(eventEvidence(run.artifacts, 'action').length, 0);
    assert.ok(run.artifacts.summary.warnings.includes('pending_record_limit'));
    assert.equal(run.artifacts.allText.includes(canaryPrefix), false);
  });
});

test('digest and per-event summaries truncate explicitly at their fixed bounds', async (t) => {
  const channels = [ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL];
  const allowedTypes = Object.values(ActionType).filter((value) => /^(root|session|chat)\//.test(value));
  assert.equal(allowedTypes.length, 61, 'AHP 0.8.0 action fixture count changed');
  const channelForType = (type) => type.startsWith('root/')
    ? ROOT_CHANNEL
    : type.startsWith('session/')
      ? SESSION_CHANNEL
      : CHAT_CHANNEL;
  const messages = Array.from({ length: 130 }, (_, index) => {
    const type = allowedTypes[index % allowedTypes.length];
    return action(channelForType(type), index + 1, type, { message: `BOUNDED-PRIVATE-${index}` });
  });
  messages.push(
    notification('root/sessionAdded', { channel: ROOT_CHANNEL }),
    notification('root/sessionRemoved', { channel: ROOT_CHANNEL }),
    notification('root/sessionSummaryChanged', { channel: ROOT_CHANNEL }),
    notification('root/progress', { channel: ROOT_CHANNEL }),
    notification('auth/required', { channel: ROOT_CHANNEL }),
    notification('otlp/exportLogs', { channel: 'ahp-otlp://logs', body: 'PRIVATE-OTLP' }),
    notification('unknown/example', { channel: 'ahp-terminal:/private', terminalOutput: 'PRIVATE-TERMINAL' }),
    {
      jsonrpc: '2.0',
      id: 900,
      method: 'resourceRead',
      params: { channel: ROOT_CHANNEL, uri: 'file:///private/truncation-fixture' },
    },
  );
  const run = await runScenario(t, {
    channels,
    subscribeSnapshots: {
      [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      [CHAT_CHANNEL]: snapshot(CHAT_CHANNEL, 0, {}),
    },
    messages,
    closeAfterResponseId: 900,
  }, {
    channels,
    max_events: 180,
    duration_ms: 10_000,
    request_timeout_ms: 1_000,
  });
  assert.equal(run.result.status, 'completed');
  assert.equal(run.artifacts.summary.source_event_digest_count, 141);
  assert.equal(run.artifacts.summary.source_event_digests.length, 128);
  assert.equal(run.artifacts.summary.source_event_digests_truncated, true);
  assert.equal(run.artifacts.summary.counts.by_event_type.length, 64);
  assert.equal(run.artifacts.summary.counts.event_type_counts_truncated, true);
  assert.equal(run.artifacts.summary.counts.persisted_events, 141);
  assert.equal(run.artifacts.events.length, 143);
  assert.doesNotMatch(run.artifacts.allText, /BOUNDED-PRIVATE|PRIVATE-OTLP|PRIVATE-TERMINAL|truncation-fixture/);
});

test('open observations release negotiated and attempted subscriptions in reverse order', async (t) => {
  const channels = [ROOT_CHANNEL, SESSION_CHANNEL, CHAT_CHANNEL];
  const run = await runScenario(t, {
    channels,
    subscribeSnapshots: {
      [SESSION_CHANNEL]: snapshot(SESSION_CHANNEL, 0, {}),
      [CHAT_CHANNEL]: snapshot(CHAT_CHANNEL, 0, {}),
    },
    keepOpen: true,
  }, {
    channels,
    duration_ms: 75,
    request_timeout_ms: 50,
  });

  assert.equal(run.result.status, 'completed');
  assert.equal(run.result.termination_reason, 'duration_limit');
  assert.deepEqual(run.outbound.map((message) => message.method), [
    'initialize',
    'subscribe',
    'subscribe',
    'unsubscribe',
    'unsubscribe',
    'unsubscribe',
  ]);
  const unsubscribes = run.outbound.filter((message) => message.method === 'unsubscribe');
  assert.deepEqual(unsubscribes.map((message) => message.params.channel), [...channels].reverse());
  assert.ok(unsubscribes.every((message) => !Object.hasOwn(message, 'id')));
  assert.ok(unsubscribes.every((message) => (
    Object.keys(message.params).length === 1 && Object.hasOwn(message.params, 'channel')
  )));
});

test('unsubscribe cleanup waits for transport sends before closing', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-unsubscribe-flush-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const [baseClient, server] = InMemoryTransport.pair();
  const lifecycle = [];
  let closeCalls = 0;
  const transport = {
    async send(value) {
      const message = typeof value === 'string' ? JSON.parse(value) : value;
      if (message.method !== 'unsubscribe') return baseClient.send(value);
      lifecycle.push('unsubscribe_send_started');
      baseClient.send(value);
      await new Promise((resolve) => setTimeout(resolve, 20));
      lifecycle.push('unsubscribe_send_settled');
    },
    recv() {
      return baseClient.recv();
    },
    async close() {
      closeCalls += 1;
      lifecycle.push('transport_close');
      await baseClient.close();
    },
  };
  const driver = scriptedServer(server, { keepOpen: true });

  const result = await observeAhp({
    dir: temp,
    transport,
    duration_ms: 100,
    request_timeout_ms: 75,
    now: () => FIXED_TIME,
  });
  await driver.done;

  assert.equal(result.status, 'completed');
  assert.equal(result.termination_reason, 'duration_limit');
  assert.deepEqual(lifecycle, [
    'unsubscribe_send_started',
    'unsubscribe_send_settled',
    'transport_close',
  ]);
  assert.equal(closeCalls, 1);
  assert.deepEqual(driver.outbound.map((message) => message.method), ['initialize', 'unsubscribe']);
});

test('hung and failing unsubscribe cleanup stays bounded and warning-only', async (t) => {
  for (const mode of ['hung', 'failed']) {
    await t.test(mode, async (subtest) => {
      const temp = await fs.mkdtemp(path.join(os.tmpdir(), `ahp-unsubscribe-${mode}-test-`));
      subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
      const [baseClient, server] = InMemoryTransport.pair();
      const privateFailure = 'PRIVATE-UNSUBSCRIBE-SEND-FAILURE';
      let closeCalls = 0;
      const transport = {
        async send(value) {
          const message = typeof value === 'string' ? JSON.parse(value) : value;
          if (message.method !== 'unsubscribe') return baseClient.send(value);
          if (mode === 'failed') throw new Error(privateFailure);
          return new Promise(() => {});
        },
        recv() {
          return baseClient.recv();
        },
        async close() {
          closeCalls += 1;
          await baseClient.close();
        },
      };
      const driver = scriptedServer(server, { keepOpen: true });
      const started = Date.now();
      const result = await observeAhp({
        dir: temp,
        transport,
        duration_ms: 50,
        request_timeout_ms: 25,
        now: () => FIXED_TIME,
      });
      await driver.done;

      assert.ok(Date.now() - started < 750);
      assert.equal(result.status, 'completed');
      assert.equal(result.termination_reason, 'duration_limit');
      assert.equal(closeCalls, 1);
      const artifacts = await readRunArtifacts(temp, result);
      assert.ok(artifacts.summary.warnings.includes('unsubscribe_cleanup_incomplete'));
      assert.equal(artifacts.allText.includes(privateFailure), false);
    });
  }
});

test('unsubscribe cleanup is skipped after failed negotiation or remote close', async (t) => {
  await t.test('failed negotiation', async (subtest) => {
    const run = await runScenario(subtest, {
      initializeResult: { protocolVersion: '0.7.0', serverSeq: 0, snapshots: [] },
      keepOpen: true,
    });
    assert.equal(run.result.status, 'blocked');
    assert.equal(run.result.termination_reason, 'unsupported_protocol_version');
    assert.deepEqual(run.outbound.map((message) => message.method), ['initialize']);
    assert.equal(run.artifacts.summary.warnings.includes('unsubscribe_cleanup_incomplete'), false);
  });

  await t.test('remote close', async (subtest) => {
    const run = await runScenario(subtest);
    assert.equal(run.result.status, 'completed');
    assert.equal(run.result.termination_reason, 'transport_closed');
    assert.deepEqual(run.outbound.map((message) => message.method), ['initialize']);
    assert.equal(run.artifacts.summary.warnings.includes('unsubscribe_cleanup_incomplete'), false);
  });
});

test('misbehaving injected transport cannot hang bounded observer shutdown', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-hung-close-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  let queued = null;
  let waiter = null;
  const transport = {
    send(value) {
      const message = typeof value === 'string' ? JSON.parse(value) : value;
      if (message.method !== 'initialize') return;
      const frame = {
        kind: 'parsed',
        message: response(message.id, {
          protocolVersion: '0.8.0',
          serverSeq: 0,
          snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
        }),
      };
      if (waiter) {
        const resolve = waiter;
        waiter = null;
        resolve(frame);
      } else {
        queued = frame;
      }
    },
    recv() {
      if (queued) {
        const frame = queued;
        queued = null;
        return Promise.resolve(frame);
      }
      return new Promise((resolve) => { waiter = resolve; });
    },
    close() {
      return new Promise(() => {});
    },
  };
  const started = Date.now();
  let deadline;
  let result;
  try {
    result = await Promise.race([
      observeAhp({
        dir: temp,
        transport,
        duration_ms: 30,
        request_timeout_ms: 25,
        now: () => FIXED_TIME,
      }),
      new Promise((_, reject) => {
        deadline = setTimeout(() => reject(new Error('observer shutdown exceeded hard test deadline')), 750);
      }),
    ]);
  } finally {
    clearTimeout(deadline);
  }
  assert.ok(Date.now() - started < 750);
  assert.equal(result.status, 'completed');
  assert.equal(result.termination_reason, 'duration_limit');
  const artifacts = await readRunArtifacts(temp, result);
  assert.ok(artifacts.summary.warnings.includes('transport_close_timeout'));
});

test('summary, event, run, and local receipt artifacts validate and digests match bytes', async (t) => {
  const run = await runScenario(t, {
    messages: [action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, sensitiveShape())],
  });
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const schemaNames = [
    'ahp-observation.v1.json',
    'harness-event.v1.json',
    'harness-evaluation.v1.json',
    'harness-run.v1.json',
    'local-receipt.v1.json',
  ];
  const schemas = {};
  for (const name of schemaNames) {
    schemas[name] = JSON.parse(await fs.readFile(path.join(root, 'schema', name), 'utf8'));
    ajv.addSchema(schemas[name]);
  }
  const assertValid = (schema, value, label) => {
    const validate = ajv.getSchema(schema.$id);
    assert.equal(validate(value), true, `${label}: ${JSON.stringify(validate.errors)}`);
  };
  assertValid(schemas['ahp-observation.v1.json'], run.artifacts.summary, 'summary');
  for (const event of run.artifacts.events) assertValid(schemas['harness-event.v1.json'], event, 'event');
  assertValid(schemas['harness-run.v1.json'], run.artifacts.state, 'state');
  assertValid(schemas['local-receipt.v1.json'], run.artifacts.receipt, 'receipt');

  const {
    output_digest: _outputDigest,
    observation_id: _observationId,
    created_at: _createdAt,
    completed_at: _CompletedAt,
    ...summaryBase
  } = run.artifacts.summary;
  assert.equal(run.artifacts.summary.output_digest, stableHash(summaryBase));
  assert.equal(run.result.output_digest, run.artifacts.summary.output_digest);
  assert.equal(run.artifacts.manifest.summary_digest, run.artifacts.summary.output_digest);
  for (const artifact of run.artifacts.manifest.artifacts) {
    const bytes = await fs.readFile(path.join(run.artifacts.runRoot, artifact.file));
    assert.equal(artifact.bytes, bytes.byteLength);
    assert.equal(artifact.sha256, `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`);
  }
  const { manifest_digest: _manifestDigest, ...manifestBase } = run.artifacts.manifest;
  assert.equal(run.artifacts.manifest.manifest_digest, stableHash(manifestBase));
  assert.equal(run.artifacts.receipt.spend.amount_usdc, 0);
  assert.equal(run.artifacts.receipt.settlement_status, 'not_settlement_receipt');
  assert.ok(AUTHORITY_KEYS.every((key) => run.artifacts.receipt.receipt_boundary[key] === false));
});

test('source event digests are stable across independent observations', async (t) => {
  const scenario = {
    initializeResult: {
      protocolVersion: '0.8.0',
      serverSeq: 40,
      snapshots: [snapshot(ROOT_CHANNEL, 40, sensitiveShape())],
    },
    messages: [action(ROOT_CHANNEL, 41, ActionType.RootConfigChanged, sensitiveShape())],
  };
  const first = await runScenario(t, scenario);
  const second = await runScenario(t, scenario);
  assert.notEqual(first.result.observation_id, second.result.observation_id);
  assert.deepEqual(
    first.artifacts.summary.source_event_digests,
    second.artifacts.summary.source_event_digests,
  );
  assert.equal(first.artifacts.summary.source_event_stream_digest, second.artifacts.summary.source_event_stream_digest);
  assert.equal(first.result.output_digest, second.result.output_digest);
});

test('injected subscribe send failure closes the underlying transport exactly once', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-subscribe-send-failure-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const [baseClient, server] = InMemoryTransport.pair();
  const attemptedMethods = [];
  const receivedMethods = [];
  let closeCalls = 0;
  const transport = {
    async send(value) {
      const message = typeof value === 'string' ? JSON.parse(value) : value;
      attemptedMethods.push(message.method);
      if (message.method === 'subscribe') throw new Error('PRIVATE-SUBSCRIBE-SEND-FAILURE');
      return baseClient.send(value);
    },
    recv() {
      return baseClient.recv();
    },
    async close() {
      closeCalls += 1;
      await baseClient.close();
    },
  };
  const serverDone = (async () => {
    while (true) {
      const frame = await server.recv();
      if (frame === null) return;
      const message = parseTransportFrame(frame);
      receivedMethods.push(message.method);
      if (message.method === 'initialize') {
        await server.send(response(message.id, {
          protocolVersion: '0.8.0',
          serverSeq: 0,
          snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
        }));
      }
    }
  })();

  const result = await observeAhp({
    dir: temp,
    transport,
    channels: [ROOT_CHANNEL, SESSION_CHANNEL],
    duration_ms: 500,
    request_timeout_ms: 100,
    now: () => FIXED_TIME,
  });
  await serverDone;
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'transport_error');
  assert.deepEqual(attemptedMethods, ['initialize', 'subscribe']);
  assert.deepEqual(receivedMethods, ['initialize']);
  assert.equal(closeCalls, 1);
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.protocol.negotiated_version, '0.8.0');
  assert.equal(artifacts.summary.counts.snapshots, 1);
  assert.equal(artifacts.allText.includes('PRIVATE-SUBSCRIBE-SEND-FAILURE'), false);
});

test('default MethodNotFound policy selection never claims response delivery', async (t) => {
  await t.test('response send failure preserves policy-only evidence', async (subtest) => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-default-rejection-send-test-'));
    subtest.after(() => fs.rm(temp, { recursive: true, force: true }));
    const [baseClient, server] = InMemoryTransport.pair();
    let defaultResponseAttempts = 0;
    let closeCalls = 0;
    const transport = {
      async send(value) {
        const message = typeof value === 'string' ? JSON.parse(value) : value;
        if (!Object.hasOwn(message, 'method') && message.error?.code === -32601) {
          defaultResponseAttempts += 1;
          throw new Error('PRIVATE-DEFAULT-REJECTION-SEND-FAILURE');
        }
        return baseClient.send(value);
      },
      recv() {
        return baseClient.recv();
      },
      async close() {
        closeCalls += 1;
        await baseClient.close();
      },
    };
    const serverDone = (async () => {
      while (true) {
        const frame = await server.recv();
        if (frame === null) return;
        const message = parseTransportFrame(frame);
        if (message.method === 'initialize') {
          await server.send(response(message.id, {
            protocolVersion: '0.8.0',
            serverSeq: 0,
            snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
          }));
          await server.send({
            jsonrpc: '2.0',
            id: 701,
            method: 'resourceRead',
            params: { channel: ROOT_CHANNEL, uri: 'file:///PRIVATE-DEFAULT-REJECTION' },
          });
        }
      }
    })();
    const result = await observeAhp({
      dir: temp,
      transport,
      duration_ms: 500,
      request_timeout_ms: 100,
      now: () => FIXED_TIME,
    });
    await serverDone;
    assert.equal(result.status, 'blocked');
    assert.equal(result.termination_reason, 'transport_error');
    assert.equal(defaultResponseAttempts, 1);
    assert.equal(closeCalls, 1);
    const artifacts = await readRunArtifacts(temp, result);
    assert.equal(artifacts.summary.counts.server_requests_default_rejection_selected, 1);
    const evidence = eventEvidence(artifacts, 'server_request_default_rejection');
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].response_policy, 'method_not_found');
    assert.equal(Object.keys(evidence[0]).some((key) => /deliver|sent/i.test(key)), false);
    assert.equal(artifacts.allText.includes('PRIVATE-DEFAULT-REJECTION-SEND-FAILURE'), false);
    assert.equal(artifacts.allText.includes('PRIVATE-DEFAULT-REJECTION'), false);
  });

  await t.test('record accepted at exact event limit remains policy-only evidence', async (subtest) => {
    const run = await runScenario(subtest, {
      messages: [{
        jsonrpc: '2.0',
        id: 702,
        method: 'resourceRead',
        params: { channel: ROOT_CHANNEL, uri: 'file:///PRIVATE-EXACT-LIMIT-REJECTION' },
      }],
      closeAfterResponseId: 702,
    }, { max_events: 2 });
    assert.equal(run.result.status, 'partial');
    assert.equal(run.result.termination_reason, 'event_limit');
    assert.equal(run.artifacts.summary.counts.persisted_events, 2);
    assert.equal(run.artifacts.summary.counts.server_requests_default_rejection_selected, 1);
    const evidence = eventEvidence(run.artifacts, 'server_request_default_rejection');
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].response_policy, 'method_not_found');
    assert.equal(Object.keys(evidence[0]).some((key) => /deliver|sent/i.test(key)), false);
    assert.equal(run.artifacts.allText.includes('PRIVATE-EXACT-LIMIT-REJECTION'), false);
  });
});

test('Node 18-compatible ws transport observes loopback without monkeypatching global WebSocket', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-ws-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const beforeGlobal = globalThis.WebSocket;
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, perMessageDeflate: false });
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, 'object');

  server.on('connection', (socket) => {
    socket.on('message', (raw) => {
      const message = JSON.parse(raw.toString('utf8'));
      if (message.method !== 'initialize') return;
      socket.send(JSON.stringify(response(message.id, {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, sensitiveShape())],
      })));
      socket.send(JSON.stringify(action(ROOT_CHANNEL, 1, ActionType.RootConfigChanged, sensitiveShape())));
      socket.close();
    });
  });

  const result = await observeAhp({
    dir: temp,
    endpoint: `ws://127.0.0.1:${address.port}/ahp`,
    duration_ms: 500,
    request_timeout_ms: 100,
    now: () => FIXED_TIME,
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.termination_reason, 'transport_closed');
  assert.equal(globalThis.WebSocket, beforeGlobal);
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.source.transport_kind, 'loopback_websocket');
  assert.equal(artifacts.summary.source.endpoint_scheme, 'ws');
  assert.doesNotMatch(artifacts.allText, new RegExp(String(address.port)));
  for (const canary of Object.values(CANARIES)) assert.doesNotMatch(artifacts.allText, new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('websocket handshake completing after the global duration emits no initialize request', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-ws-late-handshake-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const httpServer = createServer();
  const webSocketServer = new WebSocketServer({ noServer: true, perMessageDeflate: false });
  let upgradeSocket = null;
  let connectionCount = 0;
  const receivedMethods = [];
  httpServer.on('upgrade', (request, socket, head) => {
    upgradeSocket = socket;
    setTimeout(() => {
      if (socket.destroyed) return;
      webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
        webSocketServer.emit('connection', webSocket, request);
      });
    }, 75);
  });
  webSocketServer.on('connection', (socket) => {
    connectionCount += 1;
    socket.on('message', (raw) => receivedMethods.push(JSON.parse(raw.toString('utf8')).method));
  });
  await new Promise((resolve, reject) => {
    httpServer.once('listening', resolve);
    httpServer.once('error', reject);
    httpServer.listen(0, '127.0.0.1');
  });
  t.after(() => new Promise((resolve) => {
    for (const socket of webSocketServer.clients) socket.terminate();
    upgradeSocket?.destroy();
    httpServer.close(resolve);
  }));
  const address = httpServer.address();
  assert.equal(typeof address, 'object');

  const result = await observeAhp({
    dir: temp,
    endpoint: `ws://127.0.0.1:${address.port}/ahp`,
    duration_ms: 25,
    request_timeout_ms: 25,
    now: () => FIXED_TIME,
  });
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'initialize_failed');
  assert.equal(connectionCount, 0);
  assert.deepEqual(receivedMethods, []);
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.protocol.negotiated_version, null);
  assert.equal(artifacts.summary.counts.snapshots, 0);
  assert.equal(artifacts.summary.counts.persisted_events, 0);
  assert.doesNotMatch(artifacts.allText, new RegExp(String(address.port)));
});

test('oversized loopback subscribe frame fails closed and tears down the websocket', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-ws-outbound-frame-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const longChannel = `ahp-session:/${'s'.repeat(240)}`;
  const minimumSubscribeFrame = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'subscribe',
    params: { channel: longChannel },
  });
  assert.ok(Buffer.byteLength(minimumSubscribeFrame, 'utf8') > 256);

  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, perMessageDeflate: false });
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  t.after(() => new Promise((resolve) => {
    for (const socket of server.clients) socket.terminate();
    server.close(resolve);
  }));
  const address = server.address();
  assert.equal(typeof address, 'object');

  let connectionCount = 0;
  let serverSocket = null;
  let resolveSocketClosed;
  const socketClosed = new Promise((resolve) => { resolveSocketClosed = resolve; });
  const receivedMethods = [];
  server.on('connection', (socket) => {
    connectionCount += 1;
    serverSocket = socket;
    socket.once('close', () => resolveSocketClosed());
    socket.on('error', () => {});
    socket.on('message', (raw) => {
      const message = JSON.parse(raw.toString('utf8'));
      receivedMethods.push(message.method);
      if (message.method !== 'initialize') return;
      socket.send(JSON.stringify(response(message.id, {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
      })));
    });
  });

  const result = await observeAhp({
    dir: temp,
    endpoint: `ws://127.0.0.1:${address.port}/ahp`,
    channels: [ROOT_CHANNEL, longChannel],
    duration_ms: 500,
    request_timeout_ms: 100,
    max_frame_bytes: 256,
    now: () => FIXED_TIME,
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'outbound_frame_limit');
  assert.equal(connectionCount, 1);
  assert.deepEqual(receivedMethods, ['initialize']);
  const closedWithinBound = await Promise.race([
    socketClosed.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 500)),
  ]);
  assert.equal(closedWithinBound, true);
  assert.equal(server.clients.size, 0);
  assert.equal(serverSocket.readyState, WebSocket.CLOSED);
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.protocol.negotiated_version, '0.8.0');
  assert.equal(artifacts.allText.includes(longChannel), false);
  assert.doesNotMatch(artifacts.allText, new RegExp(String(address.port)));
});

test('abnormal loopback websocket termination fails closed instead of masquerading as a clean close', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-ws-terminate-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, perMessageDeflate: false });
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, 'object');

  server.on('connection', (socket) => {
    socket.on('error', () => {});
    socket.on('message', (raw) => {
      const message = JSON.parse(raw.toString('utf8'));
      if (message.method !== 'initialize') return;
      socket.send(JSON.stringify(response(message.id, {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
      })), () => socket.terminate());
    });
  });

  const result = await observeAhp({
    dir: temp,
    endpoint: `ws://127.0.0.1:${address.port}/ahp`,
    duration_ms: 500,
    request_timeout_ms: 100,
    now: () => FIXED_TIME,
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'websocket_transport_error');
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.status, 'blocked');
  assert.equal(artifacts.receipt.status, 'blocked');
  assert.equal(artifacts.summary.source.transport_kind, 'loopback_websocket');
  assert.doesNotMatch(artifacts.allText, new RegExp(String(address.port)));
});

test('loopback websocket burst exceeding inbound queue bounds fails closed', async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'ahp-ws-buffer-test-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, perMessageDeflate: false });
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, 'object');

  server.on('connection', (socket) => {
    socket.on('error', () => {});
    socket.on('message', (raw) => {
      const message = JSON.parse(raw.toString('utf8'));
      if (message.method !== 'initialize') return;
      socket.send(JSON.stringify(response(message.id, {
        protocolVersion: '0.8.0',
        serverSeq: 0,
        snapshots: [snapshot(ROOT_CHANNEL, 0, {})],
      })));
      for (let index = 0; index < 100; index += 1) {
        socket.send(JSON.stringify(action(
          ROOT_CHANNEL,
          index + 1,
          ActionType.RootConfigChanged,
          {},
        )));
      }
    });
  });

  const result = await observeAhp({
    dir: temp,
    endpoint: `ws://127.0.0.1:${address.port}/ahp`,
    duration_ms: 500,
    request_timeout_ms: 100,
    max_events: 200,
    max_frame_bytes: 256,
    now: () => FIXED_TIME,
  });
  assert.equal(result.status, 'blocked');
  assert.equal(result.termination_reason, 'inbound_buffer_limit');
  const artifacts = await readRunArtifacts(temp, result);
  assert.equal(artifacts.summary.status, 'blocked');
  assert.equal(artifacts.receipt.status, 'blocked');
  assert.ok(artifacts.summary.counts.persisted_events <= 1);
  assert.doesNotMatch(artifacts.allText, new RegExp(String(address.port)));
});

test('package exposes the observer and schema while pinning the exact AHP and ws dependencies', async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
  const [rootModule, eventsModule] = await Promise.all([
    import('agoragentic-harness-core'),
    import('agoragentic-harness-core/kernel/events'),
  ]);
  assert.equal(pkg.engines.node, '>=18.0.0');
  assert.equal(pkg.dependencies['@microsoft/agent-host-protocol'], '0.8.0');
  assert.equal(pkg.dependencies.ws, '8.21.3');
  assert.equal(pkg.exports['./adapters/ahp'], './src/adapters/ahp-observer.mjs');
  assert.equal(pkg.exports['./schema/ahp-observation.v1.json'], './schema/ahp-observation.v1.json');
  assert.equal(pkg.exports['./internal/trusted-sha256-reference'], undefined);
  assert.equal(Object.hasOwn(rootModule, 'createTrustedSha256Reference'), false);
  assert.equal(Object.hasOwn(eventsModule, 'createTrustedSha256Reference'), false);
  await assert.rejects(
    import('agoragentic-harness-core/internal/trusted-sha256-reference'),
    (error) => error?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  );
  await assert.rejects(
    import(new URL('../src/internal/trusted-sha256-reference.mjs', import.meta.url)),
    (error) => error?.code === 'ERR_MODULE_NOT_FOUND',
  );
  assert.ok(pkg.files.includes('AHP_ADAPTER.md'));
  assert.match(pkg.scripts.test, /ahp-observer\.test\.mjs/);
});
