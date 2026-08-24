import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { AhpClient } from '@microsoft/agent-host-protocol/client';
import { ActionType, AhpErrorCodes, IS_CLIENT_DISPATCHABLE } from '@microsoft/agent-host-protocol';
import { authorityBoundary, stableHash, stableId } from '../kernel/events.mjs';
import {
  appendRunEvent,
  completeRunState,
  createRunState,
  runDir,
  writeRunArtifact,
  writeTextRunArtifact,
} from '../kernel/state.mjs';
import { createAhpLoopbackWebSocketTransport } from './ahp-ws-transport.mjs';

export const AHP_OBSERVATION_SCHEMA = 'agoragentic.harness.ahp-observation.v1';
export const AHP_OBSERVER_ADAPTER_VERSION = '1.0.0';
export const AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS = Object.freeze(['0.8.0']);

export const AHP_OBSERVER_AUTHORITY_FLAGS = Object.freeze({
  dispatch_action: false,
  create_session: false,
  dispose_session: false,
  create_chat: false,
  terminal_input: false,
  terminal_claim: false,
  resource_write: false,
  resource_delete: false,
  resource_move: false,
  authenticate: false,
  provide_client_tools: false,
  approve_tool_calls: false,
  run_automation: false,
  mutate_automation: false,
  provider_dispatch: false,
  wallet_mutation: false,
  x402_settlement: false,
  marketplace_publication: false,
  trust_mutation: false,
  owner_approval_bypass: false,
});

const ALLOWED_OUTBOUND_METHODS = new Set(['initialize', 'subscribe', 'unsubscribe']);
const KNOWN_SERVER_REQUESTS = new Set([
  'resourceRead',
  'resourceWrite',
  'resourceList',
  'resourceCopy',
  'resourceDelete',
  'resourceMove',
  'resourceResolve',
  'resourceMkdir',
  'resourceRequest',
  'createResourceWatch',
]);
const PROHIBITED_CLIENT_METHODS = Object.freeze([
  'ping',
  'reconnect',
  'dispatchAction',
  'createSession',
  'disposeSession',
  'createChat',
  'disposeChat',
  'createTerminal',
  'disposeTerminal',
  'createResourceWatch',
  'listSessions',
  'resourceRead',
  'resourceWrite',
  'resourceList',
  'resourceCopy',
  'resourceDelete',
  'resourceMove',
  'resourceResolve',
  'resourceMkdir',
  'resourceRequest',
  'fetchTurns',
  'authenticate',
  'resolveSessionConfig',
  'sessionConfigCompletions',
  'completions',
  'invokeChangesetOperation',
]);
const ALLOWED_CONFIG_KEYS = new Set([
  'dir',
  'endpoint',
  'transport',
  'channels',
  'duration_ms',
  'max_events',
  'max_frame_bytes',
  'max_artifact_bytes',
  'request_timeout_ms',
  'signal',
  'now',
]);
const KNOWN_NOTIFICATIONS = new Map([
  ['root/sessionAdded', 'root_session_added'],
  ['root/sessionRemoved', 'root_session_removed'],
  ['root/sessionSummaryChanged', 'root_session_summary_changed'],
  ['root/progress', 'root_progress'],
  ['auth/required', 'auth_required'],
]);
const OTLP_NOTIFICATIONS = new Set(['otlp/exportLogs', 'otlp/exportTraces', 'otlp/exportMetrics']);
const AUDITED_ACTION_TYPE_DIGEST = 'sha256:c78f2489bfeb441c04aaaf352cd37d5e22e9cfcb6c6acc87857b6873f78ab041';
const AUDITED_CLIENT_DISPATCHABLE_DIGEST = 'sha256:c6cc3e7a98d50b954144434097b3b3674268fa896c4bd1ec2847d8156efa9eca';
const UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE = -32_005;
if (stableHash(ActionType) !== AUDITED_ACTION_TYPE_DIGEST
  || stableHash(IS_CLIENT_DISPATCHABLE) !== AUDITED_CLIENT_DISPATCHABLE_DIGEST
  || AhpErrorCodes.UnsupportedProtocolVersion !== UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE) {
  throw new Error('audited_ahp_0_8_0_constants_mismatch');
}
const ALLOWED_ACTION_TYPES = new Set(Object.values(ActionType).filter((value) => /^(root|session|chat)\//.test(value)));
const CLIENT_ORIGIN_ACTION_TYPES = new Set(Object.entries(IS_CLIENT_DISPATCHABLE)
  .filter(([, permitted]) => permitted === true)
  .map(([type]) => type));
const SAFE_STATUS_VALUES = new Set([
  'active', 'blocked', 'cancelled', 'closed', 'completed', 'connected', 'disconnected',
  'done', 'error', 'failed', 'idle', 'in_progress', 'pending', 'ready', 'running',
  'stopped', 'success', 'waiting',
]);
const REF_KEYS = new Map([
  ['sessionid', 'session_ref_digest'],
  ['session', 'session_ref_digest'],
  ['chatid', 'chat_ref_digest'],
  ['chat', 'chat_ref_digest'],
  ['turnid', 'turn_ref_digest'],
  ['toolcallid', 'tool_call_ref_digest'],
  ['terminalid', 'terminal_ref_digest'],
  ['terminal', 'terminal_ref_digest'],
]);
const DEFAULTS = Object.freeze({
  duration_ms: 5_000,
  max_events: 256,
  max_frame_bytes: 262_144,
  max_artifact_bytes: 2_097_152,
  request_timeout_ms: 3_000,
});
const LIMITS = Object.freeze({
  duration_ms: Object.freeze([25, 60_000]),
  max_events: Object.freeze([1, 1_000]),
  max_frame_bytes: Object.freeze([256, 1_048_576]),
  max_artifact_bytes: Object.freeze([81_920, 8_388_608]),
  request_timeout_ms: Object.freeze([25, 30_000]),
  max_channels: 16,
  max_channel_bytes: 512,
});
const ARTIFACT_RESERVE_BYTES = 65_536;
const EVENT_BUDGET_BYTES = 4_096;
const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Validate AHP observer configuration without opening a connection.
 * The returned view is safe to log: it contains no endpoint, local path,
 * transport, AbortSignal, or client identity.
 */
export function validateAhpObservationConfig(config = {}) {
  const normalized = normalizeConfig(config);
  return Object.freeze({
    ok: true,
    mode: 'local_no_spend_observation_only',
    transport_kind: normalized.transport_kind,
    endpoint_scheme: normalized.endpoint_scheme,
    endpoint_digest: normalized.endpoint_digest,
    channels: normalized.channel_evidence.map((entry) => ({ ...entry })),
    limits: { ...normalized.limits },
    supported_protocol_versions: [...AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS],
    authority: { ...AHP_OBSERVER_AUTHORITY_FLAGS },
  });
}

/**
 * Observe one bounded AHP 0.8.0 connection and write redacted local evidence.
 * No control-capable AHP client or transport is returned or exported.
 */
export async function observeAhp(config = {}) {
  const normalized = normalizeConfig(config);
  await assertSafeArtifactRoot(normalized.dir);

  const createdAt = nowIso(normalized.now);
  let state;
  try {
    state = await createRunState({
      dir: normalized.dir,
      profile: 'ahp_observer_local_no_spend',
      task: 'bounded observer-only Agent Host Protocol metadata capture',
      project_paths: {
        adapter: 'ahp_observer',
        endpoint_digest: normalized.endpoint_digest,
      },
      created_at: createdAt,
    });
  } catch {
    throw observerError('artifact_initialization_failed');
  }

  const controller = createStopController();
  const aggregate = createAggregate(state.run_id, normalized);
  aggregate.created_at = createdAt;
  let client = null;
  let guardedTransport = null;
  let timer = null;
  let abortHandler = null;
  let acceptingRecords = true;
  let writeTail = Promise.resolve();
  const drainTasks = [];
  const subscriptionCleanupChannels = new Set();

  const enqueueWrite = (operation) => {
    const result = writeTail.then(operation);
    writeTail = result.catch(() => {});
    return result;
  };

  const appendRecord = (record, severity = 'info', onCommit = null, prepare = null) => {
    if (!acceptingRecords) return Promise.resolve(false);
    return enqueueWrite(async () => {
      if (!acceptingRecords || controller.stopped) return false;
      if (aggregate.persisted_event_count >= normalized.effective_event_limit) {
        controller.stop(normalized.event_limit_reason, 'partial');
        return false;
      }
      const eventCreatedAt = nowIso(normalized.now);
      const prepared = prepare?.(record) || {};
      const acceptedSeverity = prepared.severity || severity;
      const eventData = {
        observation_kind: record.observation_kind,
        protocol: 'ahp',
        protocol_version: '0.8.0',
        evidence: record,
        authority: AHP_OBSERVER_AUTHORITY_FLAGS,
      };
      if (Buffer.byteLength(JSON.stringify(eventData), 'utf8') > EVENT_BUDGET_BYTES) {
        controller.stop('artifact_limit', 'blocked');
        return false;
      }
      await appendRunEvent(normalized.dir, state, {
        type: 'adapter_observation',
        severity: acceptedSeverity,
        summary: summaryForRecord(record),
        data: eventData,
        created_at: eventCreatedAt,
      });
      onCommit?.(prepared);
      aggregate.persisted_event_count += 1;
      trackPersistedRecord(aggregate, record);
      if (aggregate.persisted_event_count >= normalized.effective_event_limit) {
        controller.stop(normalized.event_limit_reason, 'partial');
      }
      return true;
    });
  };

  await enqueueWrite(() => appendRunEvent(normalized.dir, state, {
    type: 'adapter_observation',
    summary: 'AHP observer started within a bounded local-only authority envelope',
    data: {
      observation_kind: 'lifecycle',
      phase: 'started',
      endpoint_digest: normalized.endpoint_digest,
      channel_count: normalized.channels.length,
      limits: normalized.limits,
      authority: AHP_OBSERVER_AUTHORITY_FLAGS,
    },
    created_at: createdAt,
  }));

  timer = setTimeout(() => controller.stop('duration_limit', 'completed'), normalized.limits.duration_ms);
  if (normalized.signal) {
    abortHandler = () => controller.stop('cancelled', 'cancelled');
    if (normalized.signal.aborted) abortHandler();
    else normalized.signal.addEventListener('abort', abortHandler, { once: true });
  }

  try {
    if (!controller.stopped) {
      const baseTransport = normalized.transport || await createAhpLoopbackWebSocketTransport(
        normalized.endpoint,
        {
          maxFrameBytes: normalized.limits.max_frame_bytes,
          maxBufferedFrames: Math.min(64, normalized.effective_event_limit + normalized.channels.length + 4),
          maxBufferedBytes: Math.min(normalized.limits.max_frame_bytes * 4, 4_194_304),
          connectTimeoutMs: Math.min(normalized.limits.request_timeout_ms, normalized.limits.duration_ms),
          signal: normalized.signal,
        },
      );
      if (controller.stopped) {
        const closed = await settleWithin(
          Promise.resolve().then(() => baseTransport.close()),
          Math.max(50, Math.min(250, normalized.limits.request_timeout_ms)),
        );
        if (!closed) addWarning(aggregate, 'transport_close_timeout');
        throw observerError('transport_closed');
      }
      guardedTransport = createObserverTransport(baseTransport, {
        maxFrameBytes: normalized.limits.max_frame_bytes,
        channels: normalized.channels,
        onInbound: async (message, frameBytes, requestContext) => {
          if (controller.stopped || !acceptingRecords) return;
          await handleInboundMessage(
            message,
            frameBytes,
            aggregate,
            appendRecord,
            controller,
            requestContext,
            subscriptionCleanupChannels,
          );
        },
        onClosed: () => {
          aggregate.transport_closed = true;
          if (aggregate.observation_ready) controller.stop('transport_closed', 'completed');
        },
        onFailure: (code) => {
          addWarning(aggregate, code);
          controller.stop(code, 'blocked');
        },
      });
      client = new AhpClient(guardedTransport, {
        requestTimeoutMs: normalized.limits.request_timeout_ms,
        subscriptionBuffer: 1,
      });
      markChannelPending(aggregate, 'ahp-root://');
      client.connect();

      const rootSubscription = client.attachSubscription('ahp-root://');
      drainTasks.push(drainSubscription(rootSubscription));
      const initializeOutcome = await operationOrStop(client.initialize({
        clientId: stableId('ahp_observer', state.run_id),
        protocolVersions: AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS,
        initialSubscriptions: ['ahp-root://'],
      }), controller);

      if (initializeOutcome.error) {
        controller.stop(classifyRuntimeError(initializeOutcome.error, 'initialize_failed'), 'blocked');
      } else if (!initializeOutcome.stopped) {
        const result = initializeOutcome.value;
        if (!result || result.protocolVersion !== '0.8.0' || aggregate.negotiated_version !== '0.8.0') {
          controller.stop('unsupported_protocol_version', 'blocked');
        } else if (!isSafeSequence(result.serverSeq) || aggregate.initialize_server_seq !== result.serverSeq) {
          controller.stop('malformed_initialize_result', 'blocked');
        } else {
          aggregate.initialize_completed = true;
        }
      }

      for (const channel of normalized.channels.slice(1)) {
        if (controller.stopped) break;
        markChannelPending(aggregate, channel);
        subscriptionCleanupChannels.add(channel);
        const subscribeOutcome = await operationOrStop(client.subscribe(channel), controller);
        if (subscribeOutcome.error) {
          controller.stop(classifyRuntimeError(subscribeOutcome.error, 'subscribe_failed'), 'blocked');
          break;
        }
        if (subscribeOutcome.stopped) break;
        drainTasks.push(drainSubscription(subscribeOutcome.value.subscription));
        if (!subscribeOutcome.value.result?.snapshot
          || subscribeOutcome.value.result.snapshot.resource !== channel) {
          controller.stop('malformed_snapshot', 'blocked');
          break;
        }
      }
      const allChannelsReady = [...aggregate.channel_lifecycle.values()]
        .every((status) => status === 'ready');
      if (!controller.stopped && aggregate.negotiated_version && allChannelsReady) {
        aggregate.observation_ready = true;
        if (aggregate.transport_closed) controller.stop('transport_closed', 'completed');
      } else if (!controller.stopped) {
        controller.stop('subscribe_failed', 'partial');
      }
    }

    if (!controller.stopped) await controller.promise;
  } catch (error) {
    controller.stop(classifyRuntimeError(error, 'observer_runtime_error'), 'blocked');
  } finally {
    if (timer) clearTimeout(timer);
    if (abortHandler) normalized.signal?.removeEventListener('abort', abortHandler);
    acceptingRecords = false;
    const pendingWrites = writeTail;
    const cleanupTimeoutMs = Math.max(50, Math.min(250, normalized.limits.request_timeout_ms));
    const shutdownReserveMs = Math.max(25, Math.floor(cleanupTimeoutMs / 2));
    const unsubscribeTimeoutMs = cleanupTimeoutMs - shutdownReserveMs;
    const cleanupStartedAt = Date.now();
    const unsubscribeSettled = await settleWithin(
      releaseObserverSubscriptions(client, guardedTransport, subscriptionCleanupChannels),
      unsubscribeTimeoutMs,
    );
    if (!unsubscribeSettled) addWarning(aggregate, 'unsubscribe_cleanup_incomplete');
    const shutdownTimeoutMs = Math.max(
      shutdownReserveMs,
      cleanupTimeoutMs - (Date.now() - cleanupStartedAt),
    );
    const shutdown = Promise.allSettled([
      Promise.resolve().then(() => client?.shutdown()),
      Promise.resolve().then(() => guardedTransport?.close()),
    ]);
    const cleanupSettled = await settleWithin(
      Promise.allSettled([shutdown, ...drainTasks]),
      shutdownTimeoutMs,
    );
    if (!cleanupSettled) addWarning(aggregate, 'transport_close_timeout');
    await pendingWrites;
  }

  const stop = { ...(controller.value || { reason: 'observer_runtime_error', status: 'blocked' }) };
  if (stop.status === 'partial' && !aggregate.negotiated_version) {
    stop.reason = 'initialize_failed';
    stop.status = 'blocked';
  } else if (stop.status === 'completed' && !aggregate.observation_ready) {
    if (!aggregate.initialize_completed) {
      stop.reason = 'initialize_failed';
      stop.status = 'blocked';
    } else {
      stop.reason = 'subscribe_failed';
      stop.status = 'partial';
    }
  }
  aggregate.status = stop.status;
  aggregate.termination_reason = stop.reason;
  aggregate.completed_at = nowIso(normalized.now);

  await enqueueWrite(() => appendRunEvent(normalized.dir, state, {
    type: 'adapter_observation',
    severity: stop.status === 'blocked' ? 'blocked' : stop.status === 'partial' ? 'warning' : 'info',
    summary: 'AHP observer stopped and sealed its local evidence',
    data: {
      observation_kind: 'lifecycle',
      phase: 'completed',
      status: stop.status,
      termination_reason: stop.reason,
      authority: AHP_OBSERVER_AUTHORITY_FLAGS,
    },
    created_at: aggregate.completed_at,
  }));

  const summary = buildSummary(aggregate, normalized);
  const receipt = buildLocalReceipt(summary);
  const markdown = buildSummaryMarkdown(summary);
  await writeRunArtifact(normalized.dir, state, 'summary.json', summary);
  await writeTextRunArtifact(normalized.dir, state, 'summary.md', markdown);
  await writeRunArtifact(normalized.dir, state, 'local-receipt.json', receipt);
  await completeRunState(normalized.dir, state, stop.status === 'completed' ? 'passed' : 'blocked', {
    completed_at: aggregate.completed_at,
  });

  const manifest = await buildManifest(normalized.dir, state, summary);
  await writeRunArtifact(normalized.dir, state, 'manifest.json', manifest);
  const totalBytes = await aggregateRunBytes(normalized.dir, state.run_id);
  if (totalBytes > normalized.limits.max_artifact_bytes) {
    throw observerError('artifact_limit_invariant_failed');
  }

  return Object.freeze({
    status: summary.status,
    termination_reason: summary.termination_reason,
    observation_id: summary.observation_id,
    output_digest: summary.output_digest,
    run_path: `.agoragentic/runs/${state.run_id}`,
    artifacts: Object.freeze({
      state: 'state.json',
      events: 'events.jsonl',
      summary: 'summary.json',
      summary_markdown: 'summary.md',
      local_receipt: 'local-receipt.json',
      manifest: 'manifest.json',
    }),
    authority: AHP_OBSERVER_AUTHORITY_FLAGS,
  });
}

function normalizeConfig(config) {
  if (!isPlainRecord(config)) throw observerError('invalid_config');
  for (const key of Object.keys(config)) {
    if (!ALLOWED_CONFIG_KEYS.has(key)) throw observerError('unsupported_config_key');
  }
  if (config.endpoint !== undefined && config.transport !== undefined) {
    throw observerError('endpoint_transport_mutually_exclusive');
  }
  if (config.endpoint === undefined && config.transport === undefined) {
    throw observerError('endpoint_or_transport_required');
  }
  if (config.transport !== undefined && !isTransport(config.transport)) {
    throw observerError('invalid_transport');
  }
  if (config.signal !== undefined && !isAbortSignal(config.signal)) {
    throw observerError('invalid_abort_signal');
  }
  if (config.now !== undefined && typeof config.now !== 'function') {
    throw observerError('invalid_clock');
  }
  if (config.dir !== undefined
    && (typeof config.dir !== 'string'
      || config.dir.length === 0
      || config.dir.length > 4_096
      || /[\u0000-\u001f\u007f]/.test(config.dir))) {
    throw observerError('invalid_output_directory');
  }

  const channels = validateChannels(config.channels ?? ['ahp-root://']);
  const durationMs = boundedInteger(config.duration_ms, DEFAULTS.duration_ms, ...LIMITS.duration_ms, 'invalid_duration_limit');
  const maxEvents = boundedInteger(config.max_events, DEFAULTS.max_events, ...LIMITS.max_events, 'invalid_event_limit');
  const maxFrameBytes = boundedInteger(config.max_frame_bytes, DEFAULTS.max_frame_bytes, ...LIMITS.max_frame_bytes, 'invalid_frame_limit');
  const maxArtifactBytes = boundedInteger(config.max_artifact_bytes, DEFAULTS.max_artifact_bytes, ...LIMITS.max_artifact_bytes, 'invalid_artifact_limit');
  const requestTimeoutMs = boundedInteger(config.request_timeout_ms, DEFAULTS.request_timeout_ms, ...LIMITS.request_timeout_ms, 'invalid_request_timeout');
  if (requestTimeoutMs > durationMs) throw observerError('request_timeout_exceeds_duration');

  const capacity = Math.max(1, Math.floor((maxArtifactBytes - ARTIFACT_RESERVE_BYTES) / EVENT_BUDGET_BYTES) - 2);
  const effectiveEventLimit = Math.min(maxEvents, capacity);
  const endpoint = config.endpoint === undefined ? null : validateEndpoint(config.endpoint);
  const endpointDigest = endpoint
    ? stableHash(`ahp_endpoint:${endpoint.toString()}`)
    : stableHash('ahp_transport:injected');

  return {
    dir: path.resolve(config.dir ?? process.cwd()),
    endpoint: endpoint?.toString() ?? null,
    endpoint_scheme: endpoint ? endpoint.protocol.slice(0, -1) : 'injected',
    endpoint_digest: endpointDigest,
    transport: config.transport ?? null,
    transport_kind: endpoint ? 'loopback_websocket' : 'injected',
    channels,
    channel_evidence: channels.map(channelEvidence),
    signal: config.signal ?? null,
    now: config.now ?? (() => new Date().toISOString()),
    effective_event_limit: effectiveEventLimit,
    event_limit_reason: effectiveEventLimit < maxEvents ? 'artifact_limit' : 'event_limit',
    limits: Object.freeze({
      duration_ms: durationMs,
      max_events: maxEvents,
      max_frame_bytes: maxFrameBytes,
      max_artifact_bytes: maxArtifactBytes,
      request_timeout_ms: requestTimeoutMs,
      max_channels: LIMITS.max_channels,
    }),
  };
}

function validateEndpoint(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw observerError('invalid_endpoint');
  }
  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw observerError('invalid_endpoint');
  }
  if (!['ws:', 'wss:'].includes(endpoint.protocol)) throw observerError('unsupported_endpoint_scheme');
  if (endpoint.username || endpoint.password) throw observerError('endpoint_credentials_forbidden');
  if (endpoint.search || endpoint.hash) throw observerError('endpoint_query_or_fragment_forbidden');
  const hostname = endpoint.hostname.toLowerCase();
  if (!['localhost', '127.0.0.1', '[::1]'].includes(hostname)) throw observerError('remote_endpoint_forbidden');
  return endpoint;
}

function validateChannels(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > LIMITS.max_channels) {
    throw observerError('invalid_channels');
  }
  const channels = value.map((channel) => {
    if (typeof channel !== 'string' || Buffer.byteLength(channel, 'utf8') > LIMITS.max_channel_bytes) {
      throw observerError('invalid_channel');
    }
    if (channel === 'ahp-root://') return channel;
    const match = /^(ahp-session|ahp-chat):\/([^/?#\\]+)$/.exec(channel);
    if (!match) throw observerError('unsupported_channel');
    if (/%(?:2f|5c)/i.test(match[2])) throw observerError('unsupported_channel');
    let decoded;
    try {
      decoded = decodeURIComponent(match[2]);
    } catch {
      throw observerError('invalid_channel');
    }
    if (!decoded || /[/\\\u0000-\u001f\u007f]/.test(decoded)) throw observerError('unsupported_channel');
    return channel;
  });
  if (channels[0] !== 'ahp-root://' || channels.filter((entry) => entry === 'ahp-root://').length !== 1) {
    throw observerError('root_channel_required_first');
  }
  if (new Set(channels).size !== channels.length) throw observerError('duplicate_channel');
  return Object.freeze(channels);
}

function createObserverTransport(inner, options) {
  let initialized = false;
  let closed = false;
  let failed = false;
  let remoteClosed = false;
  let unsubscribeAttemptCount = 0;
  let outboundFailureCount = 0;
  const pendingRequests = new Map();
  const inFlightSends = new Set();
  return Object.freeze({
    async send(value) {
      if (closed || failed || remoteClosed) throw observerError('transport_closed');
      let message;
      try {
        message = typeof value === 'string' ? JSON.parse(value) : value;
      } catch {
        throw observerError('outbound_malformed');
      }
      assertOutboundMessage(message, options.channels, initialized);
      if (message.method === 'initialize') initialized = true;
      if (Number.isSafeInteger(message.id) && ['initialize', 'subscribe'].includes(message.method)) {
        pendingRequests.set(message.id, {
          method: message.method,
          channel: message.params?.channel,
        });
      }
      if (message.method === 'unsubscribe') unsubscribeAttemptCount += 1;
      try {
        const sending = Promise.resolve(inner.send(value));
        inFlightSends.add(sending);
        try {
          return await sending;
        } finally {
          inFlightSends.delete(sending);
        }
      } catch (error) {
        failed = true;
        outboundFailureCount += 1;
        if (Number.isSafeInteger(message.id)) pendingRequests.delete(message.id);
        const code = classifyRuntimeError(error, 'transport_error');
        if (!closed) options.onFailure(code);
        throw observerError(code);
      }
    },

    async recv() {
      if (closed) return null;
      let frame;
      try {
        frame = await inner.recv();
      } catch (error) {
        failed = true;
        const code = classifyRuntimeError(error, 'transport_error');
        options.onFailure(code);
        throw observerError(code);
      }
      if (frame === null) {
        remoteClosed = true;
        options.onClosed();
        return null;
      }
      try {
        const { message, bytes } = decodeBoundedFrame(frame, options.maxFrameBytes);
        const requestContext = !Object.hasOwn(message, 'method') && Number.isSafeInteger(message.id)
          ? pendingRequests.get(message.id) || null
          : null;
        await options.onInbound(message, bytes, requestContext);
        if (requestContext) pendingRequests.delete(message.id);
        return { kind: 'parsed', message };
      } catch (error) {
        failed = true;
        const code = classifyRuntimeError(error, 'observer_runtime_error');
        options.onFailure(code);
        try { await inner.close(); } catch { /* bounded failure already recorded */ }
        throw observerError(code);
      }
    },

    async close() {
      if (closed) return;
      closed = true;
      await inner.close();
    },

    isOpen() {
      return !closed && !failed && !remoteClosed;
    },

    outboundFailureCount() {
      return outboundFailureCount;
    },

    unsubscribeAttemptCount() {
      return unsubscribeAttemptCount;
    },

    async settleOutbound() {
      const outcomes = await Promise.allSettled([...inFlightSends]);
      return outcomes.every((outcome) => outcome.status === 'fulfilled');
    },
  });
}

function assertOutboundMessage(message, channels, initialized) {
  if (!isPlainRecord(message) || message.jsonrpc !== '2.0') throw observerError('outbound_malformed');
  if (!Object.hasOwn(message, 'method')) {
    if (!Number.isSafeInteger(message.id) || !isPlainRecord(message.error) || message.error.code !== -32601 || Object.hasOwn(message, 'result')) {
      throw observerError('outbound_response_forbidden');
    }
    return;
  }
  if (typeof message.method !== 'string' || !ALLOWED_OUTBOUND_METHODS.has(message.method)) {
    throw observerError('outbound_method_forbidden');
  }
  if (message.method === 'initialize') {
    if (initialized || !Number.isSafeInteger(message.id)) throw observerError('initialize_order_violation');
    const params = message.params;
    if (!isPlainRecord(params)
      || params.channel !== 'ahp-root://'
      || !Array.isArray(params.protocolVersions)
      || params.protocolVersions.length !== 1
      || params.protocolVersions[0] !== '0.8.0'
      || typeof params.clientId !== 'string'
      || params.clientId.length > 128
      || Object.hasOwn(params, 'capabilities')
      || Object.hasOwn(params, 'locale')) {
      throw observerError('unsafe_initialize_request');
    }
    if (!Array.isArray(params.initialSubscriptions)
      || params.initialSubscriptions.length !== 1
      || params.initialSubscriptions[0] !== 'ahp-root://') {
      throw observerError('unsafe_initial_subscriptions');
    }
    return;
  }
  if (!initialized) throw observerError('initialize_order_violation');
  const channel = message.params?.channel;
  if (!channels.includes(channel)) throw observerError('outbound_channel_forbidden');
  if (message.method === 'subscribe' && !Number.isSafeInteger(message.id)) throw observerError('outbound_malformed');
  if (message.method === 'unsubscribe' && Object.hasOwn(message, 'id')) throw observerError('outbound_malformed');
}

function decodeBoundedFrame(frame, maxFrameBytes) {
  if (!isPlainRecord(frame) || !['text', 'binary', 'parsed'].includes(frame.kind)) {
    throw observerError('malformed_frame');
  }
  let message;
  let bytes;
  if (frame.kind === 'text') {
    if (typeof frame.text !== 'string') throw observerError('malformed_frame');
    bytes = Buffer.byteLength(frame.text, 'utf8');
    if (bytes > maxFrameBytes) throw observerError('frame_limit');
    try { message = JSON.parse(frame.text); } catch { throw observerError('malformed_frame'); }
  } else if (frame.kind === 'binary') {
    if (!(frame.data instanceof Uint8Array)) throw observerError('malformed_frame');
    bytes = frame.data.byteLength;
    if (bytes > maxFrameBytes) throw observerError('frame_limit');
    let text;
    try { text = utf8.decode(frame.data); } catch { throw observerError('invalid_utf8'); }
    try { message = JSON.parse(text); } catch { throw observerError('malformed_frame'); }
  } else {
    try {
      const serialized = JSON.stringify(frame.message);
      bytes = Buffer.byteLength(serialized, 'utf8');
      if (bytes > maxFrameBytes) throw observerError('frame_limit');
      message = frame.message;
    } catch (error) {
      if (error?.code === 'frame_limit') throw error;
      throw observerError('malformed_frame');
    }
  }
  validateInboundMessage(message);
  return { message, bytes };
}

function validateInboundMessage(message) {
  if (!isPlainRecord(message) || message.jsonrpc !== '2.0') throw observerError('malformed_frame');
  const shape = inspectStructure(message);
  if (!shape.ok) throw observerError('malformed_frame');
  const hasMethod = Object.hasOwn(message, 'method');
  if (hasMethod) {
    if (Object.hasOwn(message, 'result') || Object.hasOwn(message, 'error')) {
      throw observerError('malformed_frame');
    }
    if (typeof message.method !== 'string' || message.method.length === 0 || message.method.length > 128) {
      throw observerError('malformed_frame');
    }
    if (Object.hasOwn(message, 'id') && !Number.isSafeInteger(message.id)) throw observerError('malformed_frame');
    if (Object.hasOwn(message, 'params') && !isPlainRecord(message.params)) throw observerError('malformed_frame');
    return;
  }
  if (Object.hasOwn(message, 'params')) throw observerError('malformed_frame');
  if (!Number.isSafeInteger(message.id)) throw observerError('malformed_frame');
  const hasResult = Object.hasOwn(message, 'result');
  const hasError = Object.hasOwn(message, 'error');
  if (hasResult === hasError) throw observerError('malformed_frame');
  if (hasError && (!isPlainRecord(message.error) || !Number.isSafeInteger(message.error.code) || typeof message.error.message !== 'string')) {
    throw observerError('malformed_frame');
  }
}

async function handleInboundMessage(
  message,
  frameBytes,
  aggregate,
  appendRecord,
  controller,
  requestContext,
  subscriptionCleanupChannels,
) {
  if (!Object.hasOwn(message, 'method')) {
    if (requestContext && Object.hasOwn(message, 'result')) {
      await handleObservedResponse(
        message.result,
        requestContext,
        aggregate,
        appendRecord,
        controller,
        subscriptionCleanupChannels,
      );
    }
    return;
  }
  if (message.method === 'action') {
    const record = normalizeAction(message.params, frameBytes, aggregate);
    if (!record) {
      addWarning(aggregate, 'malformed_action');
      controller.stop('malformed_action', 'blocked');
      return;
    }
    const channelState = aggregate.channel_lifecycle.get(record.channel.ref_digest);
    const snapshotWatermark = aggregate.snapshot_watermarks.get(record.channel.ref_digest);
    const equalityFingerprint = ephemeralFingerprint(message.params, aggregate.fingerprint_key);
    if (!['pending', 'ready'].includes(channelState)) {
      addWarning(aggregate, 'snapshot_required_before_action');
      controller.stop('malformed_action', 'blocked');
      return;
    }
    if (channelState === 'ready' && (snapshotWatermark === undefined || record.server_seq <= snapshotWatermark)) {
      addWarning(aggregate, 'snapshot_watermark_violation');
      controller.stop('malformed_action', 'blocked');
      return;
    }
    if (aggregate.pending_phase_digest !== null) {
      queuePendingRecord(aggregate, { kind: 'action', record, equalityFingerprint }, controller);
      return;
    }
    await persistActionRecord(record, equalityFingerprint, aggregate, appendRecord);
    return;
  }

  if (Object.hasOwn(message, 'id')) {
    if (aggregate.channel_lifecycle.get(aggregate.root_channel_digest) !== 'ready') {
      addWarning(aggregate, 'protocol_order_violation');
      controller.stop('malformed_frame', 'blocked');
      return;
    }
    const record = normalizeServerRequest(message, frameBytes, aggregate);
    const channelState = record.configured_channel
      ? aggregate.channel_lifecycle.get(record.channel.ref_digest)
      : 'unconfigured';
    if (channelState === 'configured') {
      addWarning(aggregate, 'snapshot_required_before_event');
      controller.stop('malformed_frame', 'blocked');
      return;
    }
    if (aggregate.pending_phase_digest !== null) {
      queuePendingRecord(aggregate, { kind: 'server_request', record }, controller);
      return;
    }
    await persistServerRequestRecord(record, aggregate, appendRecord);
    return;
  }

  const record = normalizeNotification(message, frameBytes, aggregate);
  if (!record) {
    addWarning(aggregate, 'malformed_notification');
    controller.stop('malformed_frame', 'blocked');
    return;
  }
  const channelState = record.configured_channel
    ? aggregate.channel_lifecycle.get(record.channel.ref_digest)
    : 'unconfigured';
  if (channelState === 'configured'
    || (channelState === 'unconfigured'
      && aggregate.channel_lifecycle.get(aggregate.root_channel_digest) !== 'ready')) {
    addWarning(aggregate, 'snapshot_required_before_event');
    controller.stop('malformed_frame', 'blocked');
    return;
  }
  if (aggregate.pending_phase_digest !== null) {
    queuePendingRecord(aggregate, { kind: 'notification', record }, controller);
    return;
  }
  await persistNotificationRecord(record, aggregate, appendRecord);
}

function queuePendingRecord(aggregate, entry, controller) {
  if (aggregate.pending_phase_digest === null
    || aggregate.pending_records.length >= aggregate.pending_record_limit) {
    addWarning(aggregate, 'pending_record_limit');
    controller.stop(aggregate.pending_record_limit_reason, 'partial');
    return false;
  }
  aggregate.pending_records.push(entry);
  return true;
}

async function persistNotificationRecord(record, aggregate, appendRecord) {
  const severity = record.notification_type.endsWith('_discarded') ? 'warning' : 'info';
  await appendRecord(record, severity, () => {
    aggregate.notification_count += 1;
    aggregate.redaction_count += sumCounts(record.redactions);
    if (record.notification_type === 'otlp_discarded') aggregate.otlp_discarded_count += 1;
    if (record.notification_type === 'unknown_discarded') aggregate.unknown_notification_count += 1;
  });
}

async function persistServerRequestRecord(record, aggregate, appendRecord) {
  await appendRecord(record, 'warning', () => {
    aggregate.server_request_count += 1;
  });
}

async function persistActionRecord(record, equalityFingerprint, aggregate, appendRecord) {
  await appendRecord(record, 'info', ({ outcome }) => {
    commitSequenceAggregate(aggregate, record, equalityFingerprint, outcome);
    if (outcome.classification === 'duplicate') aggregate.duplicate_count += 1;
    else aggregate.action_count += 1;
    if (outcome.classification === 'gap_observed') {
      aggregate.sequence_gap_count += 1;
      if (aggregate.sequence_gaps.length < 32) {
        aggregate.sequence_gaps.push({
          after: outcome.after,
          before: outcome.before,
          observed_discontinuity: outcome.before - outcome.after - 1,
        });
      }
      addWarning(aggregate, 'sequence_gap_observed');
    } else if (outcome.classification === 'collision') {
      aggregate.sequence_collision_count += 1;
      addWarning(aggregate, 'sequence_collision_observed');
    } else if (outcome.classification === 'out_of_order') {
      aggregate.out_of_order_count += 1;
      addWarning(aggregate, 'out_of_order_observed');
    }
    if (record.origin === 'client') updateClientSequenceAggregate(aggregate, record);
    aggregate.redaction_count += sumCounts(record.redactions);
  }, () => {
    const outcome = classifySequenceAggregate(aggregate, record, equalityFingerprint);
    record.sequence_classification = outcome.classification;
    return {
      outcome,
      severity: outcome.classification === 'accepted' || outcome.classification === 'duplicate'
        ? 'info'
        : 'warning',
    };
  });
}

async function handleObservedResponse(
  result,
  requestContext,
  aggregate,
  appendRecord,
  controller,
  subscriptionCleanupChannels,
) {
  if (!isPlainRecord(result)) {
    controller.stop(requestContext.method === 'initialize' ? 'malformed_initialize_result' : 'malformed_snapshot', 'blocked');
    return;
  }
  if (requestContext.method === 'initialize') {
    if (result.protocolVersion !== '0.8.0') {
      controller.stop('unsupported_protocol_version', 'blocked');
      return;
    }
    if (!isSafeSequence(result.serverSeq)
      || !Array.isArray(result.snapshots)
      || result.snapshots.length !== 1
      || result.snapshots[0]?.resource !== 'ahp-root://') {
      controller.stop('malformed_initialize_result', 'blocked');
      return;
    }
    if (!isSafeSequence(result.snapshots[0].fromSeq)
      || result.snapshots[0].fromSeq > result.serverSeq) {
      controller.stop('malformed_snapshot', 'blocked');
      return;
    }
    const record = normalizeSnapshot(result.snapshots[0], aggregate);
    if (!record) {
      controller.stop('malformed_snapshot', 'blocked');
      return;
    }
    // Cleanup eligibility follows the validated wire response rather than the
    // later artifact commit, which can finish after the observation deadline.
    subscriptionCleanupChannels.add('ahp-root://');
    const accepted = await appendRecord(record, 'info', () => {
      aggregate.negotiated_version = result.protocolVersion;
      aggregate.initialize_server_seq = result.serverSeq;
      updateSnapshotAggregate(aggregate, record);
    });
    if (accepted) await activateSnapshotChannel(record, aggregate, appendRecord, controller);
    return;
  }
  if (requestContext.method === 'subscribe') {
    const snapshot = result.snapshot;
    if (!snapshot || snapshot.resource !== requestContext.channel) {
      controller.stop('malformed_snapshot', 'blocked');
      return;
    }
    const record = normalizeSnapshot(snapshot, aggregate);
    if (!record) {
      controller.stop('malformed_snapshot', 'blocked');
      return;
    }
    const accepted = await appendRecord(record, 'info', () => updateSnapshotAggregate(aggregate, record));
    if (accepted) await activateSnapshotChannel(record, aggregate, appendRecord, controller);
  }
}

async function activateSnapshotChannel(record, aggregate, appendRecord, controller) {
  const digest = record.channel.ref_digest;
  if (aggregate.pending_phase_digest !== digest) {
    controller.stop('malformed_snapshot', 'blocked');
    return;
  }
  const pending = aggregate.pending_records.splice(0);
  aggregate.pending_phase_digest = null;
  if (pending.some((entry) => entry.kind === 'action'
    && entry.record.channel.ref_digest === digest
    && entry.record.server_seq <= record.from_seq)) {
    addWarning(aggregate, 'snapshot_watermark_violation');
    controller.stop('malformed_action', 'blocked');
    return;
  }
  aggregate.channel_lifecycle.set(digest, 'ready');
  for (const entry of pending) {
    if (controller.stopped) break;
    if (entry.kind === 'action') {
      const watermark = aggregate.snapshot_watermarks.get(entry.record.channel.ref_digest);
      if (watermark === undefined || entry.record.server_seq <= watermark) {
        addWarning(aggregate, 'snapshot_watermark_violation');
        controller.stop('malformed_action', 'blocked');
        break;
      }
      await persistActionRecord(entry.record, entry.equalityFingerprint, aggregate, appendRecord);
    } else if (entry.kind === 'notification') {
      await persistNotificationRecord(entry.record, aggregate, appendRecord);
    } else {
      await persistServerRequestRecord(entry.record, aggregate, appendRecord);
    }
  }
}

function normalizeSnapshot(snapshot, aggregate) {
  if (!isPlainRecord(snapshot)
    || !aggregate.channels.includes(snapshot.resource)
    || !isSafeSequence(snapshot.fromSeq)
    || !isPlainRecord(snapshot.state)) return null;
  const channel = channelEvidence(snapshot.resource);
  const redactions = scanSensitiveShape(snapshot.state);
  const stateShape = safeShape(snapshot.state);
  const projection = {
    observation_kind: 'snapshot',
    channel,
    from_seq: snapshot.fromSeq,
    state_shape: stateShape,
    redactions,
  };
  return {
    ...projection,
    source_event_digest: stableHash(projection),
  };
}

function normalizeAction(params, frameBytes, aggregate) {
  if (!isPlainRecord(params)
    || !aggregate.channels.includes(params.channel)
    || !isPlainRecord(params.action)
    || !isSafeSequence(params.serverSeq)) return null;
  const actionType = safeActionType(params.action.type, params.channel);
  if (!actionType) return null;
  if (params.origin !== undefined && (!isPlainRecord(params.origin)
    || typeof params.origin.clientId !== 'string'
    || !isSafeSequence(params.origin.clientSeq))) return null;
  if (params.origin !== undefined && !CLIENT_ORIGIN_ACTION_TYPES.has(actionType)) return null;
  if (params.rejectionReason !== undefined
    && (typeof params.rejectionReason !== 'string' || params.origin === undefined)) return null;
  const channel = channelEvidence(params.channel);
  const redactions = scanSensitiveShape({
    action: params.action,
    rejectionReason: params.rejectionReason,
  });
  const references = extractReferenceDigests(params.action);
  const status = extractSafeStatus(params.action);
  const projection = {
    observation_kind: 'action',
    action_type: actionType,
    channel,
    server_seq: params.serverSeq,
    origin: params.origin ? 'client' : 'server',
    ...(params.origin ? {
      origin_client_digest: stableHash(`ahp_client:${params.origin.clientId}`),
      origin_client_seq: params.origin.clientSeq,
    } : {}),
    ...(status ? { status } : {}),
    references,
    payload_shape: safeShape(params.action),
    redactions,
    rejection_reason_present: typeof params.rejectionReason === 'string' && params.rejectionReason.length > 0,
  };
  return {
    ...projection,
    frame_bytes: frameBytes,
    source_event_digest: stableHash(projection),
  };
}

function normalizeNotification(message, frameBytes, aggregate) {
  const params = isPlainRecord(message.params) ? message.params : {};
  if (message.method.startsWith('root/') && params.channel !== 'ahp-root://') return null;
  const configured = typeof params.channel === 'string' && aggregate.channels.includes(params.channel);
  const channel = configured ? channelEvidence(params.channel) : unknownChannelEvidence(params.channel);
  const notificationType = OTLP_NOTIFICATIONS.has(message.method)
    ? 'otlp_discarded'
    : KNOWN_NOTIFICATIONS.get(message.method) || 'unknown_discarded';
  const redactions = scanSensitiveShape(params);
  const projection = {
    observation_kind: 'notification',
    notification_type: notificationType,
    channel,
    configured_channel: configured,
    payload_shape: safeShape(params),
    redactions,
  };
  return {
    ...projection,
    frame_bytes: frameBytes,
    source_event_digest: stableHash(projection),
  };
}

function normalizeServerRequest(message, frameBytes, aggregate) {
  const params = isPlainRecord(message.params) ? message.params : {};
  const configured = typeof params.channel === 'string' && aggregate.channels.includes(params.channel);
  const methodKnown = KNOWN_SERVER_REQUESTS.has(message.method);
  const redactions = scanSensitiveShape(params);
  const projection = {
    observation_kind: 'server_request_default_rejection',
    method: methodKnown ? message.method : 'unknown',
    ...(methodKnown ? {} : { method_digest: stableHash(`ahp_method:${message.method}`) }),
    channel: configured ? channelEvidence(params.channel) : unknownChannelEvidence(params.channel),
    configured_channel: configured,
    response_policy: 'method_not_found',
    payload_shape: safeShape(params),
    redactions,
  };
  return {
    ...projection,
    frame_bytes: frameBytes,
    source_event_digest: stableHash(projection),
  };
}

function createAggregate(observationId, normalized) {
  const channelLifecycle = new Map(normalized.channel_evidence.map((entry) => [entry.ref_digest, 'configured']));
  return {
    observation_id: observationId,
    created_at: null,
    completed_at: null,
    status: 'partial',
    termination_reason: 'observer_runtime_error',
    negotiated_version: null,
    initialize_server_seq: null,
    channels: normalized.channels,
    persisted_event_count: 0,
    snapshot_count: 0,
    action_count: 0,
    duplicate_count: 0,
    notification_count: 0,
    server_request_count: 0,
    redaction_count: 0,
    otlp_discarded_count: 0,
    unknown_notification_count: 0,
    sequence_gap_count: 0,
    sequence_collision_count: 0,
    out_of_order_count: 0,
    client_sequence_regression_count: 0,
    first_server_seq: null,
    last_server_seq: null,
    sequence_gaps: [],
    sequence_digests: new Map(),
    client_sequences: new Map(),
    snapshot_watermarks: new Map(),
    channel_lifecycle: channelLifecycle,
    root_channel_digest: normalized.channel_evidence[0].ref_digest,
    pending_phase_digest: null,
    pending_records: [],
    pending_record_limit: normalized.effective_event_limit,
    pending_record_limit_reason: normalized.event_limit_reason,
    fingerprint_key: crypto.randomBytes(32),
    source_event_digests: [],
    source_event_digest_count: 0,
    source_event_digests_truncated: false,
    source_event_stream_digest: stableHash('ahp_observer_event_stream_v1'),
    channel_counts: new Map(normalized.channel_evidence.map((entry) => [entry.ref_digest, {
      ...entry,
      snapshots: 0,
      actions: 0,
      notifications: 0,
      server_requests: 0,
      total: 0,
    }])),
    event_type_counts: new Map(),
    event_type_counts_truncated: false,
    transport_closed: false,
    initialize_completed: false,
    observation_ready: false,
    warnings: [],
  };
}

function markChannelPending(aggregate, channel) {
  const digest = channelEvidence(channel).ref_digest;
  if (aggregate.channel_lifecycle.get(digest) !== 'configured'
    || aggregate.pending_phase_digest !== null
    || aggregate.pending_records.length !== 0) {
    throw observerError('channel_lifecycle_violation');
  }
  aggregate.channel_lifecycle.set(digest, 'pending');
  aggregate.pending_phase_digest = digest;
}

function updateSnapshotAggregate(aggregate, record) {
  aggregate.snapshot_count += 1;
  aggregate.redaction_count += sumCounts(record.redactions);
  aggregate.snapshot_watermarks.set(record.channel.ref_digest, record.from_seq);
}

function trackPersistedRecord(aggregate, record) {
  if (typeof record.source_event_digest === 'string') {
    aggregate.source_event_digest_count += 1;
    aggregate.source_event_stream_digest = stableHash({
      previous: aggregate.source_event_stream_digest,
      source_event_digest: record.source_event_digest,
    });
    if (!aggregate.source_event_digests.includes(record.source_event_digest)) {
      if (aggregate.source_event_digests.length < 128) aggregate.source_event_digests.push(record.source_event_digest);
      else aggregate.source_event_digests_truncated = true;
    }
  }

  const channel = record.channel;
  if (channel && aggregate.channel_counts.has(channel.ref_digest)) {
    const counts = aggregate.channel_counts.get(channel.ref_digest);
    counts.total += 1;
    if (record.observation_kind === 'snapshot') counts.snapshots += 1;
    else if (record.observation_kind === 'action') counts.actions += 1;
    else if (record.observation_kind === 'notification') counts.notifications += 1;
    else if (record.observation_kind === 'server_request_default_rejection') counts.server_requests += 1;
  }

  const kind = record.observation_kind === 'server_request_default_rejection' ? 'server_request' : record.observation_kind;
  const eventType = record.observation_kind === 'action'
    ? record.action_type
    : record.observation_kind === 'notification'
      ? record.notification_type
      : record.observation_kind === 'server_request_default_rejection'
        ? record.method
        : 'snapshot';
  const key = `${kind}:${eventType}`;
  if (aggregate.event_type_counts.has(key)) {
    aggregate.event_type_counts.get(key).count += 1;
  } else if (aggregate.event_type_counts.size < 64) {
    aggregate.event_type_counts.set(key, { kind, event_type: eventType, count: 1 });
  } else {
    aggregate.event_type_counts_truncated = true;
  }
}

function classifySequenceAggregate(aggregate, record, equalityFingerprint) {
  const seq = record.server_seq;
  const prior = aggregate.sequence_digests.get(seq);
  if (prior?.equality_fingerprint === equalityFingerprint) return { classification: 'duplicate' };
  if (prior) return { classification: 'collision' };
  const priorLast = aggregate.last_server_seq;
  if (priorLast !== null && seq < priorLast) return { classification: 'out_of_order' };
  if (priorLast !== null && seq > priorLast + 1) return { classification: 'gap_observed', after: priorLast, before: seq };
  return { classification: 'accepted' };
}

function commitSequenceAggregate(aggregate, record, equalityFingerprint, outcome) {
  if (outcome.classification === 'duplicate' || outcome.classification === 'collision') return;
  const seq = record.server_seq;
  aggregate.sequence_digests.set(seq, {
    equality_fingerprint: equalityFingerprint,
    source_event_digest: record.source_event_digest,
  });
  aggregate.first_server_seq = aggregate.first_server_seq === null ? seq : Math.min(aggregate.first_server_seq, seq);
  aggregate.last_server_seq = aggregate.last_server_seq === null ? seq : Math.max(aggregate.last_server_seq, seq);
}

function updateClientSequenceAggregate(aggregate, record) {
  const prior = aggregate.client_sequences.get(record.origin_client_digest);
  if (prior !== undefined && record.origin_client_seq < prior) {
    aggregate.client_sequence_regression_count += 1;
    addWarning(aggregate, 'client_sequence_regression_observed');
  }
  if (prior === undefined || record.origin_client_seq > prior) {
    aggregate.client_sequences.set(record.origin_client_digest, record.origin_client_seq);
  }
}

function ephemeralFingerprint(value, key) {
  return crypto.createHmac('sha256', key).update(stableCanonicalJson(value)).digest('hex');
}

function stableCanonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCanonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableCanonicalJson(value[key])}`).join(',')}}`;
}

function buildSummary(aggregate, normalized) {
  const base = {
    schema: AHP_OBSERVATION_SCHEMA,
    observation_id: aggregate.observation_id,
    adapter: 'ahp_observer',
    adapter_version: AHP_OBSERVER_ADAPTER_VERSION,
    created_at: aggregate.created_at || aggregate.completed_at,
    completed_at: aggregate.completed_at,
    status: aggregate.status,
    termination_reason: aggregate.termination_reason,
    mode: 'local_no_spend_observation_only',
    protocol: {
      name: 'Agent Host Protocol',
      package: '@microsoft/agent-host-protocol',
      pinned_version: '0.8.0',
      supported_versions: [...AHP_OBSERVER_SUPPORTED_PROTOCOL_VERSIONS],
      negotiated_version: aggregate.negotiated_version,
    },
    source: {
      transport_kind: normalized.transport_kind,
      endpoint_scheme: normalized.endpoint_scheme,
      endpoint_digest: normalized.endpoint_digest,
    },
    scope: {
      channels: normalized.channel_evidence,
      channel_count: normalized.channels.length,
    },
    limits: normalized.limits,
    counts: {
      persisted_events: aggregate.persisted_event_count,
      snapshots: aggregate.snapshot_count,
      unique_actions: aggregate.action_count,
      duplicates: aggregate.duplicate_count,
      notifications: aggregate.notification_count,
      server_requests_default_rejection_selected: aggregate.server_request_count,
      redactions: aggregate.redaction_count,
      discarded_otlp_notifications: aggregate.otlp_discarded_count,
      discarded_unknown_notifications: aggregate.unknown_notification_count,
      sequence_gaps_observed: aggregate.sequence_gap_count,
      sequence_collisions_observed: aggregate.sequence_collision_count,
      out_of_order_observed: aggregate.out_of_order_count,
      client_sequence_regressions_observed: aggregate.client_sequence_regression_count,
      by_channel: [...aggregate.channel_counts.values()]
        .sort((left, right) => left.ref_digest.localeCompare(right.ref_digest)),
      by_event_type: [...aggregate.event_type_counts.values()]
        .sort((left, right) => `${left.kind}:${left.event_type}`.localeCompare(`${right.kind}:${right.event_type}`)),
      event_type_counts_truncated: aggregate.event_type_counts_truncated,
    },
    sequence: {
      initialize_server_seq: aggregate.initialize_server_seq,
      first_observed_action_seq: aggregate.first_server_seq,
      last_observed_action_seq: aggregate.last_server_seq,
      observed_discontinuities: aggregate.sequence_gaps,
      loss_proven: false,
      receipt_claimed: false,
    },
    warnings: [...aggregate.warnings],
    source_event_digests: [...aggregate.source_event_digests],
    source_event_digest_count: aggregate.source_event_digest_count,
    source_event_digests_truncated: aggregate.source_event_digests_truncated,
    source_event_stream_digest: aggregate.source_event_stream_digest,
    claims: {
      observer_only: true,
      governed_action_execution: false,
      sequence_is_receipt: false,
      sequence_gap_proves_loss: false,
      telemetry_is_audit_log: false,
      certification_claimed: false,
    },
    authority: { ...AHP_OBSERVER_AUTHORITY_FLAGS },
  };
  const {
    observation_id: _observationId,
    created_at: _createdAt,
    completed_at: _completedAt,
    ...deterministicContent
  } = base;
  return { ...base, output_digest: stableHash(deterministicContent) };
}

function buildLocalReceipt(summary) {
  return {
    schema: 'agoragentic.harness.local-receipt.v1',
    receipt_id: stableId('local_receipt', `${summary.observation_id}:${summary.output_digest}`),
    proof_id: summary.observation_id,
    created_at: summary.completed_at,
    mode: 'local_no_spend_receipt',
    status: summary.status === 'completed' ? 'recorded' : 'blocked',
    settlement_status: 'not_settlement_receipt',
    spend: {
      amount_usdc: 0,
      settlement_network: 'none',
      settlement_status: 'not_applicable',
    },
    evidence: {
      agent_name: 'AHP host identity redacted',
      primary_goal: 'observer-only AHP metadata capture',
      proof_status: summary.status,
      local_artifacts: ['events.jsonl', 'summary.json', 'summary.md', 'manifest.json'],
      observation_digest: summary.output_digest,
      durable_local_evidence_only: true,
      protocol_sequence_is_not_receipt: true,
      telemetry_is_not_audit_log: true,
    },
    receipt_boundary: {
      router_invocation_created: false,
      x402_payment_attempted: false,
      marketplace_published: false,
      hosted_runtime_provisioned: false,
      memory_written: false,
      ...AHP_OBSERVER_AUTHORITY_FLAGS,
    },
  };
}

function buildSummaryMarkdown(summary) {
  return [
    '# AHP observer summary',
    '',
    `- Observation: ${summary.observation_id}`,
    `- Status: ${summary.status}`,
    `- Termination: ${summary.termination_reason}`,
    `- Protocol: ${summary.protocol.negotiated_version || 'not negotiated'} (supported: 0.8.0 only)`,
    `- Snapshots: ${summary.counts.snapshots}`,
    `- Unique actions: ${summary.counts.unique_actions}`,
    `- Duplicate actions: ${summary.counts.duplicates}`,
    `- Redacted fields: ${summary.counts.redactions}`,
    '',
    'This is bounded observer-only local evidence. It did not dispatch, control, authenticate, spend, settle, publish, or mutate trust.',
    'AHP serverSeq values are correlation metadata, not Agoragentic receipts, and observed gaps do not prove message loss.',
    'OTLP notification metadata is not a durable audit ledger; payload bodies are discarded.',
    '',
  ].join('\n');
}

async function buildManifest(dir, state, summary) {
  const files = ['events.jsonl', 'summary.json', 'summary.md', 'local-receipt.json'];
  const artifacts = [];
  for (const file of files) {
    const bytes = await fs.readFile(path.join(runDir(dir, state.run_id), file));
    artifacts.push({
      file,
      bytes: bytes.byteLength,
      sha256: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`,
    });
  }
  const base = {
    schema: 'agoragentic.harness.ahp-observation-manifest.v1',
    observation_id: state.run_id,
    adapter: 'ahp_observer',
    adapter_version: AHP_OBSERVER_ADAPTER_VERSION,
    protocol_version: summary.protocol.negotiated_version,
    summary_digest: summary.output_digest,
    artifacts,
    authority: { ...AHP_OBSERVER_AUTHORITY_FLAGS },
  };
  return { ...base, manifest_digest: stableHash(base) };
}

async function aggregateRunBytes(dir, runId) {
  const root = runDir(dir, runId);
  const entries = await fs.readdir(root, { withFileTypes: true });
  let total = 0;
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    total += (await fs.stat(path.join(root, entry.name))).size;
  }
  return total;
}

function safeActionType(value, channel) {
  if (typeof value !== 'string' || !ALLOWED_ACTION_TYPES.has(value)) return null;
  const expected = channel === 'ahp-root://' ? 'root/' : channel.startsWith('ahp-session:') ? 'session/' : 'chat/';
  return value.startsWith(expected) ? value : null;
}

function channelEvidence(channel) {
  const scheme = channel === 'ahp-root://' ? 'ahp-root' : channel.startsWith('ahp-session:') ? 'ahp-session' : 'ahp-chat';
  return {
    scheme,
    ref_digest: stableHash(`ahp_channel:${channel}`),
  };
}

function unknownChannelEvidence(value) {
  const candidate = typeof value === 'string' && /^ahp-[a-z][a-z0-9-]{0,31}:/.test(value)
    ? value.slice(0, value.indexOf(':'))
    : 'unknown';
  const scheme = ['ahp-terminal', 'ahp-otlp', 'ahp-resource-watch', 'ahp-changeset', 'ahp-annotations'].includes(candidate)
    ? candidate
    : 'unknown';
  return {
    scheme,
    ref_digest: stableHash(`ahp_channel:${typeof value === 'string' ? value : 'missing'}`),
  };
}

function extractReferenceDigests(value) {
  const refs = {};
  visit(value, (key, child) => {
    const outputKey = REF_KEYS.get(normalizeKey(key));
    if (outputKey && refs[outputKey] === undefined && typeof child === 'string') {
      refs[outputKey] = stableHash(`ahp_ref:${normalizeKey(key)}:${child}`);
    }
  });
  return refs;
}

function extractSafeStatus(value) {
  let status = null;
  visit(value, (key, child) => {
    if (status || normalizeKey(key) !== 'status' || typeof child !== 'string') return;
    const candidate = child.toLowerCase();
    if (SAFE_STATUS_VALUES.has(candidate)) status = candidate;
  });
  return status;
}

function scanSensitiveShape(value) {
  const counts = {
    message_content: 0,
    reasoning_content: 0,
    tool_input: 0,
    tool_result_content: 0,
    bearer_or_secret: 0,
    resource_or_path: 0,
    terminal_content: 0,
    telemetry_body: 0,
    rejection_reason: 0,
    opaque_metadata: 0,
  };
  visit(value, (key) => {
    const normalized = normalizeKey(key);
    if (normalized === 'rejectionreason') counts.rejection_reason += 1;
    else if (/reason|rationale|thought|chainofthought/.test(normalized)) counts.reasoning_content += 1;
    else if (/tool(input|arguments|params)|editableinput|arguments/.test(normalized)) counts.tool_input += 1;
    else if (/tool(output|result)|resultcontent/.test(normalized)) counts.tool_result_content += 1;
    else if (/authorization|bearer|token|secret|password|apikey|privatekey|credential|environment|envvalue/.test(normalized)) counts.bearer_or_secret += 1;
    else if (/terminal|stdout|stderr|command|cwd|pty/.test(normalized)) counts.terminal_content += 1;
    else if (/otlp|telemetry|trace|metric|logrecord|resourcelogs|scopelogs|attributes|body/.test(normalized)) counts.telemetry_body += 1;
    else if (normalized === 'resource' || /uri|url|path|file|workingdirectory/.test(normalized)) counts.resource_or_path += 1;
    else if (normalized === 'meta' || normalized === 'metadata') counts.opaque_metadata += 1;
    else if (/message|content|text|delta|draft|prompt|response/.test(normalized)) counts.message_content += 1;
  });
  return counts;
}

function safeShape(value) {
  const stats = inspectStructure(value);
  return {
    top_level_keys: isPlainRecord(value) ? Math.min(Object.keys(value).length, 128) : 0,
    object_count: Math.min(stats.objectCount, 4_096),
    array_count: Math.min(stats.arrayCount, 1_024),
    array_items: Math.min(stats.arrayItems, 65_536),
    scalar_count: Math.min(stats.scalarCount, 65_536),
  };
}

function inspectStructure(value) {
  const seen = new WeakSet();
  const stack = [{ value, depth: 0 }];
  let objectCount = 0;
  let arrayCount = 0;
  let arrayItems = 0;
  let scalarCount = 0;
  let nodes = 0;
  while (stack.length) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > 4_096 || current.depth > 16) return { ok: false, objectCount, arrayCount, arrayItems, scalarCount };
    if (current.value === null || typeof current.value !== 'object') {
      scalarCount += 1;
      continue;
    }
    if (seen.has(current.value)) return { ok: false, objectCount, arrayCount, arrayItems, scalarCount };
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      arrayCount += 1;
      arrayItems += current.value.length;
      if (arrayItems > 65_536) return { ok: false, objectCount, arrayCount, arrayItems, scalarCount };
      for (const child of current.value) stack.push({ value: child, depth: current.depth + 1 });
      continue;
    }
    objectCount += 1;
    const entries = Object.entries(current.value);
    if (entries.length > 1_024) return { ok: false, objectCount, arrayCount, arrayItems, scalarCount };
    for (const [key, child] of entries) {
      if (['__proto__', 'prototype', 'constructor'].includes(key)) return { ok: false, objectCount, arrayCount, arrayItems, scalarCount };
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
  return { ok: true, objectCount, arrayCount, arrayItems, scalarCount };
}

function visit(value, callback) {
  const seen = new WeakSet();
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length && nodes < 4_096) {
    const current = stack.pop();
    nodes += 1;
    if (!current.value || typeof current.value !== 'object' || current.depth > 16 || seen.has(current.value)) continue;
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      for (const child of current.value.slice(0, 1_024)) stack.push({ value: child, depth: current.depth + 1 });
      continue;
    }
    for (const [key, child] of Object.entries(current.value).slice(0, 1_024)) {
      callback(key, child);
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

function createStopController() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  const controller = {
    promise,
    stopped: false,
    value: null,
    stop(reason, status) {
      if (controller.stopped) return;
      controller.stopped = true;
      controller.value = { reason, status };
      resolve(controller.value);
    },
  };
  return controller;
}

async function operationOrStop(operation, controller) {
  const settled = Promise.resolve(operation).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  return Promise.race([
    settled,
    controller.promise.then(() => ({ stopped: true })),
  ]);
}

async function settleWithin(operation, timeoutMs) {
  let timeout;
  const deadline = new Promise((resolve) => {
    timeout = setTimeout(() => resolve(false), timeoutMs);
  });
  try {
    return await Promise.race([
      Promise.resolve(operation).then(() => true, () => false),
      deadline,
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

async function drainSubscription(subscription) {
  try {
    for await (const _event of subscription) {
      // The bounded transport tap writes the redacted evidence. Draining keeps
      // the official SDK queue from silently dropping old entries.
    }
  } catch {
    // Shutdown and malformed transports terminate subscription iterators.
  }
}

async function releaseObserverSubscriptions(client, transport, channels) {
  if (!client || !transport || channels.size === 0) return;
  if (client.connectionState.status !== 'connected' || !transport.isOpen()) return;
  const failureCount = transport.outboundFailureCount();
  try {
    for (const channel of [...channels].reverse()) {
      if (client.connectionState.status !== 'connected' || !transport.isOpen()) {
        throw observerError('unsubscribe_cleanup_incomplete');
      }
      const attemptCount = transport.unsubscribeAttemptCount();
      await client.unsubscribe(channel);
      const settled = await transport.settleOutbound();
      if (transport.unsubscribeAttemptCount() !== attemptCount + 1
        || !settled
        || transport.outboundFailureCount() !== failureCount) {
        throw observerError('unsubscribe_cleanup_incomplete');
      }
    }
  } catch {
    throw observerError('unsubscribe_cleanup_incomplete');
  }
}

async function assertSafeArtifactRoot(dir) {
  for (const target of [path.join(dir, '.agoragentic'), path.join(dir, '.agoragentic', 'runs')]) {
    try {
      const stat = await fs.lstat(target);
      if (stat.isSymbolicLink()) throw observerError('symlinked_artifact_root_forbidden');
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      if (error?.name === 'AhpObserverError') throw error;
      throw observerError('artifact_root_check_failed');
    }
  }
}

function boundedInteger(value, fallback, min, max, code) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected) || selected < min || selected > max) throw observerError(code);
  return selected;
}

function isSafeSequence(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isPlainRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isTransport(value) {
  return value && typeof value.send === 'function' && typeof value.recv === 'function' && typeof value.close === 'function';
}

function isAbortSignal(value) {
  return value && typeof value.aborted === 'boolean' && typeof value.addEventListener === 'function' && typeof value.removeEventListener === 'function';
}

function normalizeKey(key) {
  return String(key || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function nowIso(now) {
  let value;
  try { value = now(); } catch { throw observerError('clock_failed'); }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw observerError('clock_failed');
  return date.toISOString();
}

function sumCounts(counts) {
  return Object.values(counts).reduce((sum, value) => sum + value, 0);
}

function addWarning(aggregate, code) {
  if (!aggregate.warnings.includes(code) && aggregate.warnings.length < 16) aggregate.warnings.push(code);
}

function summaryForRecord(record) {
  if (record.observation_kind === 'snapshot') return 'AHP snapshot metadata observed and raw state discarded';
  if (record.observation_kind === 'action') return 'AHP action metadata observed and payload discarded';
  if (record.observation_kind === 'notification') return 'AHP notification metadata observed and payload discarded';
  if (record.observation_kind === 'server_request_default_rejection') return 'AHP server request observed; safe MethodNotFound policy selected';
  return 'AHP observer metadata recorded';
}

function classifyRuntimeError(error, fallback) {
  const safeCodes = new Set([
    'cancelled',
    'frame_limit',
    'inbound_buffer_limit',
    'invalid_utf8',
    'malformed_frame',
    'outbound_frame_limit',
    'outbound_malformed',
    'outbound_method_forbidden',
    'outbound_response_forbidden',
    'request_timeout',
    'transport_closed',
    'transport_error',
    'websocket_closed',
    'websocket_connect_failed',
    'websocket_send_failed',
    'websocket_transport_error',
  ]);
  if (safeCodes.has(error?.code)) return error.code;
  if (error?.name === 'RpcError' && error.code === UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE) {
    return 'unsupported_protocol_version';
  }
  if (error?.name === 'RpcTimeoutError') return 'request_timeout';
  if (error?.name === 'ClientClosedError') return 'transport_closed';
  return fallback;
}

function observerError(code) {
  const error = new Error(code);
  error.name = 'AhpObserverError';
  error.code = code;
  return error;
}

export const AHP_OBSERVER_PROHIBITED_METHODS = PROHIBITED_CLIENT_METHODS;
export const AHP_OBSERVER_ALLOWED_OUTBOUND_METHODS = Object.freeze([...ALLOWED_OUTBOUND_METHODS]);
export const AHP_OBSERVER_LIMITS = LIMITS;
export const AHP_OBSERVER_DEFAULTS = DEFAULTS;
export const AHP_OBSERVER_BASE_AUTHORITY = Object.freeze(authorityBoundary(AHP_OBSERVER_AUTHORITY_FLAGS));
