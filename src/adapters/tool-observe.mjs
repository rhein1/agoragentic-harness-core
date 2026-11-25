import { createHash } from 'node:crypto';
import { types } from 'node:util';

const HASH_FORMAT = 'agoragentic.control-json-binary64.v1';
const OBSERVATION_SCHEMA = 'agoragentic.control-observation.v1';
const MAX_BYTES = 65_536;
const REF = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const LABEL = /^[a-z0-9][a-z0-9._:-]{0,63}(?![\s\S])/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const REQUIRED_REFS = [
  'request_id', 'principal', 'agent', 'session', 'tool', 'resource', 'authority',
  'policy', 'idempotency_key_hash', 'trace',
];
const OPTIONAL_REFS = ['delegation', 'model', 'economic_context'];
const LABELS = ['framework', 'adapter_version', 'operation', 'consequence', 'policy_version'];
const LISTS = ['data_classes', 'external_side_effect_classes'];
const CONTEXT_KEYS = [...REQUIRED_REFS, ...OPTIONAL_REFS, ...LABELS, ...LISTS, 'proposed_at', 'expires_at'];
const OUTCOMES = new Set(['allow', 'ask', 'modify', 'deny']);

function invalid() {
  throw new TypeError('Invalid control observation data');
}

function dataFields(value, array = false) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) !== array) invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== (array ? Array.prototype : Object.prototype)) invalid();
  const fields = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(fields);
  if (keys.length > 4097) invalid();
  for (const key of keys) {
    const entry = fields[key];
    if (array && key === 'length') continue;
    if (typeof key !== 'string' || !entry.enumerable || !Object.hasOwn(entry, 'value')) invalid();
  }
  return fields;
}

function stringValue(value, state) {
  if (/[\ud800-\udfff]/u.test(value)) invalid();
  state.bytes += Buffer.byteLength(value);
  if (state.bytes > MAX_BYTES) invalid();
  return value;
}

function encode(value, state, depth) {
  if (depth > 16 || ++state.nodes > 4096) invalid();
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return stringValue(value, state);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0) ||
        (Number.isInteger(value) && !Number.isSafeInteger(value))) invalid();
    const bytes = Buffer.alloc(8);
    bytes.writeDoubleBE(value);
    return ['number', bytes.toString('hex')];
  }

  const array = Array.isArray(value);
  const fields = dataFields(value, array);
  if (array) {
    const length = fields.length.value;
    if (length > 4096 || Object.keys(fields).length !== length + 1) invalid();
    const items = [];
    for (let index = 0; index < length; index += 1) {
      if (!Object.hasOwn(fields, index)) invalid();
      items.push(encode(fields[index].value, state, depth + 1));
    }
    return ['array', items];
  }
  const keys = Object.keys(fields);
  const ordered = keys.map(key => [stringValue(key, state), Buffer.from(key)]);
  ordered.sort((left, right) => Buffer.compare(left[1], right[1]));
  return ['object', ordered.map(([key]) => [key, encode(fields[key].value, state, depth + 1)])];
}

/** Hash decoded JSON values with the versioned cross-language control encoding. */
export function controlValueHash(value) {
  const encoded = JSON.stringify([HASH_FORMAT, encode(value, { bytes: 0, nodes: 0 }, 0)]);
  if (Buffer.byteLength(encoded) > MAX_BYTES) invalid();
  return 'sha256:' + createHash('sha256').update(encoded).digest('hex');
}

function ref(value) {
  if (typeof value !== 'string' || !REF.test(value)) invalid();
  return value;
}

function label(value) {
  if (typeof value !== 'string' || !LABEL.test(value)) invalid();
  return value;
}

function labels(value) {
  const fields = dataFields(value, true);
  const length = fields.length.value;
  if (length > 16 || Object.keys(fields).length !== length + 1) invalid();
  const result = [];
  for (let index = 0; index < length; index += 1) {
    if (!Object.hasOwn(fields, index)) invalid();
    result.push(label(fields[index].value));
  }
  if (new Set(result).size !== result.length) invalid();
  return result.sort();
}

function timestamp(value) {
  if (typeof value !== 'string' || !TIMESTAMP.test(value) || value.startsWith('0000') ||
      new Date(value).toISOString() !== value) invalid();
  return value;
}

function buildRequest(context, args) {
  const fields = dataFields(context);
  if (Object.keys(fields).some(key => !CONTEXT_KEYS.includes(key))) invalid();
  const request = { schema: 'agoragentic.control-request.v1', hash_format: HASH_FORMAT, mode: 'observe' };
  for (const key of REQUIRED_REFS) request[key] = ref(fields[key]?.value);
  for (const key of OPTIONAL_REFS) {
    const field = fields[key];
    request[key] = !field || field.value === null ? null : ref(field.value);
  }
  for (const key of LABELS) request[key] = label(fields[key]?.value);
  for (const key of LISTS) request[key] = labels(fields[key]?.value);
  request.proposed_at = timestamp(fields.proposed_at?.value);
  request.expires_at = timestamp(fields.expires_at?.value);
  if (request.expires_at <= request.proposed_at) invalid();
  request.arguments_hash = controlValueHash(args);
  request.action_hash = controlValueHash({
    tool: request.tool,
    operation: request.operation,
    resource: request.resource,
    arguments_hash: request.arguments_hash,
  });
  return request;
}

function buildDecision(request, requestHash, assessment) {
  const fields = dataFields(assessment);
  const outcome = fields.outcome?.value;
  if (!OUTCOMES.has(outcome) || fields.request_hash?.value !== requestHash) invalid();
  const allowed = outcome === 'modify' ? ['outcome', 'request_hash', 'transformed_arguments'] : ['outcome', 'request_hash'];
  if (Object.keys(fields).length !== allowed.length || allowed.some(key => !Object.hasOwn(fields, key))) invalid();
  const decision = {
    schema: 'agoragentic.control-decision.v1',
    hash_format: HASH_FORMAT,
    mode: 'observe',
    request_hash: requestHash,
    outcome,
    policy: request.policy,
    policy_version: request.policy_version,
    authority: request.authority,
    delegation: request.delegation,
    expires_at: request.expires_at,
    transformation_hash: outcome === 'modify' ? controlValueHash(fields.transformed_arguments.value) : null,
    approval_proposal_ref: null,
    authoritative: false,
    execution_observed: false,
  };
  return { ...decision, decision_hash: controlValueHash(decision) };
}

/**
 * Observe a host-owned proposal. The host alone chooses when to dispatch the original tool.
 * The assessor receives a detached request containing references and hashes.
 */
export async function observeToolProposal({ mode = 'off', context, arguments: args, assess } = {}) {
  if (mode === 'off') return null;
  if (mode !== 'observe') throw new RangeError('Unsupported tool observation mode');
  const result = {
    schema: OBSERVATION_SCHEMA,
    hash_format: HASH_FORMAT,
    mode: 'observe',
    authoritative: false,
    execution_observed: false,
    status: 'unavailable',
    reason: 'invalid_proposal',
    request: null,
    request_hash: null,
    decision: null,
  };
  try {
    const request = buildRequest(context, args);
    result.request_hash = controlValueHash(request);
    result.request = request;
  } catch {
    return result;
  }
  result.reason = 'assessment_unavailable';
  try {
    const assessment = await assess(structuredClone(result.request), result.request_hash);
    result.decision = buildDecision(result.request, result.request_hash, assessment);
    result.status = 'observed';
    result.reason = null;
  } catch {
    // A missing or invalid shadow assessment remains unavailable.
  }
  return result;
}

/**
 * Project a decoded MCP tools/call request into shadow evidence. The caller
 * supplies the trusted server reference and owns the transport and dispatch.
 */
export async function observeMcpToolCall({ mode = 'off', request, server, context, assess } = {}) {
  if (mode === 'off') return null;
  if (mode !== 'observe') throw new RangeError('Unsupported tool observation mode');

  let proposal;
  let args;
  try {
    const message = dataFields(request);
    if (message.method?.value !== 'tools/call') invalid();
    const params = dataFields(message.params?.value);
    const name = params.name?.value;
    if (typeof name !== 'string' || !/^[A-Za-z0-9_.-]{1,128}(?![\s\S])/.test(name)) invalid();
    args = params.arguments ? params.arguments.value : {};
    dataFields(args);

    const fields = dataFields(context);
    for (const key of ['tool', 'operation', 'framework', 'adapter_version']) {
      if (Object.hasOwn(fields, key)) invalid();
    }
    proposal = Object.fromEntries(Object.entries(fields).map(([key, field]) => [key, field.value]));
    Object.assign(proposal, {
      tool: controlValueHash(['agoragentic.mcp-tool.v1', ref(server), name]),
      operation: 'tools.call',
      framework: 'mcp',
      adapter_version: '1',
    });
  } catch {
    return observeToolProposal({ mode });
  }

  return observeToolProposal({ mode, context: proposal, arguments: args, assess });
}
