# Observe generic tool proposals

The JavaScript adapter and Python source example emit hash-bound shadow evidence for a host-owned tool proposal. Observe is opt-in. The default off mode returns no evidence and never calls the assessor.

The host runs its tool independently of observation. Attach the observer to a local evidence path and keep its promise or result outside the dispatch decision. A shadow allow, ask, modify, or deny has no execution or approval authority. Enforce is unavailable in this source preview. A missing or invalid assessment produces an unavailable result without saving error details.

Use `agoragentic-harness-core/adapters/tool-observe` from a checkout containing this change. The Python counterpart is `tool_observe.py` alongside this file. Both accept the same field names. See the [observation schema](../../../schema/control-observation.v1.json) and [shared examples](fixtures.json).

Provide `mode="observe"`, the host-owned context, and the original decoded JSON arguments. The adapter sends a detached request and its hash to the host-supplied assessor. It shares the argument hash and omits the argument values. Return an `outcome` and the exact `request_hash` from that assessment. Only a modify assessment accepts `transformed_arguments`. The evidence retains their hash and leaves the original tool arguments untouched. No approvals are created.

Context references use `sha256:` identifiers. Supply principal, agent, session, authority, policy, delegation, model, resource, and similar references from the host and its local registry. Keep identity and policy inputs separate from model output. Never put secrets in labels or treat an unkeyed hash as anonymization. Keep evidence local by default and omit secret-bearing actions from observation.

The action hash binds the tool, operation, resource, and original arguments hash. The request hash additionally binds the framework, adapter, and other current context. Equivalent actions can therefore match across frameworks while request hashes retain the framework identity. The decision hash binds the exact request and its shadow outcome.

The hash format `agoragentic.control-json-binary64.v1` uses tagged JSON. The request, decision, and observation identify the format explicitly. Object entries are sorted by the UTF-8 bytes of each key. The format preserves valid Unicode strings and encodes finite numbers as their big-endian binary64 bytes. It rejects negative zero, unsafe integers, unpaired surrogates, sparse arrays, non-data properties, and out-of-bounds values. It is intended for decoded data. Reject duplicate keys in any untrusted JSON transport before handing decoded values to the adapter. This encoding is distinct from RFC 8785 and leaves existing receipt formats unchanged.

For a local preview, load the example context and attach observation after the host's own decision to run the tool.

```js
import { readFile } from 'node:fs/promises';
import { observeToolProposal } from 'agoragentic-harness-core/adapters/tool-observe';

const { context } = JSON.parse(await readFile('examples/frameworks/tool-observe/fixtures.json', 'utf8'));
const args = { directory: 'example' };
const evidence = observeToolProposal({
  mode: 'observe', context, arguments: args,
  assess: (request, request_hash) => ({ outcome: 'ask', request_hash }),
});
// The independent host call still receives args. Await evidence only in the evidence path.
console.log(await evidence);
```

Run the shared fixture check from the repository root with `npm run test:observe-parity`. The fixtures cover generic tool proposals in JavaScript and Python. Framework-specific compatibility, production policy, and host execution have separate evidence requirements.

## MCP tools/call projection

The JavaScript subpath also exports `observeMcpToolCall` for a host that already owns an MCP SDK client or server handler:

```js
import { observeMcpToolCall } from 'agoragentic-harness-core/adapters/tool-observe';

const evidence = observeMcpToolCall({
  mode: 'observe',
  request: decodedToolsCallRequest,
  server: trustedServerReference,
  context: hostContext,
  assess: (request, requestHash) => ({ outcome: 'ask', request_hash: requestHash }),
});
// The host dispatches through its SDK independently. Consume evidence on a separate path.
```

The request must be a decoded MCP `tools/call` message. `hostContext` supplies the generic context fields, except `tool`, `operation`, `framework`, and `adapter_version`, which the adapter derives and rejects when supplied by the caller. The adapter binds the trusted server reference, tool name, and decoded arguments hash into the generic shadow request. Keep the returned observation promise on the evidence path rather than awaiting it in the host dispatch path; the host must call its own SDK client or server handler independently. This projection creates no client, server, transport, authentication, approval, enforcement, or execution path. The resulting evidence is local, non-authoritative, and does not prove that the host dispatched the call or that an external effect occurred.

The official MCP SDK round-trip fixture is isolated under `test/fixtures/mcp-sdk` and is not a main-package dependency. Validate it with Node 20, 22, and 24 using `npm ci --prefix test/fixtures/mcp-sdk --ignore-scripts --engine-strict --strict-peer-deps` followed by `npm test --prefix test/fixtures/mcp-sdk`; Node 18 retains the dependency-free projection coverage.
