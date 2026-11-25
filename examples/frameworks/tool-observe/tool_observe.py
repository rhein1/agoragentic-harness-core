"""Local Python counterpart for Harness Core's generic tool observation adapter."""

from datetime import datetime
import hashlib
import json
import math
import re
import struct

_HASH_FORMAT = "agoragentic.control-json-binary64.v1"
_MAX_BYTES = 65_536
_UNSET = object()
_REF = re.compile(r"sha256:[a-f0-9]{64}")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_REQUIRED_REFS = (
    "request_id", "principal", "agent", "session", "tool", "resource", "authority",
    "policy", "idempotency_key_hash", "trace",
)
_OPTIONAL_REFS = ("delegation", "model", "economic_context")
_LABELS = ("framework", "adapter_version", "operation", "consequence", "policy_version")
_LISTS = ("data_classes", "external_side_effect_classes")
_CONTEXT_KEYS = {*_REQUIRED_REFS, *_OPTIONAL_REFS, *_LABELS, *_LISTS, "proposed_at", "expires_at"}


def _invalid():
    raise ValueError("Invalid control observation data")


def _bytes(value, state):
    encoded = value.encode("utf-8")
    state["bytes"] += len(encoded)
    if state["bytes"] > _MAX_BYTES:
        _invalid()
    return encoded


def _encode(value, state, depth):
    state["nodes"] += 1
    if depth > 16 or state["nodes"] > 4096:
        _invalid()
    kind = type(value)
    if value is None or kind is bool:
        return value
    if kind is str:
        _bytes(value, state)
        return value
    if kind in (int, float):
        if kind is int and abs(value) > 2**53 - 1:
            _invalid()
        number = float(value)
        if (not math.isfinite(number) or
                (number == 0 and math.copysign(1, number) < 0) or
                (number.is_integer() and abs(number) > 2**53 - 1)):
            _invalid()
        return ["number", struct.pack(">d", number).hex()]
    if kind is list:
        return ["array", [_encode(item, state, depth + 1) for item in value]]
    if kind is not dict or len(value) > 4096 or any(type(key) is not str for key in value):
        _invalid()
    keys = sorted(value, key=lambda key: _bytes(key, state))
    return ["object", [[key, _encode(value[key], state, depth + 1)] for key in keys]]


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def control_value_hash(value):
    """Hash a decoded JSON value using the versioned cross-language encoding."""
    encoded = _json([_HASH_FORMAT, _encode(value, {"bytes": 0, "nodes": 0}, 0)]).encode("utf-8")
    if len(encoded) > _MAX_BYTES:
        _invalid()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _match(pattern, value):
    if type(value) is not str or pattern.fullmatch(value) is None:
        _invalid()
    return value


def _labels(value):
    if type(value) is not list or len(value) > 16:
        _invalid()
    checked = [_match(_LABEL, name) for name in value]
    if len(set(checked)) != len(checked):
        _invalid()
    return sorted(checked)


def _timestamp(value):
    _match(_TIMESTAMP, value)
    datetime.fromisoformat(value[:-1] + "+00:00")
    return value


def _request(context, arguments):
    if type(context) is not dict or any(type(key) is not str or key not in _CONTEXT_KEYS for key in context):
        _invalid()
    request = {"schema": "agoragentic.control-request.v1", "hash_format": _HASH_FORMAT, "mode": "observe"}
    for key in _REQUIRED_REFS:
        request[key] = _match(_REF, context.get(key))
    for key in _OPTIONAL_REFS:
        value = context.get(key)
        request[key] = None if value is None else _match(_REF, value)
    for key in _LABELS:
        request[key] = _match(_LABEL, context.get(key))
    for key in _LISTS:
        request[key] = _labels(context.get(key))
    request["proposed_at"] = _timestamp(context.get("proposed_at"))
    request["expires_at"] = _timestamp(context.get("expires_at"))
    if request["expires_at"] <= request["proposed_at"]:
        _invalid()
    request["arguments_hash"] = control_value_hash(arguments)
    request["action_hash"] = control_value_hash({
        key: request[key] for key in ("tool", "operation", "resource", "arguments_hash")
    })
    return request


def _decision(request, request_hash, assessment):
    if type(assessment) is not dict or any(type(key) is not str for key in assessment):
        _invalid()
    outcome = assessment.get("outcome")
    binding = assessment.get("request_hash")
    if (type(outcome) is not str or outcome not in ("allow", "ask", "modify", "deny")
            or type(binding) is not str or binding != request_hash):
        _invalid()
    allowed = {"outcome", "request_hash"}
    if outcome == "modify":
        allowed.add("transformed_arguments")
    if assessment.keys() != allowed:
        _invalid()
    decision = {
        "schema": "agoragentic.control-decision.v1",
        "hash_format": _HASH_FORMAT,
        "mode": "observe",
        "request_hash": request_hash,
        "outcome": outcome,
        "policy": request["policy"],
        "policy_version": request["policy_version"],
        "authority": request["authority"],
        "delegation": request["delegation"],
        "expires_at": request["expires_at"],
        "transformation_hash": control_value_hash(assessment["transformed_arguments"]) if outcome == "modify" else None,
        "approval_proposal_ref": None,
        "authoritative": False,
        "execution_observed": False,
    }
    decision["decision_hash"] = control_value_hash(decision)
    return decision


def observe_tool_proposal(*, mode="off", context=None, arguments=_UNSET, assess=None):
    """Return shadow evidence. The host retains the original arguments and dispatch."""
    if type(mode) is not str:
        raise ValueError("Unsupported tool observation mode")
    if mode == "off":
        return None
    if mode != "observe":
        raise ValueError("Unsupported tool observation mode")
    result = {
        "schema": "agoragentic.control-observation.v1",
        "hash_format": _HASH_FORMAT,
        "mode": "observe",
        "authoritative": False,
        "execution_observed": False,
        "status": "unavailable",
        "reason": "invalid_proposal",
        "request": None,
        "request_hash": None,
        "decision": None,
    }
    try:
        request = _request(context, arguments)
        result["request_hash"] = control_value_hash(request)
        result["request"] = request
    except (TypeError, ValueError):
        return result
    result["reason"] = "assessment_unavailable"
    try:
        assessment = assess(json.loads(_json(request)), result["request_hash"])
        result["decision"] = _decision(request, result["request_hash"], assessment)
        result["status"] = "observed"
        result["reason"] = None
    except Exception:
        # A missing or invalid shadow assessment remains unavailable.
        pass
    return result
