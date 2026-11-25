import importlib.util
import json
import math
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "tool_observe",
    root / "examples/frameworks/tool-observe/tool_observe.py",
)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
fixture = json.loads((root / "examples/frameworks/tool-observe/fixtures.json").read_text(encoding="utf-8"))

for vector in fixture["vectors"].values():
    assert adapter.control_value_hash(vector["value"]) == vector["hash"]

assert adapter.observe_tool_proposal(assess=lambda *_: (_ for _ in ()).throw(AssertionError())) is None
try:
    adapter.observe_tool_proposal(mode="enforce")
except ValueError:
    pass
else:
    raise AssertionError("Enforce should be unavailable")

cyclic = []
cyclic.append(cyclic)
for invalid in [-0.0, math.inf, math.nan, 2**53, "\ud800", cyclic, {1: "coercion"}, "x" * 65537]:
    receipt = adapter.observe_tool_proposal(mode="observe", context=fixture["context"], arguments=invalid)
    assert receipt["reason"] == "invalid_proposal"
    assert receipt["request"] is None

def identify(outcome):
    def assess(request, request_hash):
        assert adapter.control_value_hash(request) == request_hash
        request["principal"] = "mutable assessor-local copy"
        decision = {"outcome": outcome, "request_hash": request_hash}
        if outcome == "modify":
            decision["transformed_arguments"] = {"label": "suggested change"}
        return decision
    return assess

evidence = []
for outcome in ("allow", "ask", "modify", "deny"):
    evidence.append(adapter.observe_tool_proposal(
        mode="observe", context=fixture["context"], arguments=fixture["vectors"]["unicode"]["value"],
        assess=identify(outcome),
    ))
print(json.dumps(evidence))
