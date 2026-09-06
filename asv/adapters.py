from __future__ import annotations

from typing import Protocol

from .domain import PROBE_KINDS, ProbeObservation, ProbeResult


class ShutdownAdapter(Protocol):
    def fence(self, run: dict) -> dict: ...
    def stop_process(self, run: dict) -> dict: ...
    def discover_children(self, run: dict) -> dict: ...
    def probe(self, kind: str, run: dict) -> ProbeObservation: ...


class SafeUnknownAdapter:
    """Non-mutating default. Unknown external state can never verify a shutdown."""

    def fence(self, run: dict) -> dict:
        return {"accepted": False, "reason": "no external fencing adapter configured"}

    def stop_process(self, run: dict) -> dict:
        return {"accepted": False, "reason": "no Kubernetes adapter configured"}

    def discover_children(self, run: dict) -> dict:
        return {"observable": False, "children": []}

    def probe(self, kind: str, run: dict) -> ProbeObservation:
        if kind not in PROBE_KINDS:
            raise ValueError(f"unsupported probe kind: {kind}")
        return ProbeObservation(
            kind=kind,
            result=ProbeResult.UNKNOWN,
            observed={"reason": f"{kind} adapter is not configured"},
            authority="control-plane",
            confidence="none",
        )


class SyntheticAdapter(SafeUnknownAdapter):
    """Deterministic adapter used by tests and a future synthetic drill fixture."""

    def __init__(self, outcomes: dict[str, ProbeResult]) -> None:
        self.outcomes = outcomes

    def fence(self, run: dict) -> dict:
        return {"accepted": True, "synthetic": True}

    def stop_process(self, run: dict) -> dict:
        return {"accepted": True, "synthetic": True}

    def discover_children(self, run: dict) -> dict:
        return {"observable": True, "children": []}

    def probe(self, kind: str, run: dict) -> ProbeObservation:
        result = self.outcomes.get(kind, ProbeResult.UNKNOWN)
        return ProbeObservation(
            kind=kind,
            result=result,
            observed={"synthetic": True, "outcome": result.value},
            authority="synthetic-test-adapter",
            confidence="deterministic",
        )

