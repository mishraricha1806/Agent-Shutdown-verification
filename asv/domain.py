from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class ShutdownState(StrEnum):
    RUNNING = "RUNNING"
    REQUESTED = "REQUESTED"
    FENCING = "FENCING"
    PROCESS_STOP_SENT = "PROCESS_STOP_SENT"
    CHILD_DISCOVERY = "CHILD_DISCOVERY"
    PROBING = "PROBING"
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"


TERMINAL_STATES = {
    ShutdownState.VERIFIED,
    ShutdownState.PARTIAL,
    ShutdownState.UNKNOWN,
    ShutdownState.FAILED,
}


class ProbeResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


PROBE_KINDS = ("process", "delegation", "kafka", "credential", "network")


@dataclass(frozen=True)
class ProbeObservation:
    kind: str
    result: ProbeResult
    observed: dict[str, Any]
    authority: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["result"] = self.result.value
        return value


def aggregate_probe_results(results: list[ProbeResult]) -> ShutdownState:
    """Aggregate without ever treating missing telemetry as successful."""
    if not results:
        return ShutdownState.UNKNOWN
    if any(result == ProbeResult.FAIL for result in results):
        return ShutdownState.FAILED
    if any(result == ProbeResult.UNKNOWN for result in results):
        return ShutdownState.UNKNOWN
    if any(result == ProbeResult.PARTIAL for result in results):
        return ShutdownState.PARTIAL
    return ShutdownState.VERIFIED

