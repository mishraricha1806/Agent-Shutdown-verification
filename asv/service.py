from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .adapters import SafeUnknownAdapter, ShutdownAdapter, SyntheticAdapter
from .domain import PROBE_KINDS, ProbeResult, ShutdownState, aggregate_probe_results
from .evidence import EvidenceLedger
from .store import Store, utc_now


DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class ValidationError(ValueError):
    pass


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


class ControlPlane:
    def __init__(
        self,
        store: Store,
        *,
        signing_key: bytes,
        adapter: ShutdownAdapter | None = None,
        deadline_seconds: int = 60,
    ) -> None:
        self.store = store
        self.ledger = EvidenceLedger(store, signing_key)
        self.adapter = adapter or SafeUnknownAdapter()
        self.deadline_seconds = deadline_seconds
        self._shutdown_lock = threading.RLock()

    def register_agent(self, request: dict[str, Any]) -> dict[str, Any]:
        required = ("tenant_id", "name", "image_digest", "namespace", "scope_owner")
        missing = [field for field in required if not request.get(field)]
        if missing:
            raise ValidationError(f"missing required fields: {', '.join(missing)}")
        if not DIGEST_PATTERN.fullmatch(str(request["image_digest"])):
            raise ValidationError("image_digest must be an immutable sha256 digest")
        declared_scope = request.get("declared_scope")
        if not isinstance(declared_scope, dict):
            raise ValidationError("declared_scope must be a JSON object")
        agent = {
            "agent_id": str(uuid.uuid4()),
            "tenant_id": str(request["tenant_id"]),
            "name": str(request["name"]),
            "image_digest": str(request["image_digest"]),
            "namespace": str(request["namespace"]),
            "scope_owner": str(request["scope_owner"]),
            "declared_scope": declared_scope,
            "status": "REGISTERED",
            "created_at": utc_now(),
        }
        with self.store.connection() as connection:
            connection.execute(
                "INSERT INTO agent VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    agent["agent_id"], agent["tenant_id"], agent["name"],
                    agent["image_digest"], agent["namespace"], agent["scope_owner"],
                    json.dumps(declared_scope, sort_keys=True), agent["status"], agent["created_at"],
                ),
            )
        return agent

    def create_run(self, request: dict[str, Any]) -> dict[str, Any]:
        required = ("tenant_id", "agent_id", "identity_ref")
        missing = [field for field in required if not request.get(field)]
        if missing:
            raise ValidationError(f"missing required fields: {', '.join(missing)}")
        tenant_id = str(request["tenant_id"])
        agent_id = str(request["agent_id"])
        parent_run_id = request.get("parent_run_id")
        with self.store.connection() as connection:
            agent = connection.execute(
                "SELECT agent_id FROM agent WHERE tenant_id=? AND agent_id=?",
                (tenant_id, agent_id),
            ).fetchone()
            if agent is None:
                raise NotFoundError("agent not found for tenant")
            if parent_run_id:
                parent = connection.execute(
                    "SELECT run_id, agent_id FROM run WHERE tenant_id=? AND run_id=?",
                    (tenant_id, parent_run_id),
                ).fetchone()
                if parent is None:
                    raise NotFoundError("parent run not found for tenant")
                if parent["agent_id"] != agent_id:
                    raise ValidationError("parent run belongs to a different agent")
            run = {
                "run_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "parent_run_id": parent_run_id,
                "identity_ref": str(request["identity_ref"]),
                "started_at": utc_now(),
                "stopped_at": None,
                "state": ShutdownState.RUNNING.value,
                "correlation_id": str(request.get("correlation_id") or uuid.uuid4()),
                "policy_version": int(request.get("policy_version", 1)),
            }
            try:
                connection.execute(
                    "INSERT INTO run (run_id,tenant_id,agent_id,parent_run_id,identity_ref,started_at,stopped_at,state,correlation_id,policy_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    tuple(run.values()),
                )
            except sqlite3.IntegrityError as error:
                raise ConflictError("correlation_id already exists") from error
        self._append_event(run, "agent.run.started", {"state": run["state"]}, "agent-adapter")
        return run

    def get_agent(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        with self.store.connection() as connection:
            row = connection.execute(
                "SELECT * FROM agent WHERE tenant_id=? AND agent_id=?", (tenant_id, agent_id)
            ).fetchone()
        agent = self.store.row(row)
        if agent is None:
            raise NotFoundError("agent not found for tenant")
        return agent

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self.store.connection() as connection:
            row = connection.execute(
                "SELECT * FROM run WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
            ).fetchone()
            if row is None:
                raise NotFoundError("run not found for tenant")
            run = self.store.row(row)
            probes = connection.execute(
                "SELECT * FROM probe WHERE tenant_id=? AND run_id=? ORDER BY requested_at, kind",
                (tenant_id, run_id),
            ).fetchall()
            delegated_jobs = connection.execute(
                "SELECT * FROM delegated_job WHERE tenant_id=? AND run_id=? ORDER BY discovered_at, external_id",
                (tenant_id, run_id),
            ).fetchall()
        assert run is not None
        run["probes"] = [self.store.row(probe) for probe in probes]
        run["delegated_jobs"] = [self.store.row(job) for job in delegated_jobs]
        return run

    def request_shutdown(
        self,
        tenant_id: str,
        run_id: str,
        *,
        actor: str,
        idempotency_key: str,
        asynchronous: bool = True,
        adapter: ShutdownAdapter | None = None,
    ) -> dict[str, Any]:
        if not actor:
            raise ValidationError("actor is required")
        if not idempotency_key:
            raise ValidationError("Idempotency-Key header is required")
        with self._shutdown_lock, self.store.connection() as connection:
            row = connection.execute(
                "SELECT * FROM run WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
            ).fetchone()
            if row is None:
                raise NotFoundError("run not found for tenant")
            run = self.store.row(row)
            assert run is not None
            if run["shutdown_requested_at"]:
                if run["shutdown_idempotency_key"] != idempotency_key:
                    raise ConflictError("shutdown already requested with a different idempotency key")
                return self._shutdown_receipt(run)
            requested_at = utc_now()
            deadline_at = (datetime.now(UTC) + timedelta(seconds=self.deadline_seconds)).isoformat()
            connection.execute(
                "UPDATE run SET state=?,shutdown_requested_at=?,deadline_at=?,shutdown_idempotency_key=? WHERE tenant_id=? AND run_id=?",
                (ShutdownState.REQUESTED.value, requested_at, deadline_at, idempotency_key, tenant_id, run_id),
            )
            run.update(
                state=ShutdownState.REQUESTED.value,
                shutdown_requested_at=requested_at,
                deadline_at=deadline_at,
                shutdown_idempotency_key=idempotency_key,
            )
        self._append_event(run, "shutdown.requested", {"deadline_at": deadline_at}, actor)
        if asynchronous:
            threading.Thread(
                target=self._orchestrate,
                args=(tenant_id, run_id, actor, adapter or self.adapter),
                daemon=True,
            ).start()
        else:
            self._orchestrate(tenant_id, run_id, actor, adapter or self.adapter)
        return self._shutdown_receipt(run)

    def _orchestrate(
        self, tenant_id: str, run_id: str, actor: str, adapter: ShutdownAdapter
    ) -> None:
        try:
            run = self._adapter_run(tenant_id, run_id)
            self._transition(run, ShutdownState.FENCING, "shutdown.fenced", adapter.fence(run), actor)
            run = self._adapter_run(tenant_id, run_id)
            self._transition(run, ShutdownState.PROCESS_STOP_SENT, "shutdown.process.stop.sent", adapter.stop_process(run), actor)
            run = self._adapter_run(tenant_id, run_id)
            discovery = adapter.discover_children(run)
            self._save_delegated_jobs(run, discovery.get("children", []))
            self._transition(run, ShutdownState.CHILD_DISCOVERY, "agent.child.discovered", discovery, actor)
            run = self._adapter_run(tenant_id, run_id)
            self._transition(run, ShutdownState.PROBING, "shutdown.probe.requested", {"kinds": list(PROBE_KINDS)}, actor)
            results: list[ProbeResult] = []
            for kind in PROBE_KINDS:
                observation = adapter.probe(kind, run)
                results.append(observation.result)
                self._save_probe(run, observation)
            terminal = aggregate_probe_results(results)
            run = self.get_run(tenant_id, run_id)
            self._transition(
                run, terminal, "shutdown.completed",
                {"result": terminal.value, "probe_results": [result.value for result in results]}, actor,
                stopped=True,
            )
        except Exception as error:
            try:
                run = self.get_run(tenant_id, run_id)
                self._transition(
                    run, ShutdownState.FAILED, "shutdown.completed",
                    {"result": "FAILED", "error": type(error).__name__, "message": str(error)},
                    "orchestrator", stopped=True,
                )
            except Exception:
                pass

    def _adapter_run(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        run = self.get_run(tenant_id, run_id)
        run["agent"] = self.get_agent(tenant_id, run["agent_id"])
        return run

    def _transition(
        self,
        run: dict[str, Any],
        state: ShutdownState,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        *,
        stopped: bool = False,
    ) -> None:
        stopped_at = utc_now() if stopped else None
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE run SET state=?, stopped_at=COALESCE(?, stopped_at) WHERE tenant_id=? AND run_id=?",
                (state.value, stopped_at, run["tenant_id"], run["run_id"]),
            )
        run["state"] = state.value
        run["stopped_at"] = stopped_at or run.get("stopped_at")
        self._append_event(run, event_type, {"state": state.value, **payload}, actor)

    def _save_probe(self, run: dict[str, Any], observation: Any) -> None:
        requested_at = utc_now()
        with self.store.connection() as connection:
            connection.execute(
                "INSERT INTO probe VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid.uuid4()), run["tenant_id"], run["run_id"], observation.kind,
                    f"synthetic/{observation.kind}", requested_at, utc_now(),
                    observation.result.value, json.dumps(observation.observed, sort_keys=True),
                    observation.authority, observation.confidence,
                ),
            )
        self._append_event(run, "shutdown.probe.result", observation.to_dict(), "probe-runner")

    def _save_delegated_jobs(self, run: dict[str, Any], children: list[dict[str, Any]]) -> None:
        with self.store.connection() as connection:
            for child in children:
                status = child.get("status", {})
                if status.get("active") not in (None, [], 0):
                    state = "ACTIVE"
                elif status:
                    state = "INACTIVE"
                else:
                    state = "UNKNOWN"
                connection.execute(
                    "INSERT INTO delegated_job VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(run_id,system,external_id) DO UPDATE SET state=excluded.state,discovered_at=excluded.discovered_at",
                    (
                        str(uuid.uuid4()), run["tenant_id"], run["run_id"],
                        f"kubernetes:{child.get('kind', 'unknown')}", str(child.get("name", "unknown")),
                        state, utc_now(),
                    ),
                )

    def _append_event(self, run: dict[str, Any], event_type: str, payload: dict[str, Any], actor: str) -> None:
        self.ledger.append(
            tenant_id=run["tenant_id"], run_id=run["run_id"], event_type=event_type,
            payload=payload, actor=actor, policy_version=run["policy_version"],
            correlation_id=run["correlation_id"],
        )

    def evidence(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        self.get_run(tenant_id, run_id)
        return {
            "records": self.ledger.records(tenant_id, run_id),
            "manifest": self.ledger.manifest(tenant_id, run_id),
        }

    def export_events(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        run = self.get_run(tenant_id, run_id)
        events = []
        for record in self.ledger.records(tenant_id, run_id):
            events.append(
                {
                    "event_id": record["evidence_id"],
                    "run_id": run_id,
                    "parent_run_id": run["parent_run_id"],
                    "agent_id": run["agent_id"],
                    "correlation_id": record["correlation_id"],
                    "policy_version": record["policy_version"],
                    "occurred_at": record["observed_at"],
                    "producer": record["actor"],
                    "schema_version": "1.0",
                    "idempotency_key": f"{run_id}:{record['sequence_no']}",
                    "event_type": record["event_type"],
                    "payload": record["payload"],
                }
            )
        return {"events": events, "count": len(events)}

    def start_synthetic_drill(
        self,
        request: dict[str, Any],
        *,
        actor: str,
        asynchronous: bool = True,
    ) -> dict[str, Any]:
        tenant_id = str(request.get("tenant_id", ""))
        agent_id = str(request.get("agent_id", ""))
        if not tenant_id or not agent_id:
            raise ValidationError("tenant_id and agent_id are required")
        agent = self.get_agent(tenant_id, agent_id)
        if not agent["namespace"].startswith("asv-"):
            raise ValidationError("synthetic drills require an asv-* namespace")
        if agent["declared_scope"].get("synthetic_only") is not True:
            raise ValidationError("agent scope must explicitly set synthetic_only=true")
        raw_outcomes = request.get("outcomes")
        drill_adapter = self.adapter
        simulated = raw_outcomes is not None
        if simulated:
            if not isinstance(raw_outcomes, dict):
                raise ValidationError("outcomes must be a JSON object")
            missing_kinds = set(PROBE_KINDS) - set(raw_outcomes)
            unknown_kinds = set(raw_outcomes) - set(PROBE_KINDS)
            if missing_kinds or unknown_kinds:
                raise ValidationError(
                    "simulated outcomes must contain exactly: " + ", ".join(PROBE_KINDS)
                )
            try:
                outcomes = {kind: ProbeResult(str(raw_outcomes[kind])) for kind in PROBE_KINDS}
            except ValueError as error:
                raise ValidationError("probe outcomes must be PASS, FAIL, PARTIAL, or UNKNOWN") from error
            drill_adapter = SyntheticAdapter(outcomes)
        drill_id = str(uuid.uuid4())
        run = self.create_run(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "identity_ref": f"synthetic/drill/{drill_id}",
                "policy_version": int(request.get("policy_version", 1)),
            }
        )
        receipt = self.request_shutdown(
            tenant_id,
            run["run_id"],
            actor=actor,
            idempotency_key=f"drill:{drill_id}",
            asynchronous=asynchronous,
            adapter=drill_adapter,
        )
        return {"drill_id": drill_id, "synthetic_target": True, "simulated": simulated, **receipt}

    @staticmethod
    def _shutdown_receipt(run: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run["run_id"],
            "correlation_id": run["correlation_id"],
            "requested_at": run["shutdown_requested_at"],
            "deadline_at": run["deadline_at"],
            "state": run["state"],
        }
