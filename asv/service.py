from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .adapters import SafeUnknownAdapter, ShutdownAdapter, SyntheticAdapter
from .domain import PROBE_KINDS, TERMINAL_STATES, ProbeResult, ShutdownState, aggregate_probe_results
from .evidence import EvidenceLedger, canonical_json
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
        recovery_lease_seconds: int = 30,
    ) -> None:
        self.store = store
        self.ledger = EvidenceLedger(store, signing_key)
        self.adapter = adapter or SafeUnknownAdapter()
        self.deadline_seconds = deadline_seconds
        self.recovery_lease_seconds = recovery_lease_seconds
        self._worker_id = str(uuid.uuid4())
        self._shutdown_lock = threading.RLock()
        self._report_lock = threading.RLock()
        self._drill_lock = threading.RLock()

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
                "run_id": str(request.get("_run_id") or uuid.uuid4()),
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
            connection.execute(
                "INSERT INTO shutdown_work VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET status='PENDING',updated_at=excluded.updated_at",
                (run_id, tenant_id, "PENDING", 0, None, None, None, requested_at),
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
        self, tenant_id: str, run_id: str, actor: str, adapter: ShutdownAdapter,
        *, recovering: bool = False, lease_owner: str | None = None,
    ) -> None:
        lease_owner = lease_owner or self._claim_shutdown_work(tenant_id, run_id)
        if lease_owner is None:
            return
        try:
            run = self._adapter_run(tenant_id, run_id)
            if recovering:
                self._append_event(
                    run, "shutdown.recovery.resumed",
                    {"state": run["state"], "worker_id": self._worker_id},
                    "recovery-worker",
                )
            if self._deadline_expired(run):
                self._expire_shutdown(run, lease_owner)
                return
            state = ShutdownState(run["state"])
            if state == ShutdownState.REQUESTED:
                self._renew_shutdown_lease(run_id, lease_owner)
                self._transition(run, ShutdownState.FENCING, "shutdown.fenced", adapter.fence(run), actor)
                run = self._adapter_run(tenant_id, run_id)
                state = ShutdownState.FENCING
            if state == ShutdownState.FENCING:
                self._renew_shutdown_lease(run_id, lease_owner)
                self._transition(run, ShutdownState.PROCESS_STOP_SENT, "shutdown.process.stop.sent", adapter.stop_process(run), actor)
                run = self._adapter_run(tenant_id, run_id)
                state = ShutdownState.PROCESS_STOP_SENT
            if state == ShutdownState.PROCESS_STOP_SENT:
                self._renew_shutdown_lease(run_id, lease_owner)
                discovery = adapter.discover_children(run)
                self._save_delegated_jobs(run, discovery.get("children", []))
                self._transition(run, ShutdownState.CHILD_DISCOVERY, "agent.child.discovered", discovery, actor)
                run = self._adapter_run(tenant_id, run_id)
                state = ShutdownState.CHILD_DISCOVERY
            if state == ShutdownState.CHILD_DISCOVERY:
                self._transition(run, ShutdownState.PROBING, "shutdown.probe.requested", {"kinds": list(PROBE_KINDS)}, actor)
                run = self._adapter_run(tenant_id, run_id)
                state = ShutdownState.PROBING
            if state != ShutdownState.PROBING:
                if state in TERMINAL_STATES:
                    self._finish_shutdown_work(run_id, lease_owner)
                    return
                raise RuntimeError(f"cannot orchestrate shutdown from state {state.value}")
            existing = {probe["kind"]: ProbeResult(probe["result"]) for probe in run["probes"]}
            for kind in PROBE_KINDS:
                if kind in existing:
                    continue
                if self._deadline_expired(run):
                    self._expire_shutdown(run, lease_owner)
                    return
                self._renew_shutdown_lease(run_id, lease_owner)
                observation = adapter.probe(kind, run)
                existing[kind] = observation.result
                self._save_probe(run, observation)
            results = [existing.get(kind, ProbeResult.UNKNOWN) for kind in PROBE_KINDS]
            terminal = aggregate_probe_results(results)
            run = self.get_run(tenant_id, run_id)
            self._transition(
                run, terminal, "shutdown.completed",
                {"result": terminal.value, "probe_results": [result.value for result in results]}, actor,
                stopped=True,
            )
            self._finish_shutdown_work(run_id, lease_owner)
        except Exception as error:
            self._fail_shutdown_work(run_id, lease_owner, error)
            try:
                run = self.get_run(tenant_id, run_id)
                self._transition(
                    run, ShutdownState.FAILED, "shutdown.completed",
                    {"result": "FAILED", "error": type(error).__name__, "message": str(error)},
                    "orchestrator", stopped=True,
                )
            except Exception:
                pass

    def recover_incomplete_shutdowns(self, *, asynchronous: bool = True) -> dict[str, int]:
        """Resume persisted shutdowns whose lease is available.

        Re-entry starts at the last committed state and skips probe kinds that
        already have durable observations. Expired runs are terminal UNKNOWN.
        """
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM run WHERE shutdown_requested_at IS NOT NULL "
                "AND state NOT IN ('VERIFIED','PARTIAL','UNKNOWN','FAILED') "
                "ORDER BY shutdown_requested_at"
            ).fetchall()
        resumed = expired = busy = 0
        for row in rows:
            run = self.store.row(row)
            assert run is not None
            if self._deadline_expired(run):
                lease_owner = self._claim_shutdown_work(run["tenant_id"], run["run_id"])
                if lease_owner is not None:
                    self._expire_shutdown(run, lease_owner)
                    expired += 1
                else:
                    busy += 1
                continue
            lease_owner = self._claim_shutdown_work(run["tenant_id"], run["run_id"])
            if lease_owner is None:
                busy += 1
                continue
            adapter = self._recovery_adapter(run["tenant_id"], run["run_id"])
            if asynchronous:
                threading.Thread(
                    target=self._orchestrate,
                    args=(run["tenant_id"], run["run_id"], "recovery-worker", adapter),
                    kwargs={"recovering": True, "lease_owner": lease_owner},
                    daemon=True,
                ).start()
            else:
                self._orchestrate(
                    run["tenant_id"], run["run_id"], "recovery-worker", adapter,
                    recovering=True, lease_owner=lease_owner,
                )
            resumed += 1
        return {"resumed": resumed, "expired": expired, "busy": busy}

    def start_recovery_worker(self, interval_seconds: float = 5.0) -> threading.Event:
        if interval_seconds <= 0:
            raise ValueError("recovery interval must be positive")
        stop = threading.Event()

        def run() -> None:
            while not stop.is_set():
                try:
                    self.recover_approved_drills()
                    self.recover_incomplete_shutdowns()
                except Exception as error:
                    print(f"recovery worker error: {type(error).__name__}: {error}")
                stop.wait(interval_seconds)

        threading.Thread(target=run, name="asv-recovery", daemon=True).start()
        return stop

    def recover_approved_drills(self, *, asynchronous: bool = True) -> int:
        """Start or reconcile drills interrupted after approval was committed."""
        recovered = 0
        with self._drill_lock:
            with self.store.connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM drill WHERE status='APPROVED' ORDER BY approved_at"
                ).fetchall()
            for row in rows:
                drill = dict(row)
                request = json.loads(drill["request_payload"])
                try:
                    run = self.get_run(drill["tenant_id"], drill["run_id"])
                except NotFoundError:
                    execution = self.start_synthetic_drill(
                        {
                            **request,
                            "_drill_id": drill["drill_id"],
                            "_run_id": drill["run_id"],
                        },
                        actor=drill["approved_by"] or "recovery-worker",
                        asynchronous=asynchronous,
                    )
                    run_id = execution["run_id"]
                else:
                    run_id = run["run_id"]
                    if not run.get("shutdown_requested_at"):
                        self.request_shutdown(
                            drill["tenant_id"], run_id,
                            actor=drill["approved_by"] or "recovery-worker",
                            idempotency_key=f"drill:{drill['drill_id']}",
                            asynchronous=asynchronous,
                            adapter=self._recovery_adapter(drill["tenant_id"], run_id),
                        )
                with self.store.connection() as connection:
                    connection.execute(
                        "UPDATE drill SET status='STARTED',run_id=? "
                        "WHERE tenant_id=? AND drill_id=? AND status='APPROVED'",
                        (run_id, drill["tenant_id"], drill["drill_id"]),
                    )
                recovered += 1
        return recovered

    def _recovery_adapter(self, tenant_id: str, run_id: str) -> ShutdownAdapter:
        with self.store.connection() as connection:
            row = connection.execute(
                "SELECT request_payload FROM drill WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
        if row is not None:
            request = json.loads(row["request_payload"])
            outcomes = request.get("outcomes")
            if isinstance(outcomes, dict) and set(outcomes) == set(PROBE_KINDS):
                return SyntheticAdapter(
                    {kind: ProbeResult(str(outcomes[kind])) for kind in PROBE_KINDS}
                )
        return self.adapter

    def _claim_shutdown_work(self, tenant_id: str, run_id: str) -> str | None:
        now = utc_now()
        lease_until = (datetime.now(UTC) + timedelta(seconds=self.recovery_lease_seconds)).isoformat()
        lease_owner = f"{self._worker_id}:{uuid.uuid4()}"
        with self.store.connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO shutdown_work VALUES (?,?,?,?,?,?,?,?)",
                (run_id, tenant_id, "PENDING", 0, None, None, None, now),
            )
            cursor = connection.execute(
                "UPDATE shutdown_work SET status='RUNNING',attempts=attempts+1,"
                "lease_owner=?,lease_expires_at=?,last_error=NULL,updated_at=? "
                "WHERE run_id=? AND status!='COMPLETE' AND "
                "(lease_owner IS NULL OR lease_expires_at<=?)",
                (lease_owner, lease_until, now, run_id, now),
            )
        return lease_owner if cursor.rowcount == 1 else None

    def _renew_shutdown_lease(self, run_id: str, lease_owner: str) -> None:
        lease_until = (datetime.now(UTC) + timedelta(seconds=self.recovery_lease_seconds)).isoformat()
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE shutdown_work SET lease_expires_at=?,updated_at=? "
                "WHERE run_id=? AND lease_owner=?",
                (lease_until, utc_now(), run_id, lease_owner),
            )

    def _finish_shutdown_work(self, run_id: str, lease_owner: str) -> None:
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE shutdown_work SET status='COMPLETE',lease_owner=NULL,"
                "lease_expires_at=NULL,last_error=NULL,updated_at=? "
                "WHERE run_id=? AND lease_owner=?",
                (utc_now(), run_id, lease_owner),
            )

    def _fail_shutdown_work(self, run_id: str, lease_owner: str, error: Exception) -> None:
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE shutdown_work SET status='COMPLETE',lease_owner=NULL,"
                "lease_expires_at=NULL,last_error=?,updated_at=? "
                "WHERE run_id=? AND lease_owner=?",
                (f"{type(error).__name__}: {error}", utc_now(), run_id, lease_owner),
            )

    @staticmethod
    def _deadline_expired(run: dict[str, Any]) -> bool:
        deadline = run.get("deadline_at")
        return bool(deadline and datetime.fromisoformat(str(deadline)) <= datetime.now(UTC))

    def _expire_shutdown(self, run: dict[str, Any], lease_owner: str) -> None:
        self._transition(
            run, ShutdownState.UNKNOWN, "shutdown.recovery.deadline.exceeded",
            {"deadline_at": run.get("deadline_at")}, "recovery-worker", stopped=True,
        )
        self._finish_shutdown_work(run["run_id"], lease_owner)

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

    def _save_probe(
        self,
        run: dict[str, Any],
        observation: Any,
        event_type: str = "shutdown.probe.result",
        actor: str = "probe-runner",
    ) -> None:
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
        self._append_event(run, event_type, observation.to_dict(), actor)

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

    def request_restart(self, tenant_id: str, run_id: str, actor: str) -> dict[str, Any]:
        run = self._adapter_run(tenant_id, run_id)
        if ShutdownState(run["state"]) not in TERMINAL_STATES:
            raise ConflictError("restart probe requires a terminal shutdown state")
        existing = [probe for probe in run["probes"] if probe["kind"] == "restart"]
        if existing:
            return existing[-1]
        observation = self.adapter.restart(run)
        self._save_probe(run, observation, "shutdown.restart.probe.result", actor)
        return observation.to_dict()

    def report(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self._report_lock:
            with self.store.connection() as connection:
                existing = connection.execute(
                    "SELECT payload,signature FROM report WHERE tenant_id=? AND run_id=?",
                    (tenant_id, run_id),
                ).fetchone()
            if existing:
                return {"report": json.loads(existing["payload"]), "signature": json.loads(existing["signature"])}
            run = self.get_run(tenant_id, run_id)
            if ShutdownState(run["state"]) not in TERMINAL_STATES:
                raise ConflictError("report is available only after shutdown reaches a terminal state")
            evidence = self.evidence(tenant_id, run_id)
            report = {
                "report_version": "1.0",
                "generated_at": utc_now(),
                "tenant_id": tenant_id,
                "run_id": run_id,
                "agent_id": run["agent_id"],
                "correlation_id": run["correlation_id"],
                "policy_version": run["policy_version"],
                "shutdown_state": run["state"],
                "started_at": run["started_at"],
                "stopped_at": run["stopped_at"],
                "probe_results": {probe["kind"]: probe["result"] for probe in run["probes"]},
                "delegated_jobs": run["delegated_jobs"],
                "evidence_manifest": evidence["manifest"],
            }
            signature = self.ledger.sign_payload(report)
            with self.store.connection() as connection:
                connection.execute(
                    "INSERT INTO report VALUES (?,?,?,?,?)",
                    (run_id, tenant_id, report["generated_at"], canonical_json(report), canonical_json(signature)),
                )
            self._append_event(
                run,
                "shutdown.report.signed",
                {"report_hash": hashlib.sha256(canonical_json(report).encode()).hexdigest(), "key_id": signature["key_id"]},
                actor="evidence-writer",
            )
            return {"report": report, "signature": signature}

    def start_synthetic_drill(
        self,
        request: dict[str, Any],
        *,
        actor: str,
        asynchronous: bool = True,
    ) -> dict[str, Any]:
        tenant_id, agent_id = self._validate_drill_request(request)
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
        drill_id = str(request.get("_drill_id") or uuid.uuid4())
        run = self.create_run(
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "identity_ref": f"synthetic/drill/{drill_id}",
                "policy_version": int(request.get("policy_version", 1)),
                "_run_id": request.get("_run_id"),
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

    def _validate_drill_request(self, request: dict[str, Any]) -> tuple[str, str]:
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
        if raw_outcomes is not None:
            if not isinstance(raw_outcomes, dict) or set(raw_outcomes) != set(PROBE_KINDS):
                raise ValidationError(
                    "simulated outcomes must contain exactly: " + ", ".join(PROBE_KINDS)
                )
            try:
                for result in raw_outcomes.values():
                    ProbeResult(str(result))
            except ValueError as error:
                raise ValidationError("probe outcomes must be PASS, FAIL, PARTIAL, or UNKNOWN") from error
        return tenant_id, agent_id

    def request_drill(self, request: dict[str, Any], actor: str) -> dict[str, Any]:
        tenant_id, agent_id = self._validate_drill_request(request)
        drill_id = str(uuid.uuid4())
        planned_run_id = str(uuid.uuid4())
        requested_at = utc_now()
        payload = {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "policy_version": int(request.get("policy_version", 1)),
        }
        if "outcomes" in request:
            payload["outcomes"] = request["outcomes"]
        with self.store.connection() as connection:
            connection.execute(
                "INSERT INTO drill VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    drill_id, tenant_id, agent_id, actor, requested_at,
                    None, None, None, None, None, "PENDING_APPROVAL",
                    canonical_json(payload), planned_run_id,
                ),
            )
        return {
            "drill_id": drill_id,
            "status": "PENDING_APPROVAL",
            "requested_by": actor,
            "requested_at": requested_at,
            "run_id": planned_run_id,
        }

    def get_drill(self, tenant_id: str, drill_id: str) -> dict[str, Any]:
        with self.store.connection() as connection:
            row = connection.execute(
                "SELECT * FROM drill WHERE tenant_id=? AND drill_id=?", (tenant_id, drill_id)
            ).fetchone()
        if row is None:
            raise NotFoundError("drill not found for tenant")
        drill = dict(row)
        drill["request_payload"] = json.loads(drill["request_payload"])
        if drill["run_id"] and drill["status"] == "STARTED":
            drill["run_state"] = self.get_run(tenant_id, drill["run_id"])["state"]
        return drill

    def approve_drill(
        self, tenant_id: str, drill_id: str, actor: str, *, asynchronous: bool = True
    ) -> dict[str, Any]:
        with self._drill_lock:
            drill = self.get_drill(tenant_id, drill_id)
            if drill["status"] != "PENDING_APPROVAL":
                if drill["status"] == "STARTED" and drill["approved_by"] == actor:
                    return drill
                raise ConflictError(f"drill cannot be approved from status {drill['status']}")
            if drill["requested_by"] == actor:
                raise ConflictError("drill approver must differ from drill author")
            approved_at = utc_now()
            with self.store.connection() as connection:
                connection.execute(
                    "UPDATE drill SET status='APPROVED',approved_by=?,approved_at=? WHERE tenant_id=? AND drill_id=?",
                    (actor, approved_at, tenant_id, drill_id),
                )
            request = {
                **drill["request_payload"],
                "_drill_id": drill_id,
                "_run_id": drill["run_id"],
            }
            try:
                execution = self.start_synthetic_drill(
                    request, actor=actor, asynchronous=asynchronous
                )
            except Exception:
                with self.store.connection() as connection:
                    connection.execute(
                        "UPDATE drill SET status='FAILED' WHERE tenant_id=? AND drill_id=?",
                        (tenant_id, drill_id),
                    )
                raise
            with self.store.connection() as connection:
                connection.execute(
                    "UPDATE drill SET status='STARTED',run_id=? WHERE tenant_id=? AND drill_id=?",
                    (execution["run_id"], tenant_id, drill_id),
                )
            return {**execution, "approved_by": actor, "approved_at": approved_at}

    def reject_drill(self, tenant_id: str, drill_id: str, actor: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValidationError("rejection reason is required")
        with self._drill_lock:
            drill = self.get_drill(tenant_id, drill_id)
            if drill["status"] != "PENDING_APPROVAL":
                raise ConflictError(f"drill cannot be rejected from status {drill['status']}")
            if drill["requested_by"] == actor:
                raise ConflictError("drill reviewer must differ from drill author")
            rejected_at = utc_now()
            with self.store.connection() as connection:
                connection.execute(
                    "UPDATE drill SET status='REJECTED',rejected_by=?,rejected_at=?,rejection_reason=? WHERE tenant_id=? AND drill_id=?",
                    (actor, rejected_at, reason.strip(), tenant_id, drill_id),
                )
        return self.get_drill(tenant_id, drill_id)

    @staticmethod
    def _shutdown_receipt(run: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run["run_id"],
            "correlation_id": run["correlation_id"],
            "requested_at": run["shutdown_requested_at"],
            "deadline_at": run["deadline_at"],
            "state": run["state"],
        }
