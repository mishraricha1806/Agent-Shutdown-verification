from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .domain import PROBE_KINDS, ProbeResult, ShutdownState
from .evidence import EvidenceLedger
from .store import Store


class MetricsExporter:
    """Render bounded-cardinality, tenant-scoped Prometheus metrics."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def render(self, tenant_id: str) -> str:
        lines: list[str] = []
        self._family(
            lines,
            "asv_runs",
            "Current runs by shutdown state.",
            "gauge",
            self._group_count("run", "state", tenant_id),
            (state.value for state in ShutdownState),
            "state",
        )

        probe_counts = self._pair_count("probe", "kind", "result", tenant_id)
        lines.extend(
            [
                "# HELP asv_probe_results_total Durable probe observations by boundary and result.",
                "# TYPE asv_probe_results_total counter",
            ]
        )
        for kind in (*PROBE_KINDS, "restart"):
            for result in ProbeResult:
                lines.append(
                    f'asv_probe_results_total{{kind="{kind}",result="{result.value}"}} '
                    f'{probe_counts.get((kind, result.value), 0)}'
                )

        self._family(
            lines,
            "asv_delegated_jobs",
            "Discovered delegated jobs by last observed state.",
            "gauge",
            self._group_count("delegated_job", "state", tenant_id),
            ("ACTIVE", "INACTIVE", "UNKNOWN"),
            "state",
        )
        self._family(
            lines,
            "asv_shutdown_work_items",
            "Persisted shutdown work items by worker status.",
            "gauge",
            self._group_count("shutdown_work", "status", tenant_id),
            ("PENDING", "RUNNING", "COMPLETE"),
            "status",
        )
        self._scalar(
            lines,
            "asv_orchestration_attempts_total",
            "Persisted shutdown orchestration attempts.",
            "counter",
            self._sum("shutdown_work", "attempts", tenant_id),
        )

        event_counts = self._event_counts(tenant_id)
        self._labeled_values(
            lines,
            "asv_shutdown_phase_events_total",
            "Durable shutdown phase events.",
            "counter",
            "phase",
            {
                "fenced": event_counts.get("shutdown.fenced", 0),
                "process_stop_sent": event_counts.get("shutdown.process.stop.sent", 0),
                "completed": event_counts.get("shutdown.completed", 0),
            },
        )
        self._labeled_values(
            lines,
            "asv_shutdown_recovery_events_total",
            "Durable shutdown recovery events.",
            "counter",
            "outcome",
            {
                "resumed": event_counts.get("shutdown.recovery.resumed", 0),
                "deadline_exceeded": event_counts.get(
                    "shutdown.recovery.deadline.exceeded", 0
                ),
            },
        )

        self._scalar(
            lines,
            "asv_evidence_chain_failures",
            "Runs whose current evidence hash chain fails verification.",
            "gauge",
            self._evidence_chain_failures(tenant_id),
        )
        self._family(
            lines,
            "asv_siem_outbox_events",
            "SIEM outbox events by delivery status.",
            "gauge",
            self._group_count("event_outbox", "status", tenant_id),
            ("PENDING", "DELIVERED", "DEAD_LETTER"),
            "status",
        )
        self._scalar(
            lines,
            "asv_siem_delivery_attempts_total",
            "Persisted SIEM delivery attempts.",
            "counter",
            self._sum("event_outbox", "attempts", tenant_id),
        )
        return "\n".join(lines) + "\n"

    def _group_count(self, table: str, column: str, tenant_id: str) -> dict[str, int]:
        with self.store.connection() as connection:
            rows = connection.execute(
                f"SELECT {column},COUNT(*) AS count FROM {table} "
                f"WHERE tenant_id=? GROUP BY {column}",
                (tenant_id,),
            ).fetchall()
        return {str(row[column]): int(row["count"]) for row in rows}

    def _pair_count(
        self, table: str, first: str, second: str, tenant_id: str
    ) -> dict[tuple[str, str], int]:
        with self.store.connection() as connection:
            rows = connection.execute(
                f"SELECT {first},{second},COUNT(*) AS count FROM {table} "
                f"WHERE tenant_id=? GROUP BY {first},{second}",
                (tenant_id,),
            ).fetchall()
        return {
            (str(row[first]), str(row[second])): int(row["count"]) for row in rows
        }

    def _sum(self, table: str, column: str, tenant_id: str) -> int:
        with self.store.connection() as connection:
            row = connection.execute(
                f"SELECT COALESCE(SUM({column}),0) AS value FROM {table} WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        return int(row["value"])

    def _event_counts(self, tenant_id: str) -> dict[str, int]:
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT event_type,COUNT(*) AS count FROM evidence "
                "WHERE tenant_id=? GROUP BY event_type",
                (tenant_id,),
            ).fetchall()
        return {str(row["event_type"]): int(row["count"]) for row in rows}

    def _evidence_chain_failures(self, tenant_id: str) -> int:
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE tenant_id=? ORDER BY run_id,sequence_no",
                (tenant_id,),
            ).fetchall()
        records_by_run: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            record = self.store.row(row)
            assert record is not None
            records_by_run[str(record["run_id"])].append(record)
        return sum(
            not EvidenceLedger.verify_chain(records)[0]
            for records in records_by_run.values()
        )

    @staticmethod
    def _family(
        lines: list[str],
        name: str,
        help_text: str,
        metric_type: str,
        values: dict[str, int],
        labels: Iterable[str],
        label_name: str,
    ) -> None:
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"])
        for label in labels:
            lines.append(f'{name}{{{label_name}="{label}"}} {values.get(label, 0)}')

    @staticmethod
    def _labeled_values(
        lines: list[str],
        name: str,
        help_text: str,
        metric_type: str,
        label_name: str,
        values: dict[str, int],
    ) -> None:
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"])
        for label, value in values.items():
            lines.append(f'{name}{{{label_name}="{label}"}} {value}')

    @staticmethod
    def _scalar(
        lines: list[str], name: str, help_text: str, metric_type: str, value: int
    ) -> None:
        lines.extend(
            [
                f"# HELP {name} {help_text}",
                f"# TYPE {name} {metric_type}",
                f"{name} {value}",
            ]
        )
