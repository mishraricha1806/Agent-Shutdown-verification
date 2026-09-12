from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS agent (
  agent_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  image_digest TEXT NOT NULL,
  namespace TEXT NOT NULL,
  scope_owner TEXT NOT NULL,
  declared_scope TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run (
  run_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agent(agent_id),
  parent_run_id TEXT NULL REFERENCES run(run_id),
  identity_ref TEXT NOT NULL,
  started_at TEXT NOT NULL,
  stopped_at TEXT NULL,
  state TEXT NOT NULL,
  correlation_id TEXT NOT NULL UNIQUE,
  policy_version INTEGER NOT NULL,
  shutdown_requested_at TEXT NULL,
  deadline_at TEXT NULL,
  shutdown_idempotency_key TEXT NULL,
  UNIQUE(tenant_id, run_id)
);
CREATE TABLE IF NOT EXISTS probe (
  probe_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES run(run_id),
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  result TEXT NOT NULL,
  observed TEXT NOT NULL,
  authority TEXT NOT NULL,
  confidence TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS delegated_job (
  job_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES run(run_id),
  system TEXT NOT NULL,
  external_id TEXT NOT NULL,
  state TEXT NOT NULL,
  discovered_at TEXT NOT NULL,
  UNIQUE(run_id, system, external_id)
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL REFERENCES run(run_id),
  sequence_no INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  actor TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  correlation_id TEXT NOT NULL,
  UNIQUE(run_id, sequence_no)
);
CREATE TABLE IF NOT EXISTS event_outbox (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  last_error TEXT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT NULL
);
CREATE TABLE IF NOT EXISTS report (
  run_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drill (
  drill_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  approved_by TEXT NULL,
  approved_at TEXT NULL,
  rejected_by TEXT NULL,
  rejected_at TEXT NULL,
  rejection_reason TEXT NULL,
  status TEXT NOT NULL,
  request_payload TEXT NOT NULL,
  run_id TEXT NULL
);
CREATE TABLE IF NOT EXISTS shutdown_work (
  run_id TEXT PRIMARY KEY REFERENCES run(run_id),
  tenant_id TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  lease_owner TEXT NULL,
  lease_expires_at TEXT NULL,
  last_error TEXT NULL,
  updated_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, database: str = ":memory:") -> None:
        self.database = database
        self._lock = threading.RLock()
        if database == ":memory:":
            self._memory_connection = self._new_connection(database)
        else:
            Path(database).parent.mkdir(parents=True, exist_ok=True)
            self._memory_connection = None
        with self.connection() as connection:
            connection.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            if self._memory_connection is not None:
                self._memory_connection.close()
                self._memory_connection = None

    @staticmethod
    def _new_connection(database: str) -> sqlite3.Connection:
        connection = sqlite3.connect(database, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._memory_connection or self._new_connection(self.database)
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                if self._memory_connection is None:
                    connection.close()

    @staticmethod
    def row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        for field in ("declared_scope", "observed", "payload"):
            if field in value:
                value[field] = json.loads(value[field])
        return value
