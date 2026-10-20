from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Callable

from .store import Store, utc_now


EventSender = Callable[[dict], None]


class HttpSiemSink:
    def __init__(self, url: str, bearer_token: str) -> None:
        self.url = url
        self.bearer_token = bearer_token

    def send(self, event: dict) -> None:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(event, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Content-Type": "application/json",
                "Idempotency-Key": event["idempotency_key"],
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"SIEM returned HTTP {response.status}")
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"SIEM returned HTTP {error.code}") from error


class OutboxPublisher:
    def __init__(
        self,
        store: Store,
        sender: EventSender,
        *,
        max_attempts: int = 8,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 300.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if base_backoff_seconds < 0 or max_backoff_seconds < base_backoff_seconds:
            raise ValueError("invalid SIEM backoff configuration")
        self.store = store
        self.sender = sender
        self.max_attempts = max_attempts
        self.base_backoff_seconds = base_backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.clock = clock or (lambda: datetime.now(UTC))

    def publish_batch(self, limit: int = 100) -> dict[str, int]:
        now = self.clock()
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT outbox.event_id,outbox.payload,outbox.attempts,"
                "COALESCE(cycle.attempts_baseline,0) AS attempts_baseline "
                "FROM event_outbox AS outbox "
                "LEFT JOIN event_delivery_state AS delivery "
                "ON delivery.event_id=outbox.event_id "
                "LEFT JOIN event_retry_cycle AS cycle "
                "ON cycle.event_id=outbox.event_id "
                "WHERE outbox.status='PENDING' AND "
                "(delivery.next_attempt_at IS NULL OR delivery.next_attempt_at<=?) "
                "ORDER BY outbox.created_at,outbox.event_id LIMIT ?",
                (now.isoformat(), limit),
            ).fetchall()
        delivered = 0
        failed = 0
        dead_lettered = 0
        for row in rows:
            try:
                self.sender(json.loads(row["payload"]))
            except Exception as error:
                failed += 1
                attempts = int(row["attempts"]) + 1
                cycle_attempts = attempts - int(row["attempts_baseline"])
                with self.store.connection() as connection:
                    if cycle_attempts >= self.max_attempts:
                        dead_lettered += 1
                        connection.execute(
                            "UPDATE event_outbox SET status='DEAD_LETTER',attempts=?,"
                            "last_error=? WHERE event_id=?",
                            (attempts, str(error)[:1000], row["event_id"]),
                        )
                        connection.execute(
                            "INSERT INTO event_delivery_state VALUES (?,?,?) "
                            "ON CONFLICT(event_id) DO UPDATE SET "
                            "next_attempt_at=NULL,dead_lettered_at=excluded.dead_lettered_at",
                            (row["event_id"], None, now.isoformat()),
                        )
                    else:
                        delay = min(
                            self.max_backoff_seconds,
                            self.base_backoff_seconds * (2 ** (cycle_attempts - 1)),
                        )
                        next_attempt_at = (now + timedelta(seconds=delay)).isoformat()
                        connection.execute(
                            "UPDATE event_outbox SET attempts=?,last_error=? WHERE event_id=?",
                            (attempts, str(error)[:1000], row["event_id"]),
                        )
                        connection.execute(
                            "INSERT INTO event_delivery_state VALUES (?,?,NULL) "
                            "ON CONFLICT(event_id) DO UPDATE SET "
                            "next_attempt_at=excluded.next_attempt_at,dead_lettered_at=NULL",
                            (row["event_id"], next_attempt_at),
                        )
            else:
                delivered += 1
                with self.store.connection() as connection:
                    connection.execute(
                        "UPDATE event_outbox SET status='DELIVERED',attempts=attempts+1,last_error=NULL,delivered_at=? WHERE event_id=?",
                        (utc_now(), row["event_id"]),
                    )
                    connection.execute(
                        "DELETE FROM event_delivery_state WHERE event_id=?",
                        (row["event_id"],),
                    )
                    connection.execute(
                        "DELETE FROM event_retry_cycle WHERE event_id=?",
                        (row["event_id"],),
                    )
        return {
            "selected": len(rows),
            "delivered": delivered,
            "failed": failed,
            "dead_lettered": dead_lettered,
        }

    def run_forever(self, interval_seconds: float = 5.0) -> None:
        while True:
            self.publish_batch()
            time.sleep(interval_seconds)

    def start(self, interval_seconds: float = 5.0) -> threading.Thread:
        thread = threading.Thread(
            target=self.run_forever, args=(interval_seconds,), daemon=True, name="asv-siem-outbox"
        )
        thread.start()
        return thread
