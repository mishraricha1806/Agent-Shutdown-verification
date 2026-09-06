from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
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
    def __init__(self, store: Store, sender: EventSender) -> None:
        self.store = store
        self.sender = sender

    def publish_batch(self, limit: int = 100) -> dict[str, int]:
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT event_id,payload FROM event_outbox WHERE status='PENDING' ORDER BY created_at,event_id LIMIT ?",
                (limit,),
            ).fetchall()
        delivered = 0
        failed = 0
        for row in rows:
            try:
                self.sender(json.loads(row["payload"]))
            except Exception as error:
                failed += 1
                with self.store.connection() as connection:
                    connection.execute(
                        "UPDATE event_outbox SET attempts=attempts+1,last_error=? WHERE event_id=?",
                        (str(error)[:1000], row["event_id"]),
                    )
            else:
                delivered += 1
                with self.store.connection() as connection:
                    connection.execute(
                        "UPDATE event_outbox SET status='DELIVERED',attempts=attempts+1,last_error=NULL,delivered_at=? WHERE event_id=?",
                        (utc_now(), row["event_id"]),
                    )
        return {"selected": len(rows), "delivered": delivered, "failed": failed}

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
