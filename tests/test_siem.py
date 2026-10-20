import unittest
from datetime import UTC, datetime, timedelta

from asv.service import ControlPlane, NotFoundError
from asv.siem import OutboxPublisher
from asv.store import Store


class OutboxPublisherTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.close)
        self.control = ControlPlane(self.store, signing_key=b"test-key")
        agent = self.control.register_agent(
            {
                "tenant_id": "tenant-a",
                "name": "agent",
                "image_digest": "sha256:" + "a" * 64,
                "namespace": "asv-synthetic",
                "scope_owner": "security@example.com",
                "declared_scope": {"synthetic_only": True},
            }
        )
        self.run = self.control.create_run(
            {"tenant_id": "tenant-a", "agent_id": agent["agent_id"], "identity_ref": "synthetic/test"}
        )

    def test_outbox_is_written_transactionally_and_delivered(self):
        sent = []
        publisher = OutboxPublisher(self.store, sent.append)
        result = publisher.publish_batch()
        self.assertEqual(1, result["delivered"])
        self.assertEqual("agent.run.started", sent[0]["event_type"])
        with self.store.connection() as connection:
            row = connection.execute("SELECT status,attempts FROM event_outbox").fetchone()
        self.assertEqual("DELIVERED", row["status"])
        self.assertEqual(1, row["attempts"])

    def test_failed_delivery_remains_pending_and_retries(self):
        attempts = []

        def fail_once(event):
            attempts.append(event["event_id"])
            if len(attempts) == 1:
                raise RuntimeError("temporary SIEM failure")

        publisher = OutboxPublisher(self.store, fail_once, base_backoff_seconds=0)
        self.assertEqual(1, publisher.publish_batch()["failed"])
        self.assertEqual(1, publisher.publish_batch()["delivered"])
        with self.store.connection() as connection:
            row = connection.execute("SELECT status,attempts,last_error FROM event_outbox").fetchone()
        self.assertEqual("DELIVERED", row["status"])
        self.assertEqual(2, row["attempts"])
        self.assertIsNone(row["last_error"])

    def test_backoff_defers_retries_then_dead_letters(self):
        current = [datetime(2026, 1, 1, tzinfo=UTC)]

        def fail(_event):
            raise RuntimeError("SIEM unavailable")

        publisher = OutboxPublisher(
            self.store,
            fail,
            max_attempts=3,
            base_backoff_seconds=10,
            max_backoff_seconds=60,
            clock=lambda: current[0],
        )
        first = publisher.publish_batch()
        self.assertEqual(1, first["failed"])
        self.assertEqual(0, publisher.publish_batch()["selected"])

        current[0] += timedelta(seconds=10)
        second = publisher.publish_batch()
        self.assertEqual(1, second["failed"])
        self.assertEqual(0, second["dead_lettered"])

        current[0] += timedelta(seconds=20)
        third = publisher.publish_batch()
        self.assertEqual(1, third["failed"])
        self.assertEqual(1, third["dead_lettered"])
        with self.store.connection() as connection:
            row = connection.execute(
                "SELECT status,attempts,last_error FROM event_outbox"
            ).fetchone()
        self.assertEqual("DEAD_LETTER", row["status"])
        self.assertEqual(3, row["attempts"])
        self.assertEqual("SIEM unavailable", row["last_error"])

    def test_dead_letter_can_be_audited_and_requeued(self):
        publisher = OutboxPublisher(
            self.store,
            lambda _event: (_ for _ in ()).throw(RuntimeError("permanent failure")),
            max_attempts=1,
            base_backoff_seconds=0,
        )
        result = publisher.publish_batch()
        self.assertEqual(1, result["dead_lettered"])
        dead_letters = self.control.dead_letters("tenant-a")
        self.assertEqual(1, dead_letters["count"])

        event_id = dead_letters["dead_letters"][0]["event_id"]
        self.assertEqual(0, self.control.dead_letters("tenant-b")["count"])
        with self.assertRaises(NotFoundError):
            self.control.requeue_dead_letter("tenant-b", event_id, "intruder@example.com")
        receipt = self.control.requeue_dead_letter(
            "tenant-a", event_id, "responder@example.com"
        )
        self.assertEqual("PENDING", receipt["status"])
        self.assertEqual(0, self.control.dead_letters("tenant-a")["count"])
        with self.store.connection() as connection:
            requeued = connection.execute(
                "SELECT attempts FROM event_outbox WHERE event_id=?", (event_id,)
            ).fetchone()
        self.assertEqual(1, requeued["attempts"])

        delivered = OutboxPublisher(self.store, lambda _event: None).publish_batch()
        self.assertEqual(2, delivered["delivered"])
        with self.store.connection() as connection:
            retried = connection.execute(
                "SELECT attempts FROM event_outbox WHERE event_id=?", (event_id,)
            ).fetchone()
        self.assertEqual(2, retried["attempts"])
        events = self.control.export_events("tenant-a", self.run["run_id"])["events"]
        self.assertEqual(
            1, sum(event["event_type"] == "siem.dead_letter.requeued" for event in events)
        )


if __name__ == "__main__":
    unittest.main()
