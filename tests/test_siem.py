import unittest

from asv.service import ControlPlane
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

        publisher = OutboxPublisher(self.store, fail_once)
        self.assertEqual(1, publisher.publish_batch()["failed"])
        self.assertEqual(1, publisher.publish_batch()["delivered"])
        with self.store.connection() as connection:
            row = connection.execute("SELECT status,attempts,last_error FROM event_outbox").fetchone()
        self.assertEqual("DELIVERED", row["status"])
        self.assertEqual(2, row["attempts"])
        self.assertIsNone(row["last_error"])


if __name__ == "__main__":
    unittest.main()
