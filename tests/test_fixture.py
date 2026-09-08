import os
import unittest
from unittest.mock import patch

from fixtures import adversarial_agent


class AdversarialFixtureTest(unittest.TestCase):
    def test_exercises_only_configured_synthetic_boundaries(self):
        environment = {
            "ASV_FIXTURE_NAMESPACE": "asv-synthetic",
            "ASV_FIXTURE_KAFKA_REST_URL": "https://kafka.test",
            "ASV_FIXTURE_KAFKA_TOPIC": "asv.synthetic",
            "ASV_FIXTURE_KAFKA_TOKEN": "kafka-token",
            "ASV_FIXTURE_CREDENTIAL_BROKER_URL": "https://broker.test",
            "ASV_FIXTURE_CREDENTIAL_RESOURCE": "asv.synthetic/resource",
            "ASV_FIXTURE_CREDENTIAL_TOKEN": "credential-token",
            "ASV_FIXTURE_IDENTITY_REF": "synthetic/fixture",
            "ASV_FIXTURE_EGRESS_GATEWAY_URL": "https://egress.test",
            "ASV_FIXTURE_EGRESS_DESTINATION": "https://target.test",
            "ASV_FIXTURE_EGRESS_TOKEN": "egress-token",
        }
        calls = []
        with patch.dict(os.environ, environment, clear=True), patch.object(
            adversarial_agent, "create_child_job"
        ) as create_child, patch.object(
            adversarial_agent, "request", side_effect=lambda *args: calls.append(args) or 201
        ):
            adversarial_agent.exercise_boundaries("12345678-1234-1234-1234-123456789abc")
        create_child.assert_called_once_with(
            "12345678-1234-1234-1234-123456789abc", "asv-synthetic"
        )
        self.assertEqual(3, len(calls))
        self.assertIn("/topics/asv.synthetic", calls[0][1])
        self.assertIn("/v1/grants", calls[1][1])
        self.assertIn("/v1/connections", calls[2][1])

    def test_rejects_non_synthetic_namespace_before_creating_child(self):
        with patch.dict(os.environ, {"ASV_FIXTURE_NAMESPACE": "production"}, clear=True), patch.object(
            adversarial_agent, "create_child_job", side_effect=RuntimeError("blocked")
        ):
            with self.assertRaises(RuntimeError):
                adversarial_agent.exercise_boundaries("run-id")


if __name__ == "__main__":
    unittest.main()
