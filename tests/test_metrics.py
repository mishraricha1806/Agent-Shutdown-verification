import unittest

from asv.adapters import SyntheticAdapter
from asv.auth import Principal, TokenAuthenticator
from asv.domain import PROBE_KINDS, ProbeResult
from asv.metrics import MetricsExporter
from asv.server import ApiHandler
from asv.service import ControlPlane
from asv.store import Store


DIGEST = "sha256:" + "a" * 64


class MetricsExporterTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.close)
        adapter = SyntheticAdapter({kind: ProbeResult.PASS for kind in PROBE_KINDS})
        self.control = ControlPlane(self.store, signing_key=b"test-key", adapter=adapter)

    def _run(self, tenant_id):
        agent = self.control.register_agent(
            {
                "tenant_id": tenant_id,
                "name": "metrics-agent",
                "image_digest": DIGEST,
                "namespace": "asv-synthetic",
                "scope_owner": "security@example.com",
                "declared_scope": {"synthetic_only": True},
            }
        )
        return self.control.create_run(
            {
                "tenant_id": tenant_id,
                "agent_id": agent["agent_id"],
                "identity_ref": f"synthetic/{tenant_id}",
            }
        )

    def test_metrics_are_tenant_scoped_and_have_bounded_labels(self):
        run = self._run("tenant-a")
        self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator",
            idempotency_key="metrics-test", asynchronous=False,
        )
        self._run("tenant-b")

        rendered = MetricsExporter(self.store).render("tenant-a")

        self.assertIn('asv_runs{state="VERIFIED"} 1', rendered)
        self.assertIn('asv_runs{state="RUNNING"} 0', rendered)
        self.assertIn(
            'asv_probe_results_total{kind="credential",result="PASS"} 1', rendered
        )
        self.assertIn('asv_shutdown_phase_events_total{phase="completed"} 1', rendered)
        self.assertIn("asv_evidence_chain_failures 0", rendered)
        self.assertNotIn("tenant-a", rendered)
        self.assertNotIn("tenant-b", rendered)
        self.assertNotIn(run["run_id"], rendered)

    def test_evidence_tampering_is_visible(self):
        run = self._run("tenant-a")
        with self.store.connection() as connection:
            connection.execute(
                "UPDATE evidence SET payload='{}' WHERE run_id=? AND sequence_no=1",
                (run["run_id"],),
            )

        rendered = MetricsExporter(self.store).render("tenant-a")
        self.assertIn("asv_evidence_chain_failures 1", rendered)


class MetricsEndpointTest(unittest.TestCase):
    def test_metrics_endpoint_requires_an_operator_token(self):
        secret = "a-secure-test-secret-with-at-least-32-bytes"
        store = Store()
        self.addCleanup(store.close)
        authenticator = TokenAuthenticator(secret.encode())
        handler = ApiHandler.__new__(ApiHandler)
        handler.path = "/metrics"
        handler.authenticator = authenticator
        handler.metrics_exporter = MetricsExporter(store)

        errors = []
        handler.headers = {}
        handler._send_error = errors.append
        handler.do_GET()
        self.assertEqual("AuthenticationError", type(errors[0]).__name__)

        token = authenticator.issue(
            Principal("tenant-a", "auditor@example.com", frozenset({"auditor"}))
        )
        responses = []
        handler.headers = {"Authorization": f"Bearer {token}"}
        handler._send_text = lambda status, body, content_type: responses.append(
            (status, body, content_type)
        )
        handler.do_GET()

        status, body, content_type = responses[0]
        self.assertEqual(200, status.value)
        self.assertEqual("text/plain; version=0.0.4; charset=utf-8", content_type)
        self.assertIn("# HELP asv_runs", body)


if __name__ == "__main__":
    unittest.main()
