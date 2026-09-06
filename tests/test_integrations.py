import json
import unittest

from asv.domain import ProbeResult
from asv.integrations import (
    HttpResult,
    IntegrationError,
    KafkaRestFenceProbe,
    KubernetesClient,
    KubernetesKafkaAdapter,
    PARENT_RUN_LABEL,
    RUN_LABEL,
)
from asv.service import ControlPlane
from asv.store import Store


RUN = {
    "run_id": "12345678-1234-1234-1234-123456789abc",
    "identity_ref": "synthetic/test",
    "agent": {"namespace": "asv-synthetic"},
}


class FakeKubernetes:
    def __init__(self):
        self.fences = []
        self.suspended = []
        self.deleted = []

    def create_fence(self, namespace, run_id):
        self.fences.append((namespace, run_id))

    def list_resources(self, namespace, resource, label_selector):
        label, _ = label_selector.split("=", 1)
        if resource == "pods" and label == RUN_LABEL:
            return [{"metadata": {"name": "parent-pod"}, "status": {"phase": "Running"}}]
        if resource == "jobs" and label == PARENT_RUN_LABEL:
            return [{"metadata": {"name": "child-job"}, "status": {"active": 1}}]
        if resource == "cronjobs" and label == PARENT_RUN_LABEL:
            return [{"metadata": {"name": "child-cron"}, "status": {"active": []}}]
        return []

    def suspend_cronjob(self, namespace, name):
        self.suspended.append((namespace, name))

    def delete(self, namespace, resource, name):
        self.deleted.append((namespace, resource, name))


class KubernetesAdapterTest(unittest.TestCase):
    def test_kubernetes_client_creates_idempotent_run_and_child_fences(self):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, body))
            return HttpResult(201, {})

        client = KubernetesClient("https://kubernetes.example.test", "token", transport=transport)
        client.create_fence("asv-synthetic", RUN["run_id"])
        self.assertEqual(2, len(calls))
        manifests = [json.loads(call[3]) for call in calls]
        selectors = [manifest["spec"]["podSelector"]["matchLabels"] for manifest in manifests]
        self.assertIn({RUN_LABEL: RUN["run_id"]}, selectors)
        self.assertIn({PARENT_RUN_LABEL: RUN["run_id"]}, selectors)

    def test_fences_and_recursively_stops_parent_and_child_work(self):
        kubernetes = FakeKubernetes()
        adapter = KubernetesKafkaAdapter(kubernetes, {"asv-synthetic"})
        fence = adapter.fence(RUN)
        stopped = adapter.stop_process(RUN)
        self.assertTrue(fence["accepted"])
        self.assertEqual([("asv-synthetic", RUN["run_id"])], kubernetes.fences)
        self.assertEqual([("asv-synthetic", "child-cron")], kubernetes.suspended)
        self.assertIn(("asv-synthetic", "pods", "parent-pod"), kubernetes.deleted)
        self.assertIn(("asv-synthetic", "jobs", "child-job"), kubernetes.deleted)
        self.assertEqual(1, stopped["pods_deleted"])
        self.assertEqual(1, stopped["jobs_deleted"])

    def test_process_and_delegation_probes_report_remaining_work(self):
        adapter = KubernetesKafkaAdapter(FakeKubernetes(), {"asv-synthetic"})
        self.assertEqual(ProbeResult.FAIL, adapter.probe("process", RUN).result)
        self.assertEqual(ProbeResult.FAIL, adapter.probe("delegation", RUN).result)
        self.assertEqual(ProbeResult.UNKNOWN, adapter.probe("credential", RUN).result)

    def test_non_allowlisted_namespace_is_rejected_before_api_use(self):
        adapter = KubernetesKafkaAdapter(FakeKubernetes(), {"asv-synthetic"})
        run = {**RUN, "agent": {"namespace": "production"}}
        with self.assertRaises(IntegrationError):
            adapter.fence(run)

    def test_discovered_children_persist_in_run_registry(self):
        store = Store()
        self.addCleanup(store.close)
        adapter = KubernetesKafkaAdapter(FakeKubernetes(), {"asv-synthetic"})
        control = ControlPlane(store, signing_key=b"test-key", adapter=adapter)
        agent = control.register_agent(
            {
                "tenant_id": "tenant-a",
                "name": "agent",
                "image_digest": "sha256:" + "a" * 64,
                "namespace": "asv-synthetic",
                "scope_owner": "security@example.com",
                "declared_scope": {"synthetic_only": True},
            }
        )
        run = control.create_run(
            {"tenant_id": "tenant-a", "agent_id": agent["agent_id"], "identity_ref": "synthetic/test"}
        )
        control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="week-3", asynchronous=False
        )
        jobs = control.get_run("tenant-a", run["run_id"])["delegated_jobs"]
        self.assertEqual({"child-job", "child-cron"}, {job["external_id"] for job in jobs})
        self.assertEqual({"ACTIVE", "INACTIVE"}, {job["state"] for job in jobs})


class KafkaFenceProbeTest(unittest.TestCase):
    def probe(self, statuses):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, body))
            return HttpResult(statuses[len(calls) - 1], {})

        probe = KafkaRestFenceProbe(
            "https://kafka-rest.example.test",
            "asv.synthetic",
            "asv-fenced-probe",
            "probe-1",
            "synthetic-token",
            transport=transport,
        )
        return probe.probe(RUN), calls

    def test_publish_and_consume_denial_is_pass(self):
        observation, calls = self.probe([403, 403])
        self.assertEqual(ProbeResult.PASS, observation.result)
        self.assertEqual(["POST", "GET"], [call[0] for call in calls])
        self.assertIn("/topics/asv.synthetic", calls[0][1])
        self.assertIn("/consumers/asv-fenced-probe/instances/probe-1/records", calls[1][1])

    def test_any_accepted_operation_is_fail(self):
        observation, _ = self.probe([200, 403])
        self.assertEqual(ProbeResult.FAIL, observation.result)

    def test_unobservable_status_is_unknown(self):
        observation, _ = self.probe([503, 403])
        self.assertEqual(ProbeResult.UNKNOWN, observation.result)


if __name__ == "__main__":
    unittest.main()
