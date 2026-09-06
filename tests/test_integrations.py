import json
import unittest

from asv.domain import ProbeObservation, ProbeResult
from asv.integrations import (
    CredentialBrokerProbe,
    EgressGatewayProbe,
    HttpResult,
    IntegrationError,
    KafkaRestFenceProbe,
    KubernetesClient,
    KubernetesKafkaAdapter,
    PARENT_RUN_LABEL,
    RUN_LABEL,
    RestartGatewayProbe,
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


class FakeBoundary:
    def __init__(self, kind):
        self.kind = kind
        self.fenced = False

    def fence(self, run):
        self.fenced = True
        return {"accepted": True}

    def probe(self, run):
        return ProbeObservation(
            self.kind, ProbeResult.PASS, {"synthetic": True}, "fake-boundary", "deterministic"
        )


class KubernetesAdapterTest(unittest.TestCase):
    def test_week4_boundaries_are_fenced_and_routed_to_their_probes(self):
        credential = FakeBoundary("credential")
        egress = FakeBoundary("network")
        adapter = KubernetesKafkaAdapter(
            FakeKubernetes(), {"asv-synthetic"}, credential=credential, egress=egress
        )
        fence = adapter.fence(RUN)
        self.assertTrue(credential.fenced)
        self.assertTrue(egress.fenced)
        self.assertIn("credential_broker", fence)
        self.assertIn("egress_gateway", fence)
        self.assertEqual(ProbeResult.PASS, adapter.probe("credential", RUN).result)
        self.assertEqual(ProbeResult.PASS, adapter.probe("network", RUN).result)

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


class CredentialBrokerProbeTest(unittest.TestCase):
    def probe(self, responses):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, body))
            status, response_body = responses[len(calls) - 1]
            return HttpResult(status, response_body)

        probe = CredentialBrokerProbe(
            "https://credentials.example.test",
            "asv.synthetic/resource",
            "controller-token",
            transport=transport,
        )
        return probe.probe(RUN), calls

    def test_denied_grant_and_revoked_existing_credential_is_pass(self):
        observation, calls = self.probe([(403, {}), (200, {"active": False, "remaining_ttl_seconds": 0})])
        self.assertEqual(ProbeResult.PASS, observation.result)
        self.assertEqual(0, observation.observed["remaining_ttl_seconds"])
        self.assertEqual(["POST", "GET"], [call[0] for call in calls])

    def test_new_grant_or_active_old_credential_is_fail(self):
        accepted, _ = self.probe([(201, {}), (200, {"active": False})])
        active, _ = self.probe([(403, {}), (200, {"active": True, "remaining_ttl_seconds": 30})])
        self.assertEqual(ProbeResult.FAIL, accepted.result)
        self.assertEqual(ProbeResult.FAIL, active.result)

    def test_ambiguous_broker_response_is_unknown(self):
        observation, _ = self.probe([(503, {}), (503, {})])
        self.assertEqual(ProbeResult.UNKNOWN, observation.result)

    def test_credential_fence_requests_grant_denial_and_revocation(self):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, json.loads(body)))
            return HttpResult(202, {})

        probe = CredentialBrokerProbe(
            "https://credentials.example.test", "resource", "token", transport=transport
        )
        result = probe.fence(RUN)
        self.assertTrue(result["accepted"])
        self.assertTrue(calls[0][3]["deny_new_grants"])
        self.assertTrue(calls[0][3]["revoke_existing"])


class EgressGatewayProbeTest(unittest.TestCase):
    def probe(self, responses):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, body))
            status, response_body = responses[len(calls) - 1]
            return HttpResult(status, response_body)

        probe = EgressGatewayProbe(
            "https://egress.example.test",
            "https://denied.example.test/asv",
            "controller-token",
            transport=transport,
        )
        return probe.probe(RUN), calls

    def test_new_and_existing_connection_denial_is_pass(self):
        observation, calls = self.probe([(200, {"allowed": False}), (403, {})])
        self.assertEqual(ProbeResult.PASS, observation.result)
        modes = [json.loads(call[3])["connection_mode"] for call in calls]
        self.assertEqual(["new", "existing"], modes)

    def test_any_remaining_network_authority_is_fail(self):
        observation, _ = self.probe([(200, {"allowed": False}), (200, {"allowed": True})])
        self.assertEqual(ProbeResult.FAIL, observation.result)

    def test_unobservable_gateway_response_is_unknown(self):
        observation, _ = self.probe([(503, {}), (403, {})])
        self.assertEqual(ProbeResult.UNKNOWN, observation.result)

    def test_egress_fence_blocks_new_and_terminates_existing_connections(self):
        calls = []

        def transport(method, url, headers, body):
            calls.append((method, url, headers, json.loads(body)))
            return HttpResult(202, {})

        probe = EgressGatewayProbe(
            "https://egress.example.test", "https://target.test", "token", transport=transport
        )
        result = probe.fence(RUN)
        self.assertTrue(result["accepted"])
        self.assertTrue(calls[0][3]["block_new_connections"])
        self.assertTrue(calls[0][3]["terminate_existing_connections"])


class RestartGatewayProbeTest(unittest.TestCase):
    def probe(self, body, status=200):
        calls = []

        def transport(method, url, headers, request_body):
            calls.append((method, url, headers, json.loads(request_body)))
            return HttpResult(status, body)

        probe = RestartGatewayProbe("https://restart.example.test", "token", transport=transport)
        run = {**RUN, "agent_id": "agent-1", "policy_version": 7}
        return probe.probe(run), calls

    def test_restart_passes_only_with_same_policy_new_identity_and_old_revoked(self):
        observation, calls = self.probe(
            {
                "restarted": True,
                "policy_version": 7,
                "old_identity_active": False,
                "new_identity_ref": "synthetic/new-identity",
            }
        )
        self.assertEqual(ProbeResult.PASS, observation.result)
        self.assertEqual("restart:12345678-1234-1234-1234-123456789abc", calls[0][2]["Idempotency-Key"])

    def test_old_authority_or_changed_policy_fails_restart(self):
        old_active, _ = self.probe(
            {"restarted": True, "policy_version": 7, "old_identity_active": True, "new_identity_ref": "new"}
        )
        changed_policy, _ = self.probe(
            {"restarted": True, "policy_version": 8, "old_identity_active": False, "new_identity_ref": "new"}
        )
        self.assertEqual(ProbeResult.FAIL, old_active.result)
        self.assertEqual(ProbeResult.FAIL, changed_policy.result)

    def test_incomplete_restart_observation_is_unknown(self):
        observation, _ = self.probe({"restarted": True})
        self.assertEqual(ProbeResult.UNKNOWN, observation.result)


if __name__ == "__main__":
    unittest.main()
