import unittest

from asv.adapters import SyntheticAdapter
from asv.auth import AuthenticationError, AuthorizationError, Principal, TokenAuthenticator
from asv.domain import PROBE_KINDS, ProbeResult, ShutdownState, aggregate_probe_results
from asv.service import ConflictError, ControlPlane, ValidationError
from asv.store import Store


DIGEST = "sha256:" + "a" * 64


class ControlPlaneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store()
        self.addCleanup(self.store.close)
        self.adapter = SyntheticAdapter({kind: ProbeResult.PASS for kind in PROBE_KINDS})
        self.control = ControlPlane(self.store, signing_key=b"test-key", adapter=self.adapter)

    def agent(self):
        return self.control.register_agent(
            {
                "tenant_id": "tenant-a",
                "name": "misbehaving-test-agent",
                "image_digest": DIGEST,
                "namespace": "asv-synthetic",
                "scope_owner": "security@example.com",
                "declared_scope": {"topics": ["asv.test"], "synthetic_only": True},
            }
        )

    def make_run(self):
        agent = self.agent()
        return self.control.create_run(
            {
                "tenant_id": "tenant-a",
                "agent_id": agent["agent_id"],
                "identity_ref": "synthetic/tenant-a",
            }
        )

    def test_agent_requires_digest_owner_and_scope(self):
        with self.assertRaises(ValidationError):
            self.control.register_agent(
                {
                    "tenant_id": "tenant-a",
                    "name": "agent",
                    "image_digest": "latest",
                    "namespace": "test",
                    "scope_owner": "owner",
                    "declared_scope": {},
                }
            )

    def test_child_run_is_linked_to_same_agent(self):
        parent = self.make_run()
        child = self.control.create_run(
            {
                "tenant_id": "tenant-a",
                "agent_id": parent["agent_id"],
                "parent_run_id": parent["run_id"],
                "identity_ref": "synthetic/child",
            }
        )
        self.assertEqual(parent["run_id"], child["parent_run_id"])

    def test_shutdown_is_idempotent_and_verified_only_when_all_pass(self):
        run = self.make_run()
        first = self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-1", asynchronous=False
        )
        second = self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-1", asynchronous=False
        )
        finished = self.control.get_run("tenant-a", run["run_id"])
        self.assertEqual(first["correlation_id"], second["correlation_id"])
        self.assertEqual(ShutdownState.VERIFIED, finished["state"])
        self.assertEqual(5, len(finished["probes"]))
        requested = [
            item for item in self.control.evidence("tenant-a", run["run_id"])["records"]
            if item["event_type"] == "shutdown.requested"
        ]
        self.assertEqual(1, len(requested))

    def test_conflicting_duplicate_shutdown_is_rejected(self):
        run = self.make_run()
        self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-1", asynchronous=False
        )
        with self.assertRaises(ConflictError):
            self.control.request_shutdown(
                "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-2", asynchronous=False
            )

    def test_unknown_is_never_promoted_to_verified(self):
        self.assertEqual(
            ShutdownState.UNKNOWN,
            aggregate_probe_results([ProbeResult.PASS, ProbeResult.UNKNOWN]),
        )

    def test_unconfigured_external_adapters_fail_closed(self):
        store = Store()
        self.addCleanup(store.close)
        control = ControlPlane(store, signing_key=b"test-key")
        agent = control.register_agent(
            {
                "tenant_id": "tenant-a",
                "name": "agent",
                "image_digest": DIGEST,
                "namespace": "asv-synthetic",
                "scope_owner": "security@example.com",
                "declared_scope": {},
            }
        )
        run = control.create_run(
            {
                "tenant_id": "tenant-a",
                "agent_id": agent["agent_id"],
                "identity_ref": "synthetic/tenant-a",
            }
        )
        control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-unknown", asynchronous=False
        )
        finished = control.get_run("tenant-a", run["run_id"])
        self.assertEqual(ShutdownState.UNKNOWN, finished["state"])
        self.assertEqual({"UNKNOWN"}, {probe["result"] for probe in finished["probes"]})

    def test_evidence_chain_and_manifest_are_valid(self):
        run = self.make_run()
        self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-1", asynchronous=False
        )
        evidence = self.control.evidence("tenant-a", run["run_id"])
        self.assertTrue(evidence["manifest"]["chain_valid"])
        self.assertTrue(self.control.ledger.verify_manifest(evidence["manifest"]))
        self.assertEqual(len(evidence["records"]), evidence["manifest"]["record_count"])
        for previous, current in zip(evidence["records"], evidence["records"][1:]):
            self.assertEqual(previous["payload_hash"], current["previous_hash"])

    def test_restart_probe_and_signed_report_are_idempotent(self):
        run = self.make_run()
        self.control.request_shutdown(
            "tenant-a", run["run_id"], actor="operator", idempotency_key="stop-report", asynchronous=False
        )
        restart = self.control.request_restart("tenant-a", run["run_id"], "responder")
        repeated_restart = self.control.request_restart("tenant-a", run["run_id"], "responder")
        self.assertEqual("PASS", restart["result"])
        self.assertEqual(restart["result"], repeated_restart["result"])

        first_report = self.control.report("tenant-a", run["run_id"])
        second_report = self.control.report("tenant-a", run["run_id"])
        self.assertEqual(first_report, second_report)
        self.assertEqual("VERIFIED", first_report["report"]["shutdown_state"])
        self.assertEqual("PASS", first_report["report"]["probe_results"]["restart"])
        self.assertEqual("hmac-sha256", first_report["signature"]["algorithm"])
        self.assertTrue(
            self.control.ledger.verify_signed_payload(
                first_report["report"], first_report["signature"]
            )
        )
        events = self.control.export_events("tenant-a", run["run_id"])["events"]
        self.assertEqual(1, sum(event["event_type"] == "shutdown.report.signed" for event in events))

    def test_report_requires_terminal_shutdown(self):
        run = self.make_run()
        with self.assertRaises(ConflictError):
            self.control.report("tenant-a", run["run_id"])

    def test_synthetic_drill_runs_end_to_end_and_exports_event_schema(self):
        agent = self.agent()
        drill = self.control.start_synthetic_drill(
            {
                "tenant_id": "tenant-a",
                "agent_id": agent["agent_id"],
                "outcomes": {
                    "process": "PASS",
                    "delegation": "PASS",
                    "kafka": "PASS",
                    "credential": "PASS",
                    "network": "PARTIAL",
                },
            },
            actor="drill-author",
            asynchronous=False,
        )
        finished = self.control.get_run("tenant-a", drill["run_id"])
        self.assertTrue(drill["synthetic_target"])
        self.assertTrue(drill["simulated"])
        self.assertEqual(ShutdownState.PARTIAL, finished["state"])
        export = self.control.export_events("tenant-a", drill["run_id"])
        self.assertEqual(export["count"], len(export["events"]))
        self.assertTrue(export["events"])
        required = {
            "event_id", "run_id", "parent_run_id", "agent_id", "correlation_id",
            "policy_version", "occurred_at", "producer", "schema_version",
            "idempotency_key", "event_type", "payload",
        }
        self.assertEqual(required, set(export["events"][0]))

    def test_synthetic_drill_rejects_non_allowlisted_namespace(self):
        agent = self.control.register_agent(
            {
                "tenant_id": "tenant-a",
                "name": "production-agent",
                "image_digest": DIGEST,
                "namespace": "production",
                "scope_owner": "security@example.com",
                "declared_scope": {"synthetic_only": True},
            }
        )
        with self.assertRaises(ValidationError):
            self.control.start_synthetic_drill(
                {"tenant_id": "tenant-a", "agent_id": agent["agent_id"]},
                actor="drill-author",
                asynchronous=False,
            )

    def test_drill_without_simulation_uses_fail_closed_configured_adapter(self):
        agent = self.agent()
        control = ControlPlane(self.store, signing_key=b"test-key")
        drill = control.start_synthetic_drill(
            {"tenant_id": "tenant-a", "agent_id": agent["agent_id"]},
            actor="drill-author",
            asynchronous=False,
        )
        self.assertFalse(drill["simulated"])
        self.assertEqual(
            ShutdownState.UNKNOWN,
            control.get_run("tenant-a", drill["run_id"])["state"],
        )

    def test_partial_simulation_definition_is_rejected(self):
        agent = self.agent()
        with self.assertRaises(ValidationError):
            self.control.start_synthetic_drill(
                {
                    "tenant_id": "tenant-a",
                    "agent_id": agent["agent_id"],
                    "outcomes": {"process": "PASS"},
                },
                actor="drill-author",
                asynchronous=False,
            )


class AuthenticationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = TokenAuthenticator(b"a-secure-test-secret-that-is-long-enough")

    def test_signed_token_round_trip_and_role_check(self):
        expected = Principal("tenant-a", "alice@example.com", frozenset({"auditor"}))
        token = self.auth.issue(expected)
        actual = self.auth.authenticate(f"Bearer {token}")
        self.assertEqual(expected, actual)
        self.auth.require_role(actual, "auditor")
        with self.assertRaises(AuthorizationError):
            self.auth.require_role(actual, "responder")

    def test_tampered_token_is_rejected(self):
        token = self.auth.issue(Principal("tenant-a", "alice", frozenset({"auditor"})))
        version, payload, signature = token.split(".", 2)
        replacement = "0" if signature[0] != "0" else "1"
        tampered = f"{version}.{payload}.{replacement}{signature[1:]}"
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate(f"Bearer {tampered}")


if __name__ == "__main__":
    unittest.main()
