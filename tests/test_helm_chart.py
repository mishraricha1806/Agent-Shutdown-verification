from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/agent-shutdown-verification"


@unittest.skipUnless(shutil.which("helm"), "helm is not installed")
class HelmAdmissionPolicyTest(unittest.TestCase):
    def render(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "helm",
                "template",
                "asv",
                str(CHART),
                "--namespace",
                "asv-system",
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_policy_is_disabled_by_default(self):
        result = self.render("--kube-version", "1.30.0")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("kind: ValidatingAdmissionPolicy", result.stdout)

    def test_policy_targets_only_configured_synthetic_namespace(self):
        result = self.render(
            "--kube-version", "1.30.0", "--set", "admissionPolicy.enabled=true"
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("kind: ValidatingAdmissionPolicy", result.stdout)
        self.assertIn("kind: ValidatingAdmissionPolicyBinding", result.stdout)
        self.assertIn("kubernetes.io/metadata.name", result.stdout)
        self.assertIn("- asv-synthetic", result.stdout)
        self.assertIn("forbid hostPath volumes", result.stdout)
        self.assertIn("allowPrivilegeEscalation=false", result.stdout)

    def test_policy_rejects_unsupported_kubernetes_version(self):
        result = self.render(
            "--kube-version", "1.29.9", "--set", "admissionPolicy.enabled=true"
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("requires Kubernetes 1.30 or newer", result.stderr)

    def test_adversarial_fixture_requires_admission_policy(self):
        result = self.render(
            "--kube-version", "1.30.0", "--set", "adversarialFixture.enabled=true"
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "admissionPolicy.enabled must be true when the adversarial fixture is enabled",
            result.stderr,
        )

    def test_policy_namespace_must_be_synthetic(self):
        result = self.render(
            "--kube-version",
            "1.30.0",
            "--set",
            "admissionPolicy.enabled=true",
            "--set",
            "admissionPolicy.namespaces[0]=production",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("/admissionPolicy/namespaces/0", result.stderr)

    def test_siem_backoff_cap_cannot_be_lower_than_base(self):
        result = self.render(
            "--kube-version",
            "1.30.0",
            "--set",
            "siem.enabled=true",
            "--set",
            "siem.url=https://siem.example.test/events",
            "--set",
            "siem.baseBackoffSeconds=10",
            "--set",
            "siem.maxBackoffSeconds=5",
            "--set-json",
            'networkPolicy.extraEgress=[{"to":[{"ipBlock":{"cidr":"192.0.2.1/32"}}]}]',
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("siem.maxBackoffSeconds must be greater", result.stderr)


if __name__ == "__main__":
    unittest.main()
