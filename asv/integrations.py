from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .domain import ProbeObservation, ProbeResult


RUN_LABEL = "asv.openai.com/run-id"
PARENT_RUN_LABEL = "asv.openai.com/parent-run-id"


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: dict[str, Any]


class IntegrationError(RuntimeError):
    pass


Transport = Callable[[str, str, dict[str, str], bytes | None], HttpResult]


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> HttpResult:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return HttpResult(response.status, json.loads(raw) if raw else {})
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"message": raw.decode(errors="replace")}
        return HttpResult(error.code, parsed)


class KubernetesClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        transport: Transport | None = None,
        ca_file: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        if transport is None and ca_file:
            context = ssl.create_default_context(cafile=ca_file)

            def secure_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResult:
                request = urllib.request.Request(url, data=body, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(request, timeout=5, context=context) as response:
                        raw = response.read()
                        return HttpResult(response.status, json.loads(raw) if raw else {})
                except urllib.error.HTTPError as error:
                    raw = error.read()
                    return HttpResult(error.code, json.loads(raw) if raw else {})

            self.transport = secure_transport
        else:
            self.transport = transport or _urllib_transport

    @classmethod
    def in_cluster(cls, *, transport: Transport | None = None) -> "KubernetesClient":
        host = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        token = (host / "token").read_text().strip()
        namespace_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        return cls(
            f"https://{namespace_host}:{port}",
            token,
            transport=transport,
            ca_file=str(host / "ca.crt"),
        )

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        encoded = json.dumps(body).encode() if body is not None else None
        result = self.transport(
            method,
            f"{self.base_url}{path}",
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json",
            },
            encoded,
        )
        if result.status < 200 or result.status >= 300:
            raise IntegrationError(f"Kubernetes API returned {result.status}: {result.body}")
        return result.body

    def list_resources(self, namespace: str, resource: str, label_selector: str) -> list[dict[str, Any]]:
        group = "api/v1" if resource == "pods" else "apis/batch/v1"
        query = urllib.parse.urlencode({"labelSelector": label_selector})
        result = self.request("GET", f"/{group}/namespaces/{namespace}/{resource}?{query}")
        return list(result.get("items", []))

    def delete(self, namespace: str, resource: str, name: str) -> None:
        group = "api/v1" if resource == "pods" else "apis/batch/v1"
        self.request(
            "DELETE",
            f"/{group}/namespaces/{namespace}/{resource}/{urllib.parse.quote(name, safe='')}",
            {"propagationPolicy": "Foreground", "gracePeriodSeconds": 0},
        )

    def suspend_cronjob(self, namespace: str, name: str) -> None:
        self.request(
            "PATCH",
            f"/apis/batch/v1/namespaces/{namespace}/cronjobs/{urllib.parse.quote(name, safe='')}",
            {"spec": {"suspend": True}},
        )

    def create_fence(self, namespace: str, run_id: str) -> None:
        for suffix, label in (("run", RUN_LABEL), ("children", PARENT_RUN_LABEL)):
            name = f"asv-fence-{suffix}-{run_id[:8]}"
            manifest = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": name, "labels": {RUN_LABEL: run_id, "app.kubernetes.io/managed-by": "asv"}},
                "spec": {
                    "podSelector": {"matchLabels": {label: run_id}},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": [],
                },
            }
            try:
                self.request(
                    "POST",
                    f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
                    manifest,
                )
            except IntegrationError as error:
                if "409" not in str(error):
                    raise


class KafkaRestFenceProbe:
    """Checks a pre-provisioned synthetic Kafka identity through REST Proxy."""

    def __init__(
        self,
        base_url: str,
        topic: str,
        consumer_group: str,
        consumer_instance: str,
        bearer_token: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.topic = topic
        self.consumer_group = consumer_group
        self.consumer_instance = consumer_instance
        self.bearer_token = bearer_token
        self.transport = transport or _urllib_transport

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpResult:
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/vnd.kafka.json.v2+json",
            "Accept": "application/vnd.kafka.json.v2+json",
        }
        encoded = json.dumps(body).encode() if body is not None else None
        return self.transport(method, f"{self.base_url}{path}", headers, encoded)

    def probe(self, run: dict[str, Any]) -> ProbeObservation:
        try:
            publish = self._call(
                "POST",
                f"/topics/{urllib.parse.quote(self.topic, safe='')}",
                {"records": [{"value": {"run_id": run["run_id"], "probe": "post-shutdown"}}]},
            )
            consume = self._call(
                "GET",
                "/consumers/"
                f"{urllib.parse.quote(self.consumer_group, safe='')}/instances/"
                f"{urllib.parse.quote(self.consumer_instance, safe='')}/records?timeout=1000&max_bytes=1",
            )
        except Exception as error:
            return ProbeObservation(
                "kafka", ProbeResult.UNKNOWN, {"error": str(error)},
                "kafka-rest-proxy", "none",
            )
        statuses = {publish.status, consume.status}
        if statuses.issubset({401, 403}):
            result = ProbeResult.PASS
        elif any(status in {200, 201, 204} for status in statuses):
            result = ProbeResult.FAIL
        else:
            result = ProbeResult.UNKNOWN
        return ProbeObservation(
            "kafka",
            result,
            {"publish_status": publish.status, "consume_status": consume.status, "topic": self.topic},
            "kafka-rest-proxy",
            "deterministic" if result != ProbeResult.UNKNOWN else "none",
        )


class CredentialBrokerProbe:
    """Verifies grant denial and revocation through a synthetic credential broker."""

    def __init__(
        self,
        base_url: str,
        test_resource: str,
        controller_token: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.test_resource = test_resource
        self.controller_token = controller_token
        self.transport = transport or _urllib_transport

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpResult:
        encoded = json.dumps(body).encode() if body is not None else None
        return self.transport(
            method,
            f"{self.base_url}{path}",
            {
                "Authorization": f"Bearer {self.controller_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            encoded,
        )

    def probe(self, run: dict[str, Any]) -> ProbeObservation:
        identity_ref = str(run["identity_ref"])
        try:
            grant = self._call(
                "POST",
                "/v1/grants",
                {
                    "subject_ref": identity_ref,
                    "resource": self.test_resource,
                    "run_id": run["run_id"],
                    "purpose": "post-shutdown-verification",
                },
            )
            credential = self._call(
                "GET",
                f"/v1/credentials/{urllib.parse.quote(identity_ref, safe='')}/status",
            )
        except Exception as error:
            return ProbeObservation(
                "credential", ProbeResult.UNKNOWN, {"error": str(error)},
                "synthetic-credential-broker", "none",
            )

        grant_denied = grant.status in {401, 403}
        grant_accepted = grant.status in {200, 201, 202, 204}
        if credential.status in {401, 403, 404}:
            active: bool | None = False
        elif credential.status == 200 and isinstance(credential.body.get("active"), bool):
            active = credential.body["active"]
        else:
            active = None

        if grant_denied and active is False:
            result = ProbeResult.PASS
        elif grant_accepted or active is True:
            result = ProbeResult.FAIL
        else:
            result = ProbeResult.UNKNOWN

        observed = {
            "grant_status": grant.status,
            "credential_status": credential.status,
            "credential_active": active,
            "remaining_ttl_seconds": credential.body.get("remaining_ttl_seconds"),
            "test_resource": self.test_resource,
        }
        return ProbeObservation(
            "credential",
            result,
            observed,
            "synthetic-credential-broker",
            "deterministic" if result != ProbeResult.UNKNOWN else "none",
        )

    def fence(self, run: dict[str, Any]) -> dict[str, Any]:
        result = self._call(
            "POST",
            "/v1/fences",
            {
                "subject_ref": run["identity_ref"],
                "run_id": run["run_id"],
                "deny_new_grants": True,
                "revoke_existing": True,
            },
        )
        if result.status not in {200, 201, 202, 204, 409}:
            raise IntegrationError(f"credential fence returned {result.status}: {result.body}")
        return {"accepted": True, "status": result.status}


class EgressGatewayProbe:
    """Tests new-request and existing-connection authority at an approved gateway."""

    def __init__(
        self,
        base_url: str,
        test_destination: str,
        controller_token: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.test_destination = test_destination
        self.controller_token = controller_token
        self.transport = transport or _urllib_transport

    def _attempt(self, run: dict[str, Any], connection_mode: str) -> HttpResult:
        body = json.dumps(
            {
                "run_id": run["run_id"],
                "subject_ref": run["identity_ref"],
                "destination": self.test_destination,
                "connection_mode": connection_mode,
            }
        ).encode()
        return self.transport(
            "POST",
            f"{self.base_url}/v1/probes/egress",
            {
                "Authorization": f"Bearer {self.controller_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body,
        )

    @staticmethod
    def _allowed(result: HttpResult) -> bool | None:
        if result.status in {401, 403, 451}:
            return False
        if 200 <= result.status < 300 and isinstance(result.body.get("allowed"), bool):
            return result.body["allowed"]
        return None

    def probe(self, run: dict[str, Any]) -> ProbeObservation:
        try:
            new_request = self._attempt(run, "new")
            existing_connection = self._attempt(run, "existing")
        except Exception as error:
            return ProbeObservation(
                "network", ProbeResult.UNKNOWN, {"error": str(error)},
                "synthetic-egress-gateway", "none",
            )
        new_allowed = self._allowed(new_request)
        existing_allowed = self._allowed(existing_connection)
        if new_allowed is False and existing_allowed is False:
            result = ProbeResult.PASS
        elif new_allowed is True or existing_allowed is True:
            result = ProbeResult.FAIL
        else:
            result = ProbeResult.UNKNOWN
        return ProbeObservation(
            "network",
            result,
            {
                "new_request_status": new_request.status,
                "new_request_allowed": new_allowed,
                "existing_connection_status": existing_connection.status,
                "existing_connection_allowed": existing_allowed,
                "test_destination": self.test_destination,
            },
            "synthetic-egress-gateway",
            "deterministic" if result != ProbeResult.UNKNOWN else "none",
        )

    def fence(self, run: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(
            {
                "run_id": run["run_id"],
                "subject_ref": run["identity_ref"],
                "destination": self.test_destination,
                "block_new_connections": True,
                "terminate_existing_connections": True,
            }
        ).encode()
        result = self.transport(
            "POST",
            f"{self.base_url}/v1/fences",
            {
                "Authorization": f"Bearer {self.controller_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body,
        )
        if result.status not in {200, 201, 202, 204, 409}:
            raise IntegrationError(f"egress fence returned {result.status}: {result.body}")
        return {"accepted": True, "status": result.status}


class RestartGatewayProbe:
    """Requests an authorized restart and verifies policy and identity continuity."""

    def __init__(
        self, base_url: str, controller_token: str, *, transport: Transport | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.controller_token = controller_token
        self.transport = transport or _urllib_transport

    def probe(self, run: dict[str, Any]) -> ProbeObservation:
        request_body = {
            "run_id": run["run_id"],
            "agent_id": run["agent_id"],
            "expected_policy_version": run["policy_version"],
            "old_identity_ref": run["identity_ref"],
            "require_new_identity": True,
        }
        try:
            result = self.transport(
                "POST",
                f"{self.base_url}/v1/restarts",
                {
                    "Authorization": f"Bearer {self.controller_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Idempotency-Key": f"restart:{run['run_id']}",
                },
                json.dumps(request_body).encode(),
            )
        except Exception as error:
            return ProbeObservation(
                "restart", ProbeResult.UNKNOWN, {"error": str(error)},
                "authorized-restart-gateway", "none",
            )
        if result.status not in {200, 201, 202}:
            outcome = ProbeResult.UNKNOWN
        else:
            restarted = result.body.get("restarted")
            policy_version = result.body.get("policy_version")
            old_identity_active = result.body.get("old_identity_active")
            new_identity_ref = result.body.get("new_identity_ref")
            complete = (
                isinstance(restarted, bool)
                and isinstance(policy_version, int)
                and isinstance(old_identity_active, bool)
                and isinstance(new_identity_ref, str)
                and bool(new_identity_ref)
            )
            if not complete:
                outcome = ProbeResult.UNKNOWN
            elif restarted and policy_version == run["policy_version"] and not old_identity_active and new_identity_ref != run["identity_ref"]:
                outcome = ProbeResult.PASS
            else:
                outcome = ProbeResult.FAIL
        return ProbeObservation(
            "restart",
            outcome,
            {"http_status": result.status, **result.body},
            "authorized-restart-gateway",
            "deterministic" if outcome != ProbeResult.UNKNOWN else "none",
        )


class KubernetesKafkaAdapter:
    def __init__(
        self,
        kubernetes: KubernetesClient,
        allowed_namespaces: set[str],
        kafka: KafkaRestFenceProbe | None = None,
        credential: CredentialBrokerProbe | None = None,
        egress: EgressGatewayProbe | None = None,
        restart_gateway: RestartGatewayProbe | None = None,
    ) -> None:
        if not allowed_namespaces or any(not namespace.startswith("asv-") for namespace in allowed_namespaces):
            raise ValueError("allowed namespaces must be non-empty and use the asv-* prefix")
        self.kubernetes = kubernetes
        self.allowed_namespaces = allowed_namespaces
        self.kafka = kafka
        self.credential = credential
        self.egress = egress
        self.restart_gateway = restart_gateway

    def _namespace(self, run: dict[str, Any]) -> str:
        namespace = str(run["agent"]["namespace"])
        if namespace not in self.allowed_namespaces:
            raise IntegrationError(f"namespace {namespace!r} is not allowlisted")
        return namespace

    def fence(self, run: dict[str, Any]) -> dict[str, Any]:
        namespace = self._namespace(run)
        self.kubernetes.create_fence(namespace, run["run_id"])
        cronjobs = self._related(namespace, "cronjobs", run["run_id"])
        for cronjob in cronjobs:
            self.kubernetes.suspend_cronjob(namespace, cronjob["metadata"]["name"])
        result: dict[str, Any] = {
            "accepted": True,
            "namespace": namespace,
            "cronjobs_suspended": len(cronjobs),
        }
        if self.credential:
            result["credential_broker"] = self.credential.fence(run)
        if self.egress:
            result["egress_gateway"] = self.egress.fence(run)
        return result

    def stop_process(self, run: dict[str, Any]) -> dict[str, Any]:
        namespace = self._namespace(run)
        pods = self._related(namespace, "pods", run["run_id"])
        jobs = self._related(namespace, "jobs", run["run_id"])
        for resource, items in (("pods", pods), ("jobs", jobs)):
            for item in items:
                self.kubernetes.delete(namespace, resource, item["metadata"]["name"])
        return {"accepted": True, "pods_deleted": len(pods), "jobs_deleted": len(jobs)}

    def _related(self, namespace: str, resource: str, run_id: str) -> list[dict[str, Any]]:
        items: dict[str, dict[str, Any]] = {}
        for label in (RUN_LABEL, PARENT_RUN_LABEL):
            for item in self.kubernetes.list_resources(namespace, resource, f"{label}={run_id}"):
                items[item["metadata"]["name"]] = item
        return list(items.values())

    def discover_children(self, run: dict[str, Any]) -> dict[str, Any]:
        namespace = self._namespace(run)
        selector = f"{PARENT_RUN_LABEL}={run['run_id']}"
        children = []
        for resource in ("jobs", "cronjobs"):
            for item in self.kubernetes.list_resources(namespace, resource, selector):
                children.append({"kind": resource, "name": item["metadata"]["name"], "status": item.get("status", {})})
        return {"observable": True, "namespace": namespace, "children": children}

    def probe(self, kind: str, run: dict[str, Any]) -> ProbeObservation:
        namespace = self._namespace(run)
        try:
            if kind == "process":
                pods = self._related(namespace, "pods", run["run_id"])
                active = [pod["metadata"]["name"] for pod in pods if pod.get("status", {}).get("phase") not in {"Succeeded", "Failed"}]
                return self._observation(kind, ProbeResult.PASS if not active else ProbeResult.FAIL, {"active_pods": active})
            if kind == "delegation":
                children = self.discover_children(run)["children"]
                active = [child for child in children if self._child_active(child)]
                return self._observation(kind, ProbeResult.PASS if not active else ProbeResult.FAIL, {"active_children": active})
            if kind == "kafka":
                return self.kafka.probe(run) if self.kafka else self._observation(kind, ProbeResult.UNKNOWN, {"reason": "Kafka REST probe is not configured"}, "none")
            if kind == "credential":
                return self.credential.probe(run) if self.credential else self._observation(kind, ProbeResult.UNKNOWN, {"reason": "credential broker probe is not configured"}, "none")
            if kind == "network":
                return self.egress.probe(run) if self.egress else self._observation(kind, ProbeResult.UNKNOWN, {"reason": "egress gateway probe is not configured"}, "none")
            return self._observation(kind, ProbeResult.UNKNOWN, {"reason": f"{kind} probe is not configured"}, "none")
        except Exception as error:
            return self._observation(kind, ProbeResult.UNKNOWN, {"error": str(error)}, "none")

    def restart(self, run: dict[str, Any]) -> ProbeObservation:
        self._namespace(run)
        if not self.restart_gateway:
            return self._observation(
                "restart", ProbeResult.UNKNOWN,
                {"reason": "authorized restart gateway is not configured"}, "none",
            )
        return self.restart_gateway.probe(run)

    @staticmethod
    def _child_active(child: dict[str, Any]) -> bool:
        if child["kind"] == "cronjobs":
            return child.get("status", {}).get("active") not in (None, [])
        return int(child.get("status", {}).get("active", 0)) > 0

    @staticmethod
    def _observation(
        kind: str, result: ProbeResult, observed: dict[str, Any], confidence: str = "deterministic"
    ) -> ProbeObservation:
        return ProbeObservation(kind, result, observed, "kubernetes-control-plane", confidence)
