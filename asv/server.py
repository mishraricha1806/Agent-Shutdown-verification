from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .auth import AuthenticationError, AuthorizationError, Principal, TokenAuthenticator
from .integrations import (
    CredentialBrokerProbe,
    EgressGatewayProbe,
    KafkaRestFenceProbe,
    KubernetesClient,
    KubernetesKafkaAdapter,
    RestartGatewayProbe,
)
from .service import ConflictError, ControlPlane, NotFoundError, ValidationError
from .siem import HttpSiemSink, OutboxPublisher
from .store import Store


RUN_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)$")
SHUTDOWN_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)/shutdown$")
EVIDENCE_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)/evidence$")
EVENTS_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)/events$")
REPORT_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)/report$")
RESTART_PATH = re.compile(r"^/v1/runs/([0-9a-f-]+)/restart$")


class ApiHandler(BaseHTTPRequestHandler):
    control_plane: ControlPlane
    authenticator: TokenAuthenticator

    def do_POST(self) -> None:
        try:
            body = self._json_body()
            principal = self._principal()
            body["tenant_id"] = principal.tenant_id
            if self.path == "/v1/agents":
                self.authenticator.require_role(principal, "drill_author")
                self._send(HTTPStatus.CREATED, self.control_plane.register_agent(body))
                return
            if self.path == "/v1/runs":
                self.authenticator.require_role(principal, "drill_author")
                self._send(HTTPStatus.CREATED, self.control_plane.create_run(body))
                return
            if self.path == "/v1/drills":
                self.authenticator.require_role(principal, "drill_author")
                result = self.control_plane.start_synthetic_drill(body, actor=principal.actor)
                self._send(HTTPStatus.ACCEPTED, result)
                return
            match = SHUTDOWN_PATH.fullmatch(urlparse(self.path).path)
            if match:
                self.authenticator.require_role(principal, "responder")
                result = self.control_plane.request_shutdown(
                    principal.tenant_id, match.group(1),
                    actor=principal.actor,
                    idempotency_key=self.headers.get("Idempotency-Key", ""),
                )
                self._send(HTTPStatus.ACCEPTED, result)
                return
            match = RESTART_PATH.fullmatch(urlparse(self.path).path)
            if match:
                self.authenticator.require_role(principal, "responder")
                result = self.control_plane.request_restart(
                    principal.tenant_id, match.group(1), principal.actor
                )
                self._send(HTTPStatus.OK, result)
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "route not found"})
        except Exception as error:
            self._send_error(error)

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._send(HTTPStatus.OK, {"status": "ok"})
                return
            principal = self._principal()
            self.authenticator.require_role(principal, "drill_author", "responder", "auditor")
            match = RUN_PATH.fullmatch(parsed.path)
            if match:
                self._send(HTTPStatus.OK, self.control_plane.get_run(principal.tenant_id, match.group(1)))
                return
            match = EVIDENCE_PATH.fullmatch(parsed.path)
            if match:
                self._send(HTTPStatus.OK, self.control_plane.evidence(principal.tenant_id, match.group(1)))
                return
            match = EVENTS_PATH.fullmatch(parsed.path)
            if match:
                self._send(HTTPStatus.OK, self.control_plane.export_events(principal.tenant_id, match.group(1)))
                return
            match = REPORT_PATH.fullmatch(parsed.path)
            if match:
                self._send(HTTPStatus.OK, self.control_plane.report(principal.tenant_id, match.group(1)))
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "route not found"})
        except Exception as error:
            self._send_error(error)

    def _json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            value = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("request body must be valid JSON") from error
        if not isinstance(value, dict):
            raise ValidationError("request body must be a JSON object")
        return value

    def _send_error(self, error: Exception) -> None:
        if isinstance(error, AuthenticationError):
            status = HTTPStatus.UNAUTHORIZED
        elif isinstance(error, AuthorizationError):
            status = HTTPStatus.FORBIDDEN
        elif isinstance(error, ValidationError):
            status = HTTPStatus.BAD_REQUEST
        elif isinstance(error, NotFoundError):
            status = HTTPStatus.NOT_FOUND
        elif isinstance(error, ConflictError):
            status = HTTPStatus.CONFLICT
        else:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        self._send(status, {"error": str(error), "type": type(error).__name__})

    def _principal(self) -> Principal:
        return self.authenticator.authenticate(self.headers.get("Authorization", ""))

    def _send(self, status: HTTPStatus, body: dict) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        print(f"api {self.address_string()} {format % args}")


def build_server(
    host: str, port: int, database: str, deadline_seconds: int = 60
) -> ThreadingHTTPServer:
    store = Store(database)
    signing_key = os.environ.get("ASV_SIGNING_KEY", "").encode()
    auth_secret = os.environ.get("ASV_AUTH_SECRET", "").encode()
    if len(signing_key) < 32:
        raise RuntimeError("ASV_SIGNING_KEY must contain at least 32 bytes")
    if len(auth_secret) < 32:
        raise RuntimeError("ASV_AUTH_SECRET must contain at least 32 bytes")
    adapter = None
    adapter_mode = os.environ.get("ASV_ADAPTER_MODE", "safe-unknown")
    if adapter_mode == "kubernetes":
        namespaces = {
            item.strip() for item in os.environ.get("ASV_ALLOWED_NAMESPACES", "").split(",") if item.strip()
        }
        kafka = None
        kafka_url = os.environ.get("ASV_KAFKA_REST_URL", "")
        if kafka_url:
            token = os.environ.get("ASV_KAFKA_BEARER_TOKEN", "")
            token_path = os.environ.get("ASV_KAFKA_TOKEN_FILE", "")
            if not token and token_path:
                token = Path(token_path).read_text().strip()
            if not token:
                raise RuntimeError("ASV_KAFKA_BEARER_TOKEN or ASV_KAFKA_TOKEN_FILE is required when Kafka probing is enabled")
            kafka = KafkaRestFenceProbe(
                kafka_url,
                os.environ.get("ASV_KAFKA_TOPIC", "asv.synthetic"),
                os.environ.get("ASV_KAFKA_CONSUMER_GROUP", "asv-fenced-probe"),
                os.environ.get("ASV_KAFKA_CONSUMER_INSTANCE", "asv-fenced-probe-1"),
                token,
            )
        credential = None
        credential_url = os.environ.get("ASV_CREDENTIAL_BROKER_URL", "")
        if credential_url:
            credential_token = os.environ.get("ASV_CREDENTIAL_BROKER_TOKEN", "")
            if not credential_token:
                raise RuntimeError("ASV_CREDENTIAL_BROKER_TOKEN is required when credential probing is enabled")
            credential = CredentialBrokerProbe(
                credential_url,
                os.environ.get("ASV_CREDENTIAL_TEST_RESOURCE", "asv.synthetic/resource"),
                credential_token,
            )
        egress = None
        egress_url = os.environ.get("ASV_EGRESS_GATEWAY_URL", "")
        if egress_url:
            egress_token = os.environ.get("ASV_EGRESS_GATEWAY_TOKEN", "")
            destination = os.environ.get("ASV_EGRESS_TEST_DESTINATION", "")
            if not egress_token or not destination:
                raise RuntimeError("ASV_EGRESS_GATEWAY_TOKEN and ASV_EGRESS_TEST_DESTINATION are required when network probing is enabled")
            egress = EgressGatewayProbe(egress_url, destination, egress_token)
        restart_gateway = None
        restart_url = os.environ.get("ASV_RESTART_GATEWAY_URL", "")
        if restart_url:
            restart_token = os.environ.get("ASV_RESTART_GATEWAY_TOKEN", "")
            if not restart_token:
                raise RuntimeError("ASV_RESTART_GATEWAY_TOKEN is required when restart probing is enabled")
            restart_gateway = RestartGatewayProbe(restart_url, restart_token)
        adapter = KubernetesKafkaAdapter(
            KubernetesClient.in_cluster(), namespaces, kafka, credential, egress, restart_gateway
        )
    elif adapter_mode != "safe-unknown":
        raise RuntimeError("ASV_ADAPTER_MODE must be safe-unknown or kubernetes")
    ApiHandler.control_plane = ControlPlane(
        store, signing_key=signing_key, adapter=adapter, deadline_seconds=deadline_seconds
    )
    ApiHandler.authenticator = TokenAuthenticator(auth_secret)
    server = ThreadingHTTPServer((host, port), ApiHandler)
    siem_url = os.environ.get("ASV_SIEM_URL", "")
    if siem_url:
        siem_token = os.environ.get("ASV_SIEM_BEARER_TOKEN", "")
        if not siem_token:
            raise RuntimeError("ASV_SIEM_BEARER_TOKEN is required when SIEM delivery is enabled")
        publisher = OutboxPublisher(store, HttpSiemSink(siem_url, siem_token).send)
        server.outbox_thread = publisher.start(  # type: ignore[attr-defined]
            float(os.environ.get("ASV_SIEM_INTERVAL_SECONDS", "5"))
        )
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Shutdown Verification control API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--database", default="data/asv.db")
    parser.add_argument("--deadline-seconds", type=int, default=60)
    args = parser.parse_args()
    server = build_server(args.host, args.port, args.database, args.deadline_seconds)
    print(f"ASV control API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
