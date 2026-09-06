from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any

from .store import Store, utc_now


GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class EvidenceLedger:
    def __init__(self, store: Store, signing_key: bytes) -> None:
        if not signing_key:
            raise ValueError("signing key must not be empty")
        self.store = store
        self.signing_key = signing_key

    def append(
        self,
        *,
        tenant_id: str,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: str,
        policy_version: int,
        correlation_id: str,
    ) -> dict[str, Any]:
        encoded = canonical_json(payload)
        payload_hash = hashlib.sha256(encoded.encode()).hexdigest()
        with self.store.connection() as connection:
            previous = connection.execute(
                "SELECT sequence_no, payload_hash FROM evidence WHERE tenant_id=? AND run_id=? ORDER BY sequence_no DESC LIMIT 1",
                (tenant_id, run_id),
            ).fetchone()
            sequence = 1 if previous is None else previous["sequence_no"] + 1
            previous_hash = GENESIS_HASH if previous is None else previous["payload_hash"]
            record = {
                "evidence_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "run_id": run_id,
                "sequence_no": sequence,
                "event_type": event_type,
                "payload": payload,
                "payload_hash": payload_hash,
                "previous_hash": previous_hash,
                "observed_at": utc_now(),
                "actor": actor,
                "policy_version": policy_version,
                "correlation_id": correlation_id,
            }
            connection.execute(
                "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record["evidence_id"], tenant_id, run_id, sequence, event_type,
                    encoded, payload_hash, previous_hash, record["observed_at"], actor,
                    policy_version, correlation_id,
                ),
            )
            run = connection.execute(
                "SELECT agent_id,parent_run_id FROM run WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
            event = {
                "event_id": record["evidence_id"],
                "run_id": run_id,
                "parent_run_id": run["parent_run_id"],
                "agent_id": run["agent_id"],
                "correlation_id": correlation_id,
                "policy_version": policy_version,
                "occurred_at": record["observed_at"],
                "producer": actor,
                "schema_version": "1.0",
                "idempotency_key": f"{run_id}:{sequence}",
                "event_type": event_type,
                "payload": payload,
            }
            connection.execute(
                "INSERT INTO event_outbox VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    event["event_id"], tenant_id, run_id, canonical_json(event),
                    "PENDING", 0, None, record["observed_at"], None,
                ),
            )
        return record

    def records(self, tenant_id: str, run_id: str) -> list[dict[str, Any]]:
        with self.store.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE tenant_id=? AND run_id=? ORDER BY sequence_no",
                (tenant_id, run_id),
            ).fetchall()
        return [self.store.row(row) for row in rows]  # type: ignore[misc]

    def manifest(self, tenant_id: str, run_id: str) -> dict[str, Any]:
        records = self.records(tenant_id, run_id)
        valid, error = self.verify_chain(records)
        body = {
            "tenant_id": tenant_id,
            "run_id": run_id,
            "record_count": len(records),
            "head_hash": records[-1]["payload_hash"] if records else GENESIS_HASH,
            "chain_valid": valid,
            "chain_error": error,
            "signer_key_id": "local-dev-hmac-v1",
            "signature_algorithm": "hmac-sha256",
        }
        body["signature"] = hmac.new(
            self.signing_key, canonical_json(body).encode(), hashlib.sha256
        ).hexdigest()
        return body

    def verify_manifest(self, manifest: dict[str, Any]) -> bool:
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        expected = hmac.new(
            self.signing_key, canonical_json(unsigned).encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, str(manifest.get("signature", "")))

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        return {
            "algorithm": "hmac-sha256",
            "key_id": "local-dev-hmac-v1",
            "signature": hmac.new(
                self.signing_key, canonical_json(payload).encode(), hashlib.sha256
            ).hexdigest(),
        }

    def verify_signed_payload(self, payload: dict[str, Any], signature: dict[str, str]) -> bool:
        if signature.get("algorithm") != "hmac-sha256":
            return False
        expected = hmac.new(
            self.signing_key, canonical_json(payload).encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature.get("signature", ""))

    @staticmethod
    def verify_chain(records: list[dict[str, Any]]) -> tuple[bool, str | None]:
        previous_hash = GENESIS_HASH
        for expected_sequence, record in enumerate(records, 1):
            if record["sequence_no"] != expected_sequence:
                return False, f"expected sequence {expected_sequence}"
            if record["previous_hash"] != previous_hash:
                return False, f"broken previous hash at sequence {expected_sequence}"
            actual = hashlib.sha256(canonical_json(record["payload"]).encode()).hexdigest()
            if not hmac.compare_digest(actual, record["payload_hash"]):
                return False, f"payload hash mismatch at sequence {expected_sequence}"
            previous_hash = record["payload_hash"]
        return True, None
