# Signed reports, SIEM delivery, and restart verification

## Signed shutdown report

`GET /v1/runs/{runId}/report` is available after a run reaches a terminal
shutdown state. The first request creates and stores an immutable report; later
requests return the same payload and signature.

The report includes run and agent identifiers, correlation and policy versions,
timestamps, every probe result (including restart when executed), delegated
jobs, and the evidence-chain manifest. A `shutdown.report.signed` event records
the report hash and signing key ID.

The current signer is HMAC-SHA-256. It protects integrity within the deployment,
but does not meet the final requirement for independently verifiable KMS-backed
asymmetric signatures. That remains a production gate.

## Transactional SIEM outbox

Every evidence append writes its complete SIEM event envelope into
`event_outbox` in the same SQLite transaction. The background publisher:

1. reads pending events in creation order;
2. sends each event with its stable `Idempotency-Key` header;
3. marks successful `2xx` deliveries as `DELIVERED`;
4. increments attempts and retains failed events as `PENDING` for retry;
5. stores the latest bounded error message for operator diagnosis.

The receiver must deduplicate using `idempotency_key`. Delivery is at least once,
not exactly once. Configure `siem.url`, its bearer-token Secret key, explicit
NetworkPolicy egress, and the polling interval through Helm.

The current worker retries at a fixed interval. Exponential backoff, dead-letter
handling, delivery metrics, and bounded retention remain production gates.

## Authorized restart gateway

`POST /v1/runs/{runId}/restart` requires the `responder` role and a terminal
shutdown state. ASV calls the configured gateway:

`POST /v1/restarts`

```json
{
  "run_id": "12345678-1234-1234-1234-123456789abc",
  "agent_id": "agent-uuid",
  "expected_policy_version": 7,
  "old_identity_ref": "synthetic/old-identity",
  "require_new_identity": true
}
```

The gateway receives `Idempotency-Key: restart:{run_id}` and must return:

```json
{
  "restarted": true,
  "policy_version": 7,
  "old_identity_active": false,
  "new_identity_ref": "synthetic/new-identity"
}
```

The restart probe passes only when the run restarted with the exact expected
policy, the old identity is inactive, and the new identity reference is nonempty
and different. An explicit violation is `FAIL`; missing or ambiguous fields are
`UNKNOWN`. The result is persisted as a `restart` probe and is idempotent per run.

Use only a separately administered synthetic restart gateway. It must not expose
an unrestricted workload-creation API.

