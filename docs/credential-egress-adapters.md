# Credential broker and egress gateway contracts

The Week 4 integrations are control-plane HTTP contracts for disposable test
infrastructure. They are not calls to arbitrary production identity providers or
destinations. Both integrations are optional; an unconfigured or unobservable
boundary returns `UNKNOWN`.

## Credential broker

The broker authenticates ASV using a dedicated controller token. The subject
under test is supplied separately as `subject_ref`; the controller token must
never be evaluated as the agent identity.

### Fence authority

`POST /v1/fences`

```json
{
  "subject_ref": "synthetic/run-identity",
  "run_id": "12345678-1234-1234-1234-123456789abc",
  "deny_new_grants": true,
  "revoke_existing": true
}
```

Success statuses are `200`, `201`, `202`, `204`, or idempotent conflict `409`.
Any other response fails orchestration before process termination proceeds.

### Verify new grants

`POST /v1/grants`

```json
{
  "subject_ref": "synthetic/run-identity",
  "resource": "asv.synthetic/resource",
  "run_id": "12345678-1234-1234-1234-123456789abc",
  "purpose": "post-shutdown-verification"
}
```

The expected response is `401` or `403`. Any accepted `2xx` response is `FAIL`.

### Verify an issued credential

`GET /v1/credentials/{url-encoded-subject-ref}/status`

The preferred response is:

```json
{
  "active": false,
  "remaining_ttl_seconds": 0
}
```

`401`, `403`, or `404` also indicates that the synthetic credential is no longer
usable. A response containing `active: true` is `FAIL`, and its remaining TTL is
preserved in evidence. Ambiguous statuses or malformed bodies are `UNKNOWN`.

## Egress gateway

The gateway must own both the enforcement decision and observation of a
pre-established synthetic connection. ASV does not infer an existing connection
result by opening a second HTTP request.

### Fence authority

`POST /v1/fences`

```json
{
  "run_id": "12345678-1234-1234-1234-123456789abc",
  "subject_ref": "synthetic/run-identity",
  "destination": "https://denied-target.asv-synthetic.svc/check",
  "block_new_connections": true,
  "terminate_existing_connections": true
}
```

Success statuses are `200`, `201`, `202`, `204`, or idempotent conflict `409`.

### Verify network authority

ASV calls `POST /v1/probes/egress` twice, once with `connection_mode: new` and
once with `connection_mode: existing`:

```json
{
  "run_id": "12345678-1234-1234-1234-123456789abc",
  "subject_ref": "synthetic/run-identity",
  "destination": "https://denied-target.asv-synthetic.svc/check",
  "connection_mode": "new"
}
```

The gateway returns `{"allowed": false}` for a denied attempt. HTTP `401`, `403`,
or `451` is also treated as denial. Both modes denied is `PASS`; either mode
allowed is `FAIL`; any ambiguous observation is `UNKNOWN`.

## Security requirements

- Use only synthetic subjects, credentials, resources, and destinations.
- Authenticate ASV independently from the subject being tested.
- Make fence requests idempotent by `run_id` and subject.
- Preserve server-side timestamps and decision identifiers in gateway logs.
- Reject destinations outside an explicit allowlist.
- Use TLS with a trusted private CA or publicly verifiable certificate.
- Scope controller tokens to fence and probe operations only.
- Configure explicit Helm `networkPolicy.extraEgress` rules for both services.
- Never return `allowed: false` before the gateway has actually evaluated the
  requested subject and connection.

The full Helm example is
`deploy/helm/agent-shutdown-verification/examples/values-week4.yaml`.
