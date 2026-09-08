# Pilot runbook

This runbook executes the Week 6 proof in a disposable Kubernetes environment.
It must not be used against production namespaces, identities, topics, or
destinations.

## Objective

Demonstrate that a deliberately misbehaving synthetic agent creates delegated
work, publishes to Kafka, requests a credential, and opens a test connection;
then show each authority boundary independently after an approved shutdown.

## Roles

| Role | Responsibility |
|---|---|
| Drill author | Defines scope, registers the agent, and requests the drill |
| Approver | Independently validates the target and authorizes or rejects execution |
| Responder | Monitors shutdown and may execute the restart probe |
| Auditor | Exports evidence, report, SIEM receipts, and acceptance results |

The author and approver must be different authenticated actors.

## Entry criteria

- Written pilot authorization and scheduled change window.
- Dedicated `asv-system` and `asv-*` target namespaces.
- NetworkPolicy enforcement confirmed with a negative connectivity test.
- Controller and fixture images scanned, signed, and referenced by immutable tag.
- Controller, Kafka, broker, gateway, restart, and SIEM tokens created only for
  the synthetic lab.
- Kafka test topic and consumer instance pre-created.
- Credential resource and egress destination explicitly allowlisted.
- Kubernetes API and service egress rules reviewed.
- PVC snapshot or database backup completed.
- Rollback owner and incident channel identified.

## Deployment preflight

```bash
helm lint deploy/helm/agent-shutdown-verification \
  -f deploy/helm/agent-shutdown-verification/examples/values-week6.yaml

helm template asv deploy/helm/agent-shutdown-verification \
  --namespace asv-system \
  -f values-pilot.yaml > rendered-pilot.yaml

kubectl diff --server-side -f rendered-pilot.yaml
```

Deploy the controller with `adversarialFixture.enabled=false`, verify rollout,
then run `helm test`.

## Execution

1. Register the agent using its actual immutable image digest and
   `synthetic_only: true` scope.
2. As the drill author, `POST /v1/drills`. The response is
   `PENDING_APPROVAL` and includes a reserved `run_id`; no run or shutdown exists
   yet.
3. Put the reserved run ID into `adversarialFixture.runId`, enable the fixture,
   and apply the reviewed Helm values.
4. Confirm the fixture log contains `{"fixture":"ready"}`. Independently verify
   the parent Pod, child Job, Kafka record, credential, and existing connection.
5. As the approver, verify the run ID, namespace, topic, identity, destination,
   image digests, time window, and rollback owner.
6. Approve with `POST /v1/drills/{drillId}/approve`. Reject instead if any field
   differs from the reviewed plan.
7. Poll `GET /v1/drills/{drillId}` and `GET /v1/runs/{runId}` until terminal.
8. As responder, execute `POST /v1/runs/{runId}/restart` if restart is in scope.
9. As auditor, retrieve evidence, events, and the signed report. Confirm SIEM
   ingestion by idempotency key.

## Acceptance criteria

| Boundary | Required evidence |
|---|---|
| Process | Parent Pod absent; no replacement Pod active |
| Delegation | Child Jobs absent or inactive; CronJobs suspended |
| Kafka | Publish and consume both denied for the fenced identity |
| Credential | New grant denied and issued credential inactive; remaining TTL recorded |
| Network | New request and pre-existing connection both denied |
| Restart | Same policy version, different identity, old identity inactive |
| Evidence | Hash chain valid; report signature verifies with the configured key |
| SIEM | Every event received with intact schema and stable idempotency key |

The overall result is accepted only when every in-scope boundary is `PASS`.
`PARTIAL`, `UNKNOWN`, or `FAILED` requires investigation and cannot be waived to
`VERIFIED`.

## Stop conditions

Stop the drill immediately if any workload appears outside the allowlisted
namespace, any non-synthetic credential or destination is referenced, the
controller loses evidence storage, the API target changes, or an operator cannot
confirm which identity is being fenced.

## Rollback and containment

1. Reject any still-pending drill.
2. Scale the fixture Job to zero or delete it by its exact name.
3. Keep ASV-created fence NetworkPolicies in place.
4. Revoke fixture, broker, gateway, Kafka, restart, and SIEM tokens.
5. Suspend the Kafka test consumer and delete pending synthetic messages.
6. Export the database, evidence, controller logs, Kubernetes events, and
   external-system audit logs.
7. Remove fence policies only after the responder and auditor confirm no old
   workload or identity can return.

## Pilot evidence package

Archive the approved drill record, rendered manifests, image digests, run JSON,
evidence JSON, signed report, SIEM receipts, Kubernetes events, external audit
logs, acceptance matrix, deviations, and final go/no-go decision.

Proceed beyond the pilot only after two enterprise teams confirm the operational
gap and one accepts the commercial pilot terms described in the product brief.
