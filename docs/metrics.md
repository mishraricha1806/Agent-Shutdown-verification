# Operational metrics

ASV exposes Prometheus text format at `GET /metrics`. The endpoint requires a
valid ASV service token with any operator role and returns data only for the
token's tenant. Tenant IDs, run IDs, agent IDs, actors, namespaces, and external
resource names are deliberately excluded from labels.

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:8080/metrics \
  -H "Authorization: Bearer $RESPONDER_TOKEN"
```

Use a dedicated, narrowly distributed `auditor` token for a metrics collector.
The current local token mechanism does not provide automated rotation or
revocation and remains a production-readiness gap.

## Metric families

| Metric | Type | Meaning |
|---|---|---|
| `asv_runs{state}` | Gauge | Current runs in each shutdown state |
| `asv_probe_results_total{kind,result}` | Counter | Durable boundary observations, including restart |
| `asv_delegated_jobs{state}` | Gauge | Last observed state of delegated work |
| `asv_shutdown_work_items{status}` | Gauge | Pending, running, and completed orchestration records |
| `asv_orchestration_attempts_total` | Counter | Persisted attempts to claim and execute shutdown work |
| `asv_shutdown_phase_events_total{phase}` | Counter | Fence, process-stop, and completion evidence events |
| `asv_shutdown_recovery_events_total{outcome}` | Counter | Resumed and deadline-expired recoveries |
| `asv_evidence_chain_failures` | Gauge | Runs whose current evidence hash chain fails verification |
| `asv_siem_outbox_events{status}` | Gauge | Pending, delivered, and dead-letter SIEM envelopes |
| `asv_siem_delivery_attempts_total` | Counter | Persisted SIEM delivery attempts |

The exporter derives values from durable SQLite records at scrape time. Metrics
with the `_total` suffix remain monotonic while those records are retained; a
future retention or archival process must preserve or separately checkpoint
their cumulative values.

## Minimum alerts

- Page immediately when `asv_evidence_chain_failures` is greater than zero.
- Page when any probe result increases with `result="FAIL"`.
- Alert when an `UNKNOWN` probe result increases or a run remains in a
  non-terminal shutdown state past its deadline.
- Alert when `asv_delegated_jobs{state="ACTIVE"}` remains nonzero after a
  shutdown completes.
- Alert when pending SIEM events grow without corresponding delivery attempts.
- Page when `asv_siem_outbox_events{status="DEAD_LETTER"}` is nonzero.
- Alert on recovery deadline expiration and investigate every resumed recovery.

Metrics are an operational signal, not evidence. Acceptance decisions must use
the signed report and evidence chain rather than scrape output.
