# MVP threat model

## Protected outcome

After an authorized shutdown, the control plane must report each observable
authority boundary independently. Missing telemetry is `UNKNOWN`, never success.

## Trust boundaries

- The agent workload is untrusted and cannot write evidence or decide outcomes.
- The control API trusts only authenticated service tokens issued with a separate
  secret. Tenant and actor claims come from the token, not request data.
- External enforcement adapters are privileged and must run outside the agent
  namespace. The default adapter has no privileges and returns `UNKNOWN`.
- Synthetic drills are accepted only for an `asv-*` namespace whose declared
  scope explicitly includes `synthetic_only=true`.
- SQLite and HMAC signing are development mechanisms. A pilot must use tenant-
  isolated PostgreSQL and KMS-backed asymmetric signing.

## Primary abuse cases and controls

| Abuse case | Current control | Pilot hardening required |
|---|---|---|
| Agent reports its own successful shutdown | Probe observations originate from an injected control-plane adapter | Separate controller service account and namespace |
| Caller crosses tenant boundaries | Tenant is taken from a signed token and included in every lookup | Workload identity, mTLS, database row-level security |
| Caller replays or duplicates shutdown | Required idempotency key; conflicting key returns `409` | Persist request-level audit and token identifier |
| Missing telemetry is treated as success | Aggregator gives `UNKNOWN` precedence over `PASS` | Alerts and SLO for unknown probe count |
| Evidence record is edited or reordered | Per-run sequence and SHA-256 previous-hash chain | Append-only storage, KMS signature, immutable archive |
| Synthetic drill targets production | Namespace prefix and explicit scope allowlist | Admission policy and signed approval object |
| Low-privilege user shuts down a run | `responder` role is required | External identity provider and separation-of-duty approval |

## Explicitly unresolved

- Revocation and key rotation for service tokens.
- Durable event delivery to Kafka/SIEM.
- Kubernetes child discovery and process termination semantics.
- Kafka producer/consumer fencing, cloud credential revocation, and egress probes.
- Asymmetric evidence signing and published verification keys.
- Recovery after controller restart during an active orchestration.
