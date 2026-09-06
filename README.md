# Agent Shutdown Verification - MVP starter

This repository contains the first runnable vertical slice of the verification
control plane described in the MVP brief. It intentionally uses only the Python
standard library so the control-plane behavior can be exercised before external
Kubernetes, Kafka, cloud IAM, and PostgreSQL dependencies are introduced.

Implemented now:

- Agent registration with an immutable image digest, scope owner, tenant, and
  declared scope validation.
- Parent/child run registration with correlation IDs.
- Idempotent asynchronous shutdown requests.
- The shutdown state machine: `REQUESTED -> FENCING -> PROCESS_STOP_SENT ->
  CHILD_DISCOVERY -> PROBING -> VERIFIED | PARTIAL | UNKNOWN | FAILED`.
- Five deterministic adapter probes: process, delegation, Kafka, credential,
  and network. Adapters default to `UNKNOWN`; the system never promotes an
  unobservable result to `VERIFIED`.
- Append-only, per-run SHA-256 evidence hash chains and an HMAC-signed manifest
  for local development.
- HMAC-signed, expiring service tokens with `drill_author`, `responder`, and
  `auditor` role checks. The authenticated tenant and actor cannot be overridden
  by request JSON.
- Safe end-to-end synthetic drills and SIEM-ready event-envelope export.
- JSON API responses, SQLite persistence, and acceptance-focused tests.

## Run it

Python 3.11 or newer is recommended.

Set separate authentication and evidence-signing secrets, each at least 32 bytes:

```bash
ASV_AUTH_SECRET='replace-with-a-32-byte-auth-secret' \
ASV_SIGNING_KEY='replace-with-a-32-byte-signing-secret' \
  python3 -m asv.server
```

In another terminal, issue a local operator token using the same auth secret:

```bash
export ASV_AUTH_SECRET='replace-with-a-32-byte-auth-secret'
TOKEN=$(python3 -m asv.auth \
  --tenant demo \
  --actor operator@example.com \
  --roles drill_author,responder,auditor)
```

Create an agent:

```bash
curl -s http://localhost:8080/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-agent","image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","namespace":"asv-synthetic","scope_owner":"security@example.com","declared_scope":{"topics":["asv.test"],"synthetic_only":true}}'
```

Create a run using the returned `agent_id`, then request shutdown:

```bash
curl -s http://localhost:8080/v1/runs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"AGENT_ID","identity_ref":"synthetic/demo"}'

curl -i -s http://localhost:8080/v1/runs/RUN_ID/shutdown \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-stop-1' \
  -d '{}'
```

Read run state and evidence:

```bash
curl -s http://localhost:8080/v1/runs/RUN_ID -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/v1/runs/RUN_ID/evidence -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/v1/runs/RUN_ID/events -H "Authorization: Bearer $TOKEN"
```

Or start a simulated drill against an allowlisted synthetic target. Simulations
must explicitly provide all five outcomes; accepted values are `PASS`, `FAIL`,
`PARTIAL`, and `UNKNOWN`. If `outcomes` is omitted, the configured real adapter
runs and unconfigured boundaries remain `UNKNOWN`.

```bash
curl -s http://localhost:8080/v1/drills \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"AGENT_ID","outcomes":{"process":"PASS","delegation":"PASS","kafka":"PASS","credential":"PASS","network":"PARTIAL"}}'
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Build and deploy with Helm

Build and publish the controller image, replacing the example registry:

```bash
docker build -t ghcr.io/YOUR_ORG/agent-shutdown-verification:0.3.0 .
docker push ghcr.io/YOUR_ORG/agent-shutdown-verification:0.3.0
```

Create a dedicated namespace and supply authentication and evidence-signing
secrets outside the chart. Both values must contain at least 32 bytes:

```bash
kubectl create namespace asv-system
kubectl -n asv-system create secret generic asv-secrets \
  --from-literal=auth-secret='replace-with-a-32-byte-auth-secret' \
  --from-literal=signing-key='replace-with-a-32-byte-signing-secret'
```

Install the chart:

```bash
helm upgrade --install asv deploy/helm/agent-shutdown-verification \
  --namespace asv-system \
  --set image.repository=ghcr.io/YOUR_ORG/agent-shutdown-verification \
  --set image.tag=0.3.0

helm test asv --namespace asv-system
```

SQLite intentionally limits this starter to one replica. Enable persistent
storage for evaluations that must survive Pod replacement:

```bash
helm upgrade --install asv deploy/helm/agent-shutdown-verification \
  --namespace asv-system \
  --set image.repository=ghcr.io/YOUR_ORG/agent-shutdown-verification \
  --set persistence.enabled=true
```

Kubernetes mutation privileges are disabled by default. Do not enable the
adapter RBAC until a real adapter is configured and every target namespace is a
dedicated synthetic environment. See the chart's [values.yaml](deploy/helm/agent-shutdown-verification/values.yaml).

The opt-in Week 3 adapter now implements Kubernetes child discovery, recursive
Pod/Job shutdown, CronJob suspension, deny-all run fencing, and Kafka REST
publish/consume denial checks. Its workload labels, configuration, and safety
contract are documented in
[docs/kubernetes-kafka-adapter.md](docs/kubernetes-kafka-adapter.md).

## Safety boundary

This starter does not mutate Kubernetes, Kafka, IAM, network policy, or any
production system. The default adapters return `UNKNOWN`, which is the safe
fail-closed result. Tests inject deterministic synthetic outcomes.

Before a pilot, replace the development HMAC signer with KMS-backed asymmetric
signing, add authenticated service identities and role checks, move persistence
to PostgreSQL with tenant-scoped queries, emit the specified Kafka event schemas,
and package the controller and probes with Helm.
