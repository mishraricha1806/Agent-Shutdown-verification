# Synthetic namespace admission policy

ASV can install a cluster-scoped `ValidatingAdmissionPolicy` and binding for
disposable `asv-*` namespaces. It is disabled by default because installing
cluster-scoped admission resources requires cluster-administrator review.

The policy uses `admissionregistration.k8s.io/v1`, which is stable in Kubernetes
1.30 and newer. Helm refuses to render the policy for an older Kubernetes
version.

## Enforced controls

For every Pod created or updated in a configured synthetic namespace, the
policy denies:

- `hostNetwork`, `hostPID`, or `hostIPC`;
- `hostPath` volumes;
- privileged regular, init, or ephemeral containers;
- any container that does not explicitly set
  `allowPrivilegeEscalation: false`;
- added Linux capabilities; and
- Windows HostProcess Pods.

The binding selects namespaces through the built-in
`kubernetes.io/metadata.name` namespace label. The chart schema permits only
namespace names beginning with `asv-`. Resource identifiers and user-specific
exemptions are intentionally unsupported.

## Enable for a pilot

```yaml
admissionPolicy:
  enabled: true
  namespaces:
    - asv-synthetic
```

Render and review the cluster-scoped resources before installation:

```bash
helm template asv deploy/helm/agent-shutdown-verification \
  --namespace asv-system \
  --kube-version 1.30.0 \
  --values values-pilot.yaml \
  --show-only templates/admission-policy.yaml
```

The adversarial fixture cannot be enabled unless its namespace is included in
the admission binding. This prevents the pilot workload from bypassing the
policy through a values mismatch.

## Negative preflight

After installation, verify the API server rejects an unsafe Pod:

```bash
kubectl -n asv-synthetic apply --dry-run=server -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: asv-admission-negative-test
spec:
  hostNetwork: true
  containers:
    - name: test
      image: registry.k8s.io/pause:3.10
      securityContext:
        allowPrivilegeEscalation: false
YAML
```

The request must be denied with the message that host namespaces are forbidden.
If it is accepted, stop the pilot and verify that the
`ValidatingAdmissionPolicyBinding` exists and that the cluster enables the
`ValidatingAdmissionPolicy` admission plugin.

These controls protect the synthetic workload namespace. They do not replace a
cluster-wide Pod Security Admission profile, image policy, workload identity,
or runtime detection.
