# RBAC and ServiceAccount Audit Detection

## Overview

K8s Sentinel uses Kubernetes API audit logging to detect sensitive
ServiceAccount activity that is not directly represented as a Falco
syscall event.

This detection layer complements the five Falco runtime rules from
Phase 1.

## Detection Architecture

```text
Kubernetes API request
        |
        v
Kubernetes API Server
        |
        v
Audit Log
        |
        v
rbac_audit_detector.py
        |
        +--------------------+
        |                    |
        v                    v
      Rule 6              Rule 7
        |                    |
        v                    v
Sensitive API       cluster-admin
activity            ClusterRoleBinding
```

## Rule 6 — ServiceAccount Sensitive API Activity

**Purpose:** Detect sensitive Kubernetes API operations performed by a
ServiceAccount identity.

### Detection Logic

The detector generates an alert when:

- the audit event reaches `ResponseComplete`
- the authenticated identity starts with `system:serviceaccount:`
- the API verb is one of:
  - `create`
  - `delete`
  - `update`
  - `patch`
- the resource is one of:
  - `secrets`
  - `rolebindings`
  - `clusterrolebindings`

### Alert Fields

The detector reports:

- ServiceAccount identity
- API verb
- resource
- namespace
- resource name

### Validation

The `overpermissive-sa` ServiceAccount was used through its mounted
Kubernetes token to:

1. create `k8s-sentinel-rule6-audit-test`
2. delete `k8s-sentinel-rule6-audit-test`

Both operations appeared in the Kubernetes audit log and were detected
by Rule 6.

Example detection:

```json
{
  "rule": "K8s Sentinel ServiceAccount Sensitive API Activity",
  "rule_id": "6",
  "actor": "system:serviceaccount:default:overpermissive-sa",
  "verb": "create",
  "resource": "secrets",
  "namespace": "default",
  "name": "k8s-sentinel-rule6-audit-test"
}
```

The delete operation was also detected:

```json
{
  "rule": "K8s Sentinel ServiceAccount Sensitive API Activity",
  "rule_id": "6",
  "actor": "system:serviceaccount:default:overpermissive-sa",
  "verb": "delete",
  "resource": "secrets",
  "namespace": "default",
  "name": "k8s-sentinel-rule6-audit-test"
}
```

## Rule 7 — ClusterRoleBinding Cluster-Admin Grant

**Purpose:** Detect creation of a ClusterRoleBinding that grants the
`cluster-admin` ClusterRole.

### Detection Logic

The detector generates an alert when:

- the audit event reaches `ResponseComplete`
- the API verb is `create`
- the resource is `clusterrolebindings`
- `requestObject.roleRef.name` is `cluster-admin`

Rule 7 is evaluated before Rule 6 because a `clusterrolebindings`
creation event can also satisfy the broader Rule 6 sensitive-resource
condition. This ensures that a cluster-admin grant is reported as the
more specific Rule 7 detection.

### Alert Fields

The detector reports:

- actor identity
- API verb
- resource
- ClusterRoleBinding name
- granted role
- subjects receiving the binding

### Validation

The `overpermissive-sa` ServiceAccount used its mounted token to create:

`k8s-sentinel-rule7-audit-test`

The Kubernetes audit event confirmed:

- actor: `system:serviceaccount:default:overpermissive-sa`
- verb: `create`
- resource: `clusterrolebindings`
- role: `cluster-admin`

The detector correctly generated a Rule 7 alert.

Example detection:

```json
{
  "rule": "K8s Sentinel ClusterRoleBinding Cluster-Admin Grant",
  "rule_id": "7",
  "actor": "system:serviceaccount:default:overpermissive-sa",
  "verb": "create",
  "resource": "clusterrolebindings",
  "name": "k8s-sentinel-rule7-audit-test",
  "role": "cluster-admin",
  "subjects": [
    {
      "kind": "ServiceAccount",
      "name": "overpermissive-sa",
      "namespace": "default"
    }
  ]
}
```

## Kubernetes Audit Policy

The Kubernetes API server uses:

`cluster/audit-policy.yaml`

The policy records `RequestResponse` audit events for the Secrets and
RBAC resources required by these detections.

The relevant resources are:

- `secrets`
- `rolebindings`
- `clusterrolebindings`

The policy also contains a broader `Metadata` rule for other API
resources.

### Audit Event Information

The audit events provide information including:

- authenticated Kubernetes identity
- API verb
- requested resource
- namespace and resource name
- request object where applicable
- response status
- authorization decision
- authorization reason

For the Rule 6 validation, the audit log identified the actor as:

`system:serviceaccount:default:overpermissive-sa`

For the Rule 7 validation, the audit event additionally contained:

`requestObject.roleRef.name = cluster-admin`

This provides the information required by the detector.

## Implementation

The detector is implemented in:

`detection/rbac_audit_detector.py`

The detector:

1. reads Kubernetes audit events as JSON Lines from standard input
2. ignores events that are not at `ResponseComplete`
3. checks for the specific Rule 7 cluster-admin pattern
4. checks for the broader Rule 6 sensitive ServiceAccount activity
5. outputs matching detections as JSON

### Running the Detector

The Kubernetes audit log is stored inside the Kind control-plane
container.

The detector can process recent audit events with:

```bash
docker exec k8s-sentinel-control-plane sh -c \
'tail -n 1000 /var/log/kubernetes/audit.log' \
| python3 detection/rbac_audit_detector.py
```

### Example Output

```text
{"rule": "K8s Sentinel ServiceAccount Sensitive API Activity", "rule_id": "6", "actor": "system:serviceaccount:default:overpermissive-sa", "verb": "create", "resource": "secrets", "namespace": "default", "name": "k8s-sentinel-rule6-audit-test"}

{"rule": "K8s Sentinel ServiceAccount Sensitive API Activity", "rule_id": "6", "actor": "system:serviceaccount:default:overpermissive-sa", "verb": "delete", "resource": "secrets", "namespace": "default", "name": "k8s-sentinel-rule6-audit-test"}

{"rule": "K8s Sentinel ClusterRoleBinding Cluster-Admin Grant", "rule_id": "7", "actor": "system:serviceaccount:default:overpermissive-sa", "verb": "create", "resource": "clusterrolebindings", "name": "k8s-sentinel-rule7-audit-test", "role": "cluster-admin", "subjects": [{"kind": "ServiceAccount", "name": "overpermissive-sa", "namespace": "default"}]}
```

## Detection Layer

K8s Sentinel now uses two complementary detection layers.

### Rules 1–5 — Falco Runtime Detection

The first five rules use Falco runtime events to detect activity such
as:

- container process execution
- privileged container activity
- hostPath writes
- unexpected outbound connections
- sustained CPU-intensive process activity

### Rules 6–7 — Kubernetes API Audit Detection

The next two rules use Kubernetes API audit events to detect:

- sensitive ServiceAccount API activity
- creation of a ClusterRoleBinding granting `cluster-admin`

This separation allows K8s Sentinel to detect both:

- runtime behavior inside containers
- sensitive Kubernetes control-plane API activity

## Validation Summary

| Rule | Detection Layer | Test | Status |
|---|---|---|---|
| 6 | Kubernetes Audit | ServiceAccount creates Secret | PASS |
| 6 | Kubernetes Audit | ServiceAccount deletes Secret | PASS |
| 7 | Kubernetes Audit | ServiceAccount creates cluster-admin ClusterRoleBinding | PASS |
| 7 | Detector | Real audit event parsed successfully | PASS |

## Security Scope and Limitations

These detections are designed for the K8s Sentinel security laboratory
and portfolio project.

Rule 6 identifies sensitive API activity performed by a ServiceAccount;
it does not by itself prove that the ServiceAccount token was stolen or
compromised.

Rule 7 identifies the creation of a ClusterRoleBinding granting
`cluster-admin`; it does not determine the attacker's original access
path.

The audit policy currently uses `RequestResponse` for selected Secrets
and RBAC resources because the detector requires request information
for the tested detection scenarios. Kubernetes audit logs can contain
sensitive request and response information, so this configuration
should be treated as a laboratory configuration and reviewed before
production use.

## Phase 1 and Day 9 Result

Phase 1 established five Falco-based runtime detection rules.

Day 9 extends the platform with Kubernetes API audit-based detection
for ServiceAccount abuse and cluster-admin privilege escalation.

The project now has seven custom detection rules across two detection
sources:

- **5 Falco runtime rules**
- **2 Kubernetes audit rules**

All seven detection scenarios have been validated through controlled
test activity.