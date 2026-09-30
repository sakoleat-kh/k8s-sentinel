# K8s Sentinel

K8s Sentinel is a Kubernetes runtime security lab that deliberately deploys
misconfigured workloads, detects suspicious activity in real time using
industry-standard security tooling, and automatically remediates detected
threats without requiring human intervention.

## Phase 2 Status

**Status: Complete**

Phase 2 extends the initial runtime detection layer into a documented,
MITRE-mapped detection system covering container runtime activity and
sensitive Kubernetes API operations.

### Detection Rules

| # | Rule | Attack Surface | MITRE ATT&CK | Tactic | Status |
|---|---|---|---|---|---|
| 1 | K8s Sentinel Container Exec | Container process execution | T1609 — Container Administration Command | Execution | PASS |
| 2 | K8s Sentinel Privileged Container Process | Privileged container activity | T1611 — Escape to Host | Privilege Escalation | PASS |
| 3 | K8s Sentinel HostPath Write | Host filesystem write through hostPath | T1611 — Escape to Host | Privilege Escalation | PASS |
| 4 | K8s Sentinel Unexpected Outbound Connection | Unexpected external network connection | T1041 — Exfiltration Over C2 Channel | Exfiltration | PASS |
| 5 | K8s Sentinel Crypto Mining Heuristic | Sustained CPU-intensive process pattern | T1496 — Resource Hijacking | Impact | PASS |
| 6 | K8s Sentinel ServiceAccount Sensitive API Activity | Sensitive Kubernetes API operations | T1552.007 | Credential Access | PASS |
| 7 | K8s Sentinel ClusterRoleBinding Cluster-Admin Grant | Privilege/persistence through RBAC | T1098 — Account Manipulation | Persistence | PASS |
| 8 | K8s Sentinel Reverse Shell Activity | Interactive shell with external connection | T1059.004 — Unix Shell | Execution | PASS |

### MITRE ATT&CK Mapping

| Rule | Technique | Mapping Notes |
|---|---|---|
| Container Exec | T1609 | Container command execution |
| Privileged Container Process | T1611 | Supporting evidence related to privileged container activity |
| HostPath Write | T1611 | Supporting evidence related to host filesystem access |
| Unexpected Outbound Connection | T1041 | Supporting network evidence; does not by itself prove exfiltration or C2 |
| Crypto Mining Heuristic | T1496 | Heuristic detection of resource hijacking |
| ServiceAccount Sensitive API Activity | T1552.007 | Sensitive ServiceAccount API activity |
| ClusterRoleBinding Cluster-Admin Grant | T1098 | RBAC-based account/privilege manipulation |
| Reverse Shell Activity | T1059.004 | Unix shell activity associated with external connection |

### Phase 2 Components

- Kind Kubernetes cluster with one control-plane and one worker node
- Falco runtime security monitoring
- Intentionally vulnerable Kubernetes workloads
- Custom Falco runtime detection rules
- Kubernetes API audit logging
- ServiceAccount and RBAC audit detection
- MITRE ATT&CK technique metadata
- Standardized JSON alert schema
- Falco alert normalizer
- Integration test script covering all eight rules
- Saved Day 13 integration test results

### Validation

All eight detection rules have been verified against their corresponding
synthetic attack scenarios.

Falco runtime rules were validated through runtime logs, while Kubernetes
API detection rules were validated through Kubernetes audit events.

The crypto-mining rule is a heuristic based on sustained execution of a
CPU-intensive process pattern; it does not directly measure CPU percentage.

The unexpected outbound connection rule provides supporting network evidence
and does not by itself establish exfiltration or command-and-control activity.

### Phase 2 Result

The detection layer is fully documented, MITRE-mapped, tuned, and validated
against the defined synthetic attack scenarios.

**Next phase:** automated remediation of detected runtime threats.

## Phase 3 Status

**Status: Complete**

Phase 3 adds Kubernetes admission control using Kyverno to prevent
high-risk workload and RBAC configurations before they are admitted
to the cluster.

### Kyverno Policies

| # | Policy | Protection | Enforcement | Status |
|---|---|---|---|---|
| 1 | `disallow-privileged-containers` | Prevents privileged containers | Enforce | PASS |
| 2 | `disallow-hostpath-mounts` | Prevents HostPath mounts | Enforce | PASS |
| 3 | `require-non-root-user` | Requires workloads to explicitly run as non-root | Enforce | PASS |
| 4 | `restrict-clusterrolebinding-creation` | Restricts `cluster-admin` bindings to approved subjects | Enforce | PASS |
| 5 | `require-resource-limits` | Requires CPU and memory limits | Enforce | PASS |

### Validation

All five Kyverno policies were tested against real Kubernetes admission
requests.

- Privileged Pod → blocked
- HostPath Pod → blocked
- Root-capable Pod → blocked
- Unauthorized `cluster-admin` ClusterRoleBinding → blocked
- Approved `default/overpermissive-sa` `cluster-admin` binding → allowed
- Pod without CPU and memory limits → blocked

All five policies report `READY=True` with admission enforcement enabled.

### PolicyReport Integration

Phase 3 also integrates Kyverno `PolicyReport` and `ClusterPolicyReport`
results into the project reporting layer.

The Python utility `scripts/policy_report_summary.py` uses the Kubernetes
Python client to collect and summarize Kyverno policy evaluation results.

It reports:

- namespaced `PolicyReports`
- cluster-scoped `ClusterPolicyReports`
- PASS, FAIL, WARN, ERROR, and SKIP results
- results grouped by policy and namespace
- cluster-scoped policy results
- violating Kubernetes resources

Current cluster validation:

| Metric | Result |
|---|---:|
| PolicyReports | 35 |
| ClusterPolicyReports | 72 |
| PASS | 37 |
| FAIL | 106 |
| WARN | 0 |
| ERROR | 0 |
| SKIP | 69 |

The report output correctly identifies the intentionally vulnerable
workloads, including `hostpath-pod`, `overpermissive-sa-pod`, and
`privileged-pod`, as well as unauthorized `cluster-admin` bindings.

These results represent Kyverno background-scan evaluations and should
not be interpreted as direct counts of admission webhook denials.

The Kyverno reports-controller RBAC configuration is stored in
`config/kyverno/reports-rbac-values.yaml`.

Run the summary with:

```bash
python scripts/policy_report_summary.py
```


### Phase 3 Result

The project now combines runtime detection with preventive Kubernetes
admission controls. High-risk workload configurations and unauthorized
privilege escalation attempts can be blocked before they are admitted
to the cluster.

**Next phase:** automated remediation of detected runtime threats.