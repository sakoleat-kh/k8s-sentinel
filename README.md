# K8s Sentinel

K8s Sentinel is a Kubernetes runtime security lab that deliberately deploys
misconfigured workloads, detects suspicious activity in real time using
industry-standard security tooling, and automatically remediates detected
threats without requiring human intervention.

## Phase 1 Status

**Status: Complete**

Phase 1 establishes the initial Kubernetes runtime detection layer using
Falco and intentionally vulnerable workloads.

### Detection Rules

| # | Rule                                        | Attack Surface                          | Status |
| - | ------------------------------------------- | --------------------------------------- | ------ |
| 1 | K8s Sentinel Container Exec                 | Container process execution             | ✅ PASS |
| 2 | K8s Sentinel Privileged Container Process   | Privileged container activity           | ✅ PASS |
| 3 | K8s Sentinel HostPath Write                 | Host filesystem write through hostPath  | ✅ PASS |
| 4 | K8s Sentinel Unexpected Outbound Connection | Unexpected external network connection  | ✅ PASS |
| 5 | K8s Sentinel Crypto Mining Heuristic        | Sustained CPU-intensive process pattern | ✅ PASS |

### Phase 1 Components

* Kind Kubernetes cluster with one control-plane and one worker node
* Falco runtime security monitoring
* Intentionally vulnerable Kubernetes workloads
* Custom Falco detection rules
* Manual trigger tests for all five custom rules
* Kubernetes workload and container context in Falco alerts

### Validation

All five custom Falco rules have been manually triggered against the
corresponding test workloads and verified through Falco runtime logs.

The crypto-mining rule is a heuristic based on sustained execution of a
CPU-intensive process pattern; it does not directly measure CPU percentage.

### Phase 1 Result

The initial runtime detection layer is operational and validated against the
defined synthetic attack scenarios.

**Next phase:** automated remediation of detected runtime threats.
