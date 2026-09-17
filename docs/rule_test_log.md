# K8s Sentinel — Falco Rule Test Log

## 1. Overview

This document records the testing and verification of the custom Falco detection rules implemented for the **K8s Sentinel Kubernetes runtime security lab**.

K8s Sentinel uses intentionally vulnerable Kubernetes workloads to demonstrate runtime security detection. Falco monitors the cluster and generates security alerts when activity matching the custom detection rules occurs.

The three custom rules tested in this milestone are:

1. **K8s Sentinel Container Exec**
2. **K8s Sentinel Privileged Container Process**
3. **K8s Sentinel HostPath Write**

All tests were performed against intentionally vulnerable workloads deployed in the `default` namespace of the `k8s-sentinel` Kind cluster.

---

# 2. Test Environment

## Kubernetes Cluster

* Cluster: `k8s-sentinel`
* Kubernetes distribution: Kind
* Control-plane nodes: 1
* Worker nodes: 1
* Namespace used for vulnerable workloads: `default`

## Runtime Security

* Tool: Falco
* Falco version: `0.44.1`
* Driver: Modern eBPF
* Installation method: Helm
* Falco namespace: `falco`

## Vulnerable Workloads

The tests use the following intentionally vulnerable workloads:

| Workload                | Vulnerability                      | Purpose                                                |
| ----------------------- | ---------------------------------- | ------------------------------------------------------ |
| `privileged-pod`        | `securityContext.privileged: true` | Test privileged-container process detection            |
| `hostpath-pod`          | Host root `/` mounted at `/host`   | Test HostPath write detection                          |
| `overpermissive-sa-pod` | Excessive Kubernetes permissions   | Vulnerable workload created for later security testing |

---

# 3. Rule 1 — Container Command Execution

## Rule Name

**K8s Sentinel Container Exec**

## Purpose

The purpose of this rule is to detect command execution inside a running container.

The rule monitors process execution events and excludes events occurring on the host itself.

## Detection Condition

```yaml
condition: >
  evt.type in (execve, execveat)
  and container.id != host
```

## Test Workload

* Pod: `privileged-pod`
* Container: `privileged-container`
* Namespace: `default`

## Test Procedure

The following command was executed:

```bash
kubectl exec privileged-pod -- sh -c 'sleep 5'
```

This creates command execution activity inside the container.

## Expected Result

Falco should generate the custom K8s Sentinel alert:

```text
K8s Sentinel detected command execution in a container
```

## Actual Result

The custom rule successfully generated an alert.

Example observed event:

```text
K8s Sentinel detected command execution in a container
user=root
uid=0
process=sleep
command=sleep 5
container=privileged-container
k8s_pod=privileged-pod
k8s_namespace=default
```

Falco also observed the shell process used to execute the command.

## Verification

The alert was retrieved using:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=30s
```

The custom message:

```text
K8s Sentinel detected command execution in a container
```

was present in the Falco output.

## Result

**PASS**

The Rule 1 detection successfully identified command execution inside a container.

---

# 4. Rule 2 — Privileged Container Process

## Rule Name

**K8s Sentinel Privileged Container Process**

## Purpose

The purpose of this rule is to detect a process executing inside the intentionally privileged K8s Sentinel test pod.

The rule is scoped to the `privileged-pod` workload used by the security lab.

## Detection Condition

```yaml
condition: >
  container.id != host
  and container.privileged=true
  and k8s.pod.name=privileged-pod
```

## Test Workload

* Pod: `privileged-pod`
* Container: `privileged-container`
* Namespace: `default`
* Privileged: `true`

The privileged configuration was previously verified using:

```bash
kubectl get pod privileged-pod \
  -o jsonpath='{.spec.containers[0].securityContext.privileged}{"\n"}'
```

Expected output:

```text
true
```

## Test Procedure

A process was spawned inside the privileged container using:

```bash
kubectl exec privileged-pod -- sh -c \
  'echo K8S_SENTINEL_RULE2_TEST; sleep 3'
```

The command produced:

```text
K8S_SENTINEL_RULE2_TEST
```

and spawned a `sleep` process.

## Expected Result

Falco should generate the custom K8s Sentinel alert:

```text
K8s Sentinel detected process execution in the privileged test pod
```

## Actual Result

The custom Rule 2 alert was successfully generated.

Example observed events included:

```text
K8s Sentinel detected process execution in the privileged test pod
user=root
uid=0
process=sleep
command=sleep 3
container=privileged-container
k8s_pod=privileged-pod
k8s_namespace=default
```

Falco also detected the shell process:

```text
process=sh
command=sh -c echo K8S_SENTINEL_RULE2_TEST; sleep 3
```

## Verification

The alert was retrieved using:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=30s | \
grep -E "privileged test pod|privileged-pod"
```

The expected custom alert message was present in the output.

## Result

**PASS**

The Rule 2 detection successfully identified process execution inside the privileged test pod.

---

# 5. Rule 3 — HostPath Write

## Rule Name

**K8s Sentinel HostPath Write**

## Purpose

The purpose of this rule is to detect a file write performed through the `/host` HostPath mount.

The `hostpath-pod` workload mounts the host root filesystem at `/host`. This creates a dangerous configuration because processes inside the container can access files on the underlying host filesystem through that mount.

## Detection Condition

```yaml
condition: >
  evt.type in (openat, openat2, creat)
  and container.id != host
  and k8s.pod.name=hostpath-pod
  and fd.name startswith /host/
  and evt.arg.flags contains O_WRONLY
```

## Test Workload

* Pod: `hostpath-pod`
* Container: `hostpath-container`
* Namespace: `default`
* Mount destination: `/host`

The mount was verified using:

```bash
kubectl get pod hostpath-pod \
  -o jsonpath='{.spec.containers[0].volumeMounts}{"\n"}'
```

The output confirmed:

```text
mountPath=/host
```

## Initial HostPath Write Verification

Before testing the Falco rule, the HostPath vulnerability itself was verified.

The following command was executed:

```bash
kubectl exec hostpath-pod -- sh -c \
  'echo K8S_SENTINEL_RULE3_TEST > /host/tmp/k8s-sentinel-test'
```

The file was then read from inside the container:

```bash
kubectl exec hostpath-pod -- cat /host/tmp/k8s-sentinel-test
```

The output was:

```text
K8S_SENTINEL_RULE3_TEST
```

This confirmed that the container could successfully write through the `/host` mount.

## Falco Test Procedure

A fresh test file was created using:

```bash
kubectl exec hostpath-pod -- sh -c \
  'echo K8S_SENTINEL_RULE3_TRIGGER > /host/tmp/k8s-sentinel-rule3-test'
```

## Expected Result

Falco should generate the custom K8s Sentinel alert:

```text
K8s Sentinel detected write through hostPath mount
```

## Actual Result

The custom Rule 3 alert was successfully generated.

Observed event:

```text
K8s Sentinel detected write through hostPath mount
user=root
uid=0
process=sh
command=sh -c echo K8S_SENTINEL_RULE3_TRIGGER >/host/tmp/k8s-sentinel-rule3-test
file=/host/tmp/k8s-sentinel-rule3-test
container=hostpath-container
k8s_pod=hostpath-pod
k8s_namespace=default
```

## Verification

The alert was retrieved using:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=30s | \
grep -E "hostPath|hostpath-pod|K8s Sentinel detected write"
```

The expected custom alert was present:

```text
K8s Sentinel detected write through hostPath mount
```

The file was also successfully created through the HostPath mount.

## Result

**PASS**

The Rule 3 detection successfully identified a file write through the HostPath mount.

---

# 6. Custom Rule Verification

All three custom rules were loaded into Falco through:

```text
/etc/falco/rules.d/custom-rules.yaml
```

The deployed custom rules are:

```text
K8s Sentinel Container Exec
K8s Sentinel Privileged Container Process
K8s Sentinel HostPath Write
```

The rules were deployed using Helm:

```bash
helm upgrade falco falcosecurity/falco \
  -n falco \
  -f falco/custom_rules.yaml \
  --reuse-values
```

The final successful deployment reached:

```text
STATUS: deployed
REVISION: 11
DESCRIPTION: Upgrade complete
```

The Falco DaemonSet was then verified using:

```bash
kubectl rollout status daemonset/falco -n falco --timeout=180s
```

Result:

```text
daemon set "falco" successfully rolled out
```

---

# 7. Test Summary

| Rule   | Detection                    | Test Workload    | Expected Alert                                                       | Result   |
| ------ | ---------------------------- | ---------------- | -------------------------------------------------------------------- | -------- |
| Rule 1 | Container command execution  | `privileged-pod` | `K8s Sentinel detected command execution in a container`             | **PASS** |
| Rule 2 | Privileged container process | `privileged-pod` | `K8s Sentinel detected process execution in the privileged test pod` | **PASS** |
| Rule 3 | HostPath write               | `hostpath-pod`   | `K8s Sentinel detected write through hostPath mount`                 | **PASS** |

---

# 8. Verification Evidence

The testing produced the following evidence:

### Rule 1

```text
K8s Sentinel detected command execution in a container
```

Observed with:

```text
k8s_pod=privileged-pod
process=sh
command=sh -c sleep 5
```

### Rule 2

```text
K8s Sentinel detected process execution in the privileged test pod
```

Observed with:

```text
k8s_pod=privileged-pod
process=sleep
command=sleep 3
```

### Rule 3

```text
K8s Sentinel detected write through hostPath mount
```

Observed with:

```text
k8s_pod=hostpath-pod
process=sh
file=/host/tmp/k8s-sentinel-rule3-test
```

---

# 9. Final Result

All three custom Falco detection rules were successfully deployed and tested against intentionally vulnerable Kubernetes workloads.

The tests demonstrated that Falco can:

1. Detect command execution inside containers.
2. Detect process execution inside the intentionally privileged test pod.
3. Detect file writes performed through the HostPath mount.

All three detection rules generated their expected K8s Sentinel alerts during testing.

**Overall Detection Milestone: PASS**

The K8s Sentinel detection layer for this milestone is verified and ready for the next development stage.
