# Deliberately Vulnerable Workloads

K8s Sentinel uses intentionally insecure Kubernetes workloads as controlled security test fixtures. These workloads are deployed in the local kind cluster so that runtime security detection and automated remediation can be tested safely.

## 1. Privileged Pod

**File:** `vulnerable/privileged-pod.yaml`

### Vulnerability

The container has:

```yaml
securityContext:
  privileged: true
```

### Why it is dangerous

A privileged container receives highly elevated access compared with a normal container. Depending on the surrounding configuration and available host interfaces, this can significantly increase the impact of a container compromise and may provide paths toward host-level compromise.

### Security lesson

Containers should run with the minimum privileges required by the workload. Privileged containers should be avoided unless there is a strong, explicitly reviewed requirement.

---

## 2. HostPath Mount of the Node Root Filesystem

**File:** `vulnerable/hostpath-pod.yaml`

### Vulnerability

The pod mounts the node's root filesystem:

```yaml
hostPath:
  path: /
```

The host filesystem is exposed inside the container at:

```text
/host
```

### Why it is dangerous

A workload normally should not have unrestricted access to the Kubernetes node's filesystem. A broad host filesystem mount can expose sensitive host files and, depending on permissions and other node configuration, can turn a container compromise into a much more serious host compromise.

### Security lesson

HostPath volumes should be avoided where possible. If required, the path and access mode should be narrowly restricted.

---

## 3. ServiceAccount Bound to cluster-admin

**File:** `vulnerable/overpermissive-sa.yaml`

### Vulnerability

The ServiceAccount:

`overpermissive-sa`

is bound through a ClusterRoleBinding to:

`cluster-admin`

### Why it is dangerous

`cluster-admin` grants extremely broad Kubernetes API permissions. If an attacker compromises a pod using this ServiceAccount, they may be able to perform administrative actions across the cluster.

This violates the principle of least privilege.

### Security lesson

ServiceAccounts should receive only the Kubernetes API permissions actually required by their workloads. Namespace-scoped Roles and narrowly scoped RoleBindings should generally be preferred over cluster-wide administrative permissions.

---

## Purpose in K8s Sentinel

These workloads are intentionally vulnerable and exist only as controlled security test fixtures.

They provide three different classes of security signals:

| Workload                | Vulnerability      | Security Area            |
| ----------------------- | ------------------ | ------------------------ |
| `privileged-pod`        | `privileged: true` | Container security       |
| `hostpath-pod`          | `hostPath: /`      | Host filesystem exposure |
| `overpermissive-sa-pod` | `cluster-admin`    | Kubernetes RBAC          |

These fixtures will later be used to test K8s Sentinel's detection and automated remediation capabilities.
