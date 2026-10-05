# Kyverno Policies

K8s Sentinel uses Kyverno to enforce preventive Kubernetes security
controls at admission time. The policies below are implemented as
`ClusterPolicy` resources and use `validationFailureAction: Enforce`.

All five policies have `background: true`, so Kyverno also evaluates
existing resources during background scans.

## Policy Summary

| # | Policy | Resource | Mode | Purpose |
|---|---|---|---|---|
| 1 | `disallow-privileged-containers` | Pod | Enforce | Prevent privileged containers |
| 2 | `disallow-hostpath-mounts` | Pod | Enforce | Prevent HostPath volumes |
| 3 | `require-non-root-user` | Pod | Enforce | Require explicit non-root execution |
| 4 | `restrict-clusterrolebinding-creation` | ClusterRoleBinding | Enforce | Restrict `cluster-admin` bindings |
| 5 | `require-resource-limits` | Pod | Enforce | Require CPU and memory limits |

## 1. Disallow Privileged Containers

**Policy:** `disallow-privileged-containers`  
**Rule:** `check-privileged`  
**Resource:** Pod  
**Mode:** Enforce

### Rationale

Privileged containers have elevated access to the underlying container
runtime and host resources. This policy requires every container to
explicitly set:

`securityContext.privileged: false`

A Pod containing a privileged container is rejected by Kyverno during
admission.

**Validation message:**

> Privileged containers are not allowed.

---

## 2. Disallow HostPath Mounts

**Policy:** `disallow-hostpath-mounts`  
**Rule:** `check-hostpath`  
**Resource:** Pod  
**Mode:** Enforce

### Rationale

HostPath volumes can expose files and directories from the Kubernetes
node to a container. In K8s Sentinel, HostPath access is treated as a
preventive security boundary.

This policy rejects Pods that define a `hostPath` volume.

**Validation message:**

> HostPath volumes are not allowed.

---

## 3. Require Non-Root User

**Policy:** `require-non-root-user`  
**Rule:** `check-run-as-non-root`  
**Resource:** Pod  
**Mode:** Enforce

### Rationale

Running containers as root can increase the impact of a container
compromise. This policy requires Pods to explicitly specify:

`securityContext.runAsNonRoot: true`

Pods that do not explicitly require non-root execution are rejected by
Kyverno during admission.

**Validation message:**

> Pods must explicitly require a non-root user.

---

## 4. Restrict ClusterRoleBinding Creation

**Policy:** `restrict-clusterrolebinding-creation`  
**Rule:** `restrict-cluster-admin-binding`  
**Resource:** ClusterRoleBinding  
**Mode:** Enforce

### Rationale

A `cluster-admin` ClusterRoleBinding provides highly privileged
Kubernetes access. This policy restricts creation of
`cluster-admin` bindings.

The current project policy permits the approved ServiceAccount:

`default/overpermissive-sa`

Other subjects attempting to receive the `cluster-admin` role are
rejected by Kyverno.

**Validation message:**

> Binding cluster-admin is restricted to approved subjects.

---

## 5. Require Resource Limits

**Policy:** `require-resource-limits`  
**Rule:** `require-cpu-memory-limits`  
**Resource:** Pod  
**Mode:** Enforce

### Rationale

Resource limits help constrain CPU and memory consumption by containers.
This policy requires every container in a Pod to define both:

- CPU limit
- Memory limit

Pods without the required CPU and memory limits are rejected by Kyverno
during admission.

**Validation message:**

> Containers must define CPU and memory resource limits.

---

## Enforcement Model

All five policies use:

`validationFailureAction: Enforce`

Therefore, matching admission requests are rejected when they violate
the policy.

All five policies also use:

`background: true`

This allows Kyverno to evaluate existing resources through background
scans and generate `PolicyReport` and `ClusterPolicyReport` results.

PolicyReport results represent Kyverno policy evaluations from background
scans and should not be interpreted as direct counts of admission
webhook denials.

## Policy Files

The five policies are stored under:

`policies/kyverno/`

Files:

1. `disallow-privileged-containers.yaml`
2. `disallow-hostpath-mounts.yaml`
3. `require-non-root-user.yaml`
4. `restrict-clusterrolebinding-creation.yaml`
5. `require-resource-limits.yaml`

## Scope and Limitations

The current policies intentionally use broad resource matching for the
K8s Sentinel lab.

As a result, background scans can report violations in existing
Kubernetes infrastructure resources in addition to the intentionally
vulnerable workloads created by the project.

This is a current policy-scope limitation and can be refined in a future
phase if the project requires more selective policy targeting.
