# MITRE ATT&CK for Containers Notes

## Overview

MITRE ATT&CK provides a Containers platform matrix covering adversary
techniques that target containerized environments and container orchestration
systems such as Kubernetes.

This document summarizes five techniques selected for K8s Sentinel Phase 2
and provides a first-pass mapping of the existing Falco detection rules.

---

## 1. T1610 — Deploy Container

**Tactic:** Execution

### Summary

Deploy Container describes adversary activity where a new container is
deployed into an environment to facilitate execution or evade existing
security controls.

In Kubernetes environments, an adversary may deploy a privileged or
otherwise vulnerable container to a node. Containers may also be deployed
from malicious images or from legitimate images that execute malicious
payloads at runtime.

### K8s Sentinel relevance

This technique is relevant to the project's intentionally misconfigured
workloads because the project demonstrates how risky container configurations
can create opportunities for further malicious activity.

### Current detection coverage

The existing K8s Sentinel rules do not directly detect container deployment
through the Kubernetes API.

**Coverage: Not directly covered yet.**

A future rule could monitor suspicious creation or deployment of workloads
with risky attributes such as privileged mode or host filesystem mounts.

---

## 2. T1611 — Escape to Host

**Tactic:** Privilege Escalation

### Summary

Escape to Host describes an adversary breaking out of a containerized
environment to access the underlying host.

Examples include abusing privileged containers, mounting the host filesystem,
or abusing container management sockets such as docker.sock.

### K8s Sentinel relevance

This is highly relevant to the project's privileged and hostPath workloads.

The `privileged-pod` demonstrates a privileged container configuration, while
the `hostpath-pod` mounts the host filesystem at `/host`.

### Current detection coverage

**K8s Sentinel Privileged Container Process**

First-pass mapping: **Related to T1611**

The rule detects process execution inside a privileged container. Process
execution alone does not prove a container escape, so this is not considered
a direct T1611 detection.

**K8s Sentinel HostPath Write**

First-pass mapping: **Related to T1611**

The rule detects writes through the `/host` mount. Access to the host
filesystem can facilitate host compromise, but the current rule does not
prove that an escape occurred.

**Coverage: Partial / supporting detection.**

---

## 3. T1613 — Container and Resource Discovery

**Tactic:** Discovery

### Summary

Container and Resource Discovery describes adversary attempts to discover
containers and other resources in a container environment.

Examples include discovering pods, nodes, deployments, images, container
status, and other Kubernetes resources.

### K8s Sentinel relevance

This technique is important for the next stage of the project because an
attacker who gains access to a Kubernetes environment may enumerate cluster
resources before performing additional actions.

### Current detection coverage

The five existing K8s Sentinel rules do not directly detect Kubernetes
resource enumeration.

**Coverage: Not currently covered.**

A future detection rule could focus on suspicious Kubernetes API activity
such as repeated enumeration of pods, nodes, deployments, or other cluster
resources.

---

## 4. T1552.007 — Unsecured Credentials: Container API

**Tactic:** Credential Access

### Summary

This technique describes gathering credentials through APIs used in
container environments, including Docker and Kubernetes APIs.

An attacker with sufficient permissions may use the Kubernetes API to retrieve
credentials or secrets associated with the cluster.

### K8s Sentinel relevance

The project's `overpermissive-sa-pod` is relevant because it demonstrates an
excessively privileged Kubernetes ServiceAccount.

However, excessive permissions alone do not constitute credential access.

### Current detection coverage

The five existing Falco rules do not directly detect credential collection
through the Kubernetes or Docker APIs.

**Coverage: Not currently covered.**

A future rule could detect suspicious API access involving secrets,
ServiceAccounts, or other sensitive Kubernetes resources.

---

## 5. T1496 — Resource Hijacking

**Tactic:** Impact

### Summary

Resource Hijacking describes abuse of system resources for
resource-intensive activities.

One example is cryptocurrency mining, where an attacker uses compromised
compute resources for mining.

### K8s Sentinel relevance

This technique directly relates to the project's crypto-mining heuristic.

### Current detection coverage

**K8s Sentinel Crypto Mining Heuristic**

First-pass mapping: **T1496 Resource Hijacking**

The rule detects a sustained CPU-intensive process pattern using the `yes`
process and a process-duration threshold.

This is a heuristic and does not directly measure CPU utilization or prove
cryptocurrency mining.

**Coverage: Direct heuristic coverage.**

---

# First-Pass Rule Mapping

| K8s Sentinel Rule | ATT&CK Technique | Mapping |
|---|---|---|
| K8s Sentinel Container Exec | T1609 Container Administration Command | Related; outside the five selected techniques |
| K8s Sentinel Privileged Container Process | T1611 Escape to Host | Related / supporting |
| K8s Sentinel HostPath Write | T1611 Escape to Host | Related / supporting |
| K8s Sentinel Unexpected Outbound Connection | — | No direct mapping yet |
| K8s Sentinel Crypto Mining Heuristic | T1496 Resource Hijacking | Direct / strong |

## Coverage Gaps Identified

The current five rules do not directly cover:

- T1610 Deploy Container
- T1613 Container and Resource Discovery
- T1552.007 Container API credential access

The current rules provide supporting coverage for T1611 and direct heuristic
coverage for T1496.

These gaps will guide the additional detection rules planned for Phase 2.

## Key Takeaway

ATT&CK mapping should describe what a detection actually observes rather than
claiming that an alert proves an entire adversary technique.

For K8s Sentinel, the current rules provide runtime signals that may support
detection of certain container attack behaviors, but some techniques require
additional Kubernetes API or workload-level telemetry.
