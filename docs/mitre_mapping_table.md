# K8s Sentinel — MITRE ATT&CK Mapping Table

## Overview

This document maps each K8s Sentinel Falco detection rule to a MITRE
ATT&CK technique and tactic.

The mappings describe what each detection rule can support or indicate.
A detection alert does not by itself prove that the mapped ATT&CK technique
was successfully executed by an adversary.

## Rule-to-Technique Mapping

| K8s Sentinel Rule | Technique ID | Technique | Tactic | Justification |
|---|---|---|---|---|
| K8s Sentinel Container Exec | T1609 | Container Administration Command | Execution | Detects command execution inside a running container, which is consistent with abuse of container administration mechanisms to execute commands. |
| K8s Sentinel Privileged Container Process | T1611 | Escape to Host | Privilege Escalation | Detects process execution inside the intentionally privileged test container, which can support host-escape activity but does not by itself prove that an escape occurred. |
| K8s Sentinel HostPath Write | T1611 | Escape to Host | Privilege Escalation | Detects writes through a host filesystem mounted into a container, a configuration that can facilitate access to or modification of the underlying host. |
| K8s Sentinel Unexpected Outbound Connection | T1041 | Exfiltration Over C2 Channel | Exfiltration | Detects an unexpected external connection from the test workload and can provide supporting network evidence for suspicious outbound activity, but does not by itself prove data exfiltration or C2. |
| K8s Sentinel Crypto Mining Heuristic | T1496 | Resource Hijacking | Impact | Detects sustained execution of a CPU-intensive process pattern that can indicate abuse of container resources for resource-intensive activity such as cryptocurrency mining. |

## Mapping Notes

### T1609 — Container Administration Command

The Container Exec rule observes process execution inside containers.
This is closely related to T1609 because MITRE documents command execution
through container administration mechanisms such as Kubernetes API
interactions and `kubectl exec`.

### T1611 — Escape to Host

The privileged-container and hostPath rules are supporting detections for
T1611.

A privileged container or a container with access to the host filesystem
can provide conditions that facilitate host compromise. However, the
current rules detect activity associated with these configurations rather
than directly proving a successful container escape.

### T1041 — Exfiltration Over C2 Channel

The Unexpected Outbound Connection rule detects an external network
connection from the test workload.

The alert should therefore be treated as supporting evidence for
investigation rather than proof of T1041. The rule does not inspect the
payload or establish that data was stolen over a command-and-control
channel.

### T1496 — Resource Hijacking

The Crypto Mining Heuristic detects sustained execution of the `yes`
process in the test workload.

This is a deliberately simple laboratory heuristic. It does not directly
measure CPU percentage, identify a cryptocurrency mining binary, or prove
cryptocurrency mining. It demonstrates how sustained resource-intensive
activity can generate a runtime security alert associated with T1496.

## Current Coverage

| Technique | Coverage |
|---|---|
| T1609 — Container Administration Command | Direct behavioral mapping |
| T1611 — Escape to Host | Supporting behavioral mapping |
| T1041 — Exfiltration Over C2 Channel | Supporting network mapping |
| T1496 — Resource Hijacking | Heuristic behavioral mapping |

## Interpretation

MITRE ATT&CK mappings are used as contextual labels for K8s Sentinel
detections. The technique ID identifies the ATT&CK behavior that the alert
is intended to help detect or investigate.

The mapping should not be interpreted as confirmation that the complete
ATT&CK technique was successfully executed.

## References

- MITRE ATT&CK T1609 — Container Administration Command
- MITRE ATT&CK T1611 — Escape to Host
- MITRE ATT&CK T1041 — Exfiltration Over C2 Channel
- MITRE ATT&CK T1496 — Resource Hijacking
