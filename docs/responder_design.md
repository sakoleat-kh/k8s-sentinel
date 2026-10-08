# K8s Sentinel Auto-Remediation Responder

## Purpose

The K8s Sentinel responder closes the loop between runtime detection
and automated Kubernetes response.

A Falco runtime alert is delivered to an HTTP webhook. The FastAPI
responder evaluates the alert severity and technique, then performs
the appropriate Kubernetes action.

## Architecture

Falco
  |
  | HTTP POST /falco-webhook
  v
FastAPI Responder
  |
  | Parse and normalize alert
  v
Decision Engine
  |
  +-------------------+
  |                   |
  v                   v
Kubernetes API       Notification / Log
  |
  v
Automated Response

## Alert Flow

1. Falco detects suspicious runtime activity.
2. Falco sends the alert to the responder webhook.
3. FastAPI receives the JSON payload.
4. The responder extracts severity, technique ID, pod, namespace,
   and node information.
5. The decision engine determines the response action.
6. The responder calls the Kubernetes API when an automated action
   is required.
7. The action and original alert are logged for auditability.

## Decision Table

| Severity | Technique / Condition | Action |
|---|---|---|
| Critical | Critical security event | Kill affected Pod |
| High | High-severity security event | Cordon affected Node + notify |
| Medium | Medium-severity event | Log only |
| Low / Unknown | No automated response rule | Log only |

## Initial Automated Actions

### Critical — Kill Pod

For critical alerts, the responder identifies the affected Pod
and deletes it through the Kubernetes API.

This is intended to contain an active runtime threat quickly.

### High — Cordon Node + Notify

For high-severity alerts, the responder identifies the affected
Kubernetes node and cordons it to prevent new workloads from being
scheduled there.

A notification event is also logged.

### Medium — Log Only

Medium-severity events do not trigger destructive actions.

The responder records the event for investigation.

## Safety Principles

- Only explicitly supported actions are automated.
- Unknown techniques default to logging only.
- Missing Pod or namespace information must not trigger deletion.
- Kubernetes API errors must be logged.
- Every automated action must include the original alert context.
- The responder should fail closed: uncertain input must not result
  in a destructive action.

## Phase 4 Scope

Day 20 implements the HTTP webhook and responder skeleton.

Later phases will add:

- Kubernetes API integration
- severity and technique decision logic
- real Pod remediation
- node cordoning
- notifications
- end-to-end Falco-to-remediation testing