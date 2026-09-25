#!/usr/bin/env python3

import json
import sys


SENSITIVE_RESOURCES = {
    "secrets",
    "rolebindings",
    "clusterrolebindings",
}

SENSITIVE_VERBS = {
    "create",
    "delete",
    "update",
    "patch",
}


def normalize_alert(
    *,
    severity,
    technique_id,
    tactic,
    rule_name,
    event,
    raw_output,
):
    """Return an alert using the K8s Sentinel standardized schema."""

    object_ref = event.get("objectRef", {})

    return {
        "severity": severity,
        "technique_id": technique_id,
        "tactic": tactic,
        "rule_name": rule_name,
        "pod_name": None,
        "namespace": object_ref.get("namespace"),
        "timestamp": event.get("requestReceivedTimestamp")
        or event.get("stageTimestamp"),
        "raw_output": raw_output,
    }


def detect_event(event, raw_output):
    """Return a standardized alert if the audit event matches Rule 6 or 7."""

    if event.get("stage") != "ResponseComplete":
        return None

    user = event.get("user", {})
    username = user.get("username", "")
    object_ref = event.get("objectRef", {})
    resource = object_ref.get("resource")

    # Rule 7: ClusterRoleBinding grants cluster-admin.
    request_object = event.get("requestObject") or {}
    role_ref = request_object.get("roleRef", {})

    if (
        event.get("verb") == "create"
        and resource == "clusterrolebindings"
        and role_ref.get("name") == "cluster-admin"
    ):
        return normalize_alert(
            severity="critical",
            technique_id="T1098",
            tactic="Persistence",
            rule_name="K8s Sentinel ClusterRoleBinding Cluster-Admin Grant",
            event=event,
            raw_output=raw_output,
        )

    # Rule 6: ServiceAccount performs a sensitive API operation.
    if (
        username.startswith("system:serviceaccount:")
        and event.get("verb") in SENSITIVE_VERBS
        and resource in SENSITIVE_RESOURCES
    ):
        return normalize_alert(
            severity="high",
            technique_id="T1552.007",
            tactic="Credential Access",
            rule_name="K8s Sentinel ServiceAccount Sensitive API Activity",
            event=event,
            raw_output=raw_output,
        )

    return None


def main():
    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert = detect_event(event, line)

        if alert:
            print(json.dumps(alert), flush=True)


if __name__ == "__main__":
    main()
