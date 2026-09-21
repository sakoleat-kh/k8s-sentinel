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


def detect_event(event):
    """Return an alert dictionary if the audit event matches Rule 6 or 7."""

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
        return {
            "rule": "K8s Sentinel ClusterRoleBinding Cluster-Admin Grant",
            "rule_id": "7",
            "actor": username,
            "verb": event.get("verb"),
            "resource": "clusterrolebindings",
            "name": object_ref.get("name"),
            "role": "cluster-admin",
            "subjects": request_object.get("subjects", []),
        }

    # Rule 6: ServiceAccount performs a sensitive API operation.
    if (
        username.startswith("system:serviceaccount:")
        and event.get("verb") in SENSITIVE_VERBS
        and resource in SENSITIVE_RESOURCES
    ):
        return {
            "rule": "K8s Sentinel ServiceAccount Sensitive API Activity",
            "rule_id": "6",
            "actor": username,
            "verb": event.get("verb"),
            "resource": resource,
            "namespace": object_ref.get("namespace"),
            "name": object_ref.get("name"),
        }

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

        alert = detect_event(event)

        if alert:
            print(json.dumps(alert), flush=True)


if __name__ == "__main__":
    main()