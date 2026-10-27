from responder.app.k8s_actions import is_approved_pod_target
from responder.app.models import Action, Alert


def decide_action(alert: Alert) -> Action:
    """Select remediation only for explicitly approved test workloads."""
    severity = alert.severity.strip().lower()

    if severity in {"emergency", "alert", "critical"}:
        if (
            alert.pod_name
            and alert.namespace
            and is_approved_pod_target(alert.pod_name, alert.namespace)
        ):
            return Action.KILL_POD

    return Action.LOG_ONLY
