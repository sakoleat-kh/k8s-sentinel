from responder.app.models import Action, Alert


def decide_action(alert: Alert) -> Action:
    """Select a response action without executing remediation."""

    severity = alert.severity.strip().lower()

    # Accept raw Falco severity names as well as normalized values.
    if severity in {"emergency", "alert", "critical"}:
        if alert.pod_name and alert.namespace:
            return Action.KILL_POD
        return Action.LOG_ONLY

    if severity in {"error", "warning", "high"}:
        return Action.CORDON_NODE_AND_NOTIFY

    # Medium, low, unknown, and unrecognized severities fail closed.
    return Action.LOG_ONLY
