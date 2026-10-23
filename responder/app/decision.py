from responder.app.models import Action, Alert


def decide_action(alert: Alert) -> Action:
    """Select an action conservatively; execution is handled separately."""
    severity = alert.severity.strip().lower()

    if severity in {"emergency", "alert", "critical"}:
        if alert.pod_name and alert.namespace:
            return Action.KILL_POD
        return Action.LOG_ONLY

    return Action.LOG_ONLY
