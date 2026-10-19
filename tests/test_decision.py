import json
from pathlib import Path

import pytest

from responder.app.decision import decide_action
from responder.app.models import Action, Alert


RESULTS_PATH = Path("docs/rule_test_results.json")


def load_rule_results():
    with RESULTS_PATH.open(encoding="utf-8") as file:
        return json.load(file)["results"]


@pytest.mark.parametrize(
    "result",
    load_rule_results(),
    ids=lambda result: result["rule_name"],
)
def test_rule_maps_to_expected_action(result):
    alert = Alert(
        severity=result["severity"],
        technique_id=result.get("technique_id"),
        tactic=result.get("tactic"),
        rule_name=result["rule_name"],
        pod_name=result.get("pod"),
        namespace=result.get("namespace", "default"),
        raw_output=result["evidence"],
    )

    severity = result["severity"].lower()

    if severity == "critical":
        expected = Action.LOG_ONLY
    elif severity in {"high", "warning", "error"}:
        expected = Action.CORDON_NODE_AND_NOTIFY
    else:
        expected = Action.LOG_ONLY

    assert decide_action(alert) == expected


def test_critical_alert_with_pod_and_namespace_selects_kill():
    alert = Alert(
        severity="critical",
        rule_name="Synthetic critical Pod alert",
        pod_name="test-pod",
        namespace="default",
    )

    assert decide_action(alert) == Action.KILL_POD


def test_critical_alert_missing_pod_or_namespace_logs_only():
    missing_pod = Alert(
        severity="critical",
        pod_name=None,
        namespace="default",
    )
    missing_namespace = Alert(
        severity="critical",
        pod_name="test-pod",
        namespace=None,
    )

    assert decide_action(missing_pod) == Action.LOG_ONLY
    assert decide_action(missing_namespace) == Action.LOG_ONLY


def test_unknown_severity_logs_only():
    alert = Alert(
        severity="unexpected",
        pod_name="test-pod",
        namespace="default",
    )

    assert decide_action(alert) == Action.LOG_ONLY
