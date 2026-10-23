from fastapi.testclient import TestClient

from responder.app import main
from responder.app.models import Action

client = TestClient(main.app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_critical_approved_test_pod_triggers_remediation(monkeypatch, tmp_path):

    monkeypatch.setenv(
        "K8S_SENTINEL_AUDIT_DB",
        str(tmp_path / "remediation-audit.db"),
    )
    def fake_kill_pod(*, pod_name, namespace):
        return {
            "status": "deletion_requested",
            "namespace": namespace,
            "pod_name": pod_name,
            "api_status": "accepted",
        }

    monkeypatch.setattr(main, "kill_pod", fake_kill_pod)

    response = client.post(
        "/falco-webhook",
        json={
            "rule": "K8s Sentinel Remediation Test",
            "priority": "Critical",
            "output": "Synthetic test alert",
            "output_fields": {
                "k8s.pod.name": "k8s-sentinel-remediation-test-unit",
                "k8s.ns.name": "default",
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["action"] == Action.KILL_POD.value
    assert body["remediation_executed"] is True
    assert body["remediation_error"] is None
    assert body["remediation_result"]["pod_name"] == (
        "k8s-sentinel-remediation-test-unit"
    )


def test_critical_alert_without_target_only_logs(monkeypatch):
    def unexpected_kill_pod(**kwargs):
        raise AssertionError("Remediation must not run without a target")

    monkeypatch.setattr(main, "kill_pod", unexpected_kill_pod)

    response = client.post(
        "/falco-webhook",
        json={
            "rule": "Critical alert without target",
            "priority": "Critical",
            "output": "No pod target supplied",
            "output_fields": {},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["action"] == Action.LOG_ONLY.value
    assert body["remediation_executed"] is False


def test_invalid_payload_returns_400():
    response = client.post(
        "/falco-webhook",
        json={"rule": "Malformed alert"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid alert payload"


def test_kubernetes_timeout_is_audited_and_does_not_crash(monkeypatch, tmp_path):
    import sqlite3

    from kubernetes.client.exceptions import ApiException

    monkeypatch.setenv(
        "K8S_SENTINEL_AUDIT_DB",
        str(tmp_path / "timeout-audit.db"),
    )

    def timeout_kill_pod(*, pod_name, namespace):
        raise ApiException(status=504, reason="Gateway Timeout")

    monkeypatch.setattr(main, "kill_pod", timeout_kill_pod)

    response = client.post(
        "/falco-webhook",
        json={
            "rule": "Timeout integration test",
            "priority": "Critical",
            "time": "2026-10-23T12:00:00Z",
            "output": "Synthetic timeout test",
            "output_fields": {
                "k8s.pod.name": "k8s-sentinel-remediation-test-timeout",
                "k8s.ns.name": "default",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["remediation_executed"] is False
    assert "504" in response.json()["remediation_error"]

    with sqlite3.connect(tmp_path / "timeout-audit.db") as connection:
        row = connection.execute(
            "SELECT outcome FROM audit_log"
        ).fetchone()

    assert row == ("error",)


def test_duplicate_alert_does_not_repeat_remediation(monkeypatch, tmp_path):
    import sqlite3

    monkeypatch.setenv(
        "K8S_SENTINEL_AUDIT_DB",
        str(tmp_path / "duplicate-audit.db"),
    )

    calls = []

    def fake_kill_pod(*, pod_name, namespace):
        calls.append((pod_name, namespace))
        return {
            "status": "deletion_requested",
            "namespace": namespace,
            "pod_name": pod_name,
            "api_status": "accepted",
        }

    monkeypatch.setattr(main, "kill_pod", fake_kill_pod)

    payload = {
        "rule": "Duplicate integration test",
        "priority": "Critical",
        "time": "2026-10-23T12:05:00Z",
        "output": "Same alert sent twice",
        "output_fields": {
            "k8s.pod.name": "k8s-sentinel-remediation-test-duplicate",
            "k8s.ns.name": "default",
        },
    }

    first = client.post("/falco-webhook", json=payload)
    second = client.post("/falco-webhook", json=payload)

    assert first.status_code == 200
    assert first.json()["remediation_executed"] is True
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate_ignored"
    assert second.json()["remediation_executed"] is False
    assert len(calls) == 1

    with sqlite3.connect(tmp_path / "duplicate-audit.db") as connection:
        outcomes = connection.execute(
            "SELECT outcome FROM audit_log ORDER BY id"
        ).fetchall()

    assert outcomes == [("success",), ("duplicate_ignored",)]
