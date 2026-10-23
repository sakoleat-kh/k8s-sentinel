from fastapi.testclient import TestClient

from responder.app import main
from responder.app.models import Action

client = TestClient(main.app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_critical_approved_test_pod_triggers_remediation(monkeypatch):
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
