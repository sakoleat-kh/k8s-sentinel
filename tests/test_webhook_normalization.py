from responder.app.main import normalize_falco_payload


def test_normalizes_native_falco_payload():
    payload = {
        "rule": "Terminal shell in container",
        "priority": "Critical",
        "output": "A shell was spawned in a container",
        "time": "2026-10-19T20:47:57Z",
        "output_fields": {
            "k8s.pod.name": "k8s-sentinel-remediation-test-live",
            "k8s.ns.name": "default",
        },
    }

    alert = normalize_falco_payload(payload)

    assert alert.severity == "Critical"
    assert alert.rule_name == "Terminal shell in container"
    assert alert.pod_name == "k8s-sentinel-remediation-test-live"
    assert alert.namespace == "default"
    assert alert.raw_output == "A shell was spawned in a container"
    assert alert.timestamp == "2026-10-19T20:47:57Z"


def test_missing_target_fields_do_not_invent_remediation_target():
    payload = {
        "rule": "Unexpected activity",
        "priority": "Critical",
        "output": "An event without Kubernetes target fields",
        "output_fields": {},
    }

    alert = normalize_falco_payload(payload)

    assert alert.severity == "Critical"
    assert alert.pod_name is None
    assert alert.namespace is None


def test_normalizes_existing_synthetic_alert_payload():
    payload = {
        "severity": "critical",
        "rule_name": "Synthetic test",
        "pod_name": "k8s-sentinel-remediation-test-unit",
        "namespace": "default",
        "raw_output": "Controlled test alert",
    }

    alert = normalize_falco_payload(payload)

    assert alert.severity == "critical"
    assert alert.rule_name == "Synthetic test"
    assert alert.pod_name == "k8s-sentinel-remediation-test-unit"
    assert alert.namespace == "default"
