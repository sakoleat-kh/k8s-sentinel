import sqlite3

from responder.app.audit_log import log_action


def test_audit_action_is_durably_written(tmp_path, monkeypatch):
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("K8S_SENTINEL_AUDIT_DB", str(db_path))

    log_action(
        technique_id="T1609",
        severity="Critical",
        action_taken="kill_pod",
        target="default/k8s-sentinel-remediation-test-unit",
        outcome="success",
    )

    assert db_path.exists()

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT technique_id, severity, action_taken, target, outcome
            FROM audit_log
            """
        ).fetchone()

    assert row == (
        "T1609",
        "Critical",
        "kill_pod",
        "default/k8s-sentinel-remediation-test-unit",
        "success",
    )
