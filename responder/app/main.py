
import hashlib
import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from responder.app.audit_log import claim_alert, log_action
from responder.app.decision import decide_action
from responder.app.k8s_actions import kill_pod
from responder.app.models import Action, Alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("k8s-sentinel-responder")
app = FastAPI(title="K8s Sentinel Responder", version="0.1.0")


def normalize_falco_payload(payload: dict[str, Any]) -> Alert:
    """Convert Falco JSON fields into the responder's Alert model."""
    output = payload.get("output") or ""
    fields = payload.get("output_fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    priority = payload.get("priority") or payload.get("severity")
    if not priority:
        raise ValueError("Missing required field: priority or severity")

    rule_name = payload.get("rule") or payload.get("rule_name")
    pod_name = payload.get("pod_name") or fields.get("k8s.pod.name")
    namespace = (
        payload.get("namespace")
        or fields.get("k8s.ns.name")
        or fields.get("k8s.namespace.name")
    )

    # Falco custom rules include these values in the formatted output text.
    import re
    technique_match = re.search(r"\btechnique_id=(T\d+(?:\.\d+)?)\b", str(output))
    tactic_match = re.search(r"\btactic=([A-Za-z_]+)", str(output))

    technique_id = (
        payload.get("technique_id")
        or fields.get("technique_id")
        or (technique_match.group(1) if technique_match else None)
    )
    tactic = (
        payload.get("tactic")
        or fields.get("tactic")
        or (tactic_match.group(1) if tactic_match else None)
    )

    return Alert(
        severity=str(priority),
        rule_name=str(rule_name) if rule_name else None,
        pod_name=str(pod_name) if pod_name else None,
        namespace=str(namespace) if namespace else None,
        timestamp=payload.get("time") or payload.get("timestamp"),
        raw_output=str(output),
        technique_id=str(technique_id) if technique_id else None,
        tactic=str(tactic) if tactic else None,
    )

def alert_fingerprint(alert: Alert) -> str:
    """Build a stable key from normalized alert fields."""
    identity = {
        "technique_id": alert.technique_id,
        "severity": alert.severity.strip().lower(),
        "rule_name": alert.rule_name,
        "pod_name": alert.pod_name,
        "namespace": alert.namespace,
        "timestamp": str(alert.timestamp) if alert.timestamp else None,
        "raw_output": alert.raw_output,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/falco-webhook")
async def falco_webhook(request: Request):
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")
        alert = normalize_falco_payload(payload)
    except Exception as exc:
        logger.warning("Invalid alert payload: %s", exc)
        raise HTTPException(
            status_code=400,
            detail="Invalid alert payload",
        ) from exc

    action = decide_action(alert)
    target = (
        f"{alert.namespace}/{alert.pod_name}"
        if alert.namespace and alert.pod_name
        else None
    )
    fingerprint = alert_fingerprint(alert)

    try:
        claimed = claim_alert(fingerprint)
    except Exception as exc:
        logger.exception("Audit database unavailable; refusing to process alert")
        raise HTTPException(
            status_code=503,
            detail="Audit storage unavailable; alert was not processed",
        ) from exc

    if not claimed:
        try:
            log_action(
                technique_id=alert.technique_id,
                severity=alert.severity,
                action_taken=action.value,
                target=target,
                outcome="duplicate_ignored",
                alert_key=fingerprint,
            )
        except Exception:
            logger.exception("Failed to audit duplicate alert")
            raise HTTPException(status_code=503, detail="Audit storage unavailable")

        return {
            "status": "duplicate_ignored",
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "action": action.value,
            "remediation_executed": False,
            "remediation_result": None,
            "remediation_error": None,
        }

    remediation_executed = False
    remediation_result = None
    remediation_error = None

    if action == Action.KILL_POD:
        try:
            remediation_result = kill_pod(
                pod_name=alert.pod_name or "",
                namespace=alert.namespace or "",
            )
            remediation_executed = True
        except Exception as exc:
            remediation_error = str(exc)
            logger.exception(
                "Pod remediation failed: rule=%s pod=%s namespace=%s",
                alert.rule_name,
                alert.pod_name,
                alert.namespace,
            )

    if remediation_error:
        outcome = "error"
    elif action == Action.LOG_ONLY:
        outcome = "logged_only"
    elif isinstance(remediation_result, dict) and remediation_result.get("status") == "already_absent":
        outcome = "already_absent"
    else:
        outcome = "success"

    try:
        log_action(
            technique_id=alert.technique_id,
            severity=alert.severity,
            action_taken=action.value,
            target=target,
            outcome=outcome,
            alert_key=fingerprint,
        )
    except Exception as exc:
        logger.exception("Failed to persist audit outcome")
        raise HTTPException(
            status_code=503,
            detail="Audit storage unavailable; remediation outcome may be uncertain",
        ) from exc

    return {
        "status": "received",
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "action": action.value,
        "remediation_executed": remediation_executed,
        "remediation_result": remediation_result,
        "remediation_error": remediation_error,
    }
