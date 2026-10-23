
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request

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

    # Only use explicit, structured fields for remediation targets.
    pod_name = (
        payload.get("pod_name")
        or fields.get("k8s.pod.name")
    )
    namespace = (
        payload.get("namespace")
        or fields.get("k8s.ns.name")
        or fields.get("k8s.namespace.name")
    )

    return Alert(
        severity=str(priority or "unknown"),
        rule_name=str(rule_name) if rule_name else None,
        pod_name=str(pod_name) if pod_name else None,
        namespace=str(namespace) if namespace else None,
        timestamp=payload.get("time") or payload.get("timestamp"),
        raw_output=str(output),
        technique_id=payload.get("technique_id"),
        tactic=payload.get("tactic"),
    )


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
    remediation_executed = False
    remediation_result = None
    remediation_error = None

    logger.info(
        "Alert decision: action=%s rule=%s severity=%s pod=%s namespace=%s",
        action.value,
        alert.rule_name,
        alert.severity,
        alert.pod_name,
        alert.namespace,
    )

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

    return {
        "status": "received",
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "action": action.value,
        "remediation_executed": remediation_executed,
        "remediation_result": remediation_result,
        "remediation_error": remediation_error,
    }
