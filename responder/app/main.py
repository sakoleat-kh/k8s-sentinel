import logging

from fastapi import FastAPI, HTTPException, Request

from responder.app.decision import decide_action
from responder.app.models import Alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("k8s-sentinel-responder")

app = FastAPI(
    title="K8s Sentinel Responder",
    version="0.1.0",
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/falco-webhook")
async def falco_webhook(request: Request):
    try:
        payload = await request.json()
        alert = Alert.model_validate(payload)
    except Exception as exc:
        logger.warning("Invalid alert payload: %s", exc)
        raise HTTPException(
            status_code=400,
            detail="Invalid alert payload",
        ) from exc

    action = decide_action(alert)

    logger.info(
        "Alert decision: action=%s rule=%s severity=%s pod=%s namespace=%s",
        action.value,
        alert.rule_name,
        alert.severity,
        alert.pod_name,
        alert.namespace,
    )

    return {
        "status": "received",
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "action": action.value,
        "remediation_executed": False,
    }
