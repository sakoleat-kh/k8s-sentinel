from fastapi import FastAPI, Request
import logging

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
    payload = await request.json()

    logger.info("Received Falco alert: %s", payload)

    return {
        "status": "received",
        "message": "Falco alert received",
    }
