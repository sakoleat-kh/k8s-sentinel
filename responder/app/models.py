from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class Action(str, Enum):
    KILL_POD = "kill_pod"
    CORDON_NODE_AND_NOTIFY = "cordon_node_and_notify"
    LOG_ONLY = "log_only"


class Alert(BaseModel):
    model_config = ConfigDict(extra="ignore")

    severity: str
    technique_id: str | None = None
    tactic: str | None = None
    rule_name: str | None = None
    pod_name: str | None = None
    namespace: str | None = None
    timestamp: datetime | str | None = None
    raw_output: str = ""
