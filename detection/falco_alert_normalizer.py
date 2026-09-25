#!/usr/bin/env python3

import json
import re
import sys


SEVERITY_MAP = {
    "Emergency": "critical",
    "Alert": "critical",
    "Critical": "critical",
    "Error": "high",
    "Warning": "high",
    "Notice": "medium",
    "Informational": "low",
    "Debug": "low",
}


def extract_metadata(output):
    """Extract technique_id and tactic from Falco output."""

    technique_match = re.search(
        r"\btechnique_id=([A-Za-z0-9._-]+)",
        output,
    )

    tactic_match = re.search(
        r"\btactic=(.*?)(?=\s+container_id=|\s+container_name=|\s+k8s_pod_name=|\s+k8s_ns_name=|$)",
        output,
    )

    return {
        "technique_id": technique_match.group(1) if technique_match else None,
        "tactic": tactic_match.group(1) if tactic_match else None,
    }


def normalize_alert(event):
    """Convert a Falco JSON event into the K8s Sentinel alert schema."""

    output = event.get("output", "")
    output_fields = event.get("output_fields", {})

    metadata = extract_metadata(output)

    priority = event.get("priority", "Warning")

    return {
        "severity": SEVERITY_MAP.get(priority, "medium"),
        "technique_id": metadata["technique_id"],
        "tactic": metadata["tactic"],
        "rule_name": event.get("rule"),
        "pod_name": output_fields.get("k8s.pod.name"),
        "namespace": output_fields.get("k8s.ns.name"),
        "timestamp": event.get("time"),
        "raw_output": output,
    }


def main():
    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert = normalize_alert(event)

        print(json.dumps(alert), flush=True)


if __name__ == "__main__":
    main()
