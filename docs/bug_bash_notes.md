# Day 28 — Bug Bash and Hardening Notes

Date: 2026-10-27

## Environment
- Kubernetes: Kind cluster `k8s-sentinel`
- Falco: 0.45.1
- Responder: FastAPI webhook at `/falco-webhook`
- Kyverno: installed in the cluster

## Test results

- Python test suite: 34 passed.
- Attack simulation suite: 8 passed, 0 failed, 0 skipped.
- Falco DaemonSet: successfully rolled out on both cluster nodes.
- Responder health endpoint: returned `{"status":"ok"}`.
- SQLite audit database integrity: previously checked and returned `ok`.

## Detection evidence

- `rule_001_container_exec`: confirmed for commands executed in lab workloads.
- `rule_003_hostpath_write`: one matching event observed in the simulation log excerpt.
- `rule_004_unexpected_outbound_connection`: four matching events observed in the simulation log excerpt.
- `rule_005_crypto_mining_heuristic`: detected the sustained `yes` process, but emitted repeated alerts.
- `rule_008_reverse_shell_activity`: detected the external TCP shell-process pattern.
- `rule_002_privileged_container_process`: unresolved. The privileged pod is configured with `privileged: true`, but the controlled test triggered `rule_001` and did not trigger `rule_002`.

## Responder findings

- The responder health endpoint is operational.
- Audit records exist with targets such as `default/hostpath-pod` and `default/privileged-pod`.
- Some historical audit records have empty targets. Preserve historical records; investigate metadata only for newly generated events.
- Temporary payload and target debug logging has been removed.

## Safety notes

- The simulation script does not create Secrets or RBAC resources and does not delete workloads.
- Scenarios 6 and 7 are read-only RBAC permission checks; they do not themselves create Kubernetes API audit events.
- A successful simulation command is not proof that a corresponding detection rule fired.
- Automatic remediation has not been declared verified by this bug bash.

## Outstanding work

1. Investigate and fix or explicitly document the `rule_002` detection gap.
2. Tune `rule_005` to reduce duplicate alerts without losing useful detection.
3. Verify current Falco-to-responder delivery and target metadata for fresh events.
4. Verify a repeatable fresh-cluster rebuild before final sign-off.
5. Run final tests, review the Git diff, and commit and push the verified changes.
