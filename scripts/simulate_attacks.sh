#!/usr/bin/env bash
set -uo pipefail

NAMESPACE="${NAMESPACE:-default}"
PAUSE_SECONDS="${PAUSE_SECONDS:-2}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
declare -a RESULTS=()

print_result() {
  local status="$1"
  local label="$2"
  printf '[%s] %s\n' "$status" "$label"
  RESULTS+=("$status — $label")
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
  esac
}

run_scenario() {
  local number="$1"
  local label="$2"
  shift 2

  printf '\n[%s/8] Simulating: %s\n' "$number" "$label"
  if "$@"; then
    print_result PASS "$label"
  else
    print_result FAIL "$label"
  fi
  sleep "$PAUSE_SECONDS"
}

pod_running() {
  local pod="$1"
  [[ "$(kubectl get pod "$pod" -n "$NAMESPACE" \
    -o jsonpath='{.status.phase}' 2>/dev/null)" == "Running" ]]
}

exec_in_pod() {
  local pod="$1"
  shift
  pod_running "$pod" || {
    echo "Required Pod is not Running: $NAMESPACE/$pod" >&2
    return 1
  }
  kubectl exec -n "$NAMESPACE" "$pod" -- "$@"
}

check_read_only_rbac() {
  echo "Read-only check: inspecting effective RBAC permissions."
  kubectl auth can-i create clusterrolebindings \
    --as="system:serviceaccount:${NAMESPACE}:overpermissive-sa" \
    --quiet
}

check_read_only_secret_permission() {
  echo "Read-only check: inspecting Secret creation permission."
  kubectl auth can-i create secrets \
    --as="system:serviceaccount:${NAMESPACE}:overpermissive-sa" \
    -n "$NAMESPACE" --quiet
}

echo "=============================================="
echo " K8s Sentinel — Day 26 Attack Simulation Suite"
echo "=============================================="
echo "Namespace: $NAMESPACE"
echo "Pause between scenarios: ${PAUSE_SECONDS}s"
echo "No Secret/RBAC creation or workload deletion."
echo

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "ERROR: Kubernetes cluster is not reachable." >&2
  exit 2
fi

echo "Checking required workloads..."
for pod in hostpath-pod privileged-pod overpermissive-sa-pod; do
  if ! pod_running "$pod"; then
    echo "ERROR: Required Pod is not Running: $NAMESPACE/$pod" >&2
    echo "Start/fix the lab workloads before running this suite." >&2
    exit 2
  fi
done
echo "Required workloads are Running."
sleep "$PAUSE_SECONDS"

run_scenario 1 "Container exec" \
  exec_in_pod hostpath-pod sh -c 'echo K8S_SENTINEL_RULE1'

run_scenario 2 "Privileged container process" \
  exec_in_pod privileged-pod sh -c 'echo K8S_SENTINEL_RULE2'

run_scenario 3 "HostPath write" \
  exec_in_pod hostpath-pod sh -c \
  'echo K8S_SENTINEL_RULE3_TRIGGER > /host/tmp/k8s-sentinel-rule3-test'

run_scenario 4 "Unexpected outbound connection" \
  exec_in_pod hostpath-pod sh -c \
  'command -v curl >/dev/null && curl -fsS --connect-timeout 5 --max-time 8 https://example.com/ >/dev/null'

run_scenario 5 "CPU-intensive process heuristic" \
  exec_in_pod hostpath-pod sh -c \
  'command -v timeout >/dev/null || exit 1; timeout 7s yes >/dev/null; result=$?; [ "$result" -eq 124 ]'

run_scenario 6 "ServiceAccount Secret permission (read-only check)" \
  check_read_only_secret_permission

run_scenario 7 "ClusterRoleBinding permission (read-only check)" \
  check_read_only_rbac

run_scenario 8 "Shell-process external TCP connection pattern (no shell)" \
  exec_in_pod hostpath-pod bash -c \
  'exec 3<>/dev/tcp/example.com/443 && exec 3>&-'

echo
echo "=============================================="
echo " Simulation summary"
echo "=============================================="
printf 'PASS: %d\nFAIL: %d\nSKIP: %d\n' \
  "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
printf '\nScenario results:\n'
printf ' - %s\n' "${RESULTS[@]}"

echo
echo "Note: PASS means the scenario command/check completed."
echo "It does not independently prove that a Falco rule fired."
echo "Review Falco events separately to validate detection coverage."

if (( FAIL_COUNT > 0 )); then
  exit 1
fi
