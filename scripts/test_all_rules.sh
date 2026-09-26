#!/usr/bin/env bash

set -u

POD="hostpath-pod"
WORKER_FALCO="falco-2lkv5"

echo "========================================"
echo " K8s Sentinel — Day 13 Integration Test"
echo "========================================"

echo
echo "[1/8] Container Exec"
kubectl exec "$POD" -- sh -c 'echo K8S_SENTINEL_RULE1'

echo
echo "[2/8] Privileged Container Process"
kubectl exec privileged-pod -- sh -c 'echo K8S_SENTINEL_RULE2'

echo
echo "[3/8] HostPath Write"
kubectl exec "$POD" -- sh -c \
  'echo K8S_SENTINEL_RULE3_TRIGGER > /host/tmp/k8s-sentinel-rule3-test'

echo
echo "[4/8] Unexpected Outbound Connection"
kubectl exec "$POD" -- sh -c \
  'curl -s --connect-timeout 5 http://104.20.23.154 >/dev/null'

echo
echo "[5/8] Crypto Mining Heuristic"
kubectl exec "$POD" -- sh -c \
  'timeout 10 yes >/dev/null' || true

echo
echo "[6/8] ServiceAccount Sensitive API Activity"
kubectl exec overpermissive-sa-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -sS --cacert "$CACERT"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -X POST   https://kubernetes.default.svc/api/v1/namespaces/default/secrets   -d '"'"'{"apiVersion":"v1","kind":"Secret","metadata":{"name":"k8s-sentinel-rule6-integration"}}'"'"'
'

echo
echo "[7/8] ClusterRoleBinding Cluster-Admin Grant"
kubectl exec overpermissive-sa-pod -- sh -c '
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -sS --cacert "$CACERT"   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -X POST   https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterrolebindings   -d '"'"'{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"k8s-sentinel-rule7-integration"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"overpermissive-sa","namespace":"default"}]}'"'"'
'

echo
echo "[8/8] Reverse Shell Activity"
kubectl exec "$POD" -- bash -c \
  'exec 3<>/dev/tcp/104.20.23.154/80; exec 3>&-'

echo
echo "========================================"
echo " Attack triggers completed"
echo "========================================"
