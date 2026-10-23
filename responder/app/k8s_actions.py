"""Safeguarded Kubernetes remediation actions."""

import logging

from kubernetes.client.exceptions import ApiException
from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

logger = logging.getLogger("k8s-sentinel-responder")

# Infrastructure namespaces must never be targeted by pod deletion.
PROTECTED_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "falco",
    "kyverno",
}

def is_approved_pod_target(pod_name: str, namespace: str) -> bool:
    """Allow deletion only for explicitly designated test workloads."""
    if not pod_name or not namespace:
        return False

    if namespace != "default":
        return False

    return pod_name.startswith("k8s-sentinel-remediation-test-")


def create_core_v1_api() -> client.CoreV1Api:
    """Load Kubernetes credentials and return a CoreV1Api client."""
    try:
        config.load_kube_config()
    except ConfigException:
        config.load_incluster_config()

    return client.CoreV1Api()



def kill_pod(
    pod_name: str,
    namespace: str,
    *,
    api: client.CoreV1Api | None = None,
) -> dict:
    """Delete only an approved test pod; treat an already-missing pod as success."""
    if not pod_name or not namespace:
        raise ValueError("pod_name and namespace are required")

    if not is_approved_pod_target(pod_name, namespace):
        raise ValueError(
            f"Refusing automated deletion of unapproved target: "
            f"{namespace}/{pod_name}"
        )

    core_api = api or create_core_v1_api()

    try:
        core_api.read_namespaced_pod(name=pod_name, namespace=namespace)
    except ApiException as exc:
        if exc.status == 404:
            logger.info(
                "Pod already absent; treating deletion as idempotent success: "
                "namespace=%s pod=%s",
                namespace,
                pod_name,
            )
            return {
                "status": "already_absent",
                "namespace": namespace,
                "pod_name": pod_name,
                "api_status": "not_found",
            }
        raise

    try:
        core_api.delete_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=client.V1DeleteOptions(grace_period_seconds=0),
        )
    except ApiException as exc:
        if exc.status == 404:
            # The pod may have disappeared between the read and delete calls.
            return {
                "status": "already_absent",
                "namespace": namespace,
                "pod_name": pod_name,
                "api_status": "not_found",
            }
        raise

    logger.warning(
        "Pod deletion requested: namespace=%s pod=%s",
        namespace,
        pod_name,
    )

    return {
        "status": "deletion_requested",
        "namespace": namespace,
        "pod_name": pod_name,
        "api_status": "accepted",
    }


def cordon_node(
    node_name: str,
    *,
    api: client.CoreV1Api | None = None,
) -> dict:
    """Mark an explicitly identified node unschedulable."""
    if not node_name:
        raise ValueError("node_name is required")

    core_api = api or create_core_v1_api()
    node = core_api.read_node(name=node_name)

    if node.spec and node.spec.unschedulable:
        return {"status": "already_cordoned", "node_name": node_name}

    if node.spec is None:
        raise ValueError(f"Node {node_name} has no spec; refusing to cordon")

    node.spec.unschedulable = True
    core_api.patch_node(name=node_name, body=node)

    logger.warning("Node cordoned: node=%s", node_name)
    return {"status": "cordoned", "node_name": node_name}


def revoke_service_account_binding(
    binding_name: str,
    *,
    api: client.RbacAuthorizationV1Api | None = None,
) -> dict:
    """Remove an explicitly named ClusterRoleBinding only if it grants cluster-admin."""
    if not binding_name:
        raise ValueError("binding_name is required")

    # Reject protected names before contacting Kubernetes.
    if binding_name.startswith(("system:", "kubeadm:")):
        raise ValueError(f"Refusing to delete protected binding: {binding_name}")

    rbac_api = api or _create_rbac_api()
    binding = rbac_api.read_cluster_role_binding(name=binding_name)

    if not binding.role_ref or binding.role_ref.name != "cluster-admin":
        raise ValueError(
            f"Refusing to delete binding {binding_name!r}: it does not grant cluster-admin"
        )

    rbac_api.delete_cluster_role_binding(
        name=binding_name,
        body=client.V1DeleteOptions(),
    )

    logger.warning("ClusterRoleBinding deletion requested: binding=%s", binding_name)
    return {"status": "deletion_requested", "binding_name": binding_name}


def _create_rbac_api() -> client.RbacAuthorizationV1Api:
    """Load Kubernetes credentials and return an RBAC API client."""
    try:
        config.load_kube_config()
    except ConfigException:
        config.load_incluster_config()

    return client.RbacAuthorizationV1Api()
