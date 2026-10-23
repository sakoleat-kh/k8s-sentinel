from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from kubernetes.client.exceptions import ApiException

from responder.app.k8s_actions import (
    cordon_node,
    kill_pod,
    revoke_service_account_binding,
)


def test_kill_pod_verifies_target_before_deleting():
    api = Mock()
    api.read_namespaced_pod.return_value = SimpleNamespace(metadata=None)
    api.delete_namespaced_pod.return_value = SimpleNamespace(status="Success")

    result = kill_pod(
        "k8s-sentinel-remediation-test-unit",
        "default",
        api=api,
    )

    api.read_namespaced_pod.assert_called_once_with(
        name="k8s-sentinel-remediation-test-unit",
        namespace="default",
    )
    api.delete_namespaced_pod.assert_called_once()
    assert result["status"] == "deletion_requested"


@pytest.mark.parametrize(
    ("pod_name", "namespace"),
    [
        ("test-pod", ""),
        ("", "default"),
        ("falco-test", "default"),
        ("test-pod", "falco"),
        ("test-pod", "kube-system"),
    ],
)
def test_kill_pod_rejects_invalid_or_protected_targets(pod_name, namespace):
    api = Mock()

    with pytest.raises(ValueError):
        kill_pod(pod_name, namespace, api=api)

    api.read_namespaced_pod.assert_not_called()
    api.delete_namespaced_pod.assert_not_called()


def test_kill_pod_does_not_delete_when_target_does_not_exist():
    api = Mock()
    api.read_namespaced_pod.side_effect = ApiException(status=404)

    with pytest.raises(ApiException):
        kill_pod(
            "k8s-sentinel-remediation-test-missing",
            "default",
            api=api,
        )

    api.delete_namespaced_pod.assert_not_called()


def test_cordon_node_patches_node_as_unschedulable():
    api = Mock()
    node = SimpleNamespace(
        spec=SimpleNamespace(unschedulable=False)
    )
    api.read_node.return_value = node

    result = cordon_node("test-node", api=api)

    assert node.spec.unschedulable is True
    api.patch_node.assert_called_once_with(name="test-node", body=node)
    assert result["status"] == "cordoned"


def test_cordon_node_rejects_empty_name():
    api = Mock()

    with pytest.raises(ValueError):
        cordon_node("", api=api)

    api.read_node.assert_not_called()


def test_revoke_binding_only_deletes_cluster_admin_binding():
    api = Mock()
    api.read_cluster_role_binding.return_value = SimpleNamespace(
        role_ref=SimpleNamespace(name="cluster-admin")
    )

    result = revoke_service_account_binding("k8s-sentinel-rule7-audit-test", api=api)

    api.delete_cluster_role_binding.assert_called_once()
    assert result["status"] == "deletion_requested"


def test_revoke_binding_rejects_non_cluster_admin_binding():
    api = Mock()
    api.read_cluster_role_binding.return_value = SimpleNamespace(
        role_ref=SimpleNamespace(name="view")
    )

    with pytest.raises(ValueError):
        revoke_service_account_binding("example-binding", api=api)

    api.delete_cluster_role_binding.assert_not_called()


def test_revoke_binding_rejects_system_binding():
    api = Mock()

    with pytest.raises(ValueError):
        revoke_service_account_binding("system:example", api=api)

    api.read_cluster_role_binding.assert_not_called()
    api.delete_cluster_role_binding.assert_not_called()