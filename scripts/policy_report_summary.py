#!/usr/bin/env python3

from collections import Counter, defaultdict

from kubernetes import client, config


REPORT_GROUP = "wgpolicyk8s.io"
REPORT_VERSION = "v1alpha2"


def load_kubernetes_config():
    """Load the local kubeconfig."""
    config.load_kube_config()


def get_policy_reports():
    """Return all namespace-scoped Kyverno PolicyReports."""
    api = client.CustomObjectsApi()

    response = api.list_cluster_custom_object(
        group=REPORT_GROUP,
        version=REPORT_VERSION,
        plural="policyreports",
    )

    return response.get("items", [])


def get_cluster_policy_reports():
    """Return all cluster-scoped Kyverno ClusterPolicyReports."""
    api = client.CustomObjectsApi()

    response = api.list_cluster_custom_object(
        group=REPORT_GROUP,
        version=REPORT_VERSION,
        plural="clusterpolicyreports",
    )

    return response.get("items", [])


def summarize_reports(reports, cluster_reports):
    """Build cluster-wide, policy, namespace, and violation summaries."""
    overall = Counter()
    by_policy = defaultdict(Counter)
    by_namespace = defaultdict(Counter)
    cluster_scoped = defaultdict(Counter)
    violations = []

    def process_report(report, cluster_scope=False):
        scope = report.get("scope", {})

        namespace = scope.get(
            "namespace",
            report.get("metadata", {}).get("namespace", "-"),
        )

        kind = scope.get("kind", "-")
        name = scope.get("name", "-")

        for result in report.get("results", []):
            status = result.get("result", "unknown").upper()
            policy = result.get("policy", "unknown")

            overall[status] += 1
            by_policy[policy][status] += 1

            if cluster_scope:
                cluster_scoped[policy][status] += 1
            else:
                by_namespace[namespace][status] += 1

            if status in {"FAIL", "WARN", "ERROR"}:
                violations.append(
                    {
                        "scope": "cluster" if cluster_scope else "namespace",
                        "namespace": namespace,
                        "kind": kind,
                        "name": name,
                        "policy": policy,
                        "rule": result.get("rule", "unknown"),
                        "result": status,
                        "message": result.get("message", ""),
                    }
                )

    for report in reports:
        process_report(report, cluster_scope=False)

    for report in cluster_reports:
        process_report(report, cluster_scope=True)

    return (
        overall,
        by_policy,
        by_namespace,
        cluster_scoped,
        violations,
    )


def print_counts(counts, indent="  "):
    print(f"{indent}PASS:  {counts.get('PASS', 0)}")
    print(f"{indent}FAIL:  {counts.get('FAIL', 0)}")
    print(f"{indent}WARN:  {counts.get('WARN', 0)}")
    print(f"{indent}ERROR: {counts.get('ERROR', 0)}")
    print(f"{indent}SKIP:  {counts.get('SKIP', 0)}")


def print_summary(
    reports,
    cluster_reports,
    overall,
    by_policy,
    by_namespace,
    cluster_scoped,
    violations,
):
    print("K8s Sentinel - Kyverno Policy Report Summary")
    print("=" * 65)
    print("Evaluation source: Kyverno PolicyReports / background scans")

    print("\nReport objects")
    print("-" * 65)
    print(f"PolicyReports:          {len(reports)}")
    print(f"ClusterPolicyReports:   {len(cluster_reports)}")

    print("\nCluster-wide result summary")
    print("-" * 65)
    print_counts(overall, indent="")

    print("\nResults by policy")
    print("-" * 65)

    for policy in sorted(by_policy):
        print(policy)
        print_counts(by_policy[policy])

    print("\nResults by namespace")
    print("-" * 65)

    for namespace in sorted(by_namespace):
        print(namespace)
        print_counts(by_namespace[namespace])

    print("\nCluster-scoped results")
    print("-" * 65)

    if not cluster_scoped:
        print("No cluster-scoped PolicyReports found.")
    else:
        for policy in sorted(cluster_scoped):
            print(policy)
            print_counts(cluster_scoped[policy])

    print("\nViolating resources")
    print("-" * 65)

    if not violations:
        print("No FAIL/WARN/ERROR results found.")
        return

    for item in sorted(
        violations,
        key=lambda x: (
            x["scope"],
            x["namespace"],
            x["kind"],
            x["name"],
            x["policy"],
        ),
    ):
        if item["scope"] == "cluster":
            resource = f"{item['kind']}/{item['name']}"
        else:
            resource = (
                f"{item['namespace']}/"
                f"{item['kind']}/"
                f"{item['name']}"
            )

        print(resource)
        print(
            f"  {item['result']} "
            f"{item['policy']}/{item['rule']}"
        )
        print(f"  {item['message']}")


def main():
    load_kubernetes_config()

    reports = get_policy_reports()
    cluster_reports = get_cluster_policy_reports()

    (
        overall,
        by_policy,
        by_namespace,
        cluster_scoped,
        violations,
    ) = summarize_reports(
        reports,
        cluster_reports,
    )

    print_summary(
        reports,
        cluster_reports,
        overall,
        by_policy,
        by_namespace,
        cluster_scoped,
        violations,
    )


if __name__ == "__main__":
    main()
