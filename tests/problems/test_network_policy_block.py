"""network_policy_block must cut connections that already exist, not just new ones."""

import subprocess
from types import SimpleNamespace

import pytest

from sregym.conductor.problems.network_policy_block import (
    FAULT_POD_NAMESPACE,
    FLUSH_CONNTRACK_SCRIPT,
    RESET_SOCKETS_SCRIPT,
    NetworkPolicyBlock,
)


def _pod(service, ip, node):
    return SimpleNamespace(
        metadata=SimpleNamespace(labels={"io.kompose.service": service}),
        status=SimpleNamespace(pod_ip=ip),
        spec=SimpleNamespace(node_name=node),
    )


class _Recorder:
    def __init__(self, pods):
        self.calls = []
        self.pods = pods

    # NetworkingV1Api
    def create_namespaced_network_policy(self, namespace, body):
        self.calls.append(("create", body["spec"]["policyTypes"]))

    def patch_namespaced_network_policy(self, name, namespace, body):
        self.calls.append(("patch", body["spec"]["policyTypes"]))

    # KubeCtl
    def list_pods(self, namespace):
        return SimpleNamespace(items=self.pods)

    def create_namespace_if_not_exist(self, namespace):
        self.calls.append(("namespace", namespace))

    def run_node_script_pod(self, **kwargs):
        self.calls.append(("node", kwargs))
        return ""


def _problem(pods):
    recorder = _Recorder(pods)
    problem = object.__new__(NetworkPolicyBlock)
    problem.namespace = "hotel-reservation"
    problem.faulty_service = "recommendation"
    problem.policy_name = "deny-all-recommendation"
    problem.networking_v1 = recorder
    problem.kubectl = recorder
    return problem, recorder


def test_resets_sockets_between_ingress_and_egress_deny():
    problem, recorder = _problem(
        [
            _pod("recommendation", "10.0.0.5", "node-a"),
            _pod("frontend", "10.0.0.6", "node-a"),
        ]
    )

    problem.inject_fault()

    steps = [(c[0], c[1]["script"] if c[0] == "node" else c[1]) for c in recorder.calls]
    assert steps == [
        ("create", ["Ingress"]),
        ("namespace", FAULT_POD_NAMESPACE),
        ("node", RESET_SOCKETS_SCRIPT),
        ("patch", ["Ingress", "Egress"]),
        ("node", FLUSH_CONNTRACK_SCRIPT),
    ]
    reset, flush = (c[1] for c in recorder.calls if c[0] == "node")
    assert reset["host_pid"] is True and "host_network" not in reset
    assert flush["host_network"] is True and "host_pid" not in flush
    for call in (reset, flush):
        assert call["node_name"] == "node-a"
        assert call["namespace"] == FAULT_POD_NAMESPACE
        assert call["env"]["POD_IPS"] == "10.0.0.5"


def test_runs_one_helper_per_node_hosting_a_target_pod():
    problem, recorder = _problem(
        [
            _pod("recommendation", "10.0.0.5", "node-a"),
            _pod("recommendation", "10.0.0.7", "node-a"),
            _pod("recommendation", "10.0.1.5", "node-b"),
        ]
    )

    problem.inject_fault()

    resets = [c[1] for c in recorder.calls if c[0] == "node" and c[1]["script"] == RESET_SOCKETS_SCRIPT]
    assert {(c["node_name"], c["env"]["POD_IPS"]) for c in resets} == {
        ("node-a", "10.0.0.5 10.0.0.7"),
        ("node-b", "10.0.1.5"),
    }


def test_refuses_to_inject_when_no_target_pod_runs():
    problem, recorder = _problem([_pod("frontend", "10.0.0.6", "node-a")])

    with pytest.raises(RuntimeError, match="No running pod"):
        problem.inject_fault()
    assert ("patch", ["Ingress", "Egress"]) not in recorder.calls


@pytest.mark.parametrize("script", [RESET_SOCKETS_SCRIPT, FLUSH_CONNTRACK_SCRIPT])
def test_node_scripts_are_valid_shell(script):
    subprocess.run(["sh", "-n"], input=script, text=True, check=True)


def test_socket_reset_keeps_the_listener():
    """Only established sockets go, so the pod serves again once the policy is removed."""
    assert "-K -t state established" in RESET_SOCKETS_SCRIPT


def test_warns_when_the_kernel_cannot_destroy_sockets(caplog):
    """ss -K is a silent no-op without CONFIG_INET_DIAG_DESTROY (e.g. WSL2)."""
    problem, recorder = _problem([_pod("recommendation", "10.0.0.5", "node-a")])
    recorder.run_node_script_pod = lambda **kwargs: "destroyed 0 of 3 established sockets\nSOCKET_DESTROY_UNSUPPORTED\n"

    with caplog.at_level("WARNING"):
        problem._run_on_node("socket reset", "node-a", RESET_SOCKETS_SCRIPT, ["10.0.0.5"], host_pid=True)

    assert "CONFIG_INET_DIAG_DESTROY" in caplog.text
    assert "SOCKET_DESTROY_UNSUPPORTED" in RESET_SOCKETS_SCRIPT
