import logging

from kubernetes import client

from sregym.conductor.oracles.llm_as_a_judge.llm_as_a_judge_oracle import LLMAsAJudgeOracle
from sregym.conductor.oracles.network_policy_oracle import NetworkPolicyMitigationOracle
from sregym.conductor.problems.base import Problem
from sregym.paths import TARGET_MICROSERVICES
from sregym.service.apps.base import Application
from sregym.service.apps.hotel_reservation import HotelReservation
from sregym.service.kubectl import KubeCtl
from sregym.utils.decorators import mark_fault_injected

logger = logging.getLogger(__name__)

FAULT_POD_NAMESPACE = "khaos"

# Destroys each pod's established sockets from inside its network namespace,
# found by walking the node's processes. ss comes from the node; busybox has none.
RESET_SOCKETS_SCRIPT = r"""set -u
ss=""
for path in /usr/bin/ss /bin/ss /usr/sbin/ss /sbin/ss; do
    [ -x "/host$path" ] && ss="$path" && break
done
[ -n "$ss" ] || { echo "no ss binary on the node"; exit 1; }
for ip in $POD_IPS; do
    found=0
    seen=""
    for procdir in /proc/[0-9]*; do
        pid=${procdir#/proc/}
        ns=$(readlink "$procdir/ns/net" 2>/dev/null) || continue
        case " $seen " in *" $ns "*) continue ;; esac
        seen="$seen $ns"
        if nsenter -t "$pid" -n ip -4 -o addr show 2>/dev/null | grep -q "inet $ip/"; then
            before=$(nsenter -t "$pid" -n chroot /host "$ss" -H -t state established | wc -l)
            killed=$(nsenter -t "$pid" -n chroot /host "$ss" -H -K -t state established | wc -l)
            echo "--- $ip (pid $pid): destroyed $killed of $before established sockets"
            # Without CONFIG_INET_DIAG_DESTROY, ss -K silently destroys nothing.
            if [ "$before" -gt 0 ] && [ "$killed" -eq 0 ]; then echo "SOCKET_DESTROY_UNSUPPORTED"; fi
            found=1
            break
        fi
    done
    [ "$found" = 1 ] || { echo "network namespace for $ip not found"; exit 1; }
done
"""

# Repeated so a flush that lands before Calico has programmed the new rules
# cannot leave the peers reconnected through a still-permissive dataplane.
FLUSH_CONNTRACK_SCRIPT = r"""set -u
ct=""
for path in /usr/sbin/conntrack /usr/bin/conntrack /sbin/conntrack /bin/conntrack; do
    [ -x "/host$path" ] && ct="$path" && break
done
[ -n "$ct" ] || { echo "no conntrack binary on the node"; exit 1; }
for round in $(seq 1 "$ROUNDS"); do
    sleep "$INTERVAL"
    for ip in $POD_IPS; do
        for sel in --orig-src --orig-dst --reply-src --reply-dst; do
            chroot /host "$ct" -D "$sel" "$ip" 2>&1 | sed -n '1,20p'
        done
    done
    echo "round $round done"
done
"""


class NetworkPolicyBlock(Problem):
    # HotelReservation pods use "io.kompose.service" as their label key
    POD_LABEL_KEY = "io.kompose.service"

    def __init__(self, faulty_service="recommendation", *, app: Application | None = None):
        super().__init__(app=app if app is not None else HotelReservation())
        self.kubectl = KubeCtl()
        self.faulty_service = faulty_service
        self.policy_name = f"deny-all-{faulty_service}"

        self.app.payload_script = (
            TARGET_MICROSERVICES / "hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"
        )
        self.app.create_workload()

        self.root_cause = self.build_structured_root_cause(
            component=self.faulty_service,
            namespace=self.namespace,
            description=(
                f"A NetworkPolicy `{self.policy_name}` blocks all ingress and egress traffic for pods labeled "
                f"`{self.POD_LABEL_KEY}={self.faulty_service}`, creating complete network isolation for the target "
                "workload. Service-to-service communication to and from the component fails, so dependent request "
                "paths break even if pods remain Running. Users observe hard failures/timeouts on flows that require "
                "this service."
            ),
        )
        self.networking_v1 = client.NetworkingV1Api()

        self.diagnosis_oracle = LLMAsAJudgeOracle(problem=self, expected=self.root_cause)
        self.mitigation_oracle = NetworkPolicyMitigationOracle(problem=self)

    conntrack_flush_rounds = 3
    conntrack_flush_interval_seconds = 5

    def _policy_body(self, policy_types: tuple[str, ...]) -> dict:
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": self.policy_name, "namespace": self.namespace},
            "spec": {
                "podSelector": {"matchLabels": {self.POD_LABEL_KEY: self.faulty_service}},
                "policyTypes": list(policy_types),
                "ingress": [],
                "egress": [],
            },
        }

    @mark_fault_injected
    def inject_fault(self):
        """Block ALL traffic to/from the target service.

        A NetworkPolicy only stops new connections, so the callers' open gRPC
        channels are torn down too. Ingress is denied first so the resets can
        still leave the pod; then egress is denied and conntrack is flushed.
        """
        self.networking_v1.create_namespaced_network_policy(
            namespace=self.namespace, body=self._policy_body(("Ingress",))
        )
        targets = self._target_pods_by_node()
        self.kubectl.create_namespace_if_not_exist(FAULT_POD_NAMESPACE)
        for node, pod_ips in targets.items():
            self._run_on_node("socket reset", node, RESET_SOCKETS_SCRIPT, pod_ips, host_pid=True)
        self.networking_v1.patch_namespaced_network_policy(
            name=self.policy_name, namespace=self.namespace, body=self._policy_body(("Ingress", "Egress"))
        )
        for node, pod_ips in targets.items():
            self._run_on_node(
                "conntrack flush",
                node,
                FLUSH_CONNTRACK_SCRIPT,
                pod_ips,
                env={
                    "ROUNDS": str(self.conntrack_flush_rounds),
                    "INTERVAL": str(self.conntrack_flush_interval_seconds),
                },
                host_network=True,
            )

    def _target_pods_by_node(self) -> dict[str, list[str]]:
        by_node: dict[str, list[str]] = {}
        for pod in self.kubectl.list_pods(self.namespace).items:
            if (pod.metadata.labels or {}).get(self.POD_LABEL_KEY) != self.faulty_service:
                continue
            if pod.status.pod_ip and pod.spec.node_name:
                by_node.setdefault(pod.spec.node_name, []).append(pod.status.pod_ip)
        if not by_node:
            raise RuntimeError(f"No running pod with {self.POD_LABEL_KEY}={self.faulty_service} in {self.namespace}")
        return by_node

    def _run_on_node(self, step: str, node: str, script: str, pod_ips: list[str], env=None, **pod_options) -> None:
        logs = self.kubectl.run_node_script_pod(
            node_name=node,
            namespace=FAULT_POD_NAMESPACE,
            script=script,
            name_prefix="sregym-netpol-fault",
            env={"POD_IPS": " ".join(pod_ips), **(env or {})},
            **pod_options,
        )
        logger.info("[network_policy_block] %s on %s:\n%s", step, node, logs)
        if "SOCKET_DESTROY_UNSUPPORTED" in logs:
            logger.warning(
                "[network_policy_block] %s cannot destroy sockets (kernel lacks CONFIG_INET_DIAG_DESTROY); "
                "callers will time out instead of failing fast",
                node,
            )

    @mark_fault_injected
    def recover_fault(self):
        """Remove the NetworkPolicy"""
        self.networking_v1.delete_namespaced_network_policy(name=self.policy_name, namespace=self.namespace)
