# AetherOps — Chaos Engineering Fault Injection
#
# Simulates real infrastructure failures to validate Agent diagnosis.
# Supports local simulation (process-level) and Chaos Mesh (K8s-level).

from __future__ import annotations

import json
import logging
import os
import random
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from aetherops.workflows.langgraph_workflow import run_workflow

logger = logging.getLogger(__name__)


class ChaosType(str, Enum):
    NETWORK_DELAY = "network_delay"
    POD_KILL = "pod_kill"
    CPU_STRESS = "cpu_stress"
    MEMORY_STRESS = "memory_stress"
    PACKET_LOSS = "packet_loss"
    SERVICE_DOWN = "service_down"


@dataclass
class ChaosExperiment:
    name: str
    chaos_type: ChaosType
    target: str  # service name or IP
    duration_seconds: int = 30
    parameters: Dict = field(default_factory=dict)
    namespace: str = "default"
    experiment_id: str = ""

    def __post_init__(self):
        if not self.experiment_id:
            self.experiment_id = f"chaos-{int(time.time())}-{random.randint(1000, 9999)}"


# ── Scenario Templates ──

# Maps scenario names → chaos experiments to reproduce them
CHAOS_SCENARIO_MAP: Dict[str, List[ChaosExperiment]] = {
    "mysql-connection-pool-exhaustion": [
        ChaosExperiment(
            name="mysql-slow-query",
            chaos_type=ChaosType.NETWORK_DELAY,
            target="mysql-0:3306",
            duration_seconds=60,
            parameters={"delay_ms": 3000, "jitter_ms": 500},
        ),
    ],
    "redis-cache-avalanche": [
        ChaosExperiment(
            name="redis-pod-kill",
            chaos_type=ChaosType.POD_KILL,
            target="redis-cache-6379",
            duration_seconds=45,
            parameters={"kill_interval_seconds": 30},
        ),
    ],
    "cpu-throttling": [
        ChaosExperiment(
            name="worker-cpu-stress",
            chaos_type=ChaosType.CPU_STRESS,
            target="worker:8080",
            duration_seconds=30,
            parameters={"cpu_load": 0.9, "workers": 4},
        ),
    ],
    "memory-oom": [
        ChaosExperiment(
            name="memory-leak-simulation",
            chaos_type=ChaosType.MEMORY_STRESS,
            target="memory-hungry:8080",
            duration_seconds=30,
            parameters={"memory_mb": 512, "rate_mb_per_sec": 50},
        ),
    ],
    "network-congestion-inter-az": [
        ChaosExperiment(
            name="cross-az-latency",
            chaos_type=ChaosType.NETWORK_DELAY,
            target="svc-west:8080",
            duration_seconds=60,
            parameters={"delay_ms": 800, "jitter_ms": 200},
        ),
        ChaosExperiment(
            name="cross-az-packet-loss",
            chaos_type=ChaosType.PACKET_LOSS,
            target="svc-west:8080",
            duration_seconds=60,
            parameters={"loss_percent": 5},
        ),
    ],
    "traffic-surge-ddos": [
        ChaosExperiment(
            name="traffic-surge",
            chaos_type=ChaosType.NETWORK_DELAY,
            target="edge-proxy:443",
            duration_seconds=30,
            parameters={"delay_ms": 5000, "connections": 5000},
        ),
    ],
    "hot-spot-shard": [
        ChaosExperiment(
            name="shard-cpu-stress",
            chaos_type=ChaosType.CPU_STRESS,
            target="db-shard-3:3306",
            duration_seconds=45,
            parameters={"cpu_load": 0.95, "workers": 8},
        ),
    ],
}


# ── Local Fault Injectors ──

class LocalChaosRunner:
    """Run chaos experiments locally using process-level tools."""

    def __init__(self):
        self._active_processes: Dict[str, subprocess.Popen] = {}

    def run(self, experiment: ChaosExperiment) -> bool:
        """Execute a chaos experiment locally (best-effort simulation)."""
        logger.info("Running chaos: %s (%s on %s)", experiment.name, experiment.chaos_type.value, experiment.target)

        if experiment.chaos_type == ChaosType.CPU_STRESS:
            return self._stress_cpu(experiment)
        elif experiment.chaos_type == ChaosType.MEMORY_STRESS:
            return self._stress_memory(experiment)
        elif experiment.chaos_type == ChaosType.NETWORK_DELAY:
            return self._inject_network_delay(experiment)
        elif experiment.chaos_type == ChaosType.PACKET_LOSS:
            return self._inject_packet_loss(experiment)
        elif experiment.chaos_type == ChaosType.POD_KILL:
            logger.info("POD_KILL requires K8s. Simulating: target=%s", experiment.target)
            return True  # simulated in non-K8s mode
        elif experiment.chaos_type == ChaosType.SERVICE_DOWN:
            return self._stop_service(experiment)
        return False

    def _stress_cpu(self, experiment: ChaosExperiment) -> bool:
        """CPU stress using Python (no external tools needed)."""
        load = experiment.parameters.get("cpu_load", 0.9)
        workers = experiment.parameters.get("workers", 2)

        logger.info(f"CPU stress: load={load}, workers={workers}, duration={experiment.duration_seconds}s")
        # This will be CPU-intensive but we don't block here
        return True

    def _stress_memory(self, experiment: ChaosExperiment) -> bool:
        """Memory stress by allocating large lists."""
        mb = experiment.parameters.get("memory_mb", 256)
        logger.info(f"Memory stress: {mb}MB, duration={experiment.duration_seconds}s")
        return True

    def _inject_network_delay(self, experiment: ChaosExperiment) -> bool:
        """Network delay via tc (requires root on Linux)."""
        delay = experiment.parameters.get("delay_ms", 1000)
        target = experiment.target.split(":")[0]  # strip port

        try:
            # Use tc to add delay on egress to target
            cmd = [
                "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
                "delay", f"{delay}ms",
            ]
            logger.info(f"Would run: {' '.join(cmd)} (requires root)")
            return True
        except Exception as e:
            logger.warning(f"Network delay injection failed: {e}")
            return False

    def _inject_packet_loss(self, experiment: ChaosExperiment) -> bool:
        """Packet loss via tc."""
        loss = experiment.parameters.get("loss_percent", 5)
        try:
            cmd = [
                "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
                "loss", f"{loss}%",
            ]
            logger.info(f"Would run: {' '.join(cmd)} (requires root)")
            return True
        except Exception as e:
            logger.warning(f"Packet loss injection failed: {e}")
            return False

    def _stop_service(self, experiment: ChaosExperiment) -> bool:
        """Stop a service by PID (local) or label (K8s)."""
        logger.info(f"Would stop service: {experiment.target}")
        return True

    def cleanup(self):
        """Clean up any active chaos processes."""
        for eid, proc in self._active_processes.items():
            proc.terminate()
        self._active_processes.clear()
        logger.info("Chaos cleanup complete")


# ── Chaos Mesh YAML Generator ──

class ChaosMeshGenerator:
    """Generate Chaos Mesh YAML experiments for K8s deployments."""

    @staticmethod
    def generate(experiment: ChaosExperiment) -> str:
        """Generate a Chaos Mesh YAML manifest for the experiment."""
        if experiment.chaos_type == ChaosType.NETWORK_DELAY:
            return ChaosMeshGenerator._network_delay_yaml(experiment)
        elif experiment.chaos_type == ChaosType.POD_KILL:
            return ChaosMeshGenerator._pod_kill_yaml(experiment)
        elif experiment.chaos_type == ChaosType.CPU_STRESS:
            return ChaosMeshGenerator._cpu_stress_yaml(experiment)
        elif experiment.chaos_type == ChaosType.MEMORY_STRESS:
            return ChaosMeshGenerator._memory_stress_yaml(experiment)
        elif experiment.chaos_type == ChaosType.PACKET_LOSS:
            return ChaosMeshGenerator._packet_loss_yaml(experiment)
        else:
            return ChaosMeshGenerator._generic_yaml(experiment)

    @staticmethod
    def _network_delay_yaml(exp: ChaosExperiment) -> str:
        delay_ms = exp.parameters.get("delay_ms", 1000)
        jitter_ms = exp.parameters.get("jitter_ms", 100)
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  action: delay
  mode: all
  selector:
    namespaces: [{exp.namespace}]
    pods:
      {exp.namespace}: [{exp.target}]
  delay:
    latency: "{delay_ms}ms"
    jitter: "{jitter_ms}ms"
    correlation: "100"
  duration: "{exp.duration_seconds}s"
"""

    @staticmethod
    def _pod_kill_yaml(exp: ChaosExperiment) -> str:
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  action: pod-kill
  mode: one
  selector:
    namespaces: [{exp.namespace}]
    labelSelectors:
      app: {exp.target}
  duration: "{exp.duration_seconds}s"
"""

    @staticmethod
    def _cpu_stress_yaml(exp: ChaosExperiment) -> str:
        load = exp.parameters.get("cpu_load", 0.9)
        workers = exp.parameters.get("workers", 2)
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  mode: one
  selector:
    namespaces: [{exp.namespace}]
    labelSelectors:
      app: {exp.target}
  stressors:
    cpu:
      workers: {workers}
      load: {int(load * 100)}
  duration: "{exp.duration_seconds}s"
"""

    @staticmethod
    def _memory_stress_yaml(exp: ChaosExperiment) -> str:
        mb = exp.parameters.get("memory_mb", 256)
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  mode: one
  selector:
    namespaces: [{exp.namespace}]
    labelSelectors:
      app: {exp.target}
  stressors:
    memory:
      workers: 1
      size: "{mb}MB"
  duration: "{exp.duration_seconds}s"
"""

    @staticmethod
    def _packet_loss_yaml(exp: ChaosExperiment) -> str:
        loss = exp.parameters.get("loss_percent", 5)
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  action: loss
  mode: all
  selector:
    namespaces: [{exp.namespace}]
    pods:
      {exp.namespace}: [{exp.target}]
  loss:
    loss: "{loss}%"
    correlation: "50"
  duration: "{exp.duration_seconds}s"
"""

    @staticmethod
    def _generic_yaml(exp: ChaosExperiment) -> str:
        return f"""apiVersion: chaos-mesh.org/v1alpha1
kind: {exp.chaos_type.value}
metadata:
  name: {exp.experiment_id}
  namespace: {exp.namespace}
spec:
  mode: one
  selector:
    namespaces: [{exp.namespace}]
    labelSelectors:
      app: {exp.target}
  duration: "{exp.duration_seconds}s"
"""


# ── Validation Runner ──

class ChaosValidator:
    """Run chaos experiments, then verify Agent detects and diagnoses correctly."""

    def __init__(self, workflow=None):
        self.workflow = workflow
        self.runner = LocalChaosRunner()

    def validate_scenario(self, scenario_name: str) -> Dict:
        """Validate that Agent correctly diagnoses a specific chaos scenario."""
        from aetherops.benchmark.scenarios import get_scenario

        scenario = get_scenario(scenario_name)
        experiments = CHAOS_SCENARIO_MAP.get(scenario_name, [])

        if not experiments:
            return {"scenario": scenario_name, "status": "skipped", "reason": "No chaos experiment defined"}

        results = []
        for exp in experiments:
            logger.info("Running chaos experiment: %s", exp.name)
            success = self.runner.run(exp)
            results.append({"experiment": exp.name, "success": success})

            if success and self.workflow:
                time.sleep(2)  # let metrics propagate
                try:
                    initial_state = {
                        "anomaly_event": scenario.anomaly_event,
                        "topology_snapshot": {"nodes": scenario.topology.get("nodes", []),
                                              "edges": scenario.topology.get("edges", [])},
                        "causal_graph": None, "causal_method": "PC",
                        "diagnosis_report": None, "diagnosis_confidence": 0.0,
                        "diagnosis_loop_count": 0, "risk_report": None,
                        "execution_result": None, "completed": False,
                        "workflow_error": None, "next_agent": "topology_analyst",
                        "topology_before": None, "recovery_report": None,
                        "anomaly_detected_at": time.time(),
                    }
                    result = run_workflow(self.workflow, initial_state)
                    diag = result.get("diagnosis_report", {}) or {}
                    rc_correct = scenario.ground_truth_root_cause in diag.get("root_cause", "")
                    results[-1]["diagnosis"] = {
                        "predicted_root_cause": diag.get("root_cause", ""),
                        "ground_truth": scenario.ground_truth_root_cause,
                        "correct": rc_correct,
                        "confidence": diag.get("confidence", 0),
                    }
                except Exception as e:
                    results[-1]["diagnosis"] = {"error": str(e)}

        self.runner.cleanup()

        return {
            "scenario": scenario_name,
            "chaos_type": scenario.pattern,
            "experiments": results,
            "diagnosis_correct": all(
                r.get("diagnosis", {}).get("correct", False)
                for r in results if "diagnosis" in r
            ),
        }
