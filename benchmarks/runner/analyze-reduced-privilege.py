#!/usr/bin/env python3
"""Validate one guarded reduced-privilege homelab arm."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ARM_REQUIREMENTS = {
    "none": {"capabilities": set(), "source": None},
    "tls-none": {"capabilities": set(), "source": None},
    "exec": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON"},
        "source": "source.aya_exec",
        "kinds": {"exec"},
    },
    "network": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON"},
        "source": "source.aya_network",
        "kinds": {"network_connection_open", "network_connection_close"},
    },
    "dns": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON"},
        "source": "source.aya_dns",
        "kinds": {"dns_query", "dns_response"},
    },
    "http": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON"},
        "source": "source.aya_http",
        "kinds": {"protocol_request_observation"},
        "protocol": "http",
    },
    "protocol": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON"},
        "source": "source.aya_protocol",
        "kinds": {"protocol_request_observation"},
        "protocol": "redis",
    },
    "tls": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON", "CAP_SYS_PTRACE"},
        "source": "source.aya_tls",
        "kinds": {"protocol_request_observation"},
        "protocol": "http",
    },
    "cpu-profile": {
        "capabilities": {"CAP_BPF", "CAP_PERFMON", "CAP_SYS_PTRACE"},
        "source": "source.aya_cpu_profile",
        "kinds": {"profile_sample_observation"},
    },
    "host-resource": {
        "capabilities": set(),
        "source": "source.host_resource",
        "kinds": {
            "node_cpu_observation",
            "node_memory_observation",
            "process_resource_observation",
        },
    },
}

CAP_PATTERN = re.compile(r"CAP_[A-Z0-9_]+")


def fail(message: str) -> None:
    raise SystemExit(message)


def prefixed_json(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def capability_blocks(path: Path) -> list[dict]:
    blocks: list[dict] = []
    current: dict | None = None
    for line in path.read_text(errors="replace").splitlines():
        if ": CapEff=" in line:
            if current is not None:
                blocks.append(current)
            current = {
                "pod": line.split(":", 1)[0],
                "no_new_privs": "NoNewPrivs=1" in line,
                "seccomp": "Seccomp=2" in line,
                "capabilities": set(),
            }
        elif current is not None:
            current["capabilities"].update(CAP_PATTERN.findall(line))
    if current is not None:
        blocks.append(current)
    return blocks


def validate_workload(arm: str, run_dir: Path) -> dict:
    records = prefixed_json(run_dir / "workload-logs.txt")
    if arm in {"tls", "tls-none"}:
        summaries = [
            record
            for record in records
            if record.get("schema") == "e-navigator.go-tls-client.v1"
        ]
        if not summaries:
            fail(f"{arm}: missing Go TLS workload summary")
        summary = summaries[-1]
        if summary.get("failed") != 0 or summary.get("succeeded") != summary.get("requests"):
            fail(f"{arm}: Go TLS workload failed: {summary}")
        return summary

    summaries = [
        record
        for record in records
        if record.get("schema") == "e-navigator.reduced-privilege-workload.v1"
    ]
    if not summaries:
        fail(f"{arm}: missing reduced-privilege workload summary")
    summary = summaries[-1]
    for field in ("cpu_batches", "dns", "exec", "http", "redis"):
        if not isinstance(summary.get(field), int) or summary[field] <= 0:
            fail(f"{arm}: workload field {field} is not positive: {summary}")
    if summary.get("uid") != 65532:
        fail(f"{arm}: workload did not run as the cross-UID control: {summary}")
    return summary


def validate_no_agent(arm: str, run_dir: Path) -> dict:
    inventory = json.loads((run_dir / "pod-json.txt").read_text())
    agents = [
        item.get("metadata", {}).get("name")
        for item in inventory.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    ]
    if agents:
        fail(f"{arm}: no-agent arm contained benchmark agents: {agents}")
    return {"arm": arm, "agent": False, "workload": validate_workload(arm, run_dir)}


def signal_matches(record: dict, requirement: dict, arm: str) -> bool:
    if record.get("source") != requirement["source"]:
        return False
    if record.get("kind") not in requirement["kinds"]:
        return False
    payload = record.get("payload") or {}
    if requirement.get("protocol") and payload.get("protocol") != requirement["protocol"]:
        return False
    process = payload.get("process") or {}
    attributes = {
        attribute.get("key"): attribute.get("value")
        for attribute in payload.get("attributes") or []
        if isinstance(attribute, dict)
    }
    if arm == "exec":
        return payload.get("uid") == 65532 and payload.get("command") == "/bin/true"
    if arm == "network":
        workload_ports = {16379, 18080}
        return process.get("uid") == 65532 and bool(
            {payload.get("local_port"), payload.get("remote_port")} & workload_ports
        )
    if arm == "dns":
        name = str(payload.get("query_name", ""))
        return name.startswith("reduced-") and name.endswith(
            ".invalid.e-navigator.local"
        )
    if arm == "http":
        return attributes.get("url.path") == "/proof" and attributes.get(
            "server.port"
        ) == "18080"
    if arm == "protocol":
        return payload.get("method") == "PING" and process.get("uid") == 65532
    if arm == "tls":
        return (
            payload.get("service_name") == "go-https-proof"
            and attributes.get("url.path") == "/proof"
            and attributes.get("server.port") == "8443"
            and process.get("uid") == 65532
        )
    if arm == "cpu-profile":
        # The workload proves its in-container UID separately. On nodes using
        # user-namespace ID mapping, bpf_get_current_uid_gid reports the mapped
        # host UID, so require a non-root Python process rather than assuming
        # that the namespace-local numeric UID survives unchanged.
        if process.get("uid") in {None, 0} or not str(
            process.get("command", "")
        ).startswith("python"):
            return False
        frames = payload.get("stack_frames") or []
        return any(
            "python" in str(frame.get("module", "")).lower()
            or "python" in str(frame.get("symbol", "")).lower()
            or str(frame.get("symbol", "")).startswith("profile_")
            for frame in frames
        )
    return True


def validate_agent(arm: str, run_dir: Path, requirement: dict) -> dict:
    blocks = capability_blocks(run_dir / "capability-decode.txt")
    if len(blocks) != 2:
        fail(f"{arm}: expected two DaemonSet capability records, got {len(blocks)}")
    expected_caps = requirement["capabilities"]
    for block in blocks:
        if block["capabilities"] != expected_caps:
            fail(
                f"{arm}: {block['pod']} capabilities {sorted(block['capabilities'])} "
                f"!= {sorted(expected_caps)}"
            )
        if not block["no_new_privs"] or not block["seccomp"]:
            fail(f"{arm}: {block['pod']} lacks no-new-privileges or seccomp filtering")

    pod_inventory = json.loads((run_dir / "pod-json.txt").read_text())
    agent_pods = [
        item
        for item in pod_inventory.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    ]
    if len(agent_pods) != 2:
        fail(f"{arm}: expected two ready agent pods, got {len(agent_pods)}")
    for pod in agent_pods:
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if len(statuses) != 1 or not statuses[0].get("ready") or statuses[0].get("restartCount") != 0:
            fail(f"{arm}: unhealthy agent pod state: {pod.get('metadata', {}).get('name')}")

    logs = prefixed_json(run_dir / "logs.txt")
    matching = [record for record in logs if signal_matches(record, requirement, arm)]
    if not matching:
        fail(f"{arm}: no workload-relevant {requirement['source']} signal was captured")
    matching_kinds = sorted({record["kind"] for record in matching})
    if arm == "host-resource" and not requirement["kinds"].issubset(matching_kinds):
        fail(
            f"{arm}: required host-resource kinds {sorted(requirement['kinds'])} "
            f"were not all captured: {matching_kinds}"
        )

    source = requirement["source"]
    if source.startswith("source.aya_"):
        metric_text = "\n".join(
            path.read_text(errors="replace")
            for path in sorted(run_dir.glob("prometheus-http-metrics-*.txt"))
        )
        initialized = f'e_navigator_ebpf_source_initialized{{source="{source}"}} 1'
        if initialized not in metric_text:
            fail(f"{arm}: missing initialized metric for {source}")
        for loss_name in (
            "lost_transport_events_total",
            "ring_buffer_reservation_failures_total",
            "send_failures_total",
        ):
            pattern = re.compile(
                rf'^e_navigator_ebpf_source_{loss_name}'
                rf'\{{source="{re.escape(source)}"\}} ([0-9]+)$',
                re.MULTILINE,
            )
            values = [int(value) for value in pattern.findall(metric_text)]
            if not values or any(values):
                fail(f"{arm}: absent or nonzero {loss_name} for {source}: {values}")

    return {
        "arm": arm,
        "agent": True,
        "source": source,
        "capabilities": sorted(expected_caps),
        "agent_pods": len(agent_pods),
        "matching_signals": len(matching),
        "matching_kinds": matching_kinds,
        "workload": validate_workload(arm, run_dir),
    }


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: analyze-reduced-privilege.py <arm> <run-directory>")
    arm = sys.argv[1]
    run_dir = Path(sys.argv[2])
    requirement = ARM_REQUIREMENTS.get(arm)
    if requirement is None:
        fail(f"unknown reduced-privilege arm: {arm}")
    if not run_dir.is_dir():
        fail(f"run directory does not exist: {run_dir}")
    if requirement["source"] is None:
        result = validate_no_agent(arm, run_dir)
    else:
        result = validate_agent(arm, run_dir, requirement)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
