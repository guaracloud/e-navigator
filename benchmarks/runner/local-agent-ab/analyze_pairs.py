#!/usr/bin/env python3
"""Aggregates local whole-agent A/B arms by label prefix.

Reads benchmarks/results/local-agent-ab/*/result.json (plus the arm's
Prometheus snapshot for signal-count integrity) and prints per-label
median and mean CPU cores and RSS. Pass label prefixes to filter.
"""

import json
import re
import statistics
import sys
from pathlib import Path

out_root = Path(__file__).resolve().parents[2] / "results" / "local-agent-ab"


def main() -> None:
    groups: dict[str, list[dict]] = {}
    for result in sorted(out_root.glob("*/result.json")):
        label = result.parent.name
        match = re.match(r"(.+?)-r\d+$", label)
        key = match.group(1) if match else label
        data = json.loads(result.read_text())
        decoded = None
        prom = result.parent / "metrics.prom"
        if prom.exists():
            for line in prom.read_text().splitlines():
                if line.startswith(
                    'e_navigator_ebpf_source_decoded_samples_total{source="source.aya_protocol"}'
                ):
                    decoded = float(line.rsplit(" ", 1)[1])
                    break
        groups.setdefault(key, []).append(
            {
                "label": label,
                "cpu_cores": data["agent_cpu_cores"],
                "rss_kb": data["agent_rss_kb"],
                "protocol_decoded": decoded,
            }
        )

    prefixes = sys.argv[1:]
    for key, arms in sorted(groups.items()):
        if prefixes and not any(key.startswith(prefix) for prefix in prefixes):
            continue
        cpus = [arm["cpu_cores"] for arm in arms]
        rss = [arm["rss_kb"] for arm in arms]
        print(f"== {key} (n={len(arms)})")
        stdev = f" stdev={statistics.stdev(cpus):.6f}" if len(cpus) > 1 else ""
        print(
            f"   cpu_cores median={statistics.median(cpus):.6f} "
            f"mean={statistics.mean(cpus):.6f}{stdev}"
        )
        print(f"   rss_kb median={statistics.median(rss):.0f}")
        for arm in arms:
            print(
                f"   {arm['label']}: cpu={arm['cpu_cores']:.6f} "
                f"rss={arm['rss_kb']} proto_decoded={arm['protocol_decoded']}"
            )


if __name__ == "__main__":
    main()
