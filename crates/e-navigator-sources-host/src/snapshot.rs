use e_navigator_signals::SignalEnvelope;

use crate::{
    cgroup::sample_cgroups, config::HostResourceConfig, model::HostResourceSnapshot,
    node::collect_node_observations, platform::now_unix_nanos, process::sample_processes,
};

pub(crate) fn sample_host_resources(
    config: &HostResourceConfig,
    host: Option<String>,
) -> HostResourceSnapshot {
    let started = now_unix_nanos();
    let ended = started;
    let mut snapshot = HostResourceSnapshot::default();

    collect_node_observations(config, host.clone(), started, ended, &mut snapshot);

    snapshot.signals.extend(
        sample_processes(config, started, ended, &mut snapshot.warnings)
            .into_iter()
            .map(|observation| {
                SignalEnvelope::process_resource_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            }),
    );
    for sample in sample_cgroups(config, &mut snapshot.warnings) {
        snapshot
            .signals
            .extend(sample.into_observations(host.clone(), started, ended));
    }

    snapshot
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::SignalPayload;

    use super::sample_host_resources;
    use crate::HostResourceConfig;

    #[test]
    fn sample_once_reports_missing_and_malformed_procfs_warnings() {
        let root = temp_path("warning");
        let _ = std::fs::remove_dir_all(&root);
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        std::fs::create_dir_all(&proc_root).expect("proc root");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup root");
        std::fs::write(proc_root.join("stat"), "intr 1\n").expect("stat");
        std::fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 8192 kB\nMemAvailable: 4096 kB\n",
        )
        .expect("meminfo");
        std::fs::write(proc_root.join("diskstats"), "partial\n").expect("diskstats");
        std::fs::write(cgroup_root.join("cgroup.procs"), "").expect("cgroup procs");

        let snapshot = sample_host_resources(
            &HostResourceConfig {
                procfs_root: proc_root,
                cgroup_root,
                sample_interval_millis: 0,
                max_processes: 1,
                max_cgroups: 1,
                ..HostResourceConfig::default()
            },
            None,
        );

        assert!(
            snapshot
                .warnings
                .iter()
                .any(|warning| warning.contains("aggregate cpu line"))
        );
        assert!(
            snapshot
                .warnings
                .iter()
                .any(|warning| warning.contains("loadavg"))
        );
        assert!(
            snapshot
                .signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NodeMemoryObservation(_)))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn all_generated_observations_share_stable_snapshot_timestamps() {
        let root = temp_path("timestamps");
        let _ = std::fs::remove_dir_all(&root);
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        let process_root = proc_root.join("42");
        std::fs::create_dir_all(process_root.join("fd")).expect("process");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup");
        std::fs::write(
            proc_root.join("stat"),
            "cpu  100 0 50 500 10 0 0 2 0 0\nprocs_running 3\nprocs_blocked 1\n",
        )
        .expect("stat");
        std::fs::write(proc_root.join("loadavg"), "0.25 0.50 0.75 2/200 12345\n").expect("loadavg");
        std::fs::write(proc_root.join("meminfo"), "MemTotal: 8192 kB\n").expect("meminfo");
        std::fs::write(
            proc_root.join("diskstats"),
            "259 0 nvme0n1 10 0 8 0 20 0 16 0 0 0 0 0 0 0 0\n",
        )
        .expect("diskstats");
        std::fs::write(
            process_root.join("stat"),
            "42 (api) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 8192 1\n",
        )
        .expect("process stat");
        std::fs::write(cgroup_root.join("cgroup.procs"), "").expect("cgroup");
        std::fs::write(cgroup_root.join("cpu.stat"), "usage_usec 100\n").expect("cpu");

        let snapshot = sample_host_resources(
            &HostResourceConfig {
                procfs_root: proc_root,
                cgroup_root,
                max_processes: 4,
                max_cgroups: 4,
                ..HostResourceConfig::default()
            },
            None,
        );

        let mut timestamps = snapshot.signals.iter().map(signal_timestamp);
        let first = timestamps.next().expect("at least one signal");
        assert!(timestamps.all(|timestamp| timestamp == first));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn signal_timestamp(signal: &e_navigator_signals::SignalEnvelope) -> u64 {
        match &signal.payload {
            SignalPayload::NodeCpuObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::NodeLoadObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::NodeMemoryObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::NodeDiskIoObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::ProcessResourceObservation(observation) => {
                observation.timestamp_unix_nanos
            }
            SignalPayload::CgroupCpuObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::CgroupMemoryObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::CgroupPidsObservation(observation) => observation.timestamp_unix_nanos,
            SignalPayload::CgroupFileDescriptorObservation(observation) => {
                observation.timestamp_unix_nanos
            }
            _ => 0,
        }
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
