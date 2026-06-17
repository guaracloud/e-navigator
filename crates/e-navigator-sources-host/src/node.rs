use e_navigator_signals::SignalEnvelope;
use std::path::Path;

use crate::{
    config::HostResourceConfig,
    filesystem::read_bounded_to_string,
    model::HostResourceSnapshot,
    parsers::{parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo},
    platform::clock_ticks_per_second,
};

pub(crate) fn collect_node_observations(
    config: &HostResourceConfig,
    host: Option<String>,
    started: u64,
    ended: u64,
    snapshot: &mut HostResourceSnapshot,
) {
    let clock_ticks_per_second = clock_ticks_per_second();

    push_file_observation(
        snapshot,
        &config.procfs_root.join("stat"),
        |contents| {
            parse_cpu_stat(&contents, clock_ticks_per_second, started, ended).map(|observation| {
                SignalEnvelope::node_cpu_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );
    push_file_observation(
        snapshot,
        &config.procfs_root.join("loadavg"),
        |contents| {
            parse_loadavg(&contents, started, ended).map(|observation| {
                SignalEnvelope::node_load_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );
    push_file_observation(
        snapshot,
        &config.procfs_root.join("meminfo"),
        |contents| {
            parse_meminfo(&contents, started, ended).map(|observation| {
                SignalEnvelope::node_memory_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );

    match read_bounded_to_string(&config.procfs_root.join("diskstats"), config.max_file_bytes)
        .and_then(|contents| parse_diskstats(&contents, started, ended))
    {
        Ok(disks) => snapshot
            .signals
            .extend(disks.into_iter().map(|observation| {
                SignalEnvelope::node_disk_io_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })),
        Err(err) => snapshot.warnings.push(format!("diskstats: {err}")),
    }
}

fn push_file_observation(
    snapshot: &mut HostResourceSnapshot,
    path: &Path,
    parser: impl FnOnce(String) -> Result<SignalEnvelope, String>,
    max_bytes: u64,
) {
    match read_bounded_to_string(path, max_bytes).and_then(parser) {
        Ok(signal) => snapshot.signals.push(signal),
        Err(err) => snapshot.warnings.push(format!("{}: {err}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::SignalPayload;

    use super::collect_node_observations;
    use crate::{HostResourceConfig, HostResourceSnapshot};

    #[test]
    fn node_sampling_emits_cpu_load_memory_and_disk_from_procfs_fixture() {
        let root = temp_path("node-fixture");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join("stat"),
            "cpu  100 0 50 500 10 0 0 2 0 0\nprocs_running 3\nprocs_blocked 1\n",
        )
        .expect("stat");
        std::fs::write(root.join("loadavg"), "0.25 0.50 0.75 2/200 12345\n").expect("loadavg");
        std::fs::write(
            root.join("meminfo"),
            "MemTotal:        8192 kB\nMemFree:         2048 kB\nMemAvailable:    4096 kB\n",
        )
        .expect("meminfo");
        std::fs::write(
            root.join("diskstats"),
            "259 0 nvme0n1 10 0 8 0 20 0 16 0 0 0 0 0 0 0 0\n",
        )
        .expect("diskstats");

        let config = HostResourceConfig {
            procfs_root: root.clone(),
            ..HostResourceConfig::default()
        };
        let mut snapshot = HostResourceSnapshot::default();
        collect_node_observations(
            &config,
            Some("node-a".to_string()),
            1_000,
            2_000,
            &mut snapshot,
        );

        assert!(snapshot.warnings.is_empty());
        assert_eq!(snapshot.signals.len(), 4);
        assert!(
            snapshot
                .signals
                .iter()
                .all(|signal| signal.host.as_deref() == Some("node-a"))
        );
        assert!(matches!(
            snapshot.signals[0].payload,
            SignalPayload::NodeCpuObservation(_)
        ));
        assert!(matches!(
            snapshot.signals[1].payload,
            SignalPayload::NodeLoadObservation(_)
        ));
        assert!(matches!(
            snapshot.signals[2].payload,
            SignalPayload::NodeMemoryObservation(_)
        ));
        assert!(matches!(
            snapshot.signals[3].payload,
            SignalPayload::NodeDiskIoObservation(_)
        ));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
