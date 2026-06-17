use e_navigator_signals::ProcessResourceObservation;

use crate::{
    config::HostResourceConfig,
    filesystem::{
        bounded_numeric_dirs, count_dir_entries, count_socket_fds, read_bounded_to_string,
    },
    parsers::parse_process_stat,
    platform::{clock_ticks_per_second, page_size_bytes},
};

pub(crate) fn sample_processes(
    config: &HostResourceConfig,
    started: u64,
    ended: u64,
    warnings: &mut Vec<String>,
) -> Vec<ProcessResourceObservation> {
    let clock_ticks_per_second = clock_ticks_per_second();
    let page_size_bytes = page_size_bytes();
    let mut entries = match bounded_numeric_dirs(
        &config.procfs_root,
        config.max_processes,
        "process",
        warnings,
    ) {
        Ok(entries) => entries,
        Err(err) => {
            warnings.push(format!("{}: {err}", config.procfs_root.display()));
            return Vec::new();
        }
    };
    entries.sort_by_key(|(pid, _)| *pid);

    let mut observations = Vec::new();
    for (pid, path) in entries.into_iter().take(config.max_processes) {
        let stat = match read_bounded_to_string(&path.join("stat"), config.max_file_bytes) {
            Ok(stat) => stat,
            Err(err) => {
                warnings.push(format!("{}/stat: {err}", path.display()));
                continue;
            }
        };
        let status = read_bounded_to_string(&path.join("status"), config.max_file_bytes).ok();
        let fd_count = count_dir_entries(&path.join("fd"), config.max_fds_per_process).unwrap_or(0);
        let socket_count =
            count_socket_fds(&path.join("fd"), config.max_fds_per_process).unwrap_or(0);
        match parse_process_stat(
            pid,
            &stat,
            status.as_deref(),
            clock_ticks_per_second,
            page_size_bytes,
            fd_count,
            socket_count,
            started,
            ended,
        ) {
            Ok(observation) => observations.push(observation),
            Err(err) => warnings.push(format!("process {pid}: {err}")),
        }
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::sample_processes;
    use crate::HostResourceConfig;

    #[test]
    fn process_scan_is_bounded_before_collection() {
        let root = temp_path("process-cap");
        let _ = std::fs::remove_dir_all(&root);
        for pid in [100, 101, 102] {
            std::fs::create_dir_all(root.join(pid.to_string())).expect("pid dir");
            std::fs::write(
                root.join(pid.to_string()).join("stat"),
                format!("{pid} (api) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 8192 1\n"),
            )
            .expect("stat");
        }

        let config = HostResourceConfig {
            procfs_root: root.clone(),
            max_processes: 1,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let observations = sample_processes(&config, 1_000, 2_000, &mut warnings);

        assert_eq!(observations.len(), 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("process scan truncated"))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn process_sampling_emits_expected_observation_from_procfs_fixture() {
        let root = temp_path("process-fixture");
        let _ = std::fs::remove_dir_all(&root);
        let pid_root = root.join("42");
        std::fs::create_dir_all(pid_root.join("fd")).expect("fd dir");
        std::fs::write(
            pid_root.join("stat"),
            "42 (api worker) S 1 1 1 0 -1 0 0 0 0 0 12 6 0 0 20 0 4 0 100 8192 8\n",
        )
        .expect("stat");
        std::fs::write(
            pid_root.join("status"),
            "Name:\tapi\nUid:\t1000\t1000\t1000\t1000\nThreads:\t4\n",
        )
        .expect("status");
        std::fs::write(pid_root.join("fd/0"), "").expect("fd");
        std::fs::write(pid_root.join("fd/1"), "").expect("fd");

        let config = HostResourceConfig {
            procfs_root: root.clone(),
            max_processes: 4,
            max_fds_per_process: 1,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let observations = sample_processes(&config, 1_000, 2_000, &mut warnings);

        assert!(warnings.is_empty());
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].process.pid, 42);
        assert_eq!(observations[0].process.command, "api");
        assert_eq!(observations[0].process.uid, Some(1000));
        assert_eq!(observations[0].open_fds, Some(1));
        assert_eq!(observations[0].thread_count, Some(4));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
