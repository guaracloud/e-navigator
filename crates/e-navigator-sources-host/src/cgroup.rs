use std::{collections::VecDeque, fs, path::Path};

use crate::{
    config::HostResourceConfig,
    filesystem::{bounded_child_dirs, read_bounded_to_string},
    model::CgroupSample,
};

pub(crate) fn sample_cgroups(
    config: &HostResourceConfig,
    warnings: &mut Vec<String>,
) -> Vec<CgroupSample> {
    let mut samples = Vec::new();
    let mut queue = VecDeque::from([config.cgroup_root.clone()]);
    let mut visited = 0usize;
    let mut traversal_truncated = false;
    while let Some(path) = queue.pop_front() {
        if samples.len() >= config.max_cgroups || visited >= config.max_cgroups {
            if !traversal_truncated {
                warnings.push(format!(
                    "{}: cgroup traversal truncated at {} entries",
                    path.display(),
                    config.max_cgroups
                ));
            }
            break;
        }
        visited = visited.saturating_add(1);
        if path.join("cgroup.procs").exists()
            || path.join("cpu.stat").exists()
            || path.join("memory.current").exists()
        {
            samples.push(CgroupSample {
                path: normalize_cgroup_path(&config.cgroup_root, &path),
                cpu_stat: read_bounded_to_string(&path.join("cpu.stat"), config.max_file_bytes)
                    .ok(),
                memory_current: read_bounded_to_string(
                    &path.join("memory.current"),
                    config.max_file_bytes,
                )
                .ok(),
                memory_peak: read_bounded_to_string(
                    &path.join("memory.peak"),
                    config.max_file_bytes,
                )
                .ok(),
                memory_max: read_bounded_to_string(&path.join("memory.max"), config.max_file_bytes)
                    .ok(),
                pids_current: read_bounded_to_string(
                    &path.join("pids.current"),
                    config.max_file_bytes,
                )
                .ok(),
                pids_max: read_bounded_to_string(&path.join("pids.max"), config.max_file_bytes)
                    .ok(),
                fd_count: None,
                socket_count: None,
            });
        }
        match fs::read_dir(&path) {
            Ok(entries) => {
                let mut children = bounded_child_dirs(
                    entries,
                    config.max_cgroups.saturating_sub(samples.len()),
                    &path,
                    warnings,
                );
                children.sort();
                for child in children {
                    if queue.len().saturating_add(samples.len()) >= config.max_cgroups {
                        if !traversal_truncated {
                            warnings.push(format!(
                                "{}: cgroup traversal truncated at {} entries",
                                path.display(),
                                config.max_cgroups
                            ));
                            traversal_truncated = true;
                        }
                        break;
                    }
                    queue.push_back(child);
                }
            }
            Err(err) => warnings.push(format!("{}: {err}", path.display())),
        }
    }
    samples
}

pub(crate) fn normalize_cgroup_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let text = relative.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", text.trim_start_matches('/'))
    }
}
#[cfg(test)]
mod tests {
    use super::{normalize_cgroup_path, sample_cgroups};
    use crate::HostResourceConfig;

    #[test]
    fn normalizes_cgroup_paths_to_linux_cgroup_form() {
        let root = std::path::Path::new("/sys/fs/cgroup");
        assert_eq!(normalize_cgroup_path(root, root), "/");
        assert_eq!(
            normalize_cgroup_path(root, &root.join("kubepods.slice/pod123")),
            "/kubepods.slice/pod123"
        );
    }

    #[test]
    fn cgroup_child_scan_is_bounded_before_collection() {
        let root = temp_path("cgroup-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("a")).expect("cgroup dir");
        std::fs::create_dir_all(root.join("a/a1")).expect("cgroup dir");
        std::fs::create_dir_all(root.join("a/a2")).expect("cgroup dir");
        std::fs::create_dir_all(root.join("b")).expect("cgroup dir");
        std::fs::write(root.join("cgroup.procs"), "").expect("root cgroup procs");
        std::fs::write(root.join("a/cgroup.procs"), "").expect("child cgroup procs");

        let config = HostResourceConfig {
            cgroup_root: root.clone(),
            max_cgroups: 3,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let samples = sample_cgroups(&config, &mut warnings);

        assert!(samples.len() <= 2);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("cgroup scan truncated"))
        );
        assert_eq!(
            warnings
                .iter()
                .filter(|warning| warning.contains("cgroup traversal truncated"))
                .count(),
            1
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn cgroup_empty_directory_traversal_is_bounded() {
        let root = temp_path("cgroup-empty-chain-cap");
        let _ = std::fs::remove_dir_all(&root);
        let mut current = root.clone();
        for segment in ["a", "b", "c", "d", "e"] {
            current = current.join(segment);
            std::fs::create_dir_all(&current).expect("cgroup dir");
        }
        std::fs::write(current.join("cgroup.procs"), "").expect("leaf cgroup procs");

        let config = HostResourceConfig {
            cgroup_root: root.clone(),
            max_cgroups: 3,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let samples = sample_cgroups(&config, &mut warnings);

        assert!(samples.is_empty());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("cgroup traversal truncated"))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn cgroup_sampling_emits_expected_sample_from_fixture() {
        let root = temp_path("cgroup-fixture");
        let _ = std::fs::remove_dir_all(&root);
        let cgroup = root.join("kubepods.slice/pod123/container.scope");
        std::fs::create_dir_all(&cgroup).expect("cgroup dir");
        std::fs::write(cgroup.join("cgroup.procs"), "123\n").expect("procs");
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 100\n").expect("cpu");
        std::fs::write(cgroup.join("memory.current"), "8192\n").expect("memory");
        std::fs::write(cgroup.join("pids.current"), "3\n").expect("pids");

        let config = HostResourceConfig {
            cgroup_root: root.clone(),
            max_cgroups: 8,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let samples = sample_cgroups(&config, &mut warnings);

        assert!(warnings.is_empty());
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].path, "/kubepods.slice/pod123/container.scope");
        assert_eq!(samples[0].cpu_stat.as_deref(), Some("usage_usec 100\n"));
        assert_eq!(samples[0].memory_current.as_deref(), Some("8192\n"));
        assert_eq!(samples[0].pids_current.as_deref(), Some("3\n"));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "e-navigator-host-source-{label}-{}",
            std::process::id()
        ))
    }
}
