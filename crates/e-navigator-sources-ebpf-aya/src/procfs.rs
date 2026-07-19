use e_navigator_core::capture_filter::parse_container_id_from_cgroup_path;
use e_navigator_signals::ContainerContext;
#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, VecDeque};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use tracing::{debug, warn};

const MAX_CGROUP_BYTES: u64 = 4096;
const ESRCH: i32 = 3;

/// Bounded source-time container attribution keyed by both PID and cgroup.
///
/// Hot protocol sources can emit many observations for one long-lived
/// process. Reopening `/proc/<pid>/cgroup` for every observation needlessly
/// puts filesystem I/O in the capture path. Including the kernel cgroup ID in
/// the key prevents a recycled PID from inheriting attribution from a prior
/// process. Unknown cgroup IDs and failed lookups are intentionally not
/// cached, so transient procfs races can recover on a later observation.
#[derive(Debug)]
#[cfg(any(target_os = "linux", test))]
pub(crate) struct ContainerContextCache {
    capacity: usize,
    entries: BTreeMap<(u32, u64), ContainerContext>,
    insertion_order: VecDeque<(u32, u64)>,
}

#[cfg(any(target_os = "linux", test))]
impl ContainerContextCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(crate) fn resolve(
        &mut self,
        procfs_root: &Path,
        pid: u32,
        cgroup_id: u64,
    ) -> Option<ContainerContext> {
        if cgroup_id == 0 {
            return container_from_pid_cgroup(procfs_root, pid);
        }

        let key = (pid, cgroup_id);
        if let Some(container) = self.entries.get(&key) {
            return Some(container.clone());
        }

        let container = container_from_pid_cgroup(procfs_root, pid)?;
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self.insertion_order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, container.clone());
        self.insertion_order.push_back(key);
        Some(container)
    }
}

pub(crate) fn container_from_pid_cgroup(procfs_root: &Path, pid: u32) -> Option<ContainerContext> {
    let path = procfs_root.join(pid.to_string()).join("cgroup");
    match read_bounded_to_string(&path, MAX_CGROUP_BYTES) {
        Ok(contents) => parse_container_from_cgroup(&contents),
        Err(err) => {
            if is_disappeared_process_error(&err) {
                debug!(
                    pid,
                    path = %path.display(),
                    "source-time process cgroup disappeared before attribution"
                );
            } else {
                warn!(
                    pid,
                    path = %path.display(),
                    error = %err,
                    "unable to read source-time process cgroup"
                );
            }
            None
        }
    }
}

fn is_disappeared_process_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(ESRCH)
}

fn read_bounded_to_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = String::new();
    file.by_ref().take(max_bytes).read_to_string(&mut buffer)?;
    Ok(buffer)
}

fn parse_container_from_cgroup(contents: &str) -> Option<ContainerContext> {
    let container_id = parse_container_id_from_cgroup_path(contents)?;
    let runtime = infer_runtime(contents);
    Some(ContainerContext {
        container_id,
        runtime,
    })
}

fn infer_runtime(contents: &str) -> Option<String> {
    if contents.contains("cri-containerd") || contents.contains("containerd") {
        Some("containerd".to_string())
    } else if contents.contains("crio") || contents.contains("cri-o") {
        Some("cri-o".to_string())
    } else if contents.contains("docker") {
        Some("docker".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn extracts_container_from_live_procfs_cgroup_file() {
        let temp = test_temp_dir("source-time-cgroup");
        let cgroup = temp.join("123/cgroup");
        std::fs::create_dir_all(cgroup.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &cgroup,
            format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
        )
        .expect("write cgroup");

        let container = container_from_pid_cgroup(&temp, 123).expect("container");

        assert_eq!(container.container_id, CONTAINER_ID);
        assert_eq!(container.runtime.as_deref(), Some("containerd"));

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn missing_procfs_cgroup_is_not_attributed() {
        let temp = test_temp_dir("missing-source-time-cgroup");

        assert!(container_from_pid_cgroup(&temp, 404).is_none());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn longer_hexadecimal_procfs_cgroup_id_is_not_attributed() {
        let contents = format!("0::/kubepods.slice/cri-containerd-f{CONTAINER_ID}.scope\n");

        assert!(parse_container_from_cgroup(&contents).is_none());
    }

    #[test]
    fn esrch_procfs_race_is_treated_as_disappeared_process() {
        let err = io::Error::from_raw_os_error(ESRCH);

        assert!(is_disappeared_process_error(&err));
    }

    #[test]
    fn source_container_cache_reuses_attribution_for_the_same_process_cgroup() {
        let temp = test_temp_dir("source-container-cache");
        let cgroup = temp.join("123/cgroup");
        std::fs::create_dir_all(cgroup.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &cgroup,
            format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
        )
        .expect("write cgroup");
        let mut cache = ContainerContextCache::new(2);

        let first = cache.resolve(&temp, 123, 41).expect("first attribution");
        std::fs::remove_file(&cgroup).expect("remove source file");
        let cached = cache.resolve(&temp, 123, 41).expect("cached attribution");

        assert_eq!(cached, first);
        assert!(cache.resolve(&temp, 123, 42).is_none());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn source_container_cache_evicts_at_its_bound() {
        let temp = test_temp_dir("source-container-cache-bound");
        for pid in [101_u32, 102] {
            let cgroup = temp.join(format!("{pid}/cgroup"));
            std::fs::create_dir_all(cgroup.parent().expect("parent")).expect("mkdir");
            std::fs::write(
                cgroup,
                format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
            )
            .expect("write cgroup");
        }
        let mut cache = ContainerContextCache::new(1);

        assert!(cache.resolve(&temp, 101, 51).is_some());
        assert!(cache.resolve(&temp, 102, 52).is_some());

        assert_eq!(cache.entries.len(), 1);
        assert!(!cache.entries.contains_key(&(101, 51)));
        assert!(cache.entries.contains_key(&(102, 52)));
        let _ = std::fs::remove_dir_all(temp);
    }

    fn test_temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("e-navigator-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
