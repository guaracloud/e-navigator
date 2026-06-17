use e_navigator_signals::ContainerContext;
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};
use tracing::{debug, warn};

use super::cgroup::{parse_container_from_cgroup, read_bounded_to_string};

const MAX_CGROUP_BYTES: u64 = 16 * 1024;
const MAX_PID_ATTRIBUTION_CACHE_ENTRIES: usize = 4096;

#[derive(Debug, Default)]
pub(super) struct PidAttributionCache {
    cache: Mutex<BTreeMap<u32, ContainerContext>>,
}

impl PidAttributionCache {
    pub(super) async fn container_for_pid_async(
        &self,
        procfs_root: &Path,
        pid: u32,
    ) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_pid(pid) {
            return Some(container);
        }

        let path = process_cgroup_path(procfs_root, pid);
        let read_path = path.clone();
        let container = match tokio::task::spawn_blocking(move || {
            read_bounded_to_string(&read_path, MAX_CGROUP_BYTES)
                .map(|contents| parse_container_from_cgroup(&contents))
        })
        .await
        {
            Ok(Ok(container)) => container,
            Ok(Err(err)) => {
                log_process_cgroup_read_error(pid, &path, &err);
                None
            }
            Err(err) => {
                warn!(
                    pid,
                    path = %path.display(),
                    error = %err,
                    "unable to join process cgroup attribution task"
                );
                None
            }
        };
        if let Some(container) = &container {
            self.store_cached_container_for_pid(pid, container.clone());
        }
        container
    }

    pub(super) fn evict_pid(&self, pid: u32) {
        if let Ok(mut cache) = self.pid_cache() {
            cache.remove(&pid);
        }
    }

    fn cached_container_for_pid(&self, pid: u32) -> Option<ContainerContext> {
        self.pid_cache()
            .ok()
            .and_then(|cache| cache.get(&pid).cloned())
    }

    fn store_cached_container_for_pid(&self, pid: u32, container: ContainerContext) {
        let Ok(mut cache) = self.pid_cache() else {
            return;
        };
        if cache.len() >= MAX_PID_ATTRIBUTION_CACHE_ENTRIES
            && !cache.contains_key(&pid)
            && let Some(oldest_pid) = cache.keys().next().copied()
        {
            cache.remove(&oldest_pid);
        }
        cache.insert(pid, container);
    }

    fn pid_cache(&self) -> Result<MutexGuard<'_, BTreeMap<u32, ContainerContext>>, String> {
        self.cache.lock().map_err(|err| err.to_string())
    }
}

fn process_cgroup_path(procfs_root: &Path, pid: u32) -> PathBuf {
    procfs_root.join(pid.to_string()).join("cgroup")
}

pub(super) fn log_process_cgroup_read_error(pid: u32, path: &Path, err: &io::Error) {
    if is_expected_process_exit_race(err) {
        debug!(
            pid,
            path = %path.display(),
            error = %err,
            "process cgroup disappeared before attribution"
        );
    } else {
        warn!(
            pid,
            path = %path.display(),
            error = %err,
            "unable to read process cgroup for attribution"
        );
    }
}

pub(super) fn is_expected_process_exit_race(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
}
