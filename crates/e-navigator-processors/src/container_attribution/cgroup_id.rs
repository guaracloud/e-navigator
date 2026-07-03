use e_navigator_signals::{CgroupResourceContext, ContainerContext};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::warn;

use super::bounded_cache::BoundedContainerCache;
use super::cgroup::parse_container_from_cgroup;

const MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES: usize = 4096;
const MAX_CGROUP_ATTRIBUTION_SCAN_ENTRIES: usize = 16_384;
const MIN_CGROUP_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
pub(super) struct CgroupIdAttributionCache {
    cache: Mutex<BoundedContainerCache<u64>>,
    last_refresh: Mutex<Option<Instant>>,
}

impl CgroupIdAttributionCache {
    pub(super) async fn container_for_cgroup_id_async(
        &self,
        cgroup_root: &Path,
        cgroup_id: u64,
    ) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_cgroup_id(cgroup_id) {
            return Some(container);
        }
        if self.should_refresh_cgroup_cache() {
            self.refresh_cgroup_id_cache_async(cgroup_root.to_path_buf())
                .await;
        }
        self.cached_container_for_cgroup_id(cgroup_id)
    }

    pub(super) async fn cache_cgroup_context_async(
        &self,
        cgroup_root: &Path,
        cgroup: &CgroupResourceContext,
    ) {
        let Some(container) = cgroup.container.clone() else {
            return;
        };
        let path = cgroup_root.join(cgroup.cgroup_path.trim_start_matches('/'));
        let cgroup_id = match cgroup_path_id_async(path).await {
            Some(cgroup_id) => cgroup_id,
            None => return,
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(cgroup_id, container, MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES);
        }
    }

    fn cached_container_for_cgroup_id(&self, cgroup_id: u64) -> Option<ContainerContext> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cgroup_id))
    }

    fn should_refresh_cgroup_cache(&self) -> bool {
        let Ok(mut last_refresh) = self.last_refresh.lock() else {
            return false;
        };
        let now = Instant::now();
        if last_refresh
            .is_some_and(|last| now.duration_since(last) < MIN_CGROUP_METADATA_REFRESH_INTERVAL)
        {
            return false;
        }
        *last_refresh = Some(now);
        true
    }

    async fn refresh_cgroup_id_cache_async(&self, cgroup_root: PathBuf) {
        match tokio::task::spawn_blocking(move || scan_cgroup_id_cache(&cgroup_root)).await {
            Ok(cache) if cache.is_empty() => {}
            Ok(cache) => {
                if let Ok(mut cgroup_cache) = self.cache.lock() {
                    cgroup_cache.replace_entries(cache);
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "unable to join cgroup id attribution cache refresh task"
                );
            }
        }
    }
}

pub(super) fn scan_cgroup_id_cache(root: &Path) -> BTreeMap<u64, ContainerContext> {
    scan_cgroup_id_cache_with_limits(
        root,
        MAX_CGROUP_ATTRIBUTION_SCAN_ENTRIES,
        MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES,
    )
}

fn scan_cgroup_id_cache_with_limits(
    root: &Path,
    max_scan_entries: usize,
    max_cache_entries: usize,
) -> BTreeMap<u64, ContainerContext> {
    let mut cache = BTreeMap::new();
    if max_scan_entries == 0 || max_cache_entries == 0 {
        return cache;
    }

    let mut queue = vec![root.to_path_buf()];
    let mut scanned_entries = 0_usize;

    while let Some(path) = queue.pop() {
        if cache.len() >= max_cache_entries || scanned_entries >= max_scan_entries {
            break;
        }
        scanned_entries = scanned_entries.saturating_add(1);
        let Some(id) = cgroup_path_id(&path) else {
            continue;
        };
        if let Ok(relative) = path.strip_prefix(root) {
            let cgroup_path = normalized_cgroup_path(relative);
            if let Some(container) = parse_container_from_cgroup(&cgroup_path) {
                cache.insert(id, container);
            }
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if queue.len().saturating_add(scanned_entries) >= max_scan_entries {
                break;
            }
            if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                queue.push(entry.path());
            }
        }
    }

    cache
}

pub(super) fn normalized_cgroup_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", text.trim_start_matches('/'))
    }
}

#[cfg(unix)]
pub(super) fn cgroup_path_id(path: &Path) -> Option<u64> {
    path.metadata().ok().map(|metadata| metadata.ino())
}

#[cfg(unix)]
async fn cgroup_path_id_async(path: PathBuf) -> Option<u64> {
    match tokio::task::spawn_blocking(move || cgroup_path_id(&path)).await {
        Ok(cgroup_id) => cgroup_id,
        Err(err) => {
            warn!(
                error = %err,
                "unable to join cgroup id attribution metadata task"
            );
            None
        }
    }
}

#[cfg(not(unix))]
pub(super) fn cgroup_path_id(_path: &Path) -> Option<u64> {
    None
}

#[cfg(not(unix))]
async fn cgroup_path_id_async(_path: PathBuf) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn cgroup_id_cache_scan_is_bounded() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-cgroup-id-bounds-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture root");
        for index in 0..(MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES + 8) {
            fs::create_dir_all(root.join(format!("kubepods/containerd-{CONTAINER_ID}-{index}")))
                .expect("fixture directory");
        }

        let cache = scan_cgroup_id_cache(&root);

        assert!(cache.len() <= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn cgroup_id_cache_scan_entry_count_is_bounded() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-cgroup-id-scan-limit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(format!("cri-containerd-{CONTAINER_ID}.scope")))
            .expect("fixture directory");

        let cache = scan_cgroup_id_cache_with_limits(&root, 1, 8);

        assert!(cache.is_empty());

        let cache = scan_cgroup_id_cache_with_limits(&root, 2, 8);

        assert_eq!(cache.len(), 1);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn cgroup_id_cache_scan_respects_cache_limit() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-cgroup-id-cache-limit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for index in 0..4 {
            fs::create_dir_all(root.join(format!("cri-containerd-{CONTAINER_ID}-{index}.scope")))
                .expect("fixture directory");
        }

        let cache = scan_cgroup_id_cache_with_limits(&root, 16, 1);

        assert_eq!(cache.len(), 1);
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
