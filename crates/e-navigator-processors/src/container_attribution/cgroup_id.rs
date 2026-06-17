use e_navigator_signals::{CgroupResourceContext, ContainerContext};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

use super::cgroup::parse_container_from_cgroup;

const MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES: usize = 4096;
const MIN_CGROUP_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
pub(super) struct CgroupIdAttributionCache {
    cache: Mutex<BTreeMap<u64, ContainerContext>>,
    last_refresh: Mutex<Option<Instant>>,
}

impl CgroupIdAttributionCache {
    pub(super) fn container_for_cgroup_id(
        &self,
        cgroup_root: &Path,
        cgroup_id: u64,
    ) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_cgroup_id(cgroup_id) {
            return Some(container);
        }
        if self.should_refresh_cgroup_cache() {
            self.refresh_cgroup_id_cache(cgroup_root);
        }
        self.cached_container_for_cgroup_id(cgroup_id)
    }

    pub(super) fn cache_cgroup_context(&self, cgroup_root: &Path, cgroup: &CgroupResourceContext) {
        let Some(container) = cgroup.container.clone() else {
            return;
        };
        let path = cgroup_root.join(cgroup.cgroup_path.trim_start_matches('/'));
        let Some(cgroup_id) = cgroup_path_id(&path) else {
            return;
        };
        if let Ok(mut cache) = self.cache.lock() {
            insert_bounded(&mut cache, cgroup_id, container);
        }
    }

    fn cached_container_for_cgroup_id(&self, cgroup_id: u64) -> Option<ContainerContext> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cgroup_id).cloned())
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

    fn refresh_cgroup_id_cache(&self, cgroup_root: &Path) {
        let cache = scan_cgroup_id_cache(cgroup_root);
        if cache.is_empty() {
            return;
        }
        if let Ok(mut cgroup_cache) = self.cache.lock() {
            *cgroup_cache = cache;
        }
    }
}

pub(super) fn scan_cgroup_id_cache(root: &Path) -> BTreeMap<u64, ContainerContext> {
    let mut cache = BTreeMap::new();
    let mut queue = vec![root.to_path_buf()];

    while let Some(path) = queue.pop() {
        if cache.len() >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES {
            break;
        }
        let Some(id) = cgroup_path_id(&path) else {
            continue;
        };
        if let Ok(relative) = path.strip_prefix(root) {
            let cgroup_path = normalized_cgroup_path(relative);
            if let Some(container) = parse_container_from_cgroup(&cgroup_path) {
                insert_bounded(&mut cache, id, container);
            }
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if queue.len().saturating_add(cache.len()) >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES {
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

fn insert_bounded(
    cache: &mut BTreeMap<u64, ContainerContext>,
    id: u64,
    container: ContainerContext,
) {
    if cache.len() >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES
        && !cache.contains_key(&id)
        && let Some(oldest_id) = cache.keys().next().copied()
    {
        cache.remove(&oldest_id);
    }
    cache.insert(id, container);
}

#[cfg(unix)]
pub(super) fn cgroup_path_id(path: &Path) -> Option<u64> {
    path.metadata().ok().map(|metadata| metadata.ino())
}

#[cfg(not(unix))]
pub(super) fn cgroup_path_id(_path: &Path) -> Option<u64> {
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
}
