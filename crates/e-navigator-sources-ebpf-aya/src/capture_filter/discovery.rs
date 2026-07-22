//! Event-driven cgroup-tree discovery for the capture-filter controller.
//!
//! Linux inotify is intentionally used through its safe Rust wrapper. The
//! kernel interface is not recursive, so every directory receives one bounded
//! watch. New subtrees are watched before userspace requests a reconciliation,
//! and a queue overflow rebuilds the complete watch set before continuing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use inotify::{EventMask, Inotify, StreamExt, WatchDescriptor, WatchMask, Watches};
use tracing::{info, warn};

use super::{CaptureFilterController, MAX_CGROUP_SCAN_ENTRIES};

/// Fixed userspace read buffer. Kernel queue overflow is surfaced separately
/// through `IN_Q_OVERFLOW` and always rebuilds the watch set.
const EVENT_BUFFER_BYTES: usize = 64 * 1024;
const RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const RETRY_MAX_BACKOFF: Duration = Duration::from_secs(2);

const DIRECTORY_WATCH_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVE_SELF);

#[derive(Debug)]
struct WatchTree {
    watches: Watches,
    paths_by_descriptor: HashMap<WatchDescriptor, PathBuf>,
    watched_paths: HashSet<PathBuf>,
    max_watches: usize,
}

impl WatchTree {
    fn new(watches: Watches, max_watches: usize) -> Self {
        Self {
            watches,
            paths_by_descriptor: HashMap::with_capacity(max_watches.min(1_024)),
            watched_paths: HashSet::with_capacity(max_watches.min(1_024)),
            max_watches,
        }
    }

    fn add_subtree(
        &mut self,
        root: &Path,
        controller: &CaptureFilterController,
    ) -> Result<(), String> {
        let mut pending = vec![root.to_path_buf()];
        let mut inspected = 0usize;

        while let Some(path) = pending.pop() {
            if self.watched_paths.contains(&path) {
                continue;
            }
            if self.watched_paths.len() >= self.max_watches || inspected >= MAX_CGROUP_SCAN_ENTRIES
            {
                controller
                    .telemetry
                    .inotify_watch_limit_drops
                    .fetch_add(1, Ordering::Relaxed);
                break;
            }
            inspected = inspected.saturating_add(1);

            match self.watches.add(&path, DIRECTORY_WATCH_MASK) {
                Ok(descriptor) => {
                    self.watched_paths.insert(path.clone());
                    if let Some(previous) =
                        self.paths_by_descriptor.insert(descriptor, path.clone())
                        && previous != path
                    {
                        self.watched_paths.remove(&previous);
                    }
                }
                Err(err) if path == root => {
                    return Err(format!(
                        "cannot watch cgroup directory {}: {err}",
                        path.display()
                    ));
                }
                Err(err) => {
                    controller
                        .telemetry
                        .inotify_failures
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(path = %path.display(), error = %err, "cannot add nested cgroup watch");
                    continue;
                }
            }

            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(err) => {
                    controller
                        .telemetry
                        .inotify_failures
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(path = %path.display(), error = %err, "cannot enumerate watched cgroup directory");
                    continue;
                }
            };
            for entry in entries.filter_map(Result::ok) {
                if pending.len().saturating_add(self.watched_paths.len()) >= self.max_watches {
                    controller
                        .telemetry
                        .inotify_watch_limit_drops
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                    pending.push(entry.path());
                }
            }
        }

        controller
            .telemetry
            .inotify_watches
            .store(self.watched_paths.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn parent_path(&self, descriptor: &WatchDescriptor) -> Option<PathBuf> {
        self.paths_by_descriptor.get(descriptor).cloned()
    }

    fn forget(&mut self, descriptor: &WatchDescriptor) -> Option<PathBuf> {
        let path = self.paths_by_descriptor.remove(descriptor)?;
        self.watched_paths.remove(&path);
        Some(path)
    }
}

pub(super) fn spawn(controller: Arc<CaptureFilterController>, cgroup_root: PathBuf) {
    tokio::spawn(async move {
        run(controller, cgroup_root).await;
    });
}

async fn run(controller: Arc<CaptureFilterController>, cgroup_root: PathBuf) {
    let mut backoff = RETRY_INITIAL_BACKOFF;
    loop {
        match watch_once(&controller, &cgroup_root).await {
            Ok(()) => backoff = RETRY_INITIAL_BACKOFF,
            Err(err) => {
                controller
                    .telemetry
                    .inotify_failures
                    .fetch_add(1, Ordering::Relaxed);
                controller
                    .telemetry
                    .inotify_watches
                    .store(0, Ordering::Relaxed);
                warn!(error = %err, ?backoff, "cgroup inotify watcher rebuilding");
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(RETRY_MAX_BACKOFF);
            }
        }
    }
}

async fn watch_once(
    controller: &Arc<CaptureFilterController>,
    cgroup_root: &Path,
) -> Result<(), String> {
    let inotify = Inotify::init().map_err(|err| format!("cannot initialize inotify: {err}"))?;
    let mut tree = WatchTree::new(inotify.watches(), MAX_CGROUP_SCAN_ENTRIES);
    tree.add_subtree(cgroup_root, controller)?;
    let mut stream = inotify
        .into_event_stream(vec![0_u8; EVENT_BUFFER_BYTES])
        .map_err(|err| format!("cannot create inotify event stream: {err}"))?;

    info!(
        cgroup_root = %cgroup_root.display(),
        watches = tree.watched_paths.len(),
        "event-driven cgroup discovery active"
    );
    // Reconcile after every existing directory is watched. This scan closes
    // the race between the controller's startup scan and watch installation.
    controller.enqueue_refresh();

    while let Some(result) = stream.next().await {
        let event = result.map_err(|err| format!("inotify event read failed: {err}"))?;
        controller
            .telemetry
            .inotify_events
            .fetch_add(1, Ordering::Relaxed);

        if event.mask.contains(EventMask::Q_OVERFLOW) {
            controller
                .telemetry
                .inotify_queue_overflows
                .fetch_add(1, Ordering::Relaxed);
            controller.enqueue_refresh();
            return Err("inotify queue overflowed".to_string());
        }

        let parent = tree.parent_path(&event.wd);
        let directory_created = event.mask.contains(EventMask::ISDIR)
            && event
                .mask
                .intersects(EventMask::CREATE | EventMask::MOVED_TO);
        if directory_created
            && let (Some(parent), Some(name)) = (parent.as_deref(), event.name.as_deref())
        {
            let path = parent.join(name);
            if path.starts_with(cgroup_root) {
                tree.add_subtree(&path, controller)?;
            }
        }

        let directory_membership_changed = event.mask.contains(EventMask::ISDIR)
            && event.mask.intersects(
                EventMask::CREATE | EventMask::DELETE | EventMask::MOVED_FROM | EventMask::MOVED_TO,
            );
        let watched_directory_changed = event.mask.intersects(
            EventMask::DELETE_SELF | EventMask::MOVE_SELF | EventMask::UNMOUNT | EventMask::IGNORED,
        );

        if event.mask.contains(EventMask::IGNORED) {
            let removed = tree.forget(&event.wd);
            controller
                .telemetry
                .inotify_watches
                .store(tree.watched_paths.len() as u64, Ordering::Relaxed);
            if removed.as_deref() == Some(cgroup_root) {
                return Err("cgroup root watch was removed".to_string());
            }
        }
        if event
            .mask
            .intersects(EventMask::MOVED_FROM | EventMask::MOVE_SELF | EventMask::UNMOUNT)
        {
            controller.enqueue_refresh();
            return Err("watched cgroup topology moved or unmounted".to_string());
        }
        if directory_membership_changed || watched_directory_changed {
            controller.enqueue_refresh();
        }
    }

    Err("inotify event stream ended".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_filter::CgroupHierarchyMode;
    use e_navigator_core::CgroupDiscoveryMode;

    #[test]
    fn recursive_watch_installation_obeys_the_explicit_bound() {
        let fixture =
            std::env::temp_dir().join(format!("e-nav-inotify-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("a/b/c")).expect("fixture tree");
        let controller = CaptureFilterController::new(
            0,
            CgroupHierarchyMode::UnifiedV2,
            false,
            CgroupDiscoveryMode::EventDriven,
        );
        let inotify = Inotify::init().expect("inotify");
        let mut tree = WatchTree::new(inotify.watches(), 2);

        tree.add_subtree(&fixture, &controller)
            .expect("bounded watch installation");

        assert_eq!(tree.watched_paths.len(), 2);
        assert_eq!(controller.telemetry().inotify_watch_limit_drops_total, 1);
        std::fs::remove_dir_all(&fixture).expect("fixture cleanup");
    }
}
