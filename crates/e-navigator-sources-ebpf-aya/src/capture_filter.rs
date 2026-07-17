//! Userspace control plane for the Kubernetes-aware capture filter.
//!
//! One shared [`CaptureFilterController`] (spawned once by the CLI) polls the
//! node: it scans the cgroup filesystem for container cgroups, fetches the
//! **raw, unscoped** node pod list from the Kubernetes API, resolves each
//! observed cgroup to a pod, evaluates the operator's policy, and publishes a
//! desired `{cgroup_id -> verdict}` map. Because every eBPF source loads its
//! own program object (and therefore its own copy of the filter map), the
//! expensive computation is shared here while each source cheaply applies the
//! diff to its own map via [`attach_capture_filter`].
//!
//! Only cgroup ids and a posture byte ever reach the kernel — never a
//! namespace or label.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use e_navigator_core::capture_filter::{
    CAPTURE_FILTER_MAP_CAPACITY, CgroupObservation, DesiredFilterMap, RawNodePodIndex, RawPod,
    build_desired_filter_map,
};
use e_navigator_core::{CaptureFilterConfig, CaptureFilterPolicy, KubernetesAttributionConfig};
use tracing::{debug, info, warn};

/// Steady-state interval between full pod-list refetches.
const FULL_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// Minimum spacing between eager refetches triggered by a newly observed,
/// still-unresolved cgroup. Bounds API load during pod churn.
const EAGER_REFETCH_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// Cadence of the local cgroup scan (cheap, no API traffic).
const SCAN_TICK: Duration = Duration::from_secs(2);
/// Upper bound on cgroup filesystem entries walked per scan.
const MAX_CGROUP_SCAN_ENTRIES: usize = 16_384;
/// Maximum process ids inspected per container cgroup and refresh.
const MAX_PROCESSES_PER_CGROUP: usize = 64;
/// Linux task names are normally limited to 16 bytes; retain extra headroom
/// while still bounding hostile procfs input.
const MAX_PROCESS_NAME_BYTES: usize = 256;
/// Cap on labels retained per pod for policy evaluation.
const MAX_LABELS_PER_POD: usize = 64;
/// Control-word values written into the eBPF `CAPTURE_FILTER_CONTROL` map.
const CONTROL_DISABLED: u32 = 0;
const CONTROL_UNKNOWN_CAPTURE: u32 = 1;
const CONTROL_UNKNOWN_DROP: u32 = 2;

/// Maximum Kubernetes API response accepted for the node pod list (8 MiB).
const MAX_POD_LIST_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum service-account token bytes read.
const MAX_TOKEN_BYTES: u64 = 16 * 1024;

/// Fetches the raw, unscoped node pod list.
#[async_trait]
pub(crate) trait RawPodFetcher: Send + Sync + std::fmt::Debug {
    async fn fetch(&self) -> Result<Vec<RawPod>, String>;
}

/// Compute the control word for the eBPF `CAPTURE_FILTER_CONTROL` map.
fn control_word(config: &CaptureFilterConfig) -> u32 {
    if !config.enabled {
        return CONTROL_DISABLED;
    }
    if config.unknown_cgroup.captures() {
        CONTROL_UNKNOWN_CAPTURE
    } else {
        CONTROL_UNKNOWN_DROP
    }
}

/// Published desired state plus a monotonically increasing generation so each
/// source's applier can detect and apply only real changes.
#[derive(Debug, Default)]
struct PublishedState {
    generation: u64,
    desired: Arc<DesiredFilterMap>,
}

/// Shared, node-wide capture-filter controller.
#[derive(Debug)]
pub(crate) struct CaptureFilterController {
    control_word: u32,
    state: Mutex<PublishedState>,
}

impl CaptureFilterController {
    fn new(control_word: u32) -> Self {
        Self {
            control_word,
            state: Mutex::new(PublishedState::default()),
        }
    }

    pub(crate) fn control_word(&self) -> u32 {
        self.control_word
    }

    /// The current generation and desired map. Consumed by the Linux applier
    /// and unit tests.
    #[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
    pub(crate) fn current(&self) -> (u64, Arc<DesiredFilterMap>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.generation, state.desired.clone())
    }

    fn publish(&self, desired: DesiredFilterMap) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.desired = Arc::new(desired);
    }
}

/// Process-global controller. `None` means the filter is disabled or could not
/// be initialised; sources then leave every workload captured.
static SHARED: OnceLock<Option<Arc<CaptureFilterController>>> = OnceLock::new();

/// Initialise the shared controller exactly once. Safe to call when the filter
/// is disabled (installs `None`). Spawns the background poll loop.
pub fn init_shared(
    capture_filter: &CaptureFilterConfig,
    kubernetes: &KubernetesAttributionConfig,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
    node_name: Option<String>,
) {
    SHARED.get_or_init(|| {
        build_shared(
            capture_filter,
            kubernetes,
            cgroup_root,
            procfs_root,
            node_name,
        )
    });
}

fn build_shared(
    capture_filter: &CaptureFilterConfig,
    kubernetes: &KubernetesAttributionConfig,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
    node_name: Option<String>,
) -> Option<Arc<CaptureFilterController>> {
    if !capture_filter.enabled {
        return None;
    }
    let policy = CaptureFilterPolicy::from_config(capture_filter);
    let controller = Arc::new(CaptureFilterController::new(control_word(capture_filter)));

    // Build the raw fetcher. Failure is not fatal: the controller still runs
    // and every cgroup falls to the unknown-cgroup posture, loudly logged.
    let fetcher: Option<Arc<dyn RawPodFetcher>> =
        match in_cluster::InClusterRawFetcher::from_config(kubernetes, node_name.as_deref()) {
            Ok(fetcher) => Some(Arc::new(fetcher)),
            Err(err) => {
                warn!(
                    error = %err,
                    "capture filter enabled but the Kubernetes API is unavailable; \
                     namespace/label rules cannot be resolved, applying the \
                     unknown-cgroup posture to all workloads"
                );
                None
            }
        };

    spawn_poll_loop(
        controller.clone(),
        policy,
        cgroup_root,
        procfs_root,
        fetcher,
    );
    info!(
        control_word = controller.control_word(),
        "capture filter active"
    );
    Some(controller)
}

/// The shared controller, if the filter is active. Consumed by the Linux
/// applier.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn shared() -> Option<Arc<CaptureFilterController>> {
    SHARED.get().and_then(Clone::clone)
}

fn spawn_poll_loop(
    controller: Arc<CaptureFilterController>,
    policy: CaptureFilterPolicy,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
    fetcher: Option<Arc<dyn RawPodFetcher>>,
) {
    tokio::spawn(async move {
        run_poll_loop(controller, policy, cgroup_root, procfs_root, fetcher).await;
    });
}

async fn run_poll_loop(
    controller: Arc<CaptureFilterController>,
    policy: CaptureFilterPolicy,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
    fetcher: Option<Arc<dyn RawPodFetcher>>,
) {
    let mut index = RawNodePodIndex::default();
    let mut have_index = false;
    // Force an immediate fetch on the first iteration.
    let mut since_full = FULL_REFRESH_INTERVAL;
    let mut since_fetch = EAGER_REFETCH_MIN_INTERVAL;

    loop {
        let observations = scan_cgroups(&cgroup_root, &procfs_root).await;

        let full_due = since_full >= FULL_REFRESH_INTERVAL;
        let eager_due = since_fetch >= EAGER_REFETCH_MIN_INTERVAL
            && has_unresolved(&observations, &index, have_index);
        if let Some(fetcher) = fetcher.as_ref()
            && (full_due || eager_due || !have_index)
        {
            match fetcher.fetch().await {
                Ok(pods) => {
                    index = RawNodePodIndex::from_pods(pods, CAPTURE_FILTER_MAP_CAPACITY);
                    have_index = true;
                    since_fetch = Duration::ZERO;
                    if full_due {
                        since_full = Duration::ZERO;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "capture filter node pod-list fetch failed; reusing last known pods");
                    // Avoid hammering a failing API before the eager window.
                    since_fetch = Duration::ZERO;
                }
            }
        }

        let desired =
            build_desired_filter_map(&observations, &index, &policy, CAPTURE_FILTER_MAP_CAPACITY);
        debug!(
            cgroups = observations.len(),
            pods = index.pod_count(),
            allowed = desired.allowed_count(),
            denied = desired.denied_count(),
            "capture filter refresh"
        );
        controller.publish(desired);

        tokio::time::sleep(SCAN_TICK).await;
        since_full = since_full.saturating_add(SCAN_TICK);
        since_fetch = since_fetch.saturating_add(SCAN_TICK);
    }
}

/// Whether any observed cgroup resolves to no pod in the current index — a
/// signal that a new pod may have appeared and an eager refetch is warranted.
fn has_unresolved(
    observations: &[CgroupObservation],
    index: &RawNodePodIndex,
    have_index: bool,
) -> bool {
    if !have_index {
        return true;
    }
    observations.iter().any(|observation| {
        build_desired_filter_map(std::slice::from_ref(observation), index, &ALWAYS_CAPTURE, 1)
            .is_empty()
            && (observation.pod_uid.is_some() || observation.container_id.is_some())
    })
}

/// A permissive policy used only to test resolvability in [`has_unresolved`].
static ALWAYS_CAPTURE: std::sync::LazyLock<CaptureFilterPolicy> = std::sync::LazyLock::new(|| {
    CaptureFilterPolicy::from_config(&CaptureFilterConfig {
        enabled: true,
        ..CaptureFilterConfig::default()
    })
});

/// Walk the cgroup filesystem and derive an observation per container cgroup.
/// Runs on a blocking thread; returns an empty list on any failure.
async fn scan_cgroups(cgroup_root: &Path, procfs_root: &Path) -> Vec<CgroupObservation> {
    let root = cgroup_root.to_path_buf();
    let procfs = procfs_root.to_path_buf();
    tokio::task::spawn_blocking(move || scan_cgroups_blocking(&root, &procfs))
        .await
        .unwrap_or_default()
}

fn scan_cgroups_blocking(root: &Path, procfs_root: &Path) -> Vec<CgroupObservation> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    let mut observations = Vec::new();
    let mut queue = vec![root.to_path_buf()];
    let mut scanned = 0usize;

    while let Some(path) = queue.pop() {
        if scanned >= MAX_CGROUP_SCAN_ENTRIES || observations.len() >= CAPTURE_FILTER_MAP_CAPACITY {
            break;
        }
        scanned = scanned.saturating_add(1);

        #[cfg(unix)]
        if let Ok(metadata) = path.metadata()
            && let Ok(relative) = path.strip_prefix(root)
        {
            let cgroup_path = normalized_cgroup_path(relative);
            let mut observation = CgroupObservation::from_cgroup_path(metadata.ino(), &cgroup_path);
            if observation.container_id.is_some() || observation.pod_uid.is_some() {
                observation.process_names = process_names_for_cgroup(&path, procfs_root);
                observations.push(observation);
            }
        }

        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if queue.len().saturating_add(scanned) >= MAX_CGROUP_SCAN_ENTRIES {
                break;
            }
            if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                queue.push(entry.path());
            }
        }
    }

    observations
}

fn process_names_for_cgroup(cgroup_path: &Path, procfs_root: &Path) -> Vec<String> {
    let Ok(pids) = std::fs::read_to_string(cgroup_path.join("cgroup.procs")) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for pid in pids.lines().take(MAX_PROCESSES_PER_CGROUP) {
        if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let process_root = procfs_root.join(pid);
        if let Ok(executable) = std::fs::read_link(process_root.join("exe")) {
            if let Some(name) = executable.file_name().and_then(|name| name.to_str()) {
                push_process_name(&mut names, name);
            }
            if let Some(path) = executable.to_str() {
                push_process_name(&mut names, path);
            }
        }
        if let Ok(raw) = std::fs::read_to_string(process_root.join("comm")) {
            push_process_name(&mut names, raw.trim_end_matches(['\r', '\n']));
        }
    }
    names
}

fn push_process_name(names: &mut Vec<String>, name: &str) {
    if name.is_empty() || name.len() > MAX_PROCESS_NAME_BYTES {
        return;
    }
    if !names.iter().any(|existing| existing == name) {
        names.push(name.to_string());
    }
}

fn normalized_cgroup_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", text.trim_start_matches('/'))
    }
}

mod in_cluster;
#[cfg(test)]
use in_cluster::parse_raw_pods;

#[cfg(target_os = "linux")]
mod apply;
#[cfg(target_os = "linux")]
pub(crate) use apply::attach_capture_filter;

#[cfg(test)]
mod tests;
