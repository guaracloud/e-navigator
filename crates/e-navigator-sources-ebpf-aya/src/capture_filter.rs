//! Userspace control plane for the Kubernetes-aware capture filter.
//!
//! One shared `CaptureFilterController`, spawned once by the CLI, polls the
//! node: it scans the cgroup filesystem for container cgroups and fetches one
//! bounded Kubernetes workload snapshot (node-scoped by default, optionally
//! cluster-wide with local Pods retained first). It resolves each
//! observed cgroup to a pod, evaluates the operator's policy, and publishes a
//! desired `{cgroup_id -> verdict}` map. Because every eBPF source loads its
//! own program object (and therefore its own copy of the filter map), the
//! expensive computation is shared here while each source cheaply applies the
//! diff to its own map through the internal attachment helper.
//!
//! Only cgroup ids and a posture byte ever reach the kernel, never a
//! namespace or label.

use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use e_navigator_core::capture_filter::{
    CAPTURE_FILTER_MAP_CAPACITY, CgroupObservation, DesiredFilterMap, RawEndpointSlice,
    RawNodePodIndex, RawPod, RawService, build_desired_filter_map,
};
use e_navigator_core::{CaptureFilterConfig, CaptureFilterPolicy, KubernetesAttributionConfig};
use tracing::{debug, error, info, warn};

/// Cadence of the local cgroup scan (cheap, no API traffic).
const SCAN_TICK: Duration = Duration::from_secs(2);
const WATCH_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const WATCH_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Upper bound on cgroup filesystem entries walked per scan.
const MAX_CGROUP_SCAN_ENTRIES: usize = 16_384;
/// Maximum process ids inspected per container cgroup and refresh.
const MAX_PROCESSES_PER_CGROUP: usize = 64;
/// Linux task names are normally limited to 16 bytes; retain extra headroom
/// while still bounding hostile procfs input.
const MAX_PROCESS_NAME_BYTES: usize = 256;
/// Bound on top-level hierarchy entries inspected during the startup probe.
const MAX_CGROUP_HIERARCHY_CHILDREN: usize = 256;
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

/// Host cgroup layout observed at the configured cgroup root.
///
/// The in-kernel join key comes from `bpf_get_current_cgroup_id()`, which is
/// the current task's default (cgroup v2) hierarchy id. We therefore accept
/// only a directly mounted, unified cgroup v2 tree. Legacy and mixed layouts
/// are detected explicitly and never guessed through a v1 controller inode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CgroupHierarchyMode {
    /// No controller was initialized, so no probe ran.
    #[default]
    NotChecked,
    /// The configured root is a unified cgroup v2 mount.
    UnifiedV2,
    /// Only legacy cgroup v1 controller markers were found.
    LegacyV1,
    /// Both v1 and v2 markers were found, or v2 is nested below the root.
    Hybrid,
    /// The configured root could not be read or had no recognized markers.
    Unavailable,
}

impl CgroupHierarchyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::UnifiedV2 => "unified_v2",
            Self::LegacyV1 => "legacy_v1",
            Self::Hybrid => "hybrid",
            Self::Unavailable => "unavailable",
        }
    }

    pub const fn capture_filter_compatible(self) -> bool {
        matches!(self, Self::UnifiedV2)
    }
}

/// Fetches one bounded raw Kubernetes workload snapshot.
pub(crate) type RawPodPublisher = Arc<dyn Fn(&RawPodSnapshot) + Send + Sync>;
pub type SharedKubernetesResources = (
    u64,
    Arc<Vec<RawPod>>,
    Arc<Vec<RawService>>,
    Arc<Vec<RawEndpointSlice>>,
);

#[async_trait]
pub(crate) trait RawPodFetcher: Send + Sync + std::fmt::Debug {
    async fn list(&self) -> Result<RawPodSnapshot, String>;
    async fn watch(
        &self,
        snapshot: RawPodSnapshot,
        publisher: RawPodPublisher,
    ) -> Result<RawPodSnapshot, PodWatchError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawPodSnapshot {
    resource_version: String,
    pods: Vec<RawPod>,
    services: Vec<RawService>,
    endpoint_slices: Vec<RawEndpointSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PodWatchError {
    ExpiredResourceVersion,
    Other(String),
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
    pod_generation: u64,
    raw_pods: Arc<Vec<RawPod>>,
    raw_services: Arc<Vec<RawService>>,
    raw_endpoint_slices: Arc<Vec<RawEndpointSlice>>,
}

/// Shared, process-wide Kubernetes workload controller.
#[derive(Debug)]
pub(crate) struct CaptureFilterController {
    control_word: u32,
    cgroup_hierarchy_mode: CgroupHierarchyMode,
    state: Mutex<PublishedState>,
    telemetry: WorkloadControllerTelemetry,
}

impl CaptureFilterController {
    fn new(
        control_word: u32,
        cgroup_hierarchy_mode: CgroupHierarchyMode,
        capture_filter_fail_closed: bool,
    ) -> Self {
        let telemetry = WorkloadControllerTelemetry::default();
        if capture_filter_fail_closed {
            telemetry
                .capture_filter_fail_closed
                .store(1, Ordering::Relaxed);
        }
        Self {
            control_word,
            cgroup_hierarchy_mode,
            state: Mutex::new(PublishedState::default()),
            telemetry,
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

    fn publish(&self, desired: DesiredFilterMap) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.desired.as_ref() == &desired {
            return false;
        }
        state.generation = state.generation.wrapping_add(1);
        state.desired = Arc::new(desired);
        true
    }

    fn publish_snapshot(&self, snapshot: RawPodSnapshot) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pod_generation = state.pod_generation.wrapping_add(1);
        state.raw_pods = Arc::new(snapshot.pods);
        state.raw_services = Arc::new(snapshot.services);
        state.raw_endpoint_slices = Arc::new(snapshot.endpoint_slices);
        self.telemetry
            .reconciliations
            .fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .pod_count
            .store(state.raw_pods.len() as u64, Ordering::Relaxed);
        self.telemetry
            .service_count
            .store(state.raw_services.len() as u64, Ordering::Relaxed);
        self.telemetry
            .endpoint_slice_count
            .store(state.raw_endpoint_slices.len() as u64, Ordering::Relaxed);
        self.telemetry.last_success_unix_seconds.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
            Ordering::Relaxed,
        );
    }

    fn mark_resource_relist_success(&self) {
        self.telemetry.last_resource_relist_unix_seconds.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
            Ordering::Relaxed,
        );
    }

    fn raw_pods(&self) -> (u64, Arc<Vec<RawPod>>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.pod_generation, state.raw_pods.clone())
    }

    fn raw_kubernetes_resources(&self) -> SharedKubernetesResources {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            state.pod_generation,
            state.raw_pods.clone(),
            state.raw_services.clone(),
            state.raw_endpoint_slices.clone(),
        )
    }

    fn telemetry(&self) -> WorkloadControllerTelemetrySnapshot {
        WorkloadControllerTelemetrySnapshot {
            relists: self.telemetry.relists.load(Ordering::Relaxed),
            relist_failures: self.telemetry.relist_failures.load(Ordering::Relaxed),
            watch_starts: self.telemetry.watch_starts.load(Ordering::Relaxed),
            watch_failures: self.telemetry.watch_failures.load(Ordering::Relaxed),
            expired_resource_versions: self
                .telemetry
                .expired_resource_versions
                .load(Ordering::Relaxed),
            reconciliations: self.telemetry.reconciliations.load(Ordering::Relaxed),
            pod_count: self.telemetry.pod_count.load(Ordering::Relaxed),
            service_count: self.telemetry.service_count.load(Ordering::Relaxed),
            endpoint_slice_count: self.telemetry.endpoint_slice_count.load(Ordering::Relaxed),
            allowed_cgroups: self.telemetry.allowed_cgroups.load(Ordering::Relaxed),
            denied_cgroups: self.telemetry.denied_cgroups.load(Ordering::Relaxed),
            unresolved_cgroups: self.telemetry.unresolved_cgroups.load(Ordering::Relaxed),
            cgroup_hierarchy_mode: self.cgroup_hierarchy_mode,
            capture_filter_fail_closed_total: self
                .telemetry
                .capture_filter_fail_closed
                .load(Ordering::Relaxed),
            last_success_unix_seconds: self
                .telemetry
                .last_success_unix_seconds
                .load(Ordering::Relaxed),
            last_resource_relist_unix_seconds: self
                .telemetry
                .last_resource_relist_unix_seconds
                .load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default)]
struct WorkloadControllerTelemetry {
    relists: AtomicU64,
    relist_failures: AtomicU64,
    watch_starts: AtomicU64,
    watch_failures: AtomicU64,
    expired_resource_versions: AtomicU64,
    reconciliations: AtomicU64,
    pod_count: AtomicU64,
    service_count: AtomicU64,
    endpoint_slice_count: AtomicU64,
    allowed_cgroups: AtomicU64,
    denied_cgroups: AtomicU64,
    unresolved_cgroups: AtomicU64,
    capture_filter_fail_closed: AtomicU64,
    last_success_unix_seconds: AtomicU64,
    last_resource_relist_unix_seconds: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkloadControllerTelemetrySnapshot {
    pub relists: u64,
    pub relist_failures: u64,
    pub watch_starts: u64,
    pub watch_failures: u64,
    pub expired_resource_versions: u64,
    pub reconciliations: u64,
    pub pod_count: u64,
    pub service_count: u64,
    pub endpoint_slice_count: u64,
    pub allowed_cgroups: u64,
    pub denied_cgroups: u64,
    pub unresolved_cgroups: u64,
    pub cgroup_hierarchy_mode: CgroupHierarchyMode,
    pub capture_filter_fail_closed_total: u64,
    pub last_success_unix_seconds: u64,
    pub last_resource_relist_unix_seconds: u64,
}

/// Process-global workload controller. `None` means both capture filtering and
/// Kubernetes attribution are disabled.
static SHARED: OnceLock<Option<Arc<CaptureFilterController>>> = OnceLock::new();

/// Initialise the shared controller exactly once. It remains active when the
/// capture filter is disabled but Kubernetes attribution is enabled, because
/// attribution consumes the same pod snapshot.
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
    if !capture_filter.enabled && !kubernetes.enabled {
        return None;
    }
    let cgroup_hierarchy_mode = detect_cgroup_hierarchy(&cgroup_root);
    let (effective_control_word, capture_filter_fail_closed) =
        effective_control_word(capture_filter, cgroup_hierarchy_mode);
    let policy = CaptureFilterPolicy::from_config(capture_filter);
    let controller = Arc::new(CaptureFilterController::new(
        effective_control_word,
        cgroup_hierarchy_mode,
        capture_filter_fail_closed,
    ));

    if capture_filter_fail_closed {
        error!(
            cgroup_root = %cgroup_root.display(),
            cgroup_hierarchy_mode = cgroup_hierarchy_mode.as_str(),
            configured_unknown_cgroup = ?capture_filter.unknown_cgroup,
            effective_control_word,
            "capture filter requires a unified cgroup v2 hierarchy; all unknown cgroups are denied"
        );
    } else if !cgroup_hierarchy_mode.capture_filter_compatible() {
        warn!(
            cgroup_root = %cgroup_root.display(),
            cgroup_hierarchy_mode = cgroup_hierarchy_mode.as_str(),
            "cgroup v2 workload join is unavailable; cgroup capture filtering is not active"
        );
    }

    // Build the raw fetcher. Failure is not fatal: the controller still runs
    // and every cgroup falls to the unknown-cgroup posture, loudly logged.
    let fetcher: Option<Arc<dyn RawPodFetcher>> =
        match in_cluster::InClusterRawFetcher::from_config(kubernetes, node_name.as_deref()) {
            Ok(fetcher) => Some(Arc::new(fetcher)),
            Err(err) => {
                warn!(
                    error = %err,
                    "Kubernetes workload controller cannot reach the API; \
                     attribution is stale or unavailable and capture filtering \
                     applies the unknown-cgroup posture"
                );
                None
            }
        };

    if let Some(fetcher) = fetcher {
        spawn_watch_loop(controller.clone(), fetcher);
    }
    if cgroup_hierarchy_mode.capture_filter_compatible() {
        spawn_poll_loop(controller.clone(), policy, cgroup_root, procfs_root);
    }
    info!(
        control_word = controller.control_word(),
        capture_filter_enabled = capture_filter.enabled,
        cgroup_hierarchy_mode = cgroup_hierarchy_mode.as_str(),
        capture_filter_fail_closed,
        "shared Kubernetes workload controller active"
    );
    Some(controller)
}

fn effective_control_word(
    config: &CaptureFilterConfig,
    cgroup_hierarchy_mode: CgroupHierarchyMode,
) -> (u32, bool) {
    let fail_closed = config.enabled && !cgroup_hierarchy_mode.capture_filter_compatible();
    if fail_closed {
        (CONTROL_UNKNOWN_DROP, true)
    } else {
        (control_word(config), false)
    }
}

/// Detect whether `root` is the directly mounted cgroup v2 hierarchy used by
/// `bpf_get_current_cgroup_id()`. The marker probe is bounded and conservative:
/// ambiguity is unsupported, which lets the kernel posture fail closed.
fn detect_cgroup_hierarchy(root: &Path) -> CgroupHierarchyMode {
    let root_has_v2 = root.join("cgroup.controllers").is_file();
    let mut saw_v1 = root.join("tasks").is_file() || root.join("cgroup.clone_children").is_file();
    let mut saw_nested_v2 = false;

    let Ok(entries) = std::fs::read_dir(root) else {
        return CgroupHierarchyMode::Unavailable;
    };
    let mut scanned = 0usize;
    for entry in entries {
        if scanned >= MAX_CGROUP_HIERARCHY_CHILDREN {
            return CgroupHierarchyMode::Unavailable;
        }
        scanned = scanned.saturating_add(1);
        let Ok(entry) = entry else {
            return CgroupHierarchyMode::Unavailable;
        };
        let Ok(file_type) = entry.file_type() else {
            return CgroupHierarchyMode::Unavailable;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        saw_v1 |= path.join("tasks").is_file() || path.join("cgroup.clone_children").is_file();
        saw_nested_v2 |= path.join("cgroup.controllers").is_file();
    }

    match (root_has_v2, saw_v1, saw_nested_v2) {
        (true, false, _) => CgroupHierarchyMode::UnifiedV2,
        (true, true, _) | (false, true, true) | (false, false, true) => CgroupHierarchyMode::Hybrid,
        (false, true, false) => CgroupHierarchyMode::LegacyV1,
        (false, false, false) => CgroupHierarchyMode::Unavailable,
    }
}

/// The shared controller, when workload state is required. Consumed by the
/// Linux filter applier and attribution snapshot adapter.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn shared() -> Option<Arc<CaptureFilterController>> {
    SHARED.get().and_then(Clone::clone)
}

/// Latest bounded raw Pod snapshot owned by the shared controller.
/// Attribution consumes this instead of issuing an independent Kubernetes API
/// request. `None` means the controller is disabled or not initialized.
pub fn shared_raw_pods() -> Option<(u64, Arc<Vec<RawPod>>)> {
    shared().map(|controller| controller.raw_pods())
}

/// Latest bounded cluster-wide Kubernetes resource snapshot. The capture
/// filter consumes only Pods; attribution additionally consumes Services and
/// EndpointSlices from this same controller and API client.
pub fn shared_kubernetes_resources() -> Option<SharedKubernetesResources> {
    shared().map(|controller| controller.raw_kubernetes_resources())
}

pub fn shared_telemetry() -> Option<WorkloadControllerTelemetrySnapshot> {
    shared().map(|controller| controller.telemetry())
}

fn spawn_poll_loop(
    controller: Arc<CaptureFilterController>,
    policy: CaptureFilterPolicy,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
) {
    tokio::spawn(async move {
        run_poll_loop(controller, policy, cgroup_root, procfs_root).await;
    });
}

fn spawn_watch_loop(controller: Arc<CaptureFilterController>, fetcher: Arc<dyn RawPodFetcher>) {
    tokio::spawn(async move {
        run_watch_loop(controller, fetcher).await;
    });
}

async fn run_watch_loop(controller: Arc<CaptureFilterController>, fetcher: Arc<dyn RawPodFetcher>) {
    let mut backoff = WATCH_RETRY_INITIAL_BACKOFF;
    loop {
        controller.telemetry.relists.fetch_add(1, Ordering::Relaxed);
        let snapshot = match fetcher.list().await {
            Ok(snapshot) => snapshot,
            Err(err) => {
                controller
                    .telemetry
                    .relist_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, ?backoff, "Kubernetes pod relist failed");
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(WATCH_RETRY_MAX_BACKOFF);
                continue;
            }
        };
        controller.mark_resource_relist_success();
        controller.publish_snapshot(snapshot.clone());
        backoff = WATCH_RETRY_INITIAL_BACKOFF;

        controller
            .telemetry
            .watch_starts
            .fetch_add(1, Ordering::Relaxed);
        let publishing_controller = Arc::clone(&controller);
        let publisher: RawPodPublisher = Arc::new(move |snapshot| {
            publishing_controller.publish_snapshot(snapshot.clone());
        });
        match fetcher.watch(snapshot, publisher).await {
            Ok(snapshot) => {
                controller.publish_snapshot(snapshot);
                // The bounded watch timeout is also the reconciliation
                // boundary: relist before starting the next watch.
            }
            Err(PodWatchError::ExpiredResourceVersion) => {
                controller
                    .telemetry
                    .expired_resource_versions
                    .fetch_add(1, Ordering::Relaxed);
                warn!("Kubernetes pod watch resource version expired; relisting");
            }
            Err(PodWatchError::Other(err)) => {
                controller
                    .telemetry
                    .watch_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, ?backoff, "Kubernetes pod watch failed; relisting");
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(WATCH_RETRY_MAX_BACKOFF);
            }
        }
    }
}

async fn run_poll_loop(
    controller: Arc<CaptureFilterController>,
    policy: CaptureFilterPolicy,
    cgroup_root: PathBuf,
    procfs_root: PathBuf,
) {
    let mut index = RawNodePodIndex::default();
    let mut pod_generation = 0_u64;
    let inspect_process_names = policy.requires_process_identity();

    loop {
        let observations = scan_cgroups(&cgroup_root, &procfs_root, inspect_process_names).await;
        let (next_generation, pods) = controller.raw_pods();
        if next_generation != pod_generation {
            index = RawNodePodIndex::from_pods(pods.iter().cloned(), CAPTURE_FILTER_MAP_CAPACITY);
            pod_generation = next_generation;
        }

        let desired =
            build_desired_filter_map(&observations, &index, &policy, CAPTURE_FILTER_MAP_CAPACITY);
        controller
            .telemetry
            .allowed_cgroups
            .store(desired.allowed_count() as u64, Ordering::Relaxed);
        controller
            .telemetry
            .denied_cgroups
            .store(desired.denied_count() as u64, Ordering::Relaxed);
        controller.telemetry.unresolved_cgroups.store(
            observations.len().saturating_sub(desired.len()) as u64,
            Ordering::Relaxed,
        );
        debug!(
            cgroups = observations.len(),
            pods = index.pod_count(),
            allowed = desired.allowed_count(),
            denied = desired.denied_count(),
            "capture filter refresh"
        );
        controller.publish(desired);

        tokio::time::sleep(SCAN_TICK).await;
    }
}

/// Walk the cgroup filesystem and derive an observation per container cgroup.
/// Runs on a blocking thread; returns an empty list on any failure.
async fn scan_cgroups(
    cgroup_root: &Path,
    procfs_root: &Path,
    inspect_process_names: bool,
) -> Vec<CgroupObservation> {
    let root = cgroup_root.to_path_buf();
    let procfs = procfs_root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        scan_cgroups_blocking(&root, &procfs, inspect_process_names)
    })
    .await
    .unwrap_or_default()
}

fn scan_cgroups_blocking(
    root: &Path,
    procfs_root: &Path,
    inspect_process_names: bool,
) -> Vec<CgroupObservation> {
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
                if inspect_process_names {
                    observation.process_names = process_names_for_cgroup(&path, procfs_root);
                }
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
use in_cluster::{apply_watch_line, parse_raw_pod_snapshot, parse_raw_pods};

#[cfg(target_os = "linux")]
mod apply;
#[cfg(target_os = "linux")]
pub(crate) use apply::{attach_capture_filter, seed_capture_filter_control};

#[cfg(test)]
mod tests;
