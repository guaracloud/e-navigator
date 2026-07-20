//! Turning the live node state into an eBPF filter-map delta.
//!
//! The pieces here are all pure (no I/O): the caller supplies the cgroups it
//! observed on the node ([`CgroupObservation`]) and the raw, *unscoped* node
//! pod list ([`RawNodePodIndex`]); this module resolves each cgroup to a pod,
//! evaluates the [`CaptureFilterPolicy`], and produces the desired
//! `{cgroup_id -> verdict}` map plus the minimal [`FilterMapDiff`] to apply on
//! top of what is already live ([`FilterMapMirror`]).
//!
//! Resolution prefers the **pod UID** carried in the cgroup path over the
//! container id: the UID is present in pod metadata the instant the pod is
//! created, whereas a container id only appears once the container's status is
//! populated. Preferring it shrinks the deny-posture bootstrap leak window.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{CaptureDecision, CaptureFilterPolicy};

/// Upper bound on live filter-map entries. Kept in lock-step with the eBPF
/// `CGROUP_CAPTURE_FILTER` map capacity; a node has far fewer container
/// cgroups than this, so the bound is a safety valve, not a normal limit.
pub const CAPTURE_FILTER_MAP_CAPACITY: usize = 8192;

/// A container cgroup observed on the node, tagged with whatever identifying
/// tokens its path yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupObservation {
    pub cgroup_id: u64,
    pub container_id: Option<String>,
    pub pod_uid: Option<String>,
    /// Bounded process names observed in this cgroup. Used only in userspace
    /// while computing the verdict; names never cross into an eBPF map.
    pub process_names: Vec<String>,
}

impl CgroupObservation {
    /// Derive an observation from a cgroup id and its filesystem path,
    /// extracting the pod UID and container id where present.
    pub fn from_cgroup_path(cgroup_id: u64, cgroup_path: &str) -> Self {
        Self {
            cgroup_id,
            container_id: parse_container_id_from_cgroup_path(cgroup_path),
            pod_uid: parse_pod_uid_from_cgroup_path(cgroup_path),
            process_names: Vec::new(),
        }
    }
}

/// One pod's filter-relevant identity, shared by all of its containers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PodIdentity {
    namespace: String,
    labels: BTreeMap<String, String>,
}

/// A raw pod from the node's pod list, *before* any attribution scoping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPod {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: Option<String>,
    pub node_name: Option<String>,
    pub pod_ip: Option<String>,
    pub workload_name: Option<String>,
    pub workload_type: Option<String>,
    pub container_ids: Vec<String>,
    pub container_names: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
}

/// A bounded Service identity published by the shared Kubernetes controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawService {
    pub namespace: String,
    pub service_name: String,
    pub service_uid: Option<String>,
    pub cluster_ips: Vec<String>,
}

/// Ready backend addresses for one Kubernetes Service, sourced from an
/// EndpointSlice. These are used only as a fallback when an address does not
/// already resolve to a Pod, so topology never overwrites a stronger workload
/// identity with a load-balancer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEndpointSlice {
    pub namespace: String,
    pub service_name: String,
    pub addresses: Vec<String>,
}

/// Index of the raw node pod list keyed by both pod UID and container id.
///
/// This is deliberately built from the *unscoped* node pod list: the capture
/// filter must be able to exclude a namespace even when
/// `[attribution.kubernetes]` scoping would have dropped it from the
/// enrichment cache.
#[derive(Debug, Default, Clone)]
pub struct RawNodePodIndex {
    by_pod_uid: BTreeMap<String, Arc<PodIdentity>>,
    by_container_id: BTreeMap<String, Arc<PodIdentity>>,
}

impl RawNodePodIndex {
    /// Build the index, bounding the number of retained pods.
    pub fn from_pods(pods: impl IntoIterator<Item = RawPod>, max_pods: usize) -> Self {
        let mut index = RawNodePodIndex::default();
        for pod in pods.into_iter().take(max_pods) {
            let identity = Arc::new(PodIdentity {
                namespace: pod.namespace,
                labels: pod.labels,
            });
            if let Some(uid) = pod.pod_uid {
                index
                    .by_pod_uid
                    .entry(uid)
                    .or_insert_with(|| identity.clone());
            }
            for container_id in pod.container_ids {
                index
                    .by_container_id
                    .entry(container_id)
                    .or_insert_with(|| identity.clone());
            }
        }
        index
    }

    pub fn pod_count(&self) -> usize {
        self.by_pod_uid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pod_uid.is_empty() && self.by_container_id.is_empty()
    }

    /// Resolve an observation to a pod identity, preferring the pod UID.
    fn resolve(&self, observation: &CgroupObservation) -> Option<&PodIdentity> {
        if let Some(uid) = observation.pod_uid.as_deref()
            && let Some(identity) = self.by_pod_uid.get(uid)
        {
            return Some(identity.as_ref());
        }
        if let Some(container_id) = observation.container_id.as_deref()
            && let Some(identity) = self.by_container_id.get(container_id)
        {
            return Some(identity.as_ref());
        }
        None
    }
}

/// The verdict for every cgroup that resolved to a pod. Cgroups that did not
/// resolve are intentionally absent, and the eBPF fast path applies the
/// configured unknown-cgroup posture to anything not in the map.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DesiredFilterMap {
    entries: BTreeMap<u64, CaptureDecision>,
}

impl DesiredFilterMap {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn allowed_count(&self) -> usize {
        self.entries
            .values()
            .filter(|decision| decision.captures())
            .count()
    }

    pub fn denied_count(&self) -> usize {
        self.entries
            .values()
            .filter(|decision| !decision.captures())
            .count()
    }

    pub fn get(&self, cgroup_id: u64) -> Option<CaptureDecision> {
        self.entries.get(&cgroup_id).copied()
    }

    /// The map as raw filter bytes (`1` capture, `0` drop).
    pub fn byte_entries(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.entries
            .iter()
            .map(|(&cgroup_id, decision)| (cgroup_id, decision.as_filter_byte()))
    }
}

/// Resolve every observation against the raw pod index and evaluate the
/// policy, producing the desired filter map. Bounded by `max_entries`.
pub fn build_desired_filter_map(
    observations: &[CgroupObservation],
    index: &RawNodePodIndex,
    policy: &CaptureFilterPolicy,
    max_entries: usize,
) -> DesiredFilterMap {
    let mut desired = DesiredFilterMap::default();
    if !policy.is_enabled() {
        return desired;
    }
    for observation in observations {
        if desired.entries.len() >= max_entries {
            break;
        }
        let Some(identity) = index.resolve(observation) else {
            continue;
        };
        let mut decision = policy.evaluate(&identity.namespace, &identity.labels);
        if decision.captures() {
            for process_name in &observation.process_names {
                decision = policy.evaluate_workload(
                    &identity.namespace,
                    &identity.labels,
                    Some(process_name),
                    None,
                );
                if !decision.captures() {
                    break;
                }
            }
        }
        desired.entries.insert(observation.cgroup_id, decision);
    }
    desired
}

/// The minimal set of map operations to move the live map to a desired state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilterMapDiff {
    /// `(cgroup_id, verdict_byte)` entries to insert or overwrite.
    pub upserts: Vec<(u64, u8)>,
    /// cgroup ids to delete (pods that exited).
    pub removals: Vec<u64>,
}

impl FilterMapDiff {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.removals.is_empty()
    }

    pub fn len(&self) -> usize {
        self.upserts.len() + self.removals.len()
    }
}

/// Userspace mirror of what is currently live in one eBPF filter map. Each
/// source keeps its own mirror because each loads its own eBPF object; the
/// expensive desired-state computation is shared, the cheap per-map apply is
/// not.
#[derive(Debug, Default, Clone)]
pub struct FilterMapMirror {
    current: BTreeMap<u64, u8>,
}

impl FilterMapMirror {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.current.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    pub fn get(&self, cgroup_id: u64) -> Option<u8> {
        self.current.get(&cgroup_id).copied()
    }

    /// Compute the diff from the live state to `desired` without mutating the
    /// mirror. The caller applies each operation to the real map and records
    /// the ones that succeeded via [`Self::record_upsert`] /
    /// [`Self::record_removal`], so a failed map write is retried next round.
    pub fn plan(&self, desired: &DesiredFilterMap) -> FilterMapDiff {
        let mut diff = FilterMapDiff::default();
        for (cgroup_id, byte) in desired.byte_entries() {
            if self.current.get(&cgroup_id) != Some(&byte) {
                diff.upserts.push((cgroup_id, byte));
            }
        }
        for &cgroup_id in self.current.keys() {
            if desired.get(cgroup_id).is_none() {
                diff.removals.push(cgroup_id);
            }
        }
        diff
    }

    pub fn record_upsert(&mut self, cgroup_id: u64, byte: u8) {
        self.current.insert(cgroup_id, byte);
    }

    pub fn record_removal(&mut self, cgroup_id: u64) {
        self.current.remove(&cgroup_id);
    }
}

/// Extract the first 64-hex-character container id from a cgroup path, mirroring
/// the runtime cgroup-id attribution parser.
pub fn parse_container_id_from_cgroup_path(cgroup_path: &str) -> Option<String> {
    let bytes = cgroup_path.as_bytes();
    let mut index = 0;
    while index + 64 <= bytes.len() {
        if bytes[index..index + 64]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        {
            // Require both boundaries so a sliding window cannot return the
            // last 64 digits of a longer hexadecimal identifier.
            let bounded_start = index == 0 || !bytes[index - 1].is_ascii_hexdigit();
            let bounded_end = index + 64 >= bytes.len() || !bytes[index + 64].is_ascii_hexdigit();
            if bounded_start && bounded_end {
                return Some(cgroup_path[index..index + 64].to_string());
            }
        }
        index += 1;
    }
    None
}

/// Extract and normalise a pod UID from a cgroup path.
///
/// Handles both the systemd driver
/// (`.../kubepods-besteffort-pod<uid_with_underscores>.slice/...`) and the
/// cgroupfs driver (`.../kubepods/besteffort/pod<uid-with-dashes>/...`). The
/// leading `kubepods` token is skipped because the matched `pod` must sit on a
/// `-`/`/` segment boundary. Underscores are normalised back to dashes.
pub fn parse_pod_uid_from_cgroup_path(cgroup_path: &str) -> Option<String> {
    let bytes = cgroup_path.as_bytes();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let on_boundary = index > 0 && (bytes[index - 1] == b'-' || bytes[index - 1] == b'/');
        if on_boundary && &bytes[index..index + 3] == b"pod" {
            let rest = &cgroup_path[index + 3..];
            let end = rest.find(['/', '.']).unwrap_or(rest.len());
            let candidate = normalize_pod_uid(&rest[..end]);
            if is_pod_uid_like(&candidate) {
                return Some(candidate);
            }
        }
        index += 1;
    }
    None
}

fn normalize_pod_uid(raw: &str) -> String {
    raw.replace('_', "-")
}

fn is_pod_uid_like(candidate: &str) -> bool {
    const MIN_LEN: usize = 8;
    const MAX_LEN: usize = 64;
    let len = candidate.len();
    (MIN_LEN..=MAX_LEN).contains(&len)
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        && candidate.bytes().any(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaptureFilterConfig;

    const CID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const UID: &str = "1234abcd-5678-90ab-cdef-1234567890ab";

    fn pod(namespace: &str, uid: &str, labels: &[(&str, &str)], cids: &[&str]) -> RawPod {
        RawPod {
            namespace: namespace.to_string(),
            pod_name: format!("{namespace}-pod"),
            pod_uid: Some(uid.to_string()),
            node_name: Some("node-a".to_string()),
            pod_ip: None,
            workload_name: Some(format!("{namespace}-workload")),
            workload_type: Some("Deployment".to_string()),
            container_ids: cids.iter().map(|c| c.to_string()).collect(),
            container_names: BTreeMap::new(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    fn enabled_policy(config: CaptureFilterConfig) -> CaptureFilterPolicy {
        CaptureFilterPolicy::from_config(&config)
    }

    // ----- cgroup path parsing -----

    #[test]
    fn parses_systemd_pod_uid_and_container_id() {
        let uid_underscored = UID.replace('-', "_");
        let path = format!(
            "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{uid_underscored}.slice/cri-containerd-{CID}.scope"
        );
        assert_eq!(parse_pod_uid_from_cgroup_path(&path).as_deref(), Some(UID));
        assert_eq!(
            parse_container_id_from_cgroup_path(&path).as_deref(),
            Some(CID)
        );
    }

    #[test]
    fn parses_cgroupfs_pod_uid_and_container_id() {
        let path = format!("/kubepods/besteffort/pod{UID}/{CID}");
        assert_eq!(parse_pod_uid_from_cgroup_path(&path).as_deref(), Some(UID));
        assert_eq!(
            parse_container_id_from_cgroup_path(&path).as_deref(),
            Some(CID)
        );
    }

    #[test]
    fn parses_guaranteed_qos_pod_uid() {
        let path = format!(
            "/kubepods.slice/kubepods-pod{}.slice/cri-containerd-{CID}.scope",
            UID.replace('-', "_")
        );
        assert_eq!(parse_pod_uid_from_cgroup_path(&path).as_deref(), Some(UID));
    }

    #[test]
    fn does_not_mistake_kubepods_prefix_for_a_pod_uid() {
        // No pod<uid> segment at all -> no uid.
        assert_eq!(
            parse_pod_uid_from_cgroup_path("/kubepods.slice/kubepods-besteffort.slice"),
            None
        );
    }

    #[test]
    fn host_process_cgroup_yields_no_identity() {
        let path = "/system.slice/sshd.service";
        assert_eq!(parse_pod_uid_from_cgroup_path(path), None);
        assert_eq!(parse_container_id_from_cgroup_path(path), None);
    }

    #[test]
    fn longer_hexadecimal_identifiers_are_not_truncated_into_container_ids() {
        let prefixed = format!("f{CID}");
        let suffixed = format!("{CID}f");

        assert_eq!(parse_container_id_from_cgroup_path(&prefixed), None);
        assert_eq!(parse_container_id_from_cgroup_path(&suffixed), None);
    }

    #[test]
    fn cgroup_path_parsers_never_panic_on_arbitrary_bytes() {
        let samples = [
            "",
            "pod",
            "/pod",
            "-pod",
            "/pod/",
            "podpodpod",
            "\u{1f600}pod\u{1f600}",
            "/kubepods-pod",
            "0000",
        ];
        for sample in samples {
            let _ = parse_pod_uid_from_cgroup_path(sample);
            let _ = parse_container_id_from_cgroup_path(sample);
        }
    }

    // ----- desired-map build -----

    #[test]
    fn builds_desired_map_via_pod_uid() {
        let config = CaptureFilterConfig {
            enabled: true,
            namespace_exclude: vec!["kube-system".to_string()],
            ..Default::default()
        };
        let policy = enabled_policy(config);
        let index = RawNodePodIndex::from_pods(
            vec![
                pod("payments", UID, &[], &[CID]),
                pod(
                    "kube-system",
                    "aaaa1111-2222-3333-4444-555566667777",
                    &[],
                    &["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
                ),
            ],
            1024,
        );
        let observations = vec![
            CgroupObservation {
                cgroup_id: 100,
                container_id: Some(CID.to_string()),
                pod_uid: Some(UID.to_string()),
                process_names: Vec::new(),
            },
            CgroupObservation {
                cgroup_id: 200,
                container_id: None,
                pod_uid: Some("aaaa1111-2222-3333-4444-555566667777".to_string()),
                process_names: Vec::new(),
            },
        ];
        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);
        assert_eq!(desired.get(100), Some(CaptureDecision::Capture));
        assert_eq!(desired.get(200), Some(CaptureDecision::Drop));
        assert_eq!(desired.allowed_count(), 1);
        assert_eq!(desired.denied_count(), 1);
    }

    #[test]
    fn unresolved_cgroup_is_omitted() {
        let policy = enabled_policy(CaptureFilterConfig {
            enabled: true,
            ..Default::default()
        });
        let index = RawNodePodIndex::from_pods(vec![pod("payments", UID, &[], &[CID])], 1024);
        let observations = vec![CgroupObservation {
            cgroup_id: 999,
            container_id: Some("deadbeef".to_string()),
            pod_uid: Some("no-such-uid-00000000".to_string()),
            process_names: Vec::new(),
        }];
        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);
        assert!(desired.is_empty());
    }

    #[test]
    fn disabled_policy_yields_empty_desired_map() {
        let policy = enabled_policy(CaptureFilterConfig::default());
        let index = RawNodePodIndex::from_pods(vec![pod("payments", UID, &[], &[CID])], 1024);
        let observations = vec![CgroupObservation {
            cgroup_id: 1,
            container_id: Some(CID.to_string()),
            pod_uid: Some(UID.to_string()),
            process_names: Vec::new(),
        }];
        assert!(build_desired_filter_map(&observations, &index, &policy, 8192).is_empty());
    }

    #[test]
    fn build_respects_max_entries() {
        let policy = enabled_policy(CaptureFilterConfig {
            enabled: true,
            ..Default::default()
        });
        let mut pods = Vec::new();
        let mut observations = Vec::new();
        for n in 0..10u64 {
            let uid = format!("uid-{n:04}-abcd");
            pods.push(pod("ns", &uid, &[], &[]));
            observations.push(CgroupObservation {
                cgroup_id: n,
                container_id: None,
                pod_uid: Some(uid),
                process_names: Vec::new(),
            });
        }
        let index = RawNodePodIndex::from_pods(pods, 1024);
        let desired = build_desired_filter_map(&observations, &index, &policy, 3);
        assert_eq!(desired.len(), 3);
    }

    // ----- diff / mirror -----

    #[test]
    fn plan_computes_upserts_and_removals() {
        let policy = enabled_policy(CaptureFilterConfig {
            enabled: true,
            namespace_exclude: vec!["kube-system".to_string()],
            ..Default::default()
        });
        let index = RawNodePodIndex::from_pods(
            vec![
                pod("payments", UID, &[], &[]),
                pod(
                    "kube-system",
                    "bbbb1111-2222-3333-4444-555566667777",
                    &[],
                    &[],
                ),
            ],
            1024,
        );
        let observations = vec![
            CgroupObservation {
                cgroup_id: 100,
                container_id: None,
                pod_uid: Some(UID.to_string()),
                process_names: Vec::new(),
            },
            CgroupObservation {
                cgroup_id: 200,
                container_id: None,
                pod_uid: Some("bbbb1111-2222-3333-4444-555566667777".to_string()),
                process_names: Vec::new(),
            },
        ];
        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);

        let mut mirror = FilterMapMirror::new();
        // Pretend a stale entry from an exited pod is still live.
        mirror.record_upsert(777, 1);

        let diff = mirror.plan(&desired);
        assert!(diff.upserts.contains(&(100, 1)));
        assert!(diff.upserts.contains(&(200, 0)));
        assert_eq!(diff.removals, vec![777]);

        // Apply the diff and confirm convergence -> next plan is empty.
        for (cgroup_id, byte) in &diff.upserts {
            mirror.record_upsert(*cgroup_id, *byte);
        }
        for cgroup_id in &diff.removals {
            mirror.record_removal(*cgroup_id);
        }
        assert!(mirror.plan(&desired).is_empty());
    }

    #[test]
    fn plan_detects_verdict_flip() {
        let mut mirror = FilterMapMirror::new();
        mirror.record_upsert(100, 1); // previously captured

        let policy = enabled_policy(CaptureFilterConfig {
            enabled: true,
            namespace_exclude: vec!["payments".to_string()],
            ..Default::default()
        });
        let index = RawNodePodIndex::from_pods(vec![pod("payments", UID, &[], &[])], 1024);
        let observations = vec![CgroupObservation {
            cgroup_id: 100,
            container_id: None,
            pod_uid: Some(UID.to_string()),
            process_names: Vec::new(),
        }];
        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);

        let diff = mirror.plan(&desired);
        assert_eq!(diff.upserts, vec![(100, 0)]); // flipped to drop
        assert!(diff.removals.is_empty());
    }

    #[test]
    fn desired_map_carries_only_cgroup_ids_and_verdict_bytes() {
        // Privacy invariant: namespaces and labels are matched in userspace,
        // but only cgroup ids and a 0/1 verdict byte may cross into the kernel.
        // Nothing the resolver hands to the eBPF map should carry a namespace
        // or label string.
        let config = CaptureFilterConfig {
            enabled: true,
            namespace_exclude: vec!["top-secret-namespace".to_string()],
            label_exclude: [("classification".to_string(), "restricted".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let policy = enabled_policy(config);
        let index = RawNodePodIndex::from_pods(
            vec![RawPod {
                namespace: "top-secret-namespace".to_string(),
                pod_name: "secret-pod".to_string(),
                pod_uid: Some(UID.to_string()),
                node_name: Some("node-a".to_string()),
                pod_ip: None,
                workload_name: Some("secret-workload".to_string()),
                workload_type: Some("Deployment".to_string()),
                container_ids: vec![CID.to_string()],
                container_names: BTreeMap::new(),
                labels: [("classification".to_string(), "restricted".to_string())]
                    .into_iter()
                    .collect(),
            }],
            1024,
        );
        let observations = vec![CgroupObservation {
            cgroup_id: 42,
            container_id: Some(CID.to_string()),
            pod_uid: Some(UID.to_string()),
            process_names: Vec::new(),
        }];
        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);

        // The map that reaches the kernel is (u64 cgroup id -> u8 verdict) only.
        let byte_entries: Vec<(u64, u8)> = desired.byte_entries().collect();
        assert_eq!(byte_entries, vec![(42, 0)]);

        // No representation of the desired map can leak the sensitive strings.
        let rendered = format!("{desired:?}");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("classification"));
        assert!(!rendered.contains("restricted"));
    }

    #[test]
    fn process_exclusion_changes_the_source_side_cgroup_verdict() {
        let policy = enabled_policy(CaptureFilterConfig {
            enabled: true,
            namespace_include: vec!["proj-*".to_string()],
            process_exclude: vec!["*-exporter".to_string()],
            ..Default::default()
        });
        let index = RawNodePodIndex::from_pods(vec![pod("proj-payments", UID, &[], &[CID])], 1024);
        let observations = vec![CgroupObservation {
            cgroup_id: 77,
            container_id: Some(CID.to_string()),
            pod_uid: Some(UID.to_string()),
            process_names: vec!["postgres-exporter".to_string()],
        }];

        let desired = build_desired_filter_map(&observations, &index, &policy, 8192);

        assert_eq!(desired.get(77), Some(CaptureDecision::Drop));
    }
}
