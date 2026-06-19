use e_navigator_signals::{
    ProfileSampleObservation, ProfilingAttribute, ProfilingSessionObservation, SignalEnvelope,
    SignalPayload,
};
use serde::Serialize;
use std::collections::BTreeMap;

const PROFILE_SCHEMA: &str = "e-navigator.profile.internal.v1";
pub const PYROSCOPE_CPU_PROFILE_IDENTITY: &str = "process_cpu:cpu:nanoseconds:cpu:nanoseconds";
const MAX_ATTRIBUTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRecord {
    pub schema: String,
    pub profile_id: String,
    pub profile_metric_name: Option<String>,
    pub profile_kind: String,
    pub correlation_kind: String,
    pub confidence: String,
    pub sample_count: u64,
    pub dropped_sample_count: u64,
    pub distinct_stack_count: Option<u64>,
    pub stack_id: Option<String>,
    pub frame_count: Option<u64>,
    pub sampling_period_nanos: Option<u64>,
    pub window: Option<e_navigator_signals::MetricAggregationWindow>,
    pub resource: BTreeMap<String, String>,
    pub attributes: BTreeMap<String, String>,
}

pub fn format_profile_record(signal: &SignalEnvelope) -> Option<ProfileRecord> {
    match &signal.payload {
        SignalPayload::ProfilingSessionObservation(observation) => {
            Some(session_record(signal, observation))
        }
        SignalPayload::ProfileSampleObservation(observation) => {
            Some(sample_record(signal, observation))
        }
        _ => None,
    }
}

fn session_record(
    signal: &SignalEnvelope,
    observation: &ProfilingSessionObservation,
) -> ProfileRecord {
    ProfileRecord {
        schema: PROFILE_SCHEMA.to_string(),
        profile_id: observation.profile_id.clone(),
        profile_metric_name: profile_metric_name(observation.profiling_kind),
        profile_kind: profiling_kind_name(observation.profiling_kind).to_string(),
        correlation_kind: correlation_kind_name(observation.correlation_kind).to_string(),
        confidence: confidence_name(observation.confidence).to_string(),
        sample_count: observation.observed_sample_count,
        dropped_sample_count: observation.dropped_sample_count,
        distinct_stack_count: Some(observation.distinct_stack_count),
        stack_id: None,
        frame_count: None,
        sampling_period_nanos: observation.sampling_period_nanos,
        window: Some(observation.window.clone()),
        resource: resource_attributes(
            signal,
            observation.process.as_ref(),
            observation.container.as_ref(),
            observation.kubernetes.as_ref(),
        ),
        attributes: bounded_attributes(&observation.attributes),
    }
}

fn sample_record(signal: &SignalEnvelope, observation: &ProfileSampleObservation) -> ProfileRecord {
    let profile_id = format!(
        "profile-sample:{:016x}",
        stable_hash64(
            format!(
                "{}|{}|{}|{}",
                signal.source,
                observation.timestamp_unix_nanos,
                profile_identity(
                    signal,
                    observation.process.as_ref(),
                    observation.container.as_ref(),
                    observation.kubernetes.as_ref(),
                ),
                observation.stack_id
            )
            .as_bytes(),
        )
    );

    ProfileRecord {
        schema: PROFILE_SCHEMA.to_string(),
        profile_id,
        profile_metric_name: profile_metric_name(observation.profiling_kind),
        profile_kind: profiling_kind_name(observation.profiling_kind).to_string(),
        correlation_kind: correlation_kind_name(observation.correlation_kind).to_string(),
        confidence: confidence_name(observation.confidence).to_string(),
        sample_count: observation.sample_count,
        dropped_sample_count: 0,
        distinct_stack_count: None,
        stack_id: Some(observation.stack_id.clone()),
        frame_count: Some(observation.stack_frames.len() as u64),
        sampling_period_nanos: observation.sampling_period_nanos,
        window: None,
        resource: resource_attributes(
            signal,
            observation.process.as_ref(),
            observation.container.as_ref(),
            observation.kubernetes.as_ref(),
        ),
        attributes: bounded_attributes(&observation.attributes),
    }
}

fn resource_attributes(
    signal: &SignalEnvelope,
    process: Option<&e_navigator_signals::NetworkProcessIdentity>,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
) -> BTreeMap<String, String> {
    let mut resource = BTreeMap::new();
    if let Some(host) = &signal.host {
        resource.insert("host.name".to_string(), host.clone());
    }
    if let Some(process) = process {
        resource.insert("process.pid".to_string(), process.pid.to_string());
        resource.insert("process.command".to_string(), process.command.clone());
    }
    if let Some(container) = container {
        resource.insert("container.id".to_string(), container.container_id.clone());
        if let Some(runtime) = &container.runtime {
            resource.insert("container.runtime".to_string(), runtime.clone());
        }
    }
    if let Some(kubernetes) = kubernetes {
        resource.insert(
            "k8s.namespace.name".to_string(),
            kubernetes.namespace.clone(),
        );
        resource.insert("namespace".to_string(), kubernetes.namespace.clone());
        resource.insert("k8s.pod.name".to_string(), kubernetes.pod_name.clone());
        resource.insert("pod".to_string(), kubernetes.pod_name.clone());
        if let Some(container_name) = &kubernetes.container_name {
            resource.insert("k8s.container.name".to_string(), container_name.clone());
            resource.insert("container".to_string(), container_name.clone());
        }
        if let Some(pod_uid) = &kubernetes.pod_uid {
            resource.insert("k8s.pod.uid".to_string(), pod_uid.clone());
        }
        if let Some(node_name) = &kubernetes.node_name {
            resource.insert("k8s.node.name".to_string(), node_name.clone());
            resource.insert("node".to_string(), node_name.clone());
        }
        resource.insert(
            "service_name".to_string(),
            kubernetes
                .labels
                .get("app.kubernetes.io/name")
                .or_else(|| kubernetes.labels.get("app"))
                .cloned()
                .unwrap_or_else(|| kubernetes.pod_name.clone()),
        );
        resource.insert(
            "catalog_slug".to_string(),
            kubernetes
                .labels
                .get("guara.cloud/catalog-slug")
                .cloned()
                .unwrap_or_default(),
        );
        resource.insert("source".to_string(), "e-navigator".to_string());
    }
    resource
}

fn profile_metric_name(kind: e_navigator_signals::ProfilingKind) -> Option<String> {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => Some(PYROSCOPE_CPU_PROFILE_IDENTITY.to_string()),
        _ => None,
    }
}

fn bounded_attributes(attributes: &[ProfilingAttribute]) -> BTreeMap<String, String> {
    let mut mapped = BTreeMap::new();
    for attribute in attributes.iter().take(MAX_ATTRIBUTES) {
        if should_drop_attribute(&attribute.key) {
            continue;
        }
        mapped.insert(
            truncate_utf8(&attribute.key, MAX_KEY_BYTES),
            truncate_utf8(&attribute.value, MAX_VALUE_BYTES),
        );
    }
    mapped
}

fn profile_identity(
    signal: &SignalEnvelope,
    process: Option<&e_navigator_signals::NetworkProcessIdentity>,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        signal.host.as_deref().unwrap_or(""),
        process
            .map(|process| process.pid.to_string())
            .unwrap_or_default(),
        process
            .and_then(|process| process.uid)
            .map(|uid| uid.to_string())
            .unwrap_or_default(),
        container
            .map(|container| container.container_id.as_str())
            .unwrap_or(""),
        kubernetes
            .and_then(|kubernetes| kubernetes.pod_uid.as_deref())
            .unwrap_or(""),
        kubernetes
            .and_then(|kubernetes| kubernetes.container_name.as_deref())
            .unwrap_or("")
    )
}

fn should_drop_attribute(key: &str) -> bool {
    let canonical_key = key.to_ascii_lowercase();
    matches!(
        canonical_key.as_str(),
        "schema"
            | "profile_id"
            | "profile_kind"
            | "correlation_kind"
            | "confidence"
            | "sample_count"
            | "stack_id"
            | "frame_count"
    ) || e_navigator_signals::is_sensitive_profiling_attribute_key(key)
}

fn profiling_kind_name(kind: e_navigator_signals::ProfilingKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => "cpu",
        e_navigator_signals::ProfilingKind::Memory => "memory",
        e_navigator_signals::ProfilingKind::Lock => "lock",
        e_navigator_signals::ProfilingKind::Unknown => "unknown",
        _ => "unknown",
    }
}

fn correlation_kind_name(kind: e_navigator_signals::ProfilingCorrelationKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample => {
            "observed_profile_sample"
        }
        e_navigator_signals::ProfilingCorrelationKind::Synthetic => "synthetic",
        e_navigator_signals::ProfilingCorrelationKind::RuntimeInferred => "runtime_inferred",
        _ => "unknown",
    }
}

fn confidence_name(kind: e_navigator_signals::ProfilingConfidence) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingConfidence::Low => "low",
        e_navigator_signals::ProfilingConfidence::Medium => "medium",
        e_navigator_signals::ProfilingConfidence::High => "high",
        _ => "unknown",
    }
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
