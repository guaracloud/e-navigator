use e_navigator_signals::{
    ProfileSampleObservation, ProfilingAttribute, ProfilingSessionObservation, SignalEnvelope,
    SignalPayload,
};
use serde::Serialize;
use std::collections::BTreeMap;

const PROFILE_SCHEMA: &str = "e-navigator.profile.internal.v1";
pub const E_NAVIGATOR_CPU_PROFILE_METRIC_NAME: &str = "process.cpu.time";
const MAX_ATTRIBUTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325_u64;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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
        profile_id: truncate_utf8(&observation.profile_id, MAX_VALUE_BYTES),
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
    let profile_id = sample_profile_id(signal, observation);

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
        stack_id: Some(truncate_utf8(&observation.stack_id, MAX_VALUE_BYTES)),
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
        insert_resource_string(&mut resource, "host.name", host);
    }
    if let Some(process) = process {
        resource.insert("process.pid".to_string(), process.pid.to_string());
        insert_resource_string(&mut resource, "process.command", &process.command);
    }
    if let Some(container) = container {
        insert_resource_string(&mut resource, "container.id", &container.container_id);
        if let Some(runtime) = &container.runtime {
            insert_resource_string(&mut resource, "container.runtime", runtime);
        }
    }
    if let Some(kubernetes) = kubernetes {
        insert_resource_string(&mut resource, "k8s.namespace.name", &kubernetes.namespace);
        insert_resource_string(&mut resource, "namespace", &kubernetes.namespace);
        insert_resource_string(&mut resource, "k8s.pod.name", &kubernetes.pod_name);
        insert_resource_string(&mut resource, "pod", &kubernetes.pod_name);
        if let Some(container_name) = &kubernetes.container_name {
            insert_resource_string(&mut resource, "k8s.container.name", container_name);
            insert_resource_string(&mut resource, "container", container_name);
        }
        if let Some(pod_uid) = &kubernetes.pod_uid {
            insert_resource_string(&mut resource, "k8s.pod.uid", pod_uid);
        }
        if let Some(node_name) = &kubernetes.node_name {
            insert_resource_string(&mut resource, "k8s.node.name", node_name);
            insert_resource_string(&mut resource, "node", node_name);
        }
        let service_name = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .cloned()
            .unwrap_or_else(|| kubernetes.pod_name.clone());
        insert_resource_string(&mut resource, "service_name", &service_name);
        insert_resource_string(&mut resource, "source", "e-navigator");
    }
    resource
}

fn insert_resource_string(resource: &mut BTreeMap<String, String>, key: &'static str, value: &str) {
    resource.insert(key.to_string(), truncate_utf8(value, MAX_VALUE_BYTES));
}

fn profile_metric_name(kind: e_navigator_signals::ProfilingKind) -> Option<String> {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => {
            Some(E_NAVIGATOR_CPU_PROFILE_METRIC_NAME.to_string())
        }
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

fn sample_profile_id(signal: &SignalEnvelope, observation: &ProfileSampleObservation) -> String {
    let hash = profile_sample_hash(
        signal,
        observation.timestamp_unix_nanos,
        observation.process.as_ref(),
        observation.container.as_ref(),
        observation.kubernetes.as_ref(),
        &observation.stack_id,
    );
    format!("profile-sample:{hash:016x}")
}

fn profile_sample_hash(
    signal: &SignalEnvelope,
    timestamp_unix_nanos: u64,
    process: Option<&e_navigator_signals::NetworkProcessIdentity>,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
    stack_id: &str,
) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash_str(&mut hash, &signal.source);
    hash_separator(&mut hash);
    hash_decimal(&mut hash, timestamp_unix_nanos);
    hash_separator(&mut hash);
    hash_str(&mut hash, signal.host.as_deref().unwrap_or(""));
    hash_separator(&mut hash);
    if let Some(process) = process {
        hash_decimal(&mut hash, u64::from(process.pid));
    }
    hash_separator(&mut hash);
    if let Some(uid) = process.and_then(|process| process.uid) {
        hash_decimal(&mut hash, u64::from(uid));
    }
    hash_separator(&mut hash);
    hash_str(
        &mut hash,
        container
            .map(|container| container.container_id.as_str())
            .unwrap_or(""),
    );
    hash_separator(&mut hash);
    hash_str(
        &mut hash,
        kubernetes
            .and_then(|kubernetes| kubernetes.pod_uid.as_deref())
            .unwrap_or(""),
    );
    hash_separator(&mut hash);
    hash_str(
        &mut hash,
        kubernetes
            .and_then(|kubernetes| kubernetes.container_name.as_deref())
            .unwrap_or(""),
    );
    hash_separator(&mut hash);
    hash_str(&mut hash, stack_id);
    hash
}

fn should_drop_attribute(key: &str) -> bool {
    if key.is_empty() {
        return true;
    }

    const CANONICAL_FIELDS: &[&str] = &[
        "schema",
        "profile_id",
        "profile_kind",
        "correlation_kind",
        "confidence",
        "sample_count",
        "stack_id",
        "frame_count",
    ];
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "token",
        "authorization",
        "cookie",
        "password",
        "secret",
        "api_key",
        "apikey",
        "x-api-key",
        "credential",
        "private_key",
        "jwt",
    ];

    CANONICAL_FIELDS
        .iter()
        .any(|field| key.eq_ignore_ascii_case(field))
        || SENSITIVE_FRAGMENTS
            .iter()
            .any(|fragment| contains_ascii_case_insensitive(key, fragment))
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

fn hash_str(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        hash_byte(hash, *byte);
    }
}

fn hash_decimal(hash: &mut u64, value: u64) {
    let mut buffer = [0_u8; 20];
    let mut index = buffer.len();
    let mut remaining = value;
    loop {
        index -= 1;
        buffer[index] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    for byte in &buffer[index..] {
        hash_byte(hash, *byte);
    }
}

fn hash_separator(hash: &mut u64) {
    hash_byte(hash, b'|');
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(FNV_PRIME);
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
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
