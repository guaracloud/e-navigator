use e_navigator_signals::{
    NetworkProcessIdentity, ProfileSampleObservation, ProfilingAttribute,
    ProfilingSessionObservation, SignalEnvelope, SignalPayload,
};
use std::collections::BTreeMap;

const MAX_ATTRIBUTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325_u64;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelProfileRecord {
    pub profile_id: String,
    pub profile_kind: String,
    pub sample_count: u64,
    pub dropped_sample_count: u64,
    pub timestamp_unix_nanos: u64,
    pub duration_nanos: u64,
    pub sampling_period_nanos: Option<u64>,
    pub resource: BTreeMap<String, serde_json::Value>,
    pub attributes: BTreeMap<String, serde_json::Value>,
    pub stack_frames: Vec<OtelProfileFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelProfileFrame {
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

pub fn format_otel_profile_record(signal: &SignalEnvelope) -> Option<OtelProfileRecord> {
    match &signal.payload {
        SignalPayload::ProfileSampleObservation(sample) => Some(sample_record(signal, sample)),
        SignalPayload::ProfilingSessionObservation(session) => {
            Some(session_record(signal, session))
        }
        _ => None,
    }
}

fn sample_record(signal: &SignalEnvelope, sample: &ProfileSampleObservation) -> OtelProfileRecord {
    let profile_id = sample_profile_id(signal, sample);
    let mut attributes = bounded_attributes(&sample.attributes);
    attributes.insert(
        "profile.stack.id".to_string(),
        serde_json::json!(sample.stack_id),
    );
    if let Some(thread_id) = sample.thread_id {
        attributes.insert("thread.id".to_string(), serde_json::json!(thread_id));
    }
    if let Some(thread_name) = &sample.thread_name {
        attributes.insert("thread.name".to_string(), serde_json::json!(thread_name));
    }

    OtelProfileRecord {
        profile_id,
        profile_kind: profiling_kind_name(sample.profiling_kind).to_string(),
        sample_count: sample.sample_count,
        dropped_sample_count: 0,
        timestamp_unix_nanos: sample.timestamp_unix_nanos,
        duration_nanos: 0,
        sampling_period_nanos: sample.sampling_period_nanos,
        resource: resource_attributes(
            signal,
            sample.process.as_ref(),
            sample.container.as_ref(),
            sample.kubernetes.as_ref(),
        ),
        attributes,
        stack_frames: sample
            .stack_frames
            .iter()
            .map(|frame| OtelProfileFrame {
                symbol: frame.symbol.clone(),
                module: frame.module.clone(),
                file: frame.file.clone(),
                line: frame.line,
            })
            .collect(),
    }
}

fn sample_profile_id(signal: &SignalEnvelope, sample: &ProfileSampleObservation) -> String {
    let hash = profile_sample_hash(
        signal,
        sample.timestamp_unix_nanos,
        sample.process.as_ref(),
        sample.container.as_ref(),
        sample.kubernetes.as_ref(),
        &sample.stack_id,
    );
    format!("profile-sample:{hash:016x}")
}

fn profile_sample_hash(
    signal: &SignalEnvelope,
    timestamp_unix_nanos: u64,
    process: Option<&NetworkProcessIdentity>,
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

fn session_record(
    signal: &SignalEnvelope,
    session: &ProfilingSessionObservation,
) -> OtelProfileRecord {
    let mut attributes = bounded_attributes(&session.attributes);
    attributes.insert(
        "profile.distinct_stack_count".to_string(),
        serde_json::json!(session.distinct_stack_count),
    );
    attributes.insert(
        "profile.dropped_sample_count".to_string(),
        serde_json::json!(session.dropped_sample_count),
    );
    attributes.insert(
        "profile.source".to_string(),
        serde_json::json!(session.source),
    );

    OtelProfileRecord {
        profile_id: session.profile_id.clone(),
        profile_kind: profiling_kind_name(session.profiling_kind).to_string(),
        sample_count: session.observed_sample_count,
        dropped_sample_count: session.dropped_sample_count,
        timestamp_unix_nanos: session.window.end_unix_nanos,
        duration_nanos: session
            .window
            .end_unix_nanos
            .saturating_sub(session.window.start_unix_nanos),
        sampling_period_nanos: session.sampling_period_nanos,
        resource: resource_attributes(
            signal,
            session.process.as_ref(),
            session.container.as_ref(),
            session.kubernetes.as_ref(),
        ),
        attributes,
        stack_frames: Vec::new(),
    }
}

fn resource_attributes(
    signal: &SignalEnvelope,
    process: Option<&NetworkProcessIdentity>,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = BTreeMap::new();
    if let Some(host) = &signal.host {
        resource.insert("host.name".to_string(), serde_json::json!(host));
    }
    if let Some(process) = process {
        resource.insert("process.pid".to_string(), serde_json::json!(process.pid));
        resource.insert(
            "process.command".to_string(),
            serde_json::json!(process.command),
        );
    }
    if let Some(container) = container {
        resource.insert(
            "container.id".to_string(),
            serde_json::json!(container.container_id),
        );
        if let Some(runtime) = &container.runtime {
            resource.insert("container.runtime".to_string(), serde_json::json!(runtime));
        }
    }
    if let Some(kubernetes) = kubernetes {
        resource.insert(
            "k8s.namespace.name".to_string(),
            serde_json::json!(kubernetes.namespace),
        );
        resource.insert(
            "namespace".to_string(),
            serde_json::json!(kubernetes.namespace),
        );
        resource.insert(
            "k8s.pod.name".to_string(),
            serde_json::json!(kubernetes.pod_name),
        );
        resource.insert("pod".to_string(), serde_json::json!(kubernetes.pod_name));
        if let Some(container_name) = &kubernetes.container_name {
            resource.insert(
                "k8s.container.name".to_string(),
                serde_json::json!(container_name),
            );
            resource.insert("container".to_string(), serde_json::json!(container_name));
        }
        if let Some(pod_uid) = &kubernetes.pod_uid {
            resource.insert("k8s.pod.uid".to_string(), serde_json::json!(pod_uid));
        }
        if let Some(node_name) = &kubernetes.node_name {
            resource.insert("k8s.node.name".to_string(), serde_json::json!(node_name));
            resource.insert("node".to_string(), serde_json::json!(node_name));
        }
        let service_name = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .cloned()
            .unwrap_or_else(|| kubernetes.pod_name.clone());
        resource.insert("service.name".to_string(), serde_json::json!(service_name));
        resource.insert("service_name".to_string(), serde_json::json!(service_name));
        resource.insert("source".to_string(), serde_json::json!("e-navigator"));
    }
    resource
}

fn bounded_attributes(attributes: &[ProfilingAttribute]) -> BTreeMap<String, serde_json::Value> {
    let mut mapped = BTreeMap::new();
    for attribute in attributes.iter().take(MAX_ATTRIBUTES) {
        if should_drop_attribute(&attribute.key) {
            continue;
        }
        mapped.insert(
            truncate_utf8(&attribute.key, MAX_KEY_BYTES),
            serde_json::json!(truncate_utf8(&attribute.value, MAX_VALUE_BYTES)),
        );
    }
    mapped
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

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
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
