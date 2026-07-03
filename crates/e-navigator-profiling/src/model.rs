use e_navigator_signals::{
    ContainerContext, KubernetesContext, NetworkProcessIdentity, ProfileSampleObservation,
    ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingFrame,
    ProfilingKind, is_sensitive_profiling_attribute_key,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationLimits {
    pub max_frames_per_stack: usize,
    pub max_symbol_bytes: usize,
    pub max_module_bytes: usize,
    pub max_file_bytes: usize,
    pub max_attributes: usize,
    pub max_attribute_key_bytes: usize,
    pub max_attribute_value_bytes: usize,
    pub max_samples_per_window: u64,
    pub max_fixture_bytes: usize,
}

impl Default for NormalizationLimits {
    fn default() -> Self {
        Self {
            max_frames_per_stack: 64,
            max_symbol_bytes: 256,
            max_module_bytes: 256,
            max_file_bytes: 256,
            max_attributes: 16,
            max_attribute_key_bytes: 64,
            max_attribute_value_bytes: 256,
            max_samples_per_window: 65_536,
            max_fixture_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawProfileFrame {
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawProfileSample {
    pub timestamp_unix_nanos: u64,
    pub profiling_kind: ProfilingKind,
    pub correlation_kind: ProfilingCorrelationKind,
    pub confidence: ProfilingConfidence,
    pub sample_count: u64,
    pub sampling_period_nanos: Option<u64>,
    pub stack_frames: Vec<RawProfileFrame>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub thread_id: Option<u64>,
    pub thread_name: Option<String>,
    #[serde(default)]
    pub attributes: Vec<ProfilingAttribute>,
}

impl RawProfileSample {
    pub fn normalize(
        self,
        limits: &NormalizationLimits,
    ) -> Result<ProfileSampleObservation, String> {
        if self.sample_count == 0 {
            return Err("sample_count must be greater than zero".to_string());
        }
        if limits.max_frames_per_stack == 0 {
            return Err("max_frames_per_stack must be greater than zero".to_string());
        }
        if limits.max_samples_per_window == 0 {
            return Err("max_samples_per_window must be greater than zero".to_string());
        }

        let frames_were_truncated = self.stack_frames.len() > limits.max_frames_per_stack;
        let mut attributes = normalize_attributes(
            self.attributes,
            limits.max_attributes,
            limits.max_attribute_key_bytes,
            limits.max_attribute_value_bytes,
        );
        let stack_frames = self
            .stack_frames
            .into_iter()
            .take(limits.max_frames_per_stack)
            .map(|frame| normalize_frame(frame, limits))
            .collect::<Vec<_>>();

        if frames_were_truncated && limits.max_attributes > 0 {
            let marker = ProfilingAttribute {
                key: "profiling.stack.truncated".to_string(),
                value: "true".to_string(),
            };
            if attributes.len() >= limits.max_attributes {
                attributes.pop();
            }
            attributes.push(marker);
            attributes.sort();
        }

        Ok(ProfileSampleObservation {
            timestamp_unix_nanos: self.timestamp_unix_nanos,
            profiling_kind: self.profiling_kind,
            correlation_kind: self.correlation_kind,
            confidence: self.confidence,
            sample_count: self.sample_count.min(limits.max_samples_per_window),
            sampling_period_nanos: self.sampling_period_nanos,
            stack_id: deterministic_stack_id(&stack_frames),
            stack_frames,
            process: self.process,
            container: self.container,
            kubernetes: self.kubernetes,
            thread_id: self.thread_id,
            thread_name: self.thread_name.map(|name| truncate_utf8(&name, 64)),
            attributes,
        })
    }
}

pub fn parse_profile_fixture(
    contents: &str,
    limits: &NormalizationLimits,
) -> Result<ProfileSampleObservation, String> {
    if contents.len() > limits.max_fixture_bytes {
        return Err(format!(
            "profile fixture exceeds {} bytes",
            limits.max_fixture_bytes
        ));
    }
    let value =
        serde_json::from_str::<serde_json::Value>(contents).map_err(|err| err.to_string())?;
    if value.get("sample_count").is_none() {
        return Err("sample_count is required".to_string());
    }
    let max_fixture_frames = limits.max_frames_per_stack.saturating_mul(16);
    if let Some(stack_frames) = value.get("stack_frames").and_then(|value| value.as_array())
        && stack_frames.len() > max_fixture_frames
    {
        return Err(format!(
            "stack_frames exceeds fixture preflight limit {}",
            max_fixture_frames
        ));
    }
    let max_fixture_attributes = limits.max_attributes.saturating_mul(16);
    if let Some(attributes) = value.get("attributes").and_then(|value| value.as_array())
        && attributes.len() > max_fixture_attributes
    {
        return Err(format!(
            "attributes exceeds fixture preflight limit {}",
            max_fixture_attributes
        ));
    }
    serde_json::from_value::<RawProfileSample>(value)
        .map_err(|err| err.to_string())?
        .normalize(limits)
}

fn normalize_frame(frame: RawProfileFrame, limits: &NormalizationLimits) -> ProfilingFrame {
    ProfilingFrame {
        symbol: frame
            .symbol
            .map(|value| truncate_utf8(&value, limits.max_symbol_bytes)),
        module: frame
            .module
            .map(|value| truncate_utf8(&value, limits.max_module_bytes)),
        file: frame
            .file
            .map(|value| truncate_utf8(&value, limits.max_file_bytes)),
        line: frame.line,
    }
}

fn normalize_attributes(
    attributes: Vec<ProfilingAttribute>,
    max_attributes: usize,
    max_key_bytes: usize,
    max_value_bytes: usize,
) -> Vec<ProfilingAttribute> {
    let mut attributes = attributes
        .into_iter()
        .filter(|attribute| {
            !attribute.key.is_empty()
                && !is_sensitive_profiling_attribute_key(&attribute.key)
                && !is_reserved_profile_attribute_key(&attribute.key)
        })
        .map(|attribute| ProfilingAttribute {
            key: truncate_utf8(&attribute.key, max_key_bytes),
            value: truncate_utf8(&attribute.value, max_value_bytes),
        })
        .collect::<Vec<_>>();
    attributes.sort();
    attributes.dedup_by(|left, right| left.key == right.key);
    attributes.truncate(max_attributes);
    attributes
}

fn is_reserved_profile_attribute_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "schema"
            | "profile_id"
            | "profile_kind"
            | "correlation_kind"
            | "confidence"
            | "sample_count"
            | "stack_id"
            | "frame_count"
            | "profiling.stack.truncated"
    )
}

fn deterministic_stack_id(frames: &[ProfilingFrame]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for frame in frames {
        hash_optional(&mut hash, frame.symbol.as_deref());
        hash_bytes(&mut hash, "\x1f");
        hash_optional(&mut hash, frame.module.as_deref());
        hash_bytes(&mut hash, "\x1f");
        hash_optional(&mut hash, frame.file.as_deref());
        hash_bytes(&mut hash, "\x1f");
        if let Some(line) = frame.line {
            hash_bytes(&mut hash, &line.to_string());
        }
        hash_bytes(&mut hash, "\x1e");
    }
    format!("stack:{hash:016x}")
}

fn hash_optional(hash: &mut u64, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_bytes(hash, "some:");
            hash_bytes(hash, value);
        }
        None => hash_bytes(hash, "none"),
    }
}

fn hash_bytes(hash: &mut u64, value: &str) {
    for byte in value.as_bytes() {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x100000001b3);
    }
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
