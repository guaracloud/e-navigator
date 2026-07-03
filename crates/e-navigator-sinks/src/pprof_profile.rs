use e_navigator_signals::{
    ProfileSampleObservation, ProfilingAttribute, SignalEnvelope, SignalPayload,
};
use prost::Message;
use std::collections::BTreeMap;

const MAX_ATTRIBUTES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_LABEL_VALUE_BYTES: usize = 256;
const MAX_PPROF_STACK_FRAMES: usize = 256;
const MAX_FRAME_STRING_BYTES: usize = 256;

pub fn format_pprof_profile(signal: &SignalEnvelope) -> Option<Vec<u8>> {
    let SignalPayload::ProfileSampleObservation(sample) = &signal.payload else {
        return None;
    };
    if sample.stack_frames.is_empty() {
        return None;
    }

    let mut table = StringTable::default();
    let profile_kind = profile_kind_name(sample.profiling_kind);
    let unit = "nanoseconds";
    let sample_type = ValueType {
        r#type: table.index(profile_kind),
        unit: table.index(unit),
    };
    let location = locations(sample);
    let function = functions(sample, &mut table);
    let period_nanos = sample.sampling_period_nanos.unwrap_or(1);
    let sample_value = sample.sample_count.saturating_mul(period_nanos);
    let pprof_sample = Sample {
        location_id: location.iter().map(|location| location.id).collect(),
        value: vec![u64_to_i64_saturating(sample_value)],
        label: labels(signal, sample, &mut table),
    };
    let period_type = Some(ValueType {
        r#type: table.index(profile_kind),
        unit: table.index(unit),
    });
    let string_table = table.finish();

    let profile = Profile {
        sample_type: vec![sample_type],
        sample: vec![pprof_sample],
        mapping: Vec::new(),
        location,
        function,
        string_table,
        drop_frames: 0,
        keep_frames: 0,
        time_nanos: u64_to_i64_saturating(sample.timestamp_unix_nanos),
        duration_nanos: 0,
        period_type,
        period: u64_to_i64_saturating(period_nanos),
        comment: Vec::new(),
        default_sample_type: 0,
    };

    let mut bytes = Vec::with_capacity(profile.encoded_len());
    profile.encode(&mut bytes).ok()?;
    Some(bytes)
}

fn locations(sample: &ProfileSampleObservation) -> Vec<Location> {
    sample
        .stack_frames
        .iter()
        .take(MAX_PPROF_STACK_FRAMES)
        .enumerate()
        .map(|(index, frame)| Location {
            id: u64::try_from(index + 1).unwrap_or(u64::MAX),
            mapping_id: 0,
            address: 0,
            line: vec![Line {
                function_id: u64::try_from(index + 1).unwrap_or(u64::MAX),
                line: frame.line.map(i64::from).unwrap_or_default(),
            }],
            is_folded: false,
        })
        .collect()
}

fn functions(sample: &ProfileSampleObservation, table: &mut StringTable) -> Vec<Function> {
    sample
        .stack_frames
        .iter()
        .take(MAX_PPROF_STACK_FRAMES)
        .enumerate()
        .map(|(index, frame)| {
            let name = truncate_utf8(
                frame.symbol.as_deref().unwrap_or("unknown"),
                MAX_FRAME_STRING_BYTES,
            );
            let filename = frame
                .file
                .as_deref()
                .map(|file| truncate_utf8(file, MAX_FRAME_STRING_BYTES))
                .unwrap_or_default();
            Function {
                id: u64::try_from(index + 1).unwrap_or(u64::MAX),
                name: table.index(&name),
                system_name: table.index(&name),
                filename: table.index(&filename),
                start_line: 0,
            }
        })
        .collect()
}

fn labels(
    signal: &SignalEnvelope,
    sample: &ProfileSampleObservation,
    table: &mut StringTable,
) -> Vec<Label> {
    let mut labels = BTreeMap::new();
    if let Some(host) = &signal.host {
        insert_label(&mut labels, "host.name", host);
    }
    insert_label(&mut labels, "profile.stack.id", &sample.stack_id);
    if let Some(thread_id) = sample.thread_id {
        insert_label(&mut labels, "thread.id", &thread_id.to_string());
    }
    if let Some(thread_name) = &sample.thread_name {
        insert_label(&mut labels, "thread.name", thread_name);
    }
    if let Some(process) = &sample.process {
        insert_label(&mut labels, "process.pid", &process.pid.to_string());
        insert_label(&mut labels, "process.command", &process.command);
    }
    if let Some(container) = &sample.container {
        insert_label(&mut labels, "container.id", &container.container_id);
        if let Some(runtime) = &container.runtime {
            insert_label(&mut labels, "container.runtime", runtime);
        }
    }
    if let Some(kubernetes) = &sample.kubernetes {
        insert_label(&mut labels, "k8s.namespace.name", &kubernetes.namespace);
        insert_label(&mut labels, "k8s.pod.name", &kubernetes.pod_name);
        if let Some(pod_uid) = &kubernetes.pod_uid {
            insert_label(&mut labels, "k8s.pod.uid", pod_uid);
        }
        if let Some(container_name) = &kubernetes.container_name {
            insert_label(&mut labels, "k8s.container.name", container_name);
        }
        if let Some(node_name) = &kubernetes.node_name {
            insert_label(&mut labels, "k8s.node.name", node_name);
        }
        let service_name = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .cloned()
            .unwrap_or_else(|| kubernetes.pod_name.clone());
        insert_label(&mut labels, "service.name", &service_name);
    }
    for attribute in bounded_attributes(&sample.attributes) {
        labels.insert(
            attribute.key,
            truncate_utf8(&attribute.value, MAX_LABEL_VALUE_BYTES),
        );
    }

    labels
        .into_iter()
        .map(|(key, value)| Label {
            key: table.index(&key),
            str: table.index(&value),
            num: 0,
            num_unit: 0,
        })
        .collect()
}

fn insert_label(labels: &mut BTreeMap<String, String>, key: &'static str, value: &str) {
    labels.insert(key.to_string(), truncate_utf8(value, MAX_LABEL_VALUE_BYTES));
}

fn bounded_attributes(attributes: &[ProfilingAttribute]) -> Vec<ProfilingAttribute> {
    attributes
        .iter()
        .take(MAX_ATTRIBUTES)
        .filter(|attribute| !should_drop_attribute(&attribute.key))
        .map(|attribute| ProfilingAttribute {
            key: truncate_utf8(&attribute.key, MAX_KEY_BYTES),
            value: truncate_utf8(&attribute.value, MAX_ATTRIBUTE_VALUE_BYTES),
        })
        .collect()
}

fn should_drop_attribute(key: &str) -> bool {
    const CANONICAL_FIELDS: &[&str] = &[
        "profile_id",
        "profile_kind",
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

fn profile_kind_name(kind: e_navigator_signals::ProfilingKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => "cpu",
        e_navigator_signals::ProfilingKind::Memory => "memory",
        e_navigator_signals::ProfilingKind::Lock => "lock",
        e_navigator_signals::ProfilingKind::Unknown => "unknown",
        _ => "unknown",
    }
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

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[derive(Default)]
struct StringTable {
    values: Vec<String>,
    indices: BTreeMap<String, i64>,
}

impl StringTable {
    fn index(&mut self, value: &str) -> i64 {
        if value.is_empty() {
            return 0;
        }
        if self.values.is_empty() {
            self.values.push(String::new());
        }
        if let Some(index) = self.indices.get(value) {
            return *index;
        }
        let index = i64::try_from(self.values.len()).unwrap_or(i64::MAX);
        self.values.push(value.to_string());
        self.indices.insert(value.to_string(), index);
        index
    }

    fn finish(mut self) -> Vec<String> {
        if self.values.is_empty() {
            self.values.push(String::new());
        }
        self.values
    }
}

#[derive(Clone, PartialEq, Message)]
struct Profile {
    #[prost(message, repeated, tag = "1")]
    sample_type: Vec<ValueType>,
    #[prost(message, repeated, tag = "2")]
    sample: Vec<Sample>,
    #[prost(message, repeated, tag = "3")]
    mapping: Vec<Mapping>,
    #[prost(message, repeated, tag = "4")]
    location: Vec<Location>,
    #[prost(message, repeated, tag = "5")]
    function: Vec<Function>,
    #[prost(string, repeated, tag = "6")]
    string_table: Vec<String>,
    #[prost(int64, tag = "7")]
    drop_frames: i64,
    #[prost(int64, tag = "8")]
    keep_frames: i64,
    #[prost(int64, tag = "9")]
    time_nanos: i64,
    #[prost(int64, tag = "10")]
    duration_nanos: i64,
    #[prost(message, optional, tag = "11")]
    period_type: Option<ValueType>,
    #[prost(int64, tag = "12")]
    period: i64,
    #[prost(int64, repeated, tag = "13")]
    comment: Vec<i64>,
    #[prost(int64, tag = "14")]
    default_sample_type: i64,
}

#[derive(Clone, PartialEq, Message)]
struct ValueType {
    #[prost(int64, tag = "1")]
    r#type: i64,
    #[prost(int64, tag = "2")]
    unit: i64,
}

#[derive(Clone, PartialEq, Message)]
struct Sample {
    #[prost(uint64, repeated, tag = "1")]
    location_id: Vec<u64>,
    #[prost(int64, repeated, tag = "2")]
    value: Vec<i64>,
    #[prost(message, repeated, tag = "3")]
    label: Vec<Label>,
}

#[derive(Clone, PartialEq, Message)]
struct Label {
    #[prost(int64, tag = "1")]
    key: i64,
    #[prost(int64, tag = "2")]
    str: i64,
    #[prost(int64, tag = "3")]
    num: i64,
    #[prost(int64, tag = "4")]
    num_unit: i64,
}

#[derive(Clone, PartialEq, Message)]
struct Mapping {
    #[prost(uint64, tag = "1")]
    id: u64,
}

#[derive(Clone, PartialEq, Message)]
struct Location {
    #[prost(uint64, tag = "1")]
    id: u64,
    #[prost(uint64, tag = "2")]
    mapping_id: u64,
    #[prost(uint64, tag = "3")]
    address: u64,
    #[prost(message, repeated, tag = "4")]
    line: Vec<Line>,
    #[prost(bool, tag = "5")]
    is_folded: bool,
}

#[derive(Clone, PartialEq, Message)]
struct Line {
    #[prost(uint64, tag = "1")]
    function_id: u64,
    #[prost(int64, tag = "2")]
    line: i64,
}

#[derive(Clone, PartialEq, Message)]
struct Function {
    #[prost(uint64, tag = "1")]
    id: u64,
    #[prost(int64, tag = "2")]
    name: i64,
    #[prost(int64, tag = "3")]
    system_name: i64,
    #[prost(int64, tag = "4")]
    filename: i64,
    #[prost(int64, tag = "5")]
    start_line: i64,
}
