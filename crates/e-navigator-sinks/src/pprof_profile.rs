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

/// Renders a single profile sample observation into a pprof profile.
pub fn format_pprof_profile(signal: &SignalEnvelope) -> Option<Vec<u8>> {
    format_pprof_profile_batch(std::slice::from_ref(&signal))
}

/// Folds many profile sample observations into one pprof profile, sharing a
/// single string table, deduplicated module mappings, functions, and
/// locations. Locations carry the module-relative address and mapping id so
/// the output is symbolizable offline even when local symbol names are
/// absent. Non-sample signals and empty stacks are skipped.
pub fn format_pprof_profile_batch(signals: &[&SignalEnvelope]) -> Option<Vec<u8>> {
    let mut builder = PprofBuilder::default();
    let mut any = false;
    for signal in signals {
        let SignalPayload::ProfileSampleObservation(sample) = &signal.payload else {
            continue;
        };
        if sample.stack_frames.is_empty() {
            continue;
        }
        builder.add_sample(signal, sample);
        any = true;
    }
    if !any {
        return None;
    }

    let profile = builder.finish();
    let mut bytes = Vec::with_capacity(profile.encoded_len());
    profile.encode(&mut bytes).ok()?;
    Some(bytes)
}

#[derive(Default)]
struct PprofBuilder {
    table: StringTable,
    mappings: Vec<Mapping>,
    mapping_ids: BTreeMap<String, u64>,
    functions: Vec<Function>,
    function_ids: BTreeMap<String, u64>,
    locations: Vec<Location>,
    location_ids: BTreeMap<(u64, u64, u64), u64>,
    samples: Vec<Sample>,
    profile_kind: Option<&'static str>,
    period_nanos: u64,
    time_nanos: u64,
}

impl PprofBuilder {
    fn add_sample(&mut self, signal: &SignalEnvelope, sample: &ProfileSampleObservation) {
        if self.profile_kind.is_none() {
            self.profile_kind = Some(profile_kind_name(sample.profiling_kind));
        }
        let period = sample.sampling_period_nanos.unwrap_or(1);
        if self.period_nanos == 0 {
            self.period_nanos = period;
        }
        self.time_nanos = self.time_nanos.max(sample.timestamp_unix_nanos);

        let location_ids = sample
            .stack_frames
            .iter()
            .take(MAX_PPROF_STACK_FRAMES)
            .map(|frame| self.location_id(frame))
            .collect::<Vec<_>>();
        let value = sample.sample_count.saturating_mul(period);
        let label = self.labels(signal, sample);
        self.samples.push(Sample {
            location_id: location_ids,
            value: vec![u64_to_i64_saturating(value)],
            label,
        });
    }

    fn location_id(&mut self, frame: &e_navigator_signals::ProfilingFrame) -> u64 {
        let mapping_id = frame
            .module
            .as_deref()
            .map(|module| self.mapping_id(module))
            .unwrap_or(0);
        let address = frame.module_offset.unwrap_or(0);
        let name = truncate_utf8(
            frame.symbol.as_deref().unwrap_or("unknown"),
            MAX_FRAME_STRING_BYTES,
        );
        let filename = frame
            .file
            .as_deref()
            .map(|file| truncate_utf8(file, MAX_FRAME_STRING_BYTES))
            .unwrap_or_default();
        let function_id = self.function_id(&name, &filename);

        let key = (mapping_id, address, function_id);
        if let Some(id) = self.location_ids.get(&key) {
            return *id;
        }
        let id = u64::try_from(self.locations.len() + 1).unwrap_or(u64::MAX);
        self.locations.push(Location {
            id,
            mapping_id,
            address,
            line: vec![Line {
                function_id,
                line: frame.line.map(i64::from).unwrap_or_default(),
            }],
            is_folded: false,
        });
        self.location_ids.insert(key, id);
        id
    }

    fn mapping_id(&mut self, module: &str) -> u64 {
        if let Some(id) = self.mapping_ids.get(module) {
            return *id;
        }
        let id = u64::try_from(self.mappings.len() + 1).unwrap_or(u64::MAX);
        let filename = self
            .table
            .index(&truncate_utf8(module, MAX_FRAME_STRING_BYTES));
        self.mappings.push(Mapping {
            id,
            memory_start: 0,
            memory_limit: 0,
            file_offset: 0,
            filename,
            build_id: 0,
            has_functions: true,
            has_filenames: false,
            has_line_numbers: false,
            has_inline_frames: false,
        });
        self.mapping_ids.insert(module.to_string(), id);
        id
    }

    fn function_id(&mut self, name: &str, filename: &str) -> u64 {
        if let Some(id) = self.function_ids.get(name) {
            return *id;
        }
        let id = u64::try_from(self.functions.len() + 1).unwrap_or(u64::MAX);
        self.functions.push(Function {
            id,
            name: self.table.index(name),
            system_name: self.table.index(name),
            filename: self.table.index(filename),
            start_line: 0,
        });
        self.function_ids.insert(name.to_string(), id);
        id
    }

    fn labels(&mut self, signal: &SignalEnvelope, sample: &ProfileSampleObservation) -> Vec<Label> {
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
            labels
                .entry(attribute.key)
                .or_insert_with(|| truncate_utf8(&attribute.value, MAX_LABEL_VALUE_BYTES));
        }

        labels
            .into_iter()
            .map(|(key, value)| Label {
                key: self.table.index(&key),
                str: self.table.index(&value),
                num: 0,
                num_unit: 0,
            })
            .collect()
    }

    fn finish(mut self) -> Profile {
        let profile_kind = self.profile_kind.unwrap_or("unknown");
        let unit = "nanoseconds";
        let kind_index = self.table.index(profile_kind);
        let unit_index = self.table.index(unit);
        let period = self.period_nanos.max(1);
        Profile {
            sample_type: vec![ValueType {
                r#type: kind_index,
                unit: unit_index,
            }],
            sample: self.samples,
            mapping: self.mappings,
            location: self.locations,
            function: self.functions,
            string_table: self.table.finish(),
            drop_frames: 0,
            keep_frames: 0,
            time_nanos: u64_to_i64_saturating(self.time_nanos),
            duration_nanos: 0,
            period_type: Some(ValueType {
                r#type: kind_index,
                unit: unit_index,
            }),
            period: u64_to_i64_saturating(period),
            comment: Vec::new(),
            default_sample_type: 0,
        }
    }
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

    CANONICAL_FIELDS
        .iter()
        .any(|field| key.eq_ignore_ascii_case(field))
        || e_navigator_signals::is_sensitive_profiling_attribute_key(key)
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
    #[prost(uint64, tag = "2")]
    memory_start: u64,
    #[prost(uint64, tag = "3")]
    memory_limit: u64,
    #[prost(uint64, tag = "4")]
    file_offset: u64,
    #[prost(int64, tag = "5")]
    filename: i64,
    #[prost(int64, tag = "6")]
    build_id: i64,
    #[prost(bool, tag = "7")]
    has_functions: bool,
    #[prost(bool, tag = "8")]
    has_filenames: bool,
    #[prost(bool, tag = "9")]
    has_line_numbers: bool,
    #[prost(bool, tag = "10")]
    has_inline_frames: bool,
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
