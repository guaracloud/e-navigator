use crate::{ExporterError, OtelProfileRecord, otlp_common::key_values, otlp_common::to_any_value};
use opentelemetry_proto::tonic::{
    collector::profiles::v1development::ExportProfilesServiceRequest,
    common::v1::InstrumentationScope,
    profiles::v1development::{
        Function, KeyValueAndUnit, Line, Link, Location, Mapping, Profile, ProfilesDictionary,
        ResourceProfiles, Sample, ScopeProfiles, Stack, ValueType,
    },
    resource::v1::Resource,
};
use prost::Message;
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

pub(crate) fn encode_profile_export_request(
    records: &[OtelProfileRecord],
) -> Result<Vec<u8>, ExporterError> {
    let mut dictionary = ProfileDictionaryBuilder::new();
    let resource_profiles = records
        .iter()
        .map(|record| resource_profiles_from_record(record, &mut dictionary))
        .collect();
    let request = ExportProfilesServiceRequest {
        resource_profiles,
        dictionary: Some(dictionary.finish()),
    };
    let mut bytes = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut bytes)
        .map_err(|err| ExporterError::Encode(err.to_string()))?;
    Ok(bytes)
}

fn resource_profiles_from_record(
    record: &OtelProfileRecord,
    dictionary: &mut ProfileDictionaryBuilder,
) -> ResourceProfiles {
    ResourceProfiles {
        resource: Some(Resource {
            attributes: key_values(&record.resource),
            dropped_attributes_count: 0,
            entity_refs: Vec::new(),
        }),
        scope_profiles: vec![ScopeProfiles {
            scope: Some(InstrumentationScope {
                name: "e-navigator".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                attributes: Vec::new(),
                dropped_attributes_count: 0,
            }),
            profiles: vec![profile_from_record(record, dictionary)],
            schema_url: String::new(),
        }],
        schema_url: String::new(),
    }
}

fn profile_from_record(
    record: &OtelProfileRecord,
    dictionary: &mut ProfileDictionaryBuilder,
) -> Profile {
    let sample_type = Some(ValueType {
        type_strindex: dictionary.string_index(&record.profile_kind),
        unit_strindex: dictionary.string_index("nanoseconds"),
    });
    let stack_index = dictionary.stack_index(&record.stack_frames);
    let attribute_indices = dictionary.attribute_indices(&record.attributes);

    Profile {
        sample_type,
        samples: vec![Sample {
            stack_index,
            attribute_indices: attribute_indices.clone(),
            link_index: 0,
            values: vec![u64_to_i64_saturating(record.sample_count)],
            timestamps_unix_nano: vec![record.timestamp_unix_nanos],
        }],
        time_unix_nano: record.timestamp_unix_nanos,
        duration_nano: record.duration_nanos,
        period_type: Some(ValueType {
            type_strindex: dictionary.string_index(&record.profile_kind),
            unit_strindex: dictionary.string_index("nanoseconds"),
        }),
        period: record
            .sampling_period_nanos
            .map(u64_to_i64_saturating)
            .unwrap_or_default(),
        profile_id: profile_id_bytes(&record.profile_id),
        dropped_attributes_count: 0,
        original_payload_format: String::new(),
        original_payload: Vec::new(),
        attribute_indices,
    }
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn profile_id_bytes(profile_id: &str) -> Vec<u8> {
    let first = stable_hash64(profile_id.as_bytes());
    let second = stable_hash64(format!("otel-profile:{profile_id}").as_bytes());
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&first.to_be_bytes());
    bytes.extend_from_slice(&second.to_be_bytes());
    bytes
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug)]
struct ProfileDictionaryBuilder {
    mapping_table: Vec<Mapping>,
    location_table: Vec<Location>,
    function_table: Vec<Function>,
    link_table: Vec<Link>,
    string_table: Vec<String>,
    string_indices: BTreeMap<String, i32>,
    attribute_table: Vec<KeyValueAndUnit>,
    stack_table: Vec<Stack>,
}

impl ProfileDictionaryBuilder {
    fn new() -> Self {
        Self {
            mapping_table: vec![Mapping::default()],
            location_table: vec![Location::default()],
            function_table: vec![Function::default()],
            link_table: vec![Link::default()],
            string_table: vec![String::new()],
            string_indices: BTreeMap::new(),
            attribute_table: vec![KeyValueAndUnit::default()],
            stack_table: vec![Stack::default()],
        }
    }

    fn finish(self) -> ProfilesDictionary {
        ProfilesDictionary {
            mapping_table: self.mapping_table,
            location_table: self.location_table,
            function_table: self.function_table,
            link_table: self.link_table,
            string_table: self.string_table,
            attribute_table: self.attribute_table,
            stack_table: self.stack_table,
        }
    }

    fn string_index(&mut self, value: &str) -> i32 {
        if value.is_empty() {
            return 0;
        }
        if let Some(index) = self.string_indices.get(value) {
            return *index;
        }
        let index = i32::try_from(self.string_table.len()).unwrap_or(i32::MAX);
        self.string_table.push(value.to_string());
        self.string_indices.insert(value.to_string(), index);
        index
    }

    fn stack_index(&mut self, frames: &[crate::OtelProfileFrame]) -> i32 {
        if frames.is_empty() {
            return 0;
        }
        let location_indices = frames
            .iter()
            .map(|frame| self.location_index(frame))
            .collect::<Vec<_>>();
        let index = i32::try_from(self.stack_table.len()).unwrap_or(i32::MAX);
        self.stack_table.push(Stack { location_indices });
        index
    }

    fn location_index(&mut self, frame: &crate::OtelProfileFrame) -> i32 {
        let function_index = self.function_index(frame);
        let attribute_indices = frame
            .module
            .as_ref()
            .map(|module| {
                self.attribute_indices(&BTreeMap::from([(
                    "code.module".to_string(),
                    serde_json::json!(module),
                )]))
            })
            .unwrap_or_default();
        let index = i32::try_from(self.location_table.len()).unwrap_or(i32::MAX);
        self.location_table.push(Location {
            mapping_index: 0,
            address: 0,
            lines: vec![Line {
                function_index,
                line: frame.line.map(i64::from).unwrap_or_default(),
                column: 0,
            }],
            attribute_indices,
        });
        index
    }

    fn function_index(&mut self, frame: &crate::OtelProfileFrame) -> i32 {
        let name_index = frame
            .symbol
            .as_deref()
            .map(|symbol| self.string_index(symbol))
            .unwrap_or_default();
        let filename_index = frame
            .file
            .as_deref()
            .map(|file| self.string_index(file))
            .unwrap_or_default();
        let index = i32::try_from(self.function_table.len()).unwrap_or(i32::MAX);
        self.function_table.push(Function {
            name_strindex: name_index,
            system_name_strindex: name_index,
            filename_strindex: filename_index,
            start_line: frame.line.map(i64::from).unwrap_or_default(),
        });
        index
    }

    fn attribute_indices(&mut self, attributes: &BTreeMap<String, serde_json::Value>) -> Vec<i32> {
        attributes
            .iter()
            .map(|(key, value)| {
                let index = i32::try_from(self.attribute_table.len()).unwrap_or(i32::MAX);
                let key_strindex = self.string_index(key);
                self.attribute_table.push(KeyValueAndUnit {
                    key_strindex,
                    value: Some(to_any_value(value)),
                    unit_strindex: 0,
                });
                index
            })
            .collect()
    }
}
