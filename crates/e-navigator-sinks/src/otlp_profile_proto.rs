use crate::{ExporterError, OtelProfileRecord, otlp_common::key_values, otlp_common::to_any_value};
use collector_profile_proto::{
    ExportProfilesServiceRequest, Function, KeyValueAndUnit, Line, Link, Location, Mapping,
    Profile, ProfilesDictionary, ResourceProfiles, Sample, ScopeProfiles, Stack, ValueType,
};
use opentelemetry_proto::tonic::{common::v1::InstrumentationScope, resource::v1::Resource};
use prost::Message;
use std::collections::BTreeMap;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325_u64;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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
        type_strindex: dictionary.string_index("samples"),
        unit_strindex: dictionary.string_index("count"),
    });
    let stack_index = dictionary.stack_index(&record.stack_frames);
    let attribute_indices = dictionary.attribute_indices(&record.attributes);
    let duration_nano = if record.duration_nanos == 0 {
        record.sampling_period_nanos.unwrap_or(1)
    } else {
        record.duration_nanos
    };

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
        duration_nano,
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
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::profile_id_bytes;

    #[test]
    fn profile_id_bytes_are_stable_and_otel_sized() {
        assert_eq!(
            profile_id_bytes("profile:abc"),
            vec![
                0xbc, 0xd2, 0x5d, 0x07, 0x0a, 0x7b, 0x77, 0xd4, 0x87, 0x4d, 0x5c, 0x71, 0xd8, 0x01,
                0x58, 0xde,
            ]
        );
    }

    #[test]
    fn profile_id_bytes_distinguish_profile_ids() {
        let left = profile_id_bytes("profile-sample:d41180ea1f8882c9");
        let right = profile_id_bytes("profile-sample:31690a3ed8baedf5");

        assert_eq!(left.len(), 16);
        assert_eq!(right.len(), 16);
        assert_ne!(left, right);
    }
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
        let location_indices = frames
            .iter()
            .map(|frame| self.location_index(frame))
            .collect();
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

pub(crate) mod collector_profile_proto {
    use opentelemetry_proto::tonic::{
        common::v1::{AnyValue, InstrumentationScope},
        resource::v1::Resource,
    };
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct ExportProfilesServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub(crate) resource_profiles: Vec<ResourceProfiles>,
        #[prost(message, optional, tag = "2")]
        pub(crate) dictionary: Option<ProfilesDictionary>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct ProfilesDictionary {
        #[prost(message, repeated, tag = "1")]
        pub(crate) mapping_table: Vec<Mapping>,
        #[prost(message, repeated, tag = "2")]
        pub(crate) location_table: Vec<Location>,
        #[prost(message, repeated, tag = "3")]
        pub(crate) function_table: Vec<Function>,
        #[prost(message, repeated, tag = "4")]
        pub(crate) link_table: Vec<Link>,
        #[prost(string, repeated, tag = "5")]
        pub(crate) string_table: Vec<String>,
        #[prost(message, repeated, tag = "6")]
        pub(crate) attribute_table: Vec<KeyValueAndUnit>,
        #[prost(message, repeated, tag = "7")]
        pub(crate) stack_table: Vec<Stack>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct ResourceProfiles {
        #[prost(message, optional, tag = "1")]
        pub(crate) resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub(crate) scope_profiles: Vec<ScopeProfiles>,
        #[prost(string, tag = "3")]
        pub(crate) schema_url: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct ScopeProfiles {
        #[prost(message, optional, tag = "1")]
        pub(crate) scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub(crate) profiles: Vec<Profile>,
        #[prost(string, tag = "3")]
        pub(crate) schema_url: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Profile {
        #[prost(message, optional, tag = "1")]
        pub(crate) sample_type: Option<ValueType>,
        #[prost(message, repeated, tag = "2")]
        pub(crate) samples: Vec<Sample>,
        #[prost(fixed64, tag = "3")]
        pub(crate) time_unix_nano: u64,
        #[prost(uint64, tag = "4")]
        pub(crate) duration_nano: u64,
        #[prost(message, optional, tag = "5")]
        pub(crate) period_type: Option<ValueType>,
        #[prost(int64, tag = "6")]
        pub(crate) period: i64,
        #[prost(bytes = "vec", tag = "7")]
        pub(crate) profile_id: Vec<u8>,
        #[prost(uint32, tag = "8")]
        pub(crate) dropped_attributes_count: u32,
        #[prost(string, tag = "9")]
        pub(crate) original_payload_format: String,
        #[prost(bytes = "vec", tag = "10")]
        pub(crate) original_payload: Vec<u8>,
        #[prost(int32, repeated, packed = "true", tag = "11")]
        pub(crate) attribute_indices: Vec<i32>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct KeyValueAndUnit {
        #[prost(int32, tag = "1")]
        pub(crate) key_strindex: i32,
        #[prost(message, optional, tag = "2")]
        pub(crate) value: Option<AnyValue>,
        #[prost(int32, tag = "3")]
        pub(crate) unit_strindex: i32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Link {
        #[prost(bytes = "vec", tag = "1")]
        pub(crate) trace_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        pub(crate) span_id: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct ValueType {
        #[prost(int32, tag = "1")]
        pub(crate) type_strindex: i32,
        #[prost(int32, tag = "2")]
        pub(crate) unit_strindex: i32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Sample {
        #[prost(int32, tag = "1")]
        pub(crate) stack_index: i32,
        #[prost(int32, repeated, packed = "true", tag = "2")]
        pub(crate) attribute_indices: Vec<i32>,
        #[prost(int32, tag = "3")]
        pub(crate) link_index: i32,
        #[prost(int64, repeated, packed = "true", tag = "4")]
        pub(crate) values: Vec<i64>,
        #[prost(fixed64, repeated, packed = "true", tag = "5")]
        pub(crate) timestamps_unix_nano: Vec<u64>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Mapping {
        #[prost(uint64, tag = "1")]
        pub(crate) memory_start: u64,
        #[prost(uint64, tag = "2")]
        pub(crate) memory_limit: u64,
        #[prost(uint64, tag = "3")]
        pub(crate) file_offset: u64,
        #[prost(int32, tag = "4")]
        pub(crate) filename_strindex: i32,
        #[prost(int32, repeated, packed = "true", tag = "5")]
        pub(crate) attribute_indices: Vec<i32>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Stack {
        #[prost(int32, repeated, packed = "true", tag = "1")]
        pub(crate) location_indices: Vec<i32>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Location {
        #[prost(int32, tag = "1")]
        pub(crate) mapping_index: i32,
        #[prost(uint64, tag = "2")]
        pub(crate) address: u64,
        #[prost(message, repeated, tag = "3")]
        pub(crate) lines: Vec<Line>,
        #[prost(int32, repeated, packed = "true", tag = "4")]
        pub(crate) attribute_indices: Vec<i32>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Line {
        #[prost(int32, tag = "1")]
        pub(crate) function_index: i32,
        #[prost(int64, tag = "2")]
        pub(crate) line: i64,
        #[prost(int64, tag = "3")]
        pub(crate) column: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(crate) struct Function {
        #[prost(int32, tag = "1")]
        pub(crate) name_strindex: i32,
        #[prost(int32, tag = "2")]
        pub(crate) system_name_strindex: i32,
        #[prost(int32, tag = "3")]
        pub(crate) filename_strindex: i32,
        #[prost(int64, tag = "4")]
        pub(crate) start_line: i64,
    }
}
