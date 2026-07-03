use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_OTLP_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_OTLP_STRING_VALUE_BYTES: usize = 256;

pub(crate) fn key_values(attributes: &BTreeMap<String, Value>) -> Vec<KeyValue> {
    attributes
        .iter()
        .map(|(key, value)| KeyValue {
            key: bounded_attribute_key(key),
            value: Some(to_any_value(value)),
            key_strindex: 0,
        })
        .collect()
}

pub(crate) fn to_any_value(value: &Value) -> AnyValue {
    let value = match value {
        Value::Bool(value) => any_value::Value::BoolValue(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                any_value::Value::IntValue(value)
            } else if let Some(value) = value.as_u64() {
                match i64::try_from(value) {
                    Ok(value) => any_value::Value::IntValue(value),
                    Err(_) => any_value::Value::StringValue(bounded_string(&value.to_string())),
                }
            } else {
                any_value::Value::DoubleValue(value.as_f64().unwrap_or_default())
            }
        }
        Value::String(value) => any_value::Value::StringValue(bounded_string(value)),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            any_value::Value::StringValue(bounded_string(&value.to_string()))
        }
    };
    AnyValue { value: Some(value) }
}

fn bounded_attribute_key(value: &str) -> String {
    truncate_utf8(value, MAX_OTLP_ATTRIBUTE_KEY_BYTES)
}

fn bounded_string(value: &str) -> String {
    truncate_utf8(value, MAX_OTLP_STRING_VALUE_BYTES)
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

#[cfg(test)]
mod tests {
    use opentelemetry_proto::tonic::common::v1::any_value;

    use super::*;

    #[test]
    fn bounds_attribute_keys() {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "k".repeat(MAX_OTLP_ATTRIBUTE_KEY_BYTES + 64),
            serde_json::json!("value"),
        );

        let values = key_values(&attributes);

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].key, "k".repeat(MAX_OTLP_ATTRIBUTE_KEY_BYTES));
    }

    #[test]
    fn bounds_attribute_keys_at_utf8_boundary() {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "é".repeat(MAX_OTLP_ATTRIBUTE_KEY_BYTES),
            serde_json::json!("value"),
        );

        let values = key_values(&attributes);

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].key.len(), MAX_OTLP_ATTRIBUTE_KEY_BYTES);
        assert!(values[0].key.is_char_boundary(values[0].key.len()));
    }

    #[test]
    fn bounds_string_values() {
        let value = to_any_value(&serde_json::json!(
            "v".repeat(MAX_OTLP_STRING_VALUE_BYTES + 64)
        ));

        assert_eq!(
            value.value,
            Some(any_value::Value::StringValue(
                "v".repeat(MAX_OTLP_STRING_VALUE_BYTES)
            ))
        );
    }

    #[test]
    fn bounds_stringified_json_values() {
        let value = to_any_value(&serde_json::json!({
            "value": "v".repeat(MAX_OTLP_STRING_VALUE_BYTES + 64)
        }));
        let Some(any_value::Value::StringValue(value)) = value.value else {
            panic!("object converts to string value");
        };

        assert_eq!(value.len(), MAX_OTLP_STRING_VALUE_BYTES);
    }
}
