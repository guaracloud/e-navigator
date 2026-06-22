use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn key_values(attributes: &BTreeMap<String, Value>) -> Vec<KeyValue> {
    attributes
        .iter()
        .map(|(key, value)| KeyValue {
            key: key.clone(),
            value: Some(to_any_value(value)),
            key_strindex: 0,
        })
        .collect()
}

fn to_any_value(value: &Value) -> AnyValue {
    let value = match value {
        Value::Bool(value) => any_value::Value::BoolValue(*value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                any_value::Value::IntValue(value)
            } else if let Some(value) = value.as_u64() {
                match i64::try_from(value) {
                    Ok(value) => any_value::Value::IntValue(value),
                    Err(_) => any_value::Value::StringValue(value.to_string()),
                }
            } else {
                any_value::Value::DoubleValue(value.as_f64().unwrap_or_default())
            }
        }
        Value::String(value) => any_value::Value::StringValue(value.clone()),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            any_value::Value::StringValue(value.to_string())
        }
    };
    AnyValue { value: Some(value) }
}
