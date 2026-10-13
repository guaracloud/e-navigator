use async_trait::async_trait;
use e_navigator_core::{
    CoreResult, LogParseFailure, LogProcessingConfig, ModuleKind, ModuleMetadata, Processor,
};
use e_navigator_signals::{
    LogProcessing, LogProcessingOutcome, SignalEnvelope, SignalPayload, is_sensitive_attribute_key,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct LogProcessingProcessor {
    config: LogProcessingConfig,
}
impl LogProcessingProcessor {
    pub fn new(config: LogProcessingConfig) -> Self {
        Self { config }
    }
    fn redact(&self, mut body: String) -> Result<String, ()> {
        for value in &self.config.redact_values {
            let matches = body.matches(value).count();
            let size = body
                .len()
                .saturating_sub(matches * value.len())
                .saturating_add(matches * "[REDACTED]".len());
            if size > self.config.max_body_bytes {
                return Err(());
            }
            body = body.replace(value, "[REDACTED]");
        }
        Ok(body)
    }
    fn scrub(&self, value: &mut Value, remaining_breaks: &mut usize) -> Result<(), ()> {
        match value {
            Value::Object(fields) => {
                fields.retain(|key, _| {
                    !is_sensitive_attribute_key(key)
                        && !self
                            .config
                            .omit_keys
                            .iter()
                            .any(|v| v.eq_ignore_ascii_case(key))
                        && !self.config.redact_values.iter().any(|v| key.contains(v))
                });
                for value in fields.values_mut() {
                    self.scrub(value, remaining_breaks)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.scrub(value, remaining_breaks)?;
                }
            }
            Value::String(value) => {
                let breaks = value.bytes().filter(|b| *b == b'\n').count();
                *remaining_breaks = remaining_breaks.checked_sub(breaks).ok_or(())?;
                *value = self.redact(std::mem::take(value))?;
            }
            Value::Number(_) | Value::Bool(_) => {
                let original = value.to_string();
                let redacted = self.redact(original.clone())?;
                if redacted != original {
                    *value = Value::String(redacted);
                }
            }
            Value::Null => {}
        }
        Ok(())
    }
}
fn text(fields: &Value, key: &str) -> Option<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(|v| v[..v.floor_char_boundary(256)].to_string())
}
fn identifier(value: Option<String>, bytes: usize) -> Option<String> {
    value
        .filter(|v| {
            v.len() == bytes * 2
                && v.bytes().all(|b| b.is_ascii_hexdigit())
                && v.bytes().any(|b| b != b'0')
        })
        .map(|v| v.to_ascii_lowercase())
}
#[async_trait]
impl Processor<SignalEnvelope> for LogProcessingProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.log_processing", ModuleKind::Processor)
    }
    async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        let SignalPayload::ApplicationLogObservation(log) = &mut signal.payload else {
            return Ok(Some(signal));
        };
        // Reprocess under this policy; do not trust metadata received on input.
        log.processing = None;
        let mut processed = LogProcessing {
            outcome: LogProcessingOutcome::BodyOmitted,
            workload_name: None,
            workload_kind: None,
            severity_text: None,
            trace_id: None,
            span_id: None,
            attributes: BTreeMap::new(),
        };
        if let Some(body) = log.body.take() {
            if self.config.validate().is_err()
                || body.len() > self.config.max_body_bytes
                || body.lines().take(self.config.max_lines + 1).count() > self.config.max_lines
            {
                processed.outcome = LogProcessingOutcome::BudgetRejected;
            } else {
                let is_json = body.trim_start().starts_with(['{', '[']);
                match serde_json::from_str::<Value>(&body) {
                    Ok(mut fields) if is_json => {
                        if self
                            .scrub(&mut fields, &mut (self.config.max_lines - 1))
                            .is_err()
                        {
                            processed.outcome = LogProcessingOutcome::BudgetRejected;
                            log.processing = Some(Box::new(processed));
                            return Ok(Some(signal));
                        }
                        processed.outcome = LogProcessingOutcome::Json;
                        processed.severity_text =
                            text(&fields, "severity").or_else(|| text(&fields, "level"));
                        processed.trace_id = identifier(text(&fields, "trace_id"), 16);
                        processed.span_id = identifier(text(&fields, "span_id"), 8);
                        if processed.trace_id.is_none() {
                            processed.span_id = None;
                        }
                        for key in &self.config.attribute_keys {
                            if let Some(value) = fields
                                .get(key)
                                .filter(|v| !v.is_object() && !v.is_array() && !v.is_null())
                            {
                                let value = value
                                    .as_str()
                                    .map(str::to_string)
                                    .unwrap_or_else(|| value.to_string());
                                processed.attributes.insert(
                                    key.clone(),
                                    value[..value.floor_char_boundary(256)].to_string(),
                                );
                            }
                        }
                        log.body = Some(fields.to_string());
                    }
                    _ if is_json => {
                        processed.outcome = LogProcessingOutcome::MalformedJson;
                        if self.config.parse_failure == LogParseFailure::KeepRedacted {
                            match self.redact(body) {
                                Ok(body) => log.body = Some(body),
                                Err(()) => processed.outcome = LogProcessingOutcome::BudgetRejected,
                            }
                        }
                    }
                    _ => {
                        processed.outcome = LogProcessingOutcome::PlainText;
                        match self.redact(body) {
                            Ok(body) => log.body = Some(body),
                            Err(()) => processed.outcome = LogProcessingOutcome::BudgetRejected,
                        }
                    }
                }
                if log
                    .body
                    .as_ref()
                    .is_some_and(|v| v.len() > self.config.max_body_bytes)
                {
                    log.body = None;
                    processed.attributes.clear();
                    processed.outcome = LogProcessingOutcome::BudgetRejected;
                }
            }
        }
        log.processing = Some(Box::new(processed));
        Ok(Some(signal))
    }
}
