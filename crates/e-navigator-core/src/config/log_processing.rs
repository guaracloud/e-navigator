use super::{ConfigError, ConfigResult};
use serde::{Deserialize, Serialize};

/// Bounded payload policy. Literal redaction values never appear in Debug/errors.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogProcessingConfig {
    pub enabled: bool,
    pub max_body_bytes: usize,
    pub max_lines: usize,
    pub omit_keys: Vec<String>,
    pub redact_values: Vec<String>,
    pub attribute_keys: Vec<String>,
    pub parse_failure: LogParseFailure,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogParseFailure {
    #[default]
    OmitBody,
    KeepRedacted,
}

impl std::fmt::Debug for LogProcessingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogProcessingConfig")
            .field("enabled", &self.enabled)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_lines", &self.max_lines)
            .field("redaction_rule_count", &self.redact_values.len())
            .finish_non_exhaustive()
    }
}
impl Default for LogProcessingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_body_bytes: 16384,
            max_lines: 256,
            omit_keys: vec![],
            redact_values: vec![],
            attribute_keys: vec![],
            parse_failure: LogParseFailure::default(),
        }
    }
}
impl LogProcessingConfig {
    pub fn validate(&self) -> ConfigResult<()> {
        if self.max_body_bytes == 0
            || self.max_body_bytes > 32768
            || self.max_lines == 0
            || self.max_lines > 1024
        {
            return Err(ConfigError::invalid_value(
                "log_processing",
                "log processing requires body bytes in 1..=32768 and lines in 1..=1024",
            ));
        }
        for (path, values, maximum) in [
            ("log_processing.omit_keys", &self.omit_keys, 64),
            ("log_processing.redact_values", &self.redact_values, 64),
            ("log_processing.attribute_keys", &self.attribute_keys, 32),
        ] {
            if values.len() > maximum
                || values
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 256 || v.trim() != v)
            {
                return Err(ConfigError::invalid_value(
                    path,
                    "log rules exceed count/string bounds or contain empty/padded values",
                ));
            }
        }
        if self.attribute_keys.iter().any(|v| {
            v.len() > 64
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.".contains(&b))
        }) {
            return Err(ConfigError::invalid_value(
                "log_processing.attribute_keys",
                "log attribute keys must be at most 64 ASCII letters/digits/underscore/dot bytes",
            ));
        }
        Ok(())
    }
}
