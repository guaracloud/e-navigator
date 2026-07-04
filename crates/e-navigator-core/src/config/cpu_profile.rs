use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult, RuntimeConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuProfileSourceConfig {
    #[serde(default = "default_cpu_profile_source_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cpu_profile_source_module_name")]
    pub module_name: String,
    #[serde(default = "default_cpu_profile_sample_frequency_hz")]
    pub sample_frequency_hz: u32,
    #[serde(default = "default_cpu_profile_max_active_targets")]
    pub max_active_targets: usize,
    #[serde(default = "default_cpu_profile_max_frames_per_sample")]
    pub max_frames_per_sample: usize,
    #[serde(default = "default_cpu_profile_max_samples_per_batch")]
    pub max_samples_per_batch: usize,
    #[serde(default = "default_cpu_profile_max_symbol_bytes")]
    pub max_symbol_bytes: usize,
    #[serde(default = "default_cpu_profile_max_module_bytes")]
    pub max_module_bytes: usize,
    #[serde(default = "default_cpu_profile_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default)]
    pub backpressure: CpuProfileBackpressure,
    /// Resolve captured instruction pointers to module and offset (and
    /// best-effort local ELF symbol names) from procfs.
    #[serde(default = "default_cpu_profile_symbolize")]
    pub symbolize: bool,
    /// Read local ELF symbol tables for function-name resolution. Disable to
    /// export only module-relative offsets for offline symbolization.
    #[serde(default = "default_cpu_profile_resolve_symbol_names")]
    pub resolve_symbol_names: bool,
}

fn default_cpu_profile_symbolize() -> bool {
    true
}

fn default_cpu_profile_resolve_symbol_names() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuProfileBackpressure {
    #[default]
    DropNewest,
    StopSource,
}

impl Default for CpuProfileSourceConfig {
    fn default() -> Self {
        Self {
            enabled: default_cpu_profile_source_enabled(),
            module_name: default_cpu_profile_source_module_name(),
            sample_frequency_hz: default_cpu_profile_sample_frequency_hz(),
            max_active_targets: default_cpu_profile_max_active_targets(),
            max_frames_per_sample: default_cpu_profile_max_frames_per_sample(),
            max_samples_per_batch: default_cpu_profile_max_samples_per_batch(),
            max_symbol_bytes: default_cpu_profile_max_symbol_bytes(),
            max_module_bytes: default_cpu_profile_max_module_bytes(),
            max_file_bytes: default_cpu_profile_max_file_bytes(),
            backpressure: CpuProfileBackpressure::default(),
            symbolize: default_cpu_profile_symbolize(),
            resolve_symbol_names: default_cpu_profile_resolve_symbol_names(),
        }
    }
}

impl CpuProfileSourceConfig {
    pub const STATIC_MODULE_NAME: &'static str = "source.aya_cpu_profile";
    pub const MAX_SAMPLE_FREQUENCY_HZ: u32 = 999;
    pub const MAX_ACTIVE_TARGETS_LIMIT: usize = 4096;
    pub const MAX_FRAMES_PER_SAMPLE_LIMIT: usize = 256;
    pub const MAX_SAMPLES_PER_BATCH_LIMIT: usize = 1024;
    pub const MAX_SYMBOL_BYTES_LIMIT: usize = 1024;
    pub const MAX_MODULE_BYTES_LIMIT: usize = 1024;
    pub const MAX_FILE_BYTES_LIMIT: usize = 1024;

    pub(super) fn validate(&self, runtime: &RuntimeConfig) -> ConfigResult<()> {
        if self.module_name != Self::STATIC_MODULE_NAME {
            return Err(ConfigError::invalid_reference(
                "cpu_profile_source.module_name",
                format!(
                    "cpu_profile_source.module_name must be {}",
                    Self::STATIC_MODULE_NAME
                ),
            ));
        }
        if self.enabled && !runtime.module_enabled(&self.module_name) {
            return Err(ConfigError::invalid_reference(
                "cpu_profile_source.enabled",
                "cpu_profile_source.enabled requires enabled source.aya_cpu_profile module",
            ));
        }
        if !(1..=Self::MAX_SAMPLE_FREQUENCY_HZ).contains(&self.sample_frequency_hz) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.sample_frequency_hz",
                format!(
                    "cpu_profile_source.sample_frequency_hz must be between 1 and {}",
                    Self::MAX_SAMPLE_FREQUENCY_HZ
                ),
            ));
        }
        if !(1..=Self::MAX_ACTIVE_TARGETS_LIMIT).contains(&self.max_active_targets) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_active_targets",
                format!(
                    "cpu_profile_source.max_active_targets must be between 1 and {}",
                    Self::MAX_ACTIVE_TARGETS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_FRAMES_PER_SAMPLE_LIMIT).contains(&self.max_frames_per_sample) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_frames_per_sample",
                format!(
                    "cpu_profile_source.max_frames_per_sample must be between 1 and {}",
                    Self::MAX_FRAMES_PER_SAMPLE_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_SAMPLES_PER_BATCH_LIMIT).contains(&self.max_samples_per_batch) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_samples_per_batch",
                format!(
                    "cpu_profile_source.max_samples_per_batch must be between 1 and {}",
                    Self::MAX_SAMPLES_PER_BATCH_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_SYMBOL_BYTES_LIMIT).contains(&self.max_symbol_bytes) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_symbol_bytes",
                format!(
                    "cpu_profile_source.max_symbol_bytes must be between 1 and {}",
                    Self::MAX_SYMBOL_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_MODULE_BYTES_LIMIT).contains(&self.max_module_bytes) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_module_bytes",
                format!(
                    "cpu_profile_source.max_module_bytes must be between 1 and {}",
                    Self::MAX_MODULE_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_FILE_BYTES_LIMIT).contains(&self.max_file_bytes) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_file_bytes",
                format!(
                    "cpu_profile_source.max_file_bytes must be between 1 and {}",
                    Self::MAX_FILE_BYTES_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn default_cpu_profile_source_enabled() -> bool {
    false
}

fn default_cpu_profile_source_module_name() -> String {
    CpuProfileSourceConfig::STATIC_MODULE_NAME.to_string()
}

fn default_cpu_profile_sample_frequency_hz() -> u32 {
    49
}

fn default_cpu_profile_max_active_targets() -> usize {
    128
}

fn default_cpu_profile_max_frames_per_sample() -> usize {
    64
}

fn default_cpu_profile_max_samples_per_batch() -> usize {
    64
}

fn default_cpu_profile_max_symbol_bytes() -> usize {
    256
}

fn default_cpu_profile_max_module_bytes() -> usize {
    256
}

fn default_cpu_profile_max_file_bytes() -> usize {
    256
}
