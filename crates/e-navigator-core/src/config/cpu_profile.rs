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
    /// Capture time spent descheduled from `sched_switch`. Disabled by
    /// default because it adds global scheduler tracepoint work.
    #[serde(default)]
    pub off_cpu_enabled: bool,
    /// Capture contended Linux futex waits as lock profiles. Disabled by
    /// default; only FUTEX_WAIT and FUTEX_WAIT_BITSET are observed.
    #[serde(default)]
    pub lock_enabled: bool,
    #[serde(default = "default_off_cpu_min_duration_micros")]
    pub off_cpu_min_duration_micros: u64,
    #[serde(default = "default_lock_min_duration_micros")]
    pub lock_min_duration_micros: u64,
    /// Maximum accepted off-CPU samples per second on each CPU.
    #[serde(default = "default_profile_event_rate_per_cpu")]
    pub max_off_cpu_events_per_second_per_cpu: u32,
    /// Maximum accepted futex-wait samples per second on each CPU.
    #[serde(default = "default_profile_event_rate_per_cpu")]
    pub max_lock_events_per_second_per_cpu: u32,
    #[serde(default = "default_cpu_profile_max_active_targets")]
    pub max_active_targets: usize,
    /// Deepest stack captured per sample, both in-kernel (frame budget
    /// passed to bpf_get_stack) and during normalization. User stacks are
    /// additionally bounded by the kernel `kernel.perf_event_max_stack`
    /// sysctl (127 by default). Stacks that fill the budget are flagged and
    /// counted, never silently truncated.
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
    /// Read local ELF symbol tables and bounded target-namespace
    /// `/tmp/perf-<pid>.map` files for function-name resolution. Disable to
    /// export only module-relative offsets for offline symbolization.
    #[serde(default = "default_cpu_profile_resolve_symbol_names")]
    pub resolve_symbol_names: bool,
    /// Build `.eh_frame` unwind tables for running processes and unwind
    /// their stacks in-kernel via DWARF/CFI rules; processes without
    /// tables keep frame-pointer unwinding, with per-sample accounting
    /// of which path produced the stack.
    #[serde(default = "default_cpu_profile_dwarf_unwind")]
    pub dwarf_unwind: bool,
    /// Most processes registered for DWARF unwinding per refresh pass.
    #[serde(default = "default_cpu_profile_max_unwind_processes")]
    pub max_unwind_processes: usize,
}

fn default_cpu_profile_symbolize() -> bool {
    true
}

fn default_cpu_profile_resolve_symbol_names() -> bool {
    true
}

fn default_cpu_profile_dwarf_unwind() -> bool {
    true
}

fn default_cpu_profile_max_unwind_processes() -> usize {
    256
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
            off_cpu_enabled: false,
            lock_enabled: false,
            off_cpu_min_duration_micros: default_off_cpu_min_duration_micros(),
            lock_min_duration_micros: default_lock_min_duration_micros(),
            max_off_cpu_events_per_second_per_cpu: default_profile_event_rate_per_cpu(),
            max_lock_events_per_second_per_cpu: default_profile_event_rate_per_cpu(),
            max_active_targets: default_cpu_profile_max_active_targets(),
            max_frames_per_sample: default_cpu_profile_max_frames_per_sample(),
            max_samples_per_batch: default_cpu_profile_max_samples_per_batch(),
            max_symbol_bytes: default_cpu_profile_max_symbol_bytes(),
            max_module_bytes: default_cpu_profile_max_module_bytes(),
            max_file_bytes: default_cpu_profile_max_file_bytes(),
            backpressure: CpuProfileBackpressure::default(),
            symbolize: default_cpu_profile_symbolize(),
            resolve_symbol_names: default_cpu_profile_resolve_symbol_names(),
            dwarf_unwind: default_cpu_profile_dwarf_unwind(),
            max_unwind_processes: default_cpu_profile_max_unwind_processes(),
        }
    }
}

impl CpuProfileSourceConfig {
    pub const STATIC_MODULE_NAME: &'static str = "source.aya_cpu_profile";
    pub const MAX_SAMPLE_FREQUENCY_HZ: u32 = 999;
    pub const MAX_ACTIVE_TARGETS_LIMIT: usize = 4096;
    pub const MAX_FRAMES_PER_SAMPLE_LIMIT: usize = 128;
    pub const MAX_SAMPLES_PER_BATCH_LIMIT: usize = 1024;
    pub const MAX_SYMBOL_BYTES_LIMIT: usize = 1024;
    pub const MAX_MODULE_BYTES_LIMIT: usize = 1024;
    pub const MAX_FILE_BYTES_LIMIT: usize = 1024;
    pub const MAX_UNWIND_PROCESSES_LIMIT: usize = 1024;
    pub const MAX_EVENT_MIN_DURATION_MICROS: u64 = 60_000_000;
    pub const MAX_EVENT_RATE_PER_CPU: u32 = 4096;

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
        for (field, value) in [
            (
                "cpu_profile_source.off_cpu_min_duration_micros",
                self.off_cpu_min_duration_micros,
            ),
            (
                "cpu_profile_source.lock_min_duration_micros",
                self.lock_min_duration_micros,
            ),
        ] {
            if !(1..=Self::MAX_EVENT_MIN_DURATION_MICROS).contains(&value) {
                return Err(ConfigError::invalid_value(
                    field,
                    format!(
                        "{field} must be between 1 and {}",
                        Self::MAX_EVENT_MIN_DURATION_MICROS
                    ),
                ));
            }
        }
        for (field, value) in [
            (
                "cpu_profile_source.max_off_cpu_events_per_second_per_cpu",
                self.max_off_cpu_events_per_second_per_cpu,
            ),
            (
                "cpu_profile_source.max_lock_events_per_second_per_cpu",
                self.max_lock_events_per_second_per_cpu,
            ),
        ] {
            if !(1..=Self::MAX_EVENT_RATE_PER_CPU).contains(&value) {
                return Err(ConfigError::invalid_value(
                    field,
                    format!(
                        "{field} must be between 1 and {}",
                        Self::MAX_EVENT_RATE_PER_CPU
                    ),
                ));
            }
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
        if !(1..=Self::MAX_UNWIND_PROCESSES_LIMIT).contains(&self.max_unwind_processes) {
            return Err(ConfigError::invalid_value(
                "cpu_profile_source.max_unwind_processes",
                format!(
                    "cpu_profile_source.max_unwind_processes must be between 1 and {}",
                    Self::MAX_UNWIND_PROCESSES_LIMIT
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

fn default_off_cpu_min_duration_micros() -> u64 {
    1_000
}

fn default_lock_min_duration_micros() -> u64 {
    1_000
}

fn default_profile_event_rate_per_cpu() -> u32 {
    64
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
