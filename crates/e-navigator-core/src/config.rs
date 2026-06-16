use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, path::PathBuf};

pub type ConfigResult<T> = Result<T, ConfigError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    field: &'static str,
    category: ConfigErrorKind,
    message: String,
}

impl ConfigError {
    pub fn invalid_value(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            category: ConfigErrorKind::InvalidValue,
            message: message.into(),
        }
    }

    pub fn invalid_reference(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            category: ConfigErrorKind::InvalidReference,
            message: message.into(),
        }
    }

    pub fn field(&self) -> &'static str {
        self.field
    }

    pub fn category(&self) -> ConfigErrorKind {
        self.category
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    InvalidValue,
    InvalidReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_modules")]
    pub modules: Vec<ModuleConfig>,
    #[serde(default)]
    pub argv_capture: ArgvCaptureConfig,
    #[serde(default)]
    pub attribution: AttributionConfig,
    #[serde(default)]
    pub runtime_security: RuntimeSecurityConfig,
    #[serde(default)]
    pub resource_source: ResourceSourceConfig,
    #[serde(default)]
    pub cpu_profile_source: CpuProfileSourceConfig,
    #[serde(default)]
    pub resource_metrics: ResourceMetricsConfig,
    #[serde(default)]
    pub network_metrics: NetworkMetricsConfig,
    #[serde(default)]
    pub dns_metrics: DnsMetricsConfig,
    #[serde(default)]
    pub trace_correlation: TraceCorrelationConfig,
    #[serde(default)]
    pub request_correlation: RequestCorrelationConfig,
    #[serde(default)]
    pub profiling: ProfilingConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            queue_capacity: default_queue_capacity(),
            modules: default_modules(),
            argv_capture: ArgvCaptureConfig::default(),
            attribution: AttributionConfig::default(),
            runtime_security: RuntimeSecurityConfig::default(),
            resource_source: ResourceSourceConfig::default(),
            cpu_profile_source: CpuProfileSourceConfig::default(),
            resource_metrics: ResourceMetricsConfig::default(),
            network_metrics: NetworkMetricsConfig::default(),
            dns_metrics: DnsMetricsConfig::default(),
            trace_correlation: TraceCorrelationConfig::default(),
            request_correlation: RequestCorrelationConfig::default(),
            profiling: ProfilingConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_typed().map_err(|err| err.to_string())
    }

    pub fn validate_typed(&self) -> ConfigResult<()> {
        if self.queue_capacity == 0 {
            return Err(ConfigError::invalid_value(
                "queue_capacity",
                "queue_capacity must be greater than zero",
            ));
        }

        if self.modules.iter().filter(|module| module.enabled).count() == 0 {
            return Err(ConfigError::invalid_value(
                "modules",
                "at least one module must be enabled",
            ));
        }

        self.argv_capture.validate()?;
        self.attribution.validate()?;
        self.runtime_security.validate()?;
        self.resource_source.validate()?;
        self.cpu_profile_source.validate(self)?;
        self.resource_metrics.validate()?;
        self.network_metrics.validate()?;
        self.dns_metrics.validate()?;
        self.trace_correlation.validate()?;
        self.request_correlation.validate()?;
        self.profiling.validate()?;

        Ok(())
    }

    pub fn module_enabled(&self, name: &str) -> bool {
        self.modules
            .iter()
            .find(|module| module.name == name)
            .is_some_and(|module| module.enabled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgvCaptureConfig {
    #[serde(default = "default_argv_capture_enabled")]
    pub enabled: bool,
    #[serde(default = "default_argv_capture_max_args")]
    pub max_args: usize,
    #[serde(default = "default_argv_capture_max_bytes")]
    pub max_bytes: usize,
}

impl Default for ArgvCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: default_argv_capture_enabled(),
            max_args: default_argv_capture_max_args(),
            max_bytes: default_argv_capture_max_bytes(),
        }
    }
}

impl ArgvCaptureConfig {
    pub const MAX_ARGS_LIMIT: usize = 8;
    pub const MAX_BYTES_LIMIT: usize = 512;

    fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_ARGS_LIMIT).contains(&self.max_args) {
            return Err(ConfigError::invalid_value(
                "argv_capture.max_args",
                format!(
                    "argv_capture.max_args must be between 1 and {}",
                    Self::MAX_ARGS_LIMIT
                ),
            ));
        }

        if !(1..=Self::MAX_BYTES_LIMIT).contains(&self.max_bytes) {
            return Err(ConfigError::invalid_value(
                "argv_capture.max_bytes",
                format!(
                    "argv_capture.max_bytes must be between 1 and {}",
                    Self::MAX_BYTES_LIMIT
                ),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionConfig {
    #[serde(default = "default_procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default)]
    pub kubernetes: KubernetesAttributionConfig,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            procfs_root: default_procfs_root(),
            kubernetes: KubernetesAttributionConfig::default(),
        }
    }
}

impl AttributionConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.procfs_root",
                "attribution.procfs_root must not be empty",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RuntimeSecurityConfig {
    #[serde(default)]
    pub kubernetes_api_endpoints: Vec<NetworkEndpointConfig>,
}

impl RuntimeSecurityConfig {
    fn validate(&self) -> ConfigResult<()> {
        for endpoint in &self.kubernetes_api_endpoints {
            endpoint.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEndpointConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMetricsConfig {
    #[serde(default = "default_network_metrics_max_metric_keys")]
    pub max_metric_keys: usize,
    #[serde(default = "default_network_metrics_max_active_connections")]
    pub max_active_connections: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSourceConfig {
    #[serde(default = "default_procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default = "default_sysfs_root")]
    pub sysfs_root: PathBuf,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    #[serde(default = "default_resource_sample_interval_millis")]
    pub sample_interval_millis: u64,
    #[serde(default = "default_resource_max_processes")]
    pub max_processes: usize,
    #[serde(default = "default_resource_max_cgroups")]
    pub max_cgroups: usize,
    #[serde(default = "default_resource_max_fds_per_process")]
    pub max_fds_per_process: usize,
    #[serde(default = "default_resource_max_file_bytes")]
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMetricsConfig {
    #[serde(default = "default_resource_metrics_max_keys")]
    pub max_keys: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuProfileBackpressure {
    #[default]
    DropNewest,
    StopSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMetricsConfig {
    #[serde(default = "default_dns_metrics_max_domains")]
    pub max_domains: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCorrelationConfig {
    #[serde(default = "default_trace_correlation_max_service_paths")]
    pub max_service_paths: usize,
    #[serde(default = "default_trace_correlation_max_seen_interactions")]
    pub max_seen_interactions: usize,
    #[serde(default = "default_trace_correlation_max_warnings")]
    pub max_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCorrelationConfig {
    #[serde(default = "default_request_correlation_max_seen_requests")]
    pub max_seen_requests: usize,
    #[serde(default = "default_request_correlation_max_warnings")]
    pub max_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilingConfig {
    #[serde(default = "default_profiling_max_windows")]
    pub max_windows: usize,
    #[serde(default = "default_profiling_max_seen_samples")]
    pub max_seen_samples: usize,
    #[serde(default = "default_profiling_max_warnings")]
    pub max_warnings: usize,
    #[serde(default = "default_profiling_window_nanos")]
    pub window_nanos: u64,
}

impl Default for DnsMetricsConfig {
    fn default() -> Self {
        Self {
            max_domains: default_dns_metrics_max_domains(),
        }
    }
}

impl DnsMetricsConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.max_domains == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_domains",
                "dns_metrics.max_domains must be greater than zero",
            ));
        }

        Ok(())
    }
}

impl Default for TraceCorrelationConfig {
    fn default() -> Self {
        Self {
            max_service_paths: default_trace_correlation_max_service_paths(),
            max_seen_interactions: default_trace_correlation_max_seen_interactions(),
            max_warnings: default_trace_correlation_max_warnings(),
        }
    }
}

impl Default for RequestCorrelationConfig {
    fn default() -> Self {
        Self {
            max_seen_requests: default_request_correlation_max_seen_requests(),
            max_warnings: default_request_correlation_max_warnings(),
        }
    }
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            max_windows: default_profiling_max_windows(),
            max_seen_samples: default_profiling_max_seen_samples(),
            max_warnings: default_profiling_max_warnings(),
            window_nanos: default_profiling_window_nanos(),
        }
    }
}

impl TraceCorrelationConfig {
    pub const MAX_SERVICE_PATHS_LIMIT: usize = 65_536;
    pub const MAX_SEEN_INTERACTIONS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_SERVICE_PATHS_LIMIT).contains(&self.max_service_paths) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_service_paths",
                format!(
                    "trace_correlation.max_service_paths must be between 1 and {}",
                    Self::MAX_SERVICE_PATHS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_SEEN_INTERACTIONS_LIMIT).contains(&self.max_seen_interactions) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_seen_interactions",
                format!(
                    "trace_correlation.max_seen_interactions must be between 1 and {}",
                    Self::MAX_SEEN_INTERACTIONS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_warnings",
                format!(
                    "trace_correlation.max_warnings must be between 1 and {}",
                    Self::MAX_WARNINGS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

impl RequestCorrelationConfig {
    pub const MAX_SEEN_REQUESTS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_SEEN_REQUESTS_LIMIT).contains(&self.max_seen_requests) {
            return Err(ConfigError::invalid_value(
                "request_correlation.max_seen_requests",
                format!(
                    "request_correlation.max_seen_requests must be between 1 and {}",
                    Self::MAX_SEEN_REQUESTS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(ConfigError::invalid_value(
                "request_correlation.max_warnings",
                format!(
                    "request_correlation.max_warnings must be between 1 and {}",
                    Self::MAX_WARNINGS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

impl ProfilingConfig {
    pub const MAX_WINDOWS_LIMIT: usize = 65_536;
    pub const MAX_SEEN_SAMPLES_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;
    pub const MAX_WINDOW_NANOS_LIMIT: u64 = 86_400_000_000_000;

    fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_WINDOWS_LIMIT).contains(&self.max_windows) {
            return Err(ConfigError::invalid_value(
                "profiling.max_windows",
                format!(
                    "profiling.max_windows must be between 1 and {}",
                    Self::MAX_WINDOWS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_SEEN_SAMPLES_LIMIT).contains(&self.max_seen_samples) {
            return Err(ConfigError::invalid_value(
                "profiling.max_seen_samples",
                format!(
                    "profiling.max_seen_samples must be between 1 and {}",
                    Self::MAX_SEEN_SAMPLES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(ConfigError::invalid_value(
                "profiling.max_warnings",
                format!(
                    "profiling.max_warnings must be between 1 and {}",
                    Self::MAX_WARNINGS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WINDOW_NANOS_LIMIT).contains(&self.window_nanos) {
            return Err(ConfigError::invalid_value(
                "profiling.window_nanos",
                format!(
                    "profiling.window_nanos must be between 1 and {}",
                    Self::MAX_WINDOW_NANOS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

impl Default for NetworkMetricsConfig {
    fn default() -> Self {
        Self {
            max_metric_keys: default_network_metrics_max_metric_keys(),
            max_active_connections: default_network_metrics_max_active_connections(),
        }
    }
}

impl Default for ResourceSourceConfig {
    fn default() -> Self {
        Self {
            procfs_root: default_procfs_root(),
            sysfs_root: default_sysfs_root(),
            cgroup_root: default_cgroup_root(),
            sample_interval_millis: default_resource_sample_interval_millis(),
            max_processes: default_resource_max_processes(),
            max_cgroups: default_resource_max_cgroups(),
            max_fds_per_process: default_resource_max_fds_per_process(),
            max_file_bytes: default_resource_max_file_bytes(),
        }
    }
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
        }
    }
}

impl ResourceSourceConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.procfs_root",
                "resource_source.procfs_root must not be empty",
            ));
        }
        if self.sysfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.sysfs_root",
                "resource_source.sysfs_root must not be empty",
            ));
        }
        if self.cgroup_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.cgroup_root",
                "resource_source.cgroup_root must not be empty",
            ));
        }
        if self.max_processes == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_processes",
                "resource_source.max_processes must be greater than zero",
            ));
        }
        if self.max_cgroups == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_cgroups",
                "resource_source.max_cgroups must be greater than zero",
            ));
        }
        if self.max_fds_per_process == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_fds_per_process",
                "resource_source.max_fds_per_process must be greater than zero",
            ));
        }
        if self.max_file_bytes == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_file_bytes",
                "resource_source.max_file_bytes must be greater than zero",
            ));
        }
        Ok(())
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

    fn validate(&self, runtime: &RuntimeConfig) -> ConfigResult<()> {
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

impl Default for ResourceMetricsConfig {
    fn default() -> Self {
        Self {
            max_keys: default_resource_metrics_max_keys(),
        }
    }
}

impl ResourceMetricsConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.max_keys == 0 {
            return Err(ConfigError::invalid_value(
                "resource_metrics.max_keys",
                "resource_metrics.max_keys must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl NetworkMetricsConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.max_metric_keys == 0 {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_metric_keys",
                "network_metrics.max_metric_keys must be greater than zero",
            ));
        }

        if self.max_active_connections == 0 {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_active_connections",
                "network_metrics.max_active_connections must be greater than zero",
            ));
        }

        Ok(())
    }
}

impl NetworkEndpointConfig {
    fn validate(&self) -> ConfigResult<()> {
        self.address.parse::<IpAddr>().map_err(|_| {
            ConfigError::invalid_value(
                "runtime_security.kubernetes_api_endpoints.address",
                "runtime_security.kubernetes_api_endpoints.address must be an IP address",
            )
        })?;

        if self.port == 0 {
            return Err(ConfigError::invalid_value(
                "runtime_security.kubernetes_api_endpoints.port",
                "runtime_security.kubernetes_api_endpoints.port must be greater than zero",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesAttributionConfig {
    #[serde(default = "default_kubernetes_attribution_enabled")]
    pub enabled: bool,
    #[serde(default = "default_service_account_token_path")]
    pub token_path: PathBuf,
    #[serde(default = "default_service_account_ca_path")]
    pub ca_cert_path: PathBuf,
}

impl Default for KubernetesAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: default_kubernetes_attribution_enabled(),
            token_path: default_service_account_token_path(),
            ca_cert_path: default_service_account_ca_path(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_queue_capacity() -> usize {
    1024
}

fn default_modules() -> Vec<ModuleConfig> {
    vec![
        ModuleConfig::enabled("source.aya_exec"),
        ModuleConfig::enabled("source.aya_network"),
        ModuleConfig::disabled("source.aya_cpu_profile"),
        ModuleConfig::enabled("source.host_resource"),
        ModuleConfig::enabled("source.synthetic_exec"),
        ModuleConfig::enabled("processor.container_attribution"),
        ModuleConfig::enabled("generator.resource_metrics"),
        ModuleConfig::enabled("generator.network_metrics"),
        ModuleConfig::enabled("generator.dns_metrics"),
        ModuleConfig::enabled("generator.trace_correlation"),
        ModuleConfig::enabled("generator.request_correlation"),
        ModuleConfig::enabled("generator.profiling"),
        ModuleConfig::enabled("generator.dependency_graph"),
        ModuleConfig::enabled("generator.runtime_security"),
        ModuleConfig::enabled("sink.json_stdout"),
    ]
}

fn default_argv_capture_enabled() -> bool {
    true
}

fn default_argv_capture_max_args() -> usize {
    ArgvCaptureConfig::MAX_ARGS_LIMIT
}

fn default_argv_capture_max_bytes() -> usize {
    ArgvCaptureConfig::MAX_BYTES_LIMIT
}

fn default_procfs_root() -> PathBuf {
    PathBuf::from("/proc")
}

fn default_sysfs_root() -> PathBuf {
    PathBuf::from("/sys")
}

fn default_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

fn default_kubernetes_attribution_enabled() -> bool {
    true
}

fn default_service_account_token_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

fn default_service_account_ca_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
}

fn default_network_metrics_max_metric_keys() -> usize {
    4096
}

fn default_network_metrics_max_active_connections() -> usize {
    8192
}

fn default_dns_metrics_max_domains() -> usize {
    1024
}

fn default_trace_correlation_max_service_paths() -> usize {
    4096
}

fn default_trace_correlation_max_seen_interactions() -> usize {
    8192
}

fn default_trace_correlation_max_warnings() -> usize {
    1024
}

fn default_request_correlation_max_seen_requests() -> usize {
    8192
}

fn default_request_correlation_max_warnings() -> usize {
    1024
}

fn default_profiling_max_windows() -> usize {
    4096
}

fn default_profiling_max_seen_samples() -> usize {
    8192
}

fn default_profiling_max_warnings() -> usize {
    1024
}

fn default_profiling_window_nanos() -> u64 {
    30_000_000_000
}

fn default_resource_sample_interval_millis() -> u64 {
    15_000
}

fn default_resource_max_processes() -> usize {
    128
}

fn default_resource_max_cgroups() -> usize {
    128
}

fn default_resource_max_fds_per_process() -> usize {
    1024
}

fn default_resource_max_file_bytes() -> u64 {
    128 * 1024
}

fn default_resource_metrics_max_keys() -> usize {
    4096
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub name: String,
    pub enabled: bool,
}

impl ModuleConfig {
    pub fn enabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }

    pub fn disabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_capture_defaults_are_bounded_and_enabled() {
        let config = RuntimeConfig::default();

        assert!(config.argv_capture.enabled);
        assert_eq!(config.argv_capture.max_args, 8);
        assert_eq!(config.argv_capture.max_bytes, 512);
    }

    #[test]
    fn argv_capture_limits_are_validated() {
        let zero_args = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 0,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            zero_args.validate(),
            Err("argv_capture.max_args must be between 1 and 8".to_string())
        );

        let too_many_args = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 9,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_args.validate(),
            Err("argv_capture.max_args must be between 1 and 8".to_string())
        );

        let too_many_bytes = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 8,
                max_bytes: 513,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_bytes.validate(),
            Err("argv_capture.max_bytes must be between 1 and 512".to_string())
        );
    }

    #[test]
    fn default_config_is_valid() {
        let config = RuntimeConfig::default();

        assert!(config.validate().is_ok());
        assert!(config.module_enabled("source.aya_exec"));
        assert!(config.module_enabled("source.aya_network"));
        assert!(!config.module_enabled("source.aya_cpu_profile"));
        assert!(config.module_enabled("source.host_resource"));
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(config.module_enabled("processor.container_attribution"));
        assert!(config.module_enabled("generator.resource_metrics"));
        assert!(config.module_enabled("generator.network_metrics"));
        assert!(config.module_enabled("generator.dns_metrics"));
        assert!(config.module_enabled("generator.trace_correlation"));
        assert!(config.module_enabled("generator.request_correlation"));
        assert!(config.module_enabled("generator.profiling"));
        assert!(config.module_enabled("generator.dependency_graph"));
        assert!(config.module_enabled("generator.runtime_security"));
        assert!(config.module_enabled("sink.json_stdout"));
    }

    #[test]
    fn cpu_profile_source_defaults_are_bounded_and_disabled() {
        let config = RuntimeConfig::default();

        assert!(!config.cpu_profile_source.enabled);
        assert_eq!(
            config.cpu_profile_source.module_name,
            "source.aya_cpu_profile"
        );
        assert_eq!(config.cpu_profile_source.sample_frequency_hz, 49);
        assert_eq!(config.cpu_profile_source.max_active_targets, 128);
        assert_eq!(config.cpu_profile_source.max_frames_per_sample, 64);
        assert_eq!(config.cpu_profile_source.max_samples_per_batch, 64);
        assert_eq!(config.cpu_profile_source.max_symbol_bytes, 256);
        assert_eq!(config.cpu_profile_source.max_module_bytes, 256);
        assert_eq!(config.cpu_profile_source.max_file_bytes, 256);
        assert_eq!(
            config.cpu_profile_source.backpressure,
            CpuProfileBackpressure::DropNewest
        );
    }

    #[test]
    fn cpu_profile_source_validates_zero_and_oversized_limits() {
        let invalid_frequency = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                sample_frequency_hz: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_frequency.validate(),
            Err(format!(
                "cpu_profile_source.sample_frequency_hz must be between 1 and {}",
                CpuProfileSourceConfig::MAX_SAMPLE_FREQUENCY_HZ
            ))
        );

        let too_high_frequency = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                sample_frequency_hz: CpuProfileSourceConfig::MAX_SAMPLE_FREQUENCY_HZ + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_high_frequency.validate(),
            Err(format!(
                "cpu_profile_source.sample_frequency_hz must be between 1 and {}",
                CpuProfileSourceConfig::MAX_SAMPLE_FREQUENCY_HZ
            ))
        );

        let too_many_targets = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_active_targets: CpuProfileSourceConfig::MAX_ACTIVE_TARGETS_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_targets.validate(),
            Err(format!(
                "cpu_profile_source.max_active_targets must be between 1 and {}",
                CpuProfileSourceConfig::MAX_ACTIVE_TARGETS_LIMIT
            ))
        );

        let invalid_frames = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_frames_per_sample: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_frames.validate(),
            Err(format!(
                "cpu_profile_source.max_frames_per_sample must be between 1 and {}",
                CpuProfileSourceConfig::MAX_FRAMES_PER_SAMPLE_LIMIT
            ))
        );

        let invalid_batch = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_samples_per_batch: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_batch.validate(),
            Err(format!(
                "cpu_profile_source.max_samples_per_batch must be between 1 and {}",
                CpuProfileSourceConfig::MAX_SAMPLES_PER_BATCH_LIMIT
            ))
        );

        let too_many_symbol_bytes = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_symbol_bytes: CpuProfileSourceConfig::MAX_SYMBOL_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_symbol_bytes.validate(),
            Err(format!(
                "cpu_profile_source.max_symbol_bytes must be between 1 and {}",
                CpuProfileSourceConfig::MAX_SYMBOL_BYTES_LIMIT
            ))
        );

        let too_many_module_bytes = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_module_bytes: CpuProfileSourceConfig::MAX_MODULE_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_module_bytes.validate(),
            Err(format!(
                "cpu_profile_source.max_module_bytes must be between 1 and {}",
                CpuProfileSourceConfig::MAX_MODULE_BYTES_LIMIT
            ))
        );

        let too_many_file_bytes = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_file_bytes: CpuProfileSourceConfig::MAX_FILE_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_file_bytes.validate(),
            Err(format!(
                "cpu_profile_source.max_file_bytes must be between 1 and {}",
                CpuProfileSourceConfig::MAX_FILE_BYTES_LIMIT
            ))
        );
    }

    #[test]
    fn cpu_profile_source_requires_static_module_enablement() {
        let config = RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.aya_cpu_profile"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };

        assert!(config.validate().is_ok());
        assert!(config.module_enabled("source.aya_cpu_profile"));

        let wrong_module_name = RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                module_name: "source.dynamic_cpu_profile".to_string(),
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            wrong_module_name.validate(),
            Err("cpu_profile_source.module_name must be source.aya_cpu_profile".to_string())
        );

        let disabled_module = RuntimeConfig {
            modules: vec![
                ModuleConfig::disabled("source.aya_cpu_profile"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            disabled_module.validate(),
            Err(
                "cpu_profile_source.enabled requires enabled source.aya_cpu_profile module"
                    .to_string()
            )
        );
    }

    fn cpu_profile_modules() -> Vec<ModuleConfig> {
        vec![
            ModuleConfig::enabled("source.aya_cpu_profile"),
            ModuleConfig::enabled("sink.json_stdout"),
        ]
    }

    #[test]
    fn network_metrics_limits_are_validated() {
        let invalid_metric_keys = RuntimeConfig {
            network_metrics: NetworkMetricsConfig {
                max_metric_keys: 0,
                max_active_connections: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_metric_keys.validate(),
            Err("network_metrics.max_metric_keys must be greater than zero".to_string())
        );

        let invalid_active_connections = RuntimeConfig {
            network_metrics: NetworkMetricsConfig {
                max_metric_keys: 128,
                max_active_connections: 0,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_active_connections.validate(),
            Err("network_metrics.max_active_connections must be greater than zero".to_string())
        );
    }

    #[test]
    fn dns_metrics_limits_are_validated() {
        let config = RuntimeConfig {
            dns_metrics: DnsMetricsConfig { max_domains: 0 },
            ..RuntimeConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err("dns_metrics.max_domains must be greater than zero".to_string())
        );
    }

    #[test]
    fn trace_correlation_limits_are_validated() {
        let invalid_paths = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 0,
                max_seen_interactions: 128,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_paths.validate(),
            Err(format!(
                "trace_correlation.max_service_paths must be between 1 and {}",
                TraceCorrelationConfig::MAX_SERVICE_PATHS_LIMIT
            ))
        );

        let invalid_interactions = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: 0,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_interactions.validate(),
            Err(format!(
                "trace_correlation.max_seen_interactions must be between 1 and {}",
                TraceCorrelationConfig::MAX_SEEN_INTERACTIONS_LIMIT
            ))
        );

        let invalid_warnings = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: 128,
                max_warnings: 0,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_warnings.validate(),
            Err(format!(
                "trace_correlation.max_warnings must be between 1 and {}",
                TraceCorrelationConfig::MAX_WARNINGS_LIMIT
            ))
        );

        let too_many_paths = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: TraceCorrelationConfig::MAX_SERVICE_PATHS_LIMIT + 1,
                max_seen_interactions: 128,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_paths.validate(),
            Err(format!(
                "trace_correlation.max_service_paths must be between 1 and {}",
                TraceCorrelationConfig::MAX_SERVICE_PATHS_LIMIT
            ))
        );

        let too_many_interactions = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: TraceCorrelationConfig::MAX_SEEN_INTERACTIONS_LIMIT + 1,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_interactions.validate(),
            Err(format!(
                "trace_correlation.max_seen_interactions must be between 1 and {}",
                TraceCorrelationConfig::MAX_SEEN_INTERACTIONS_LIMIT
            ))
        );

        let too_many_warnings = RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: 128,
                max_warnings: TraceCorrelationConfig::MAX_WARNINGS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_warnings.validate(),
            Err(format!(
                "trace_correlation.max_warnings must be between 1 and {}",
                TraceCorrelationConfig::MAX_WARNINGS_LIMIT
            ))
        );
    }

    #[test]
    fn request_correlation_limits_are_validated() {
        let invalid_requests = RuntimeConfig {
            request_correlation: RequestCorrelationConfig {
                max_seen_requests: 0,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_requests.validate(),
            Err(format!(
                "request_correlation.max_seen_requests must be between 1 and {}",
                RequestCorrelationConfig::MAX_SEEN_REQUESTS_LIMIT
            ))
        );

        let invalid_warnings = RuntimeConfig {
            request_correlation: RequestCorrelationConfig {
                max_seen_requests: 128,
                max_warnings: 0,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_warnings.validate(),
            Err(format!(
                "request_correlation.max_warnings must be between 1 and {}",
                RequestCorrelationConfig::MAX_WARNINGS_LIMIT
            ))
        );
    }

    #[test]
    fn profiling_limits_are_validated() {
        let invalid_windows = RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 0,
                max_seen_samples: 128,
                max_warnings: 128,
                window_nanos: 1_000_000_000,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_windows.validate(),
            Err(format!(
                "profiling.max_windows must be between 1 and {}",
                ProfilingConfig::MAX_WINDOWS_LIMIT
            ))
        );

        let invalid_seen = RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 0,
                max_warnings: 128,
                window_nanos: 1_000_000_000,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_seen.validate(),
            Err(format!(
                "profiling.max_seen_samples must be between 1 and {}",
                ProfilingConfig::MAX_SEEN_SAMPLES_LIMIT
            ))
        );

        let invalid_window = RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 128,
                max_warnings: 128,
                window_nanos: 0,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_window.validate(),
            Err(format!(
                "profiling.window_nanos must be between 1 and {}",
                ProfilingConfig::MAX_WINDOW_NANOS_LIMIT
            ))
        );

        let too_large_window = RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 128,
                max_warnings: 128,
                window_nanos: ProfilingConfig::MAX_WINDOW_NANOS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_large_window.validate(),
            Err(format!(
                "profiling.window_nanos must be between 1 and {}",
                ProfilingConfig::MAX_WINDOW_NANOS_LIMIT
            ))
        );
    }

    #[test]
    fn resource_source_and_metrics_limits_are_validated() {
        let invalid_processes = RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_processes: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_processes.validate(),
            Err("resource_source.max_processes must be greater than zero".to_string())
        );

        let invalid_metric_keys = RuntimeConfig {
            resource_metrics: ResourceMetricsConfig { max_keys: 0 },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_metric_keys.validate(),
            Err("resource_metrics.max_keys must be greater than zero".to_string())
        );
    }

    #[test]
    fn runtime_security_kubernetes_api_endpoints_are_validated() {
        let invalid_address = RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![NetworkEndpointConfig {
                    address: "kubernetes.default.svc".to_string(),
                    port: 443,
                }],
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_address.validate(),
            Err(
                "runtime_security.kubernetes_api_endpoints.address must be an IP address"
                    .to_string()
            )
        );

        let invalid_port = RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![NetworkEndpointConfig {
                    address: "10.96.0.1".to_string(),
                    port: 0,
                }],
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            invalid_port.validate(),
            Err(
                "runtime_security.kubernetes_api_endpoints.port must be greater than zero"
                    .to_string()
            )
        );
    }

    #[test]
    fn zero_queue_capacity_is_invalid() {
        let config = RuntimeConfig {
            queue_capacity: 0,
            ..RuntimeConfig::default()
        };

        let err = config
            .validate_typed()
            .expect_err("queue capacity is invalid");
        assert_eq!(err.field(), "queue_capacity");
        assert_eq!(err.category(), ConfigErrorKind::InvalidValue);
        assert_eq!(
            err.to_string(),
            "queue_capacity must be greater than zero".to_string()
        );
        assert_eq!(
            config.validate(),
            Err("queue_capacity must be greater than zero".to_string())
        );
    }

    #[test]
    fn config_with_no_enabled_modules_is_invalid() {
        let config = RuntimeConfig {
            modules: vec![ModuleConfig {
                name: "sink.json_stdout".to_string(),
                enabled: false,
            }],
            ..RuntimeConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err("at least one module must be enabled".to_string())
        );
    }
}
