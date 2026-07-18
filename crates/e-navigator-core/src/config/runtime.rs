use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::modules::{default_modules, is_known_module_name, known_module_names};
use super::{
    ArgvCaptureConfig, AttributionConfig, CaptureFilterConfig, ConfigError, ConfigResult,
    CpuProfileSourceConfig, DnsMetricsConfig, DnsSourceConfig, HttpSourceConfig, ModuleConfig,
    NetworkMetricsConfig, OtlpHttpConfig, ProfilingConfig, PrometheusHttpConfig,
    ProtocolSourceConfig, RequestCorrelationConfig, ResourceMetricsConfig, ResourceSourceConfig,
    RuntimeSecurityConfig, SourceSupervisorConfig, TlsSourceConfig, TraceCorrelationConfig,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_max_derived_signals_per_input")]
    pub max_derived_signals_per_input: usize,
    #[serde(default = "default_max_derived_signal_depth")]
    pub max_derived_signal_depth: usize,
    #[serde(default)]
    pub source_supervisor: SourceSupervisorConfig,
    #[serde(default = "default_modules")]
    pub modules: Vec<ModuleConfig>,
    #[serde(default)]
    pub argv_capture: ArgvCaptureConfig,
    #[serde(default)]
    pub attribution: AttributionConfig,
    #[serde(default)]
    pub capture_filter: CaptureFilterConfig,
    #[serde(default)]
    pub runtime_security: RuntimeSecurityConfig,
    #[serde(default)]
    pub resource_source: ResourceSourceConfig,
    #[serde(default)]
    pub dns_source: DnsSourceConfig,
    #[serde(default)]
    pub http_source: HttpSourceConfig,
    #[serde(default)]
    pub protocol_source: ProtocolSourceConfig,
    #[serde(default)]
    pub tls_source: TlsSourceConfig,
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
    #[serde(default)]
    pub prometheus_http: PrometheusHttpConfig,
    #[serde(default)]
    pub otlp_http: OtlpHttpConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            queue_capacity: default_queue_capacity(),
            max_derived_signals_per_input: default_max_derived_signals_per_input(),
            max_derived_signal_depth: default_max_derived_signal_depth(),
            source_supervisor: SourceSupervisorConfig::default(),
            modules: default_modules(),
            argv_capture: ArgvCaptureConfig::default(),
            attribution: AttributionConfig::default(),
            capture_filter: CaptureFilterConfig::default(),
            runtime_security: RuntimeSecurityConfig::default(),
            resource_source: ResourceSourceConfig::default(),
            dns_source: DnsSourceConfig::default(),
            http_source: HttpSourceConfig::default(),
            protocol_source: ProtocolSourceConfig::default(),
            tls_source: TlsSourceConfig::default(),
            cpu_profile_source: CpuProfileSourceConfig::default(),
            resource_metrics: ResourceMetricsConfig::default(),
            network_metrics: NetworkMetricsConfig::default(),
            dns_metrics: DnsMetricsConfig::default(),
            trace_correlation: TraceCorrelationConfig::default(),
            request_correlation: RequestCorrelationConfig::default(),
            profiling: ProfilingConfig::default(),
            prometheus_http: PrometheusHttpConfig::default(),
            otlp_http: OtlpHttpConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub const MAX_QUEUE_CAPACITY_LIMIT: usize = 65_536;
    pub const MAX_DERIVED_SIGNALS_PER_INPUT_LIMIT: usize = 4096;
    pub const MAX_DERIVED_SIGNAL_DEPTH_LIMIT: usize = 64;
    pub const MAX_LOG_LEVEL_BYTES_LIMIT: usize = 512;

    pub fn validate(&self) -> Result<(), String> {
        self.validate_typed().map_err(|err| err.to_string())
    }

    pub fn validate_typed(&self) -> ConfigResult<()> {
        if self.log_level.trim().is_empty() {
            return Err(ConfigError::invalid_value(
                "log_level",
                "log_level must not be empty",
            ));
        }
        if self.log_level.trim() != self.log_level {
            return Err(ConfigError::invalid_value(
                "log_level",
                "log_level must not have leading or trailing whitespace",
            ));
        }
        if self.log_level.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ConfigError::invalid_value(
                "log_level",
                "log_level must not contain control characters",
            ));
        }
        if self.log_level.len() > Self::MAX_LOG_LEVEL_BYTES_LIMIT {
            return Err(ConfigError::invalid_value(
                "log_level",
                format!(
                    "log_level must be at most {} bytes",
                    Self::MAX_LOG_LEVEL_BYTES_LIMIT
                ),
            ));
        }

        if self.queue_capacity == 0 {
            return Err(ConfigError::invalid_value(
                "queue_capacity",
                "queue_capacity must be greater than zero",
            ));
        }
        if self.queue_capacity > Self::MAX_QUEUE_CAPACITY_LIMIT {
            return Err(ConfigError::invalid_value(
                "queue_capacity",
                format!(
                    "queue_capacity must be less than or equal to {}",
                    Self::MAX_QUEUE_CAPACITY_LIMIT
                ),
            ));
        }

        if self.modules.iter().filter(|module| module.enabled).count() == 0 {
            return Err(ConfigError::invalid_value(
                "modules",
                "at least one module must be enabled",
            ));
        }

        if self.max_derived_signals_per_input == 0 {
            return Err(ConfigError::invalid_value(
                "max_derived_signals_per_input",
                "max_derived_signals_per_input must be greater than zero",
            ));
        }
        if self.max_derived_signals_per_input > Self::MAX_DERIVED_SIGNALS_PER_INPUT_LIMIT {
            return Err(ConfigError::invalid_value(
                "max_derived_signals_per_input",
                format!(
                    "max_derived_signals_per_input must be less than or equal to {}",
                    Self::MAX_DERIVED_SIGNALS_PER_INPUT_LIMIT
                ),
            ));
        }

        if self.max_derived_signal_depth == 0 {
            return Err(ConfigError::invalid_value(
                "max_derived_signal_depth",
                "max_derived_signal_depth must be greater than zero",
            ));
        }
        if self.max_derived_signal_depth > Self::MAX_DERIVED_SIGNAL_DEPTH_LIMIT {
            return Err(ConfigError::invalid_value(
                "max_derived_signal_depth",
                format!(
                    "max_derived_signal_depth must be less than or equal to {}",
                    Self::MAX_DERIVED_SIGNAL_DEPTH_LIMIT
                ),
            ));
        }

        self.validate_modules()?;

        self.source_supervisor.validate()?;
        self.argv_capture.validate()?;
        self.attribution.validate()?;
        self.capture_filter.validate()?;
        self.runtime_security.validate()?;
        self.resource_source.validate()?;
        self.dns_source.validate()?;
        self.http_source.validate()?;
        self.protocol_source.validate()?;
        if self.module_enabled("source.aya_http")
            && self.module_enabled("source.aya_protocol")
            && !self.protocol_source.http1_ports.is_empty()
        {
            return Err(ConfigError::invalid_value(
                "protocol_source.http1_ports",
                "protocol_source.http1_ports must be empty when source.aya_http and source.aya_protocol are both enabled; overlapping HTTP/1 capture would emit duplicate telemetry",
            ));
        }
        self.tls_source.validate()?;
        self.cpu_profile_source.validate(self)?;
        self.resource_metrics.validate()?;
        self.network_metrics.validate()?;
        self.dns_metrics.validate()?;
        self.trace_correlation.validate()?;
        self.request_correlation.validate()?;
        self.profiling.validate()?;
        self.prometheus_http
            .validate(self.module_enabled("sink.prometheus_http"))?;
        self.otlp_http
            .validate(self.module_enabled("sink.otlp_http"))?;

        Ok(())
    }

    pub fn module_enabled(&self, name: &str) -> bool {
        self.modules
            .iter()
            .find(|module| module.name == name)
            .is_some_and(|module| module.enabled)
    }

    fn validate_modules(&self) -> ConfigResult<()> {
        let mut seen = BTreeSet::new();
        for module in &self.modules {
            if !is_known_module_name(&module.name) {
                return Err(ConfigError::invalid_reference(
                    "modules",
                    format!(
                        "unknown module '{}'; known modules: {}",
                        module.name,
                        known_module_names().collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
            if !seen.insert(module.name.as_str()) {
                return Err(ConfigError::invalid_value(
                    "modules",
                    format!("duplicate module '{}'", module.name),
                ));
            }
        }

        Ok(())
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_queue_capacity() -> usize {
    1024
}

fn default_max_derived_signals_per_input() -> usize {
    256
}

fn default_max_derived_signal_depth() -> usize {
    8
}
