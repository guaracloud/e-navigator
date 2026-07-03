use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::modules::{default_modules, is_known_module_name, known_module_names};
use super::{
    ArgvCaptureConfig, AttributionConfig, ConfigError, ConfigResult, CpuProfileSourceConfig,
    DnsMetricsConfig, ModuleConfig, NetworkMetricsConfig, OtlpHttpConfig, ProfilingConfig,
    PrometheusHttpConfig, RequestCorrelationConfig, ResourceMetricsConfig, ResourceSourceConfig,
    RuntimeSecurityConfig, TraceCorrelationConfig,
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
            prometheus_http: PrometheusHttpConfig::default(),
            otlp_http: OtlpHttpConfig::default(),
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

        if self.max_derived_signals_per_input == 0 {
            return Err(ConfigError::invalid_value(
                "max_derived_signals_per_input",
                "max_derived_signals_per_input must be greater than zero",
            ));
        }

        if self.max_derived_signal_depth == 0 {
            return Err(ConfigError::invalid_value(
                "max_derived_signal_depth",
                "max_derived_signal_depth must be greater than zero",
            ));
        }

        self.validate_modules()?;

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
