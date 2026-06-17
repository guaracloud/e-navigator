use serde::{Deserialize, Serialize};

use super::modules::default_modules;
use super::{
    ArgvCaptureConfig, AttributionConfig, ConfigError, ConfigResult, CpuProfileSourceConfig,
    DnsMetricsConfig, ModuleConfig, NetworkMetricsConfig, ProfilingConfig,
    RequestCorrelationConfig, ResourceMetricsConfig, ResourceSourceConfig, RuntimeSecurityConfig,
    TraceCorrelationConfig,
};

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

fn default_log_level() -> String {
    "info".to_string()
}

fn default_queue_capacity() -> usize {
    1024
}
