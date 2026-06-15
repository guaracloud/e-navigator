use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

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
    pub resource_metrics: ResourceMetricsConfig,
    #[serde(default)]
    pub network_metrics: NetworkMetricsConfig,
    #[serde(default)]
    pub dns_metrics: DnsMetricsConfig,
    #[serde(default)]
    pub trace_correlation: TraceCorrelationConfig,
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
            resource_metrics: ResourceMetricsConfig::default(),
            network_metrics: NetworkMetricsConfig::default(),
            dns_metrics: DnsMetricsConfig::default(),
            trace_correlation: TraceCorrelationConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.queue_capacity == 0 {
            return Err("queue_capacity must be greater than zero".to_string());
        }

        if self.modules.iter().filter(|module| module.enabled).count() == 0 {
            return Err("at least one module must be enabled".to_string());
        }

        self.argv_capture.validate()?;
        self.attribution.validate()?;
        self.runtime_security.validate()?;
        self.resource_source.validate()?;
        self.resource_metrics.validate()?;
        self.network_metrics.validate()?;
        self.dns_metrics.validate()?;
        self.trace_correlation.validate()?;

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

    fn validate(&self) -> Result<(), String> {
        if !(1..=Self::MAX_ARGS_LIMIT).contains(&self.max_args) {
            return Err(format!(
                "argv_capture.max_args must be between 1 and {}",
                Self::MAX_ARGS_LIMIT
            ));
        }

        if !(1..=Self::MAX_BYTES_LIMIT).contains(&self.max_bytes) {
            return Err(format!(
                "argv_capture.max_bytes must be between 1 and {}",
                Self::MAX_BYTES_LIMIT
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
    fn validate(&self) -> Result<(), String> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err("attribution.procfs_root must not be empty".to_string());
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
    fn validate(&self) -> Result<(), String> {
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

impl Default for DnsMetricsConfig {
    fn default() -> Self {
        Self {
            max_domains: default_dns_metrics_max_domains(),
        }
    }
}

impl DnsMetricsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.max_domains == 0 {
            return Err("dns_metrics.max_domains must be greater than zero".to_string());
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

impl TraceCorrelationConfig {
    pub const MAX_SERVICE_PATHS_LIMIT: usize = 65_536;
    pub const MAX_SEEN_INTERACTIONS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    fn validate(&self) -> Result<(), String> {
        if !(1..=Self::MAX_SERVICE_PATHS_LIMIT).contains(&self.max_service_paths) {
            return Err(format!(
                "trace_correlation.max_service_paths must be between 1 and {}",
                Self::MAX_SERVICE_PATHS_LIMIT
            ));
        }
        if !(1..=Self::MAX_SEEN_INTERACTIONS_LIMIT).contains(&self.max_seen_interactions) {
            return Err(format!(
                "trace_correlation.max_seen_interactions must be between 1 and {}",
                Self::MAX_SEEN_INTERACTIONS_LIMIT
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(format!(
                "trace_correlation.max_warnings must be between 1 and {}",
                Self::MAX_WARNINGS_LIMIT
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

impl ResourceSourceConfig {
    fn validate(&self) -> Result<(), String> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err("resource_source.procfs_root must not be empty".to_string());
        }
        if self.sysfs_root.as_os_str().is_empty() {
            return Err("resource_source.sysfs_root must not be empty".to_string());
        }
        if self.cgroup_root.as_os_str().is_empty() {
            return Err("resource_source.cgroup_root must not be empty".to_string());
        }
        if self.max_processes == 0 {
            return Err("resource_source.max_processes must be greater than zero".to_string());
        }
        if self.max_cgroups == 0 {
            return Err("resource_source.max_cgroups must be greater than zero".to_string());
        }
        if self.max_fds_per_process == 0 {
            return Err(
                "resource_source.max_fds_per_process must be greater than zero".to_string(),
            );
        }
        if self.max_file_bytes == 0 {
            return Err("resource_source.max_file_bytes must be greater than zero".to_string());
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
    fn validate(&self) -> Result<(), String> {
        if self.max_keys == 0 {
            return Err("resource_metrics.max_keys must be greater than zero".to_string());
        }
        Ok(())
    }
}

impl NetworkMetricsConfig {
    fn validate(&self) -> Result<(), String> {
        if self.max_metric_keys == 0 {
            return Err("network_metrics.max_metric_keys must be greater than zero".to_string());
        }

        if self.max_active_connections == 0 {
            return Err(
                "network_metrics.max_active_connections must be greater than zero".to_string(),
            );
        }

        Ok(())
    }
}

impl NetworkEndpointConfig {
    fn validate(&self) -> Result<(), String> {
        self.address.parse::<IpAddr>().map_err(|_| {
            "runtime_security.kubernetes_api_endpoints.address must be an IP address".to_string()
        })?;

        if self.port == 0 {
            return Err(
                "runtime_security.kubernetes_api_endpoints.port must be greater than zero"
                    .to_string(),
            );
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
        ModuleConfig::enabled("source.host_resource"),
        ModuleConfig::enabled("source.synthetic_exec"),
        ModuleConfig::enabled("processor.container_attribution"),
        ModuleConfig::enabled("generator.resource_metrics"),
        ModuleConfig::enabled("generator.network_metrics"),
        ModuleConfig::enabled("generator.dns_metrics"),
        ModuleConfig::enabled("generator.trace_correlation"),
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
        assert!(config.module_enabled("source.host_resource"));
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(config.module_enabled("processor.container_attribution"));
        assert!(config.module_enabled("generator.resource_metrics"));
        assert!(config.module_enabled("generator.network_metrics"));
        assert!(config.module_enabled("generator.dns_metrics"));
        assert!(config.module_enabled("generator.trace_correlation"));
        assert!(config.module_enabled("generator.dependency_graph"));
        assert!(config.module_enabled("generator.runtime_security"));
        assert!(config.module_enabled("sink.json_stdout"));
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
