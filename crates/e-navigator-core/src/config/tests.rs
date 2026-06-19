use super::*;
use crate::ModuleKind;
use std::path::PathBuf;

fn assert_invalid(config: RuntimeConfig, expected: impl Into<String>) {
    let expected = expected.into();
    let typed = config
        .validate_typed()
        .expect_err("config should be invalid");

    assert_eq!(typed.to_string(), expected);
    assert_eq!(config.validate(), Err(expected));
}

fn cpu_profile_modules() -> Vec<ModuleConfig> {
    vec![
        ModuleConfig::enabled("source.aya_cpu_profile"),
        ModuleConfig::enabled("sink.json_stdout"),
    ]
}

#[test]
fn default_config_is_valid_and_preserves_expected_modules() {
    let config = RuntimeConfig::default();

    assert!(config.validate().is_ok());
    assert!(config.queue_capacity > 0);
    assert_eq!(
        config.modules,
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
            ModuleConfig::disabled("generator.guara_compat"),
            ModuleConfig::enabled("sink.json_stdout"),
        ]
    );
}

#[test]
fn default_config_does_not_inflate_opt_in_module_claims() {
    let config = RuntimeConfig::default();

    assert!(!config.module_enabled("source.aya_cpu_profile"));
    assert!(!config.cpu_profile_source.enabled);
    assert!(!config.module_enabled("generator.guara_compat"));
}

#[test]
fn known_modules_keep_dns_as_schema_generator_support_not_runtime_capture_source() {
    assert!(!is_known_module_name("source.aya_dns"));
    assert!(is_known_module_name("generator.dns_metrics"));
}

#[test]
fn known_sinks_claim_only_json_stdout_as_concrete_registered_sink() {
    let sinks = KNOWN_MODULES
        .iter()
        .filter(|module| module.kind == ModuleKind::Sink)
        .map(|module| module.name)
        .collect::<Vec<_>>();

    assert_eq!(sinks, vec!["sink.json_stdout"]);
    assert!(!is_known_module_name("sink.otlp"));
    assert!(!is_known_module_name("sink.pyroscope"));
    assert!(!is_known_module_name("sink.pprof"));
}

#[test]
fn module_enabled_reports_enabled_disabled_and_missing_modules() {
    let config = RuntimeConfig::default();

    assert!(config.module_enabled("source.aya_exec"));
    assert!(!config.module_enabled("source.aya_cpu_profile"));
    assert!(!config.module_enabled("source.missing"));
}

#[test]
fn no_enabled_modules_is_invalid() {
    let config = RuntimeConfig {
        modules: vec![ModuleConfig {
            name: "sink.json_stdout".to_string(),
            enabled: false,
        }],
        ..RuntimeConfig::default()
    };

    assert_invalid(config, "at least one module must be enabled");
}

#[test]
fn unknown_module_names_are_invalid_and_list_known_modules() {
    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("generator.dns_typo"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            ..RuntimeConfig::default()
        },
        "unknown module 'generator.dns_typo'; known modules: source.aya_exec, source.aya_network, source.aya_cpu_profile, source.host_resource, source.synthetic_exec, processor.container_attribution, generator.resource_metrics, generator.network_metrics, generator.dns_metrics, generator.trace_correlation, generator.request_correlation, generator.profiling, generator.dependency_graph, generator.runtime_security, generator.guara_compat, sink.json_stdout",
    );
}

#[test]
fn duplicate_module_names_are_invalid() {
    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            ..RuntimeConfig::default()
        },
        "duplicate module 'source.synthetic_exec'",
    );
}

#[test]
fn zero_queue_capacity_is_invalid_with_typed_error_metadata() {
    let config = RuntimeConfig {
        queue_capacity: 0,
        ..RuntimeConfig::default()
    };

    let err = config
        .validate_typed()
        .expect_err("queue capacity is invalid");
    assert_eq!(err.field(), "queue_capacity");
    assert_eq!(err.category(), ConfigErrorKind::InvalidValue);
    assert_eq!(err.to_string(), "queue_capacity must be greater than zero");
    assert_eq!(
        config.validate(),
        Err("queue_capacity must be greater than zero".to_string())
    );
}

#[test]
fn runtime_derived_signal_bounds_are_validated() {
    assert_invalid(
        RuntimeConfig {
            max_derived_signals_per_input: 0,
            ..RuntimeConfig::default()
        },
        "max_derived_signals_per_input must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            max_derived_signal_depth: 0,
            ..RuntimeConfig::default()
        },
        "max_derived_signal_depth must be greater than zero",
    );
}

#[test]
fn argv_capture_defaults_are_bounded_and_disabled() {
    let config = RuntimeConfig::default();

    assert!(!config.argv_capture.enabled);
    assert_eq!(config.argv_capture.max_args, 8);
    assert_eq!(config.argv_capture.max_bytes, 512);
}

#[test]
fn argv_capture_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 0,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        },
        "argv_capture.max_args must be between 1 and 8",
    );

    assert_invalid(
        RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 9,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        },
        "argv_capture.max_args must be between 1 and 8",
    );

    assert_invalid(
        RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 8,
                max_bytes: 0,
            },
            ..RuntimeConfig::default()
        },
        "argv_capture.max_bytes must be between 1 and 512",
    );

    assert_invalid(
        RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 8,
                max_bytes: 513,
            },
            ..RuntimeConfig::default()
        },
        "argv_capture.max_bytes must be between 1 and 512",
    );
}

#[test]
fn attribution_paths_are_validated() {
    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                procfs_root: PathBuf::new(),
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.procfs_root must not be empty",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                cgroup_root: PathBuf::new(),
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.cgroup_root must not be empty",
    );
}

#[test]
fn kubernetes_attribution_paths_are_validated_when_enabled() {
    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    token_path: PathBuf::new(),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.token_path must not be empty when Kubernetes attribution is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    ca_cert_path: PathBuf::new(),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.ca_cert_path must not be empty when Kubernetes attribution is enabled",
    );

    let config = RuntimeConfig {
        attribution: AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                token_path: PathBuf::new(),
                ca_cert_path: PathBuf::new(),
                ..KubernetesAttributionConfig::default()
            },
            ..AttributionConfig::default()
        },
        ..RuntimeConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn resource_source_paths_and_bounds_are_validated() {
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                procfs_root: PathBuf::new(),
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.procfs_root must not be empty",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                sysfs_root: PathBuf::new(),
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.sysfs_root must not be empty",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                cgroup_root: PathBuf::new(),
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.cgroup_root must not be empty",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_processes: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.max_processes must be greater than zero",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_cgroups: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.max_cgroups must be greater than zero",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_fds_per_process: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.max_fds_per_process must be greater than zero",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_file_bytes: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.max_file_bytes must be greater than zero",
    );
}

#[test]
fn resource_metrics_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            resource_metrics: ResourceMetricsConfig { max_keys: 0 },
            ..RuntimeConfig::default()
        },
        "resource_metrics.max_keys must be greater than zero",
    );
}

#[test]
fn network_metrics_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            network_metrics: NetworkMetricsConfig {
                max_metric_keys: 0,
                max_active_connections: 128,
            },
            ..RuntimeConfig::default()
        },
        "network_metrics.max_metric_keys must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            network_metrics: NetworkMetricsConfig {
                max_metric_keys: 128,
                max_active_connections: 0,
            },
            ..RuntimeConfig::default()
        },
        "network_metrics.max_active_connections must be greater than zero",
    );
}

#[test]
fn runtime_security_kubernetes_api_endpoints_are_validated() {
    assert_invalid(
        RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![NetworkEndpointConfig {
                    address: "kubernetes.default.svc".to_string(),
                    port: 443,
                }],
            },
            ..RuntimeConfig::default()
        },
        "runtime_security.kubernetes_api_endpoints.address must be an IP address",
    );

    assert_invalid(
        RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![NetworkEndpointConfig {
                    address: "10.96.0.1".to_string(),
                    port: 0,
                }],
            },
            ..RuntimeConfig::default()
        },
        "runtime_security.kubernetes_api_endpoints.port must be greater than zero",
    );
}

#[test]
fn dns_metrics_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            dns_metrics: DnsMetricsConfig {
                max_domains: 0,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_metrics.max_domains must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            dns_metrics: DnsMetricsConfig {
                max_counters: 0,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_metrics.max_counters must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            dns_metrics: DnsMetricsConfig {
                max_latencies: 0,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_metrics.max_latencies must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            dns_metrics: DnsMetricsConfig {
                max_edges: 0,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_metrics.max_edges must be greater than zero",
    );
}

#[test]
fn trace_correlation_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 0,
                max_seen_interactions: 128,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "trace_correlation.max_service_paths must be between 1 and {}",
            TraceCorrelationConfig::MAX_SERVICE_PATHS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: TraceCorrelationConfig::MAX_SEEN_INTERACTIONS_LIMIT + 1,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "trace_correlation.max_seen_interactions must be between 1 and {}",
            TraceCorrelationConfig::MAX_SEEN_INTERACTIONS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            trace_correlation: TraceCorrelationConfig {
                max_service_paths: 128,
                max_seen_interactions: 128,
                max_warnings: 0,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "trace_correlation.max_warnings must be between 1 and {}",
            TraceCorrelationConfig::MAX_WARNINGS_LIMIT
        ),
    );
}

#[test]
fn request_correlation_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            request_correlation: RequestCorrelationConfig {
                max_seen_requests: 0,
                max_warnings: 128,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "request_correlation.max_seen_requests must be between 1 and {}",
            RequestCorrelationConfig::MAX_SEEN_REQUESTS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            request_correlation: RequestCorrelationConfig {
                max_seen_requests: 128,
                max_warnings: RequestCorrelationConfig::MAX_WARNINGS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "request_correlation.max_warnings must be between 1 and {}",
            RequestCorrelationConfig::MAX_WARNINGS_LIMIT
        ),
    );
}

#[test]
fn profiling_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 0,
                max_seen_samples: 128,
                max_warnings: 128,
                window_nanos: 1_000_000_000,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "profiling.max_windows must be between 1 and {}",
            ProfilingConfig::MAX_WINDOWS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 0,
                max_warnings: 128,
                window_nanos: 1_000_000_000,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "profiling.max_seen_samples must be between 1 and {}",
            ProfilingConfig::MAX_SEEN_SAMPLES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 128,
                max_warnings: ProfilingConfig::MAX_WARNINGS_LIMIT + 1,
                window_nanos: 1_000_000_000,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "profiling.max_warnings must be between 1 and {}",
            ProfilingConfig::MAX_WARNINGS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            profiling: ProfilingConfig {
                max_windows: 128,
                max_seen_samples: 128,
                max_warnings: 128,
                window_nanos: ProfilingConfig::MAX_WINDOW_NANOS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "profiling.window_nanos must be between 1 and {}",
            ProfilingConfig::MAX_WINDOW_NANOS_LIMIT
        ),
    );
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
    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                sample_frequency_hz: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.sample_frequency_hz must be between 1 and {}",
            CpuProfileSourceConfig::MAX_SAMPLE_FREQUENCY_HZ
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_active_targets: CpuProfileSourceConfig::MAX_ACTIVE_TARGETS_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_active_targets must be between 1 and {}",
            CpuProfileSourceConfig::MAX_ACTIVE_TARGETS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_frames_per_sample: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_frames_per_sample must be between 1 and {}",
            CpuProfileSourceConfig::MAX_FRAMES_PER_SAMPLE_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_samples_per_batch: 0,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_samples_per_batch must be between 1 and {}",
            CpuProfileSourceConfig::MAX_SAMPLES_PER_BATCH_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_symbol_bytes: CpuProfileSourceConfig::MAX_SYMBOL_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_symbol_bytes must be between 1 and {}",
            CpuProfileSourceConfig::MAX_SYMBOL_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_module_bytes: CpuProfileSourceConfig::MAX_MODULE_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_module_bytes must be between 1 and {}",
            CpuProfileSourceConfig::MAX_MODULE_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                max_file_bytes: CpuProfileSourceConfig::MAX_FILE_BYTES_LIMIT + 1,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "cpu_profile_source.max_file_bytes must be between 1 and {}",
            CpuProfileSourceConfig::MAX_FILE_BYTES_LIMIT
        ),
    );
}

#[test]
fn cpu_profile_source_requires_static_module_enablement() {
    let config = RuntimeConfig {
        modules: cpu_profile_modules(),
        cpu_profile_source: CpuProfileSourceConfig {
            enabled: true,
            ..CpuProfileSourceConfig::default()
        },
        ..RuntimeConfig::default()
    };

    assert!(config.validate().is_ok());
    assert!(config.module_enabled("source.aya_cpu_profile"));

    assert_invalid(
        RuntimeConfig {
            modules: cpu_profile_modules(),
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                module_name: "source.dynamic_cpu_profile".to_string(),
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "cpu_profile_source.module_name must be source.aya_cpu_profile",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::disabled("source.aya_cpu_profile"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            cpu_profile_source: CpuProfileSourceConfig {
                enabled: true,
                ..CpuProfileSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "cpu_profile_source.enabled requires enabled source.aya_cpu_profile module",
    );
}

#[test]
fn cpu_profile_backpressure_deserializes_and_defaults() {
    let config: RuntimeConfig = toml::from_str(
        r#"
        [[modules]]
        name = "sink.json_stdout"
        enabled = true

        [cpu_profile_source]
        enabled = false
        "#,
    )
    .expect("config parses");
    assert_eq!(
        config.cpu_profile_source.backpressure,
        CpuProfileBackpressure::DropNewest
    );

    let config: RuntimeConfig = toml::from_str(
        r#"
        [[modules]]
        name = "source.aya_cpu_profile"
        enabled = true

        [[modules]]
        name = "sink.json_stdout"
        enabled = true

        [cpu_profile_source]
        enabled = true
        backpressure = "stop_source"
        "#,
    )
    .expect("config parses");
    assert_eq!(
        config.cpu_profile_source.backpressure,
        CpuProfileBackpressure::StopSource
    );
    assert!(config.validate().is_ok());
}

#[test]
fn representative_runtime_toml_deserializes_and_validates() {
    let config: RuntimeConfig = toml::from_str(
        r#"
        log_level = "debug"
        queue_capacity = 8192

        [argv_capture]
        enabled = true
        max_args = 8
        max_bytes = 512

        [attribution]
        procfs_root = "/host/proc"
        cgroup_root = "/host/cgroup"

        [attribution.kubernetes]
        enabled = true
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        ca_cert_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        [runtime_security]
        kubernetes_api_endpoints = [{ address = "10.96.0.1", port = 443 }]

        [resource_source]
        procfs_root = "/host/proc"
        sysfs_root = "/sys"
        cgroup_root = "/host/cgroup"
        sample_interval_millis = 60000
        max_processes = 64
        max_cgroups = 64
        max_fds_per_process = 1024
        max_file_bytes = 131072

        [cpu_profile_source]
        enabled = false
        module_name = "source.aya_cpu_profile"
        sample_frequency_hz = 49
        max_active_targets = 128
        max_frames_per_sample = 64
        max_samples_per_batch = 64
        max_symbol_bytes = 256
        max_module_bytes = 256
        max_file_bytes = 256
        backpressure = "drop_newest"

        [resource_metrics]
        max_keys = 4096

        [network_metrics]
        max_metric_keys = 4096
        max_active_connections = 8192

        [dns_metrics]
        max_domains = 1024

        [trace_correlation]
        max_service_paths = 4096
        max_seen_interactions = 8192
        max_warnings = 1024

        [request_correlation]
        max_seen_requests = 8192
        max_warnings = 1024

        [profiling]
        max_windows = 4096
        max_seen_samples = 8192
        max_warnings = 1024
        window_nanos = 30000000000

        [[modules]]
        name = "source.aya_exec"
        enabled = true

        [[modules]]
        name = "source.aya_network"
        enabled = true

        [[modules]]
        name = "source.aya_cpu_profile"
        enabled = false

        [[modules]]
        name = "source.host_resource"
        enabled = true

        [[modules]]
        name = "source.synthetic_exec"
        enabled = true

        [[modules]]
        name = "processor.container_attribution"
        enabled = true

        [[modules]]
        name = "generator.resource_metrics"
        enabled = true

        [[modules]]
        name = "generator.network_metrics"
        enabled = true

        [[modules]]
        name = "generator.dns_metrics"
        enabled = true

        [[modules]]
        name = "generator.trace_correlation"
        enabled = true

        [[modules]]
        name = "generator.request_correlation"
        enabled = true

        [[modules]]
        name = "generator.profiling"
        enabled = true

        [[modules]]
        name = "generator.dependency_graph"
        enabled = true

        [[modules]]
        name = "generator.runtime_security"
        enabled = true

        [[modules]]
        name = "sink.json_stdout"
        enabled = true
        "#,
    )
    .expect("representative runtime config parses");

    assert!(config.validate().is_ok());
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.queue_capacity, 8192);
    assert!(config.module_enabled("source.synthetic_exec"));
}

#[test]
fn omitted_optional_sections_and_unknown_fields_use_serde_defaults() {
    let config: RuntimeConfig = toml::from_str(
        r#"
        unknown_root = "ignored"

        [argv_capture]
        unknown_nested = "ignored"

        [[modules]]
        name = "sink.json_stdout"
        enabled = true

        [unknown_section]
        enabled = false
        "#,
    )
    .expect("unknown fields are ignored by serde");

    assert_eq!(config.log_level, RuntimeConfig::default().log_level);
    assert_eq!(
        config.queue_capacity,
        RuntimeConfig::default().queue_capacity
    );
    assert_eq!(config.argv_capture, ArgvCaptureConfig::default());
    assert_eq!(config.attribution, AttributionConfig::default());
    assert_eq!(config.runtime_security, RuntimeSecurityConfig::default());
    assert_eq!(config.resource_source, ResourceSourceConfig::default());
    assert_eq!(config.cpu_profile_source, CpuProfileSourceConfig::default());
    assert_eq!(config.resource_metrics, ResourceMetricsConfig::default());
    assert_eq!(config.network_metrics, NetworkMetricsConfig::default());
    assert_eq!(config.dns_metrics, DnsMetricsConfig::default());
    assert_eq!(config.trace_correlation, TraceCorrelationConfig::default());
    assert_eq!(
        config.request_correlation,
        RequestCorrelationConfig::default()
    );
    assert_eq!(config.profiling, ProfilingConfig::default());
    assert!(config.validate().is_ok());
}
