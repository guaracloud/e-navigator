use super::*;
use crate::ModuleKind;
use std::collections::BTreeMap;
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

fn assert_toml_rejects_unknown_field(toml: &str, field: &str) {
    let err = toml::from_str::<RuntimeConfig>(toml)
        .expect_err("unknown config fields should be rejected");

    assert!(
        err.to_string()
            .contains(&format!("unknown field `{field}`")),
        "error {err:?} should mention unknown field {field:?}"
    );
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
            ModuleConfig::disabled("source.aya_dns"),
            ModuleConfig::disabled("source.aya_http"),
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
            ModuleConfig::disabled("sink.prometheus_http"),
            ModuleConfig::disabled("sink.otlp_http"),
        ]
    );
}

#[test]
fn default_config_does_not_inflate_opt_in_module_claims() {
    let config = RuntimeConfig::default();

    assert!(!config.module_enabled("source.aya_cpu_profile"));
    assert!(!config.cpu_profile_source.enabled);
}

#[test]
fn known_modules_include_opt_in_dns_runtime_source_without_default_runtime_claim() {
    let config = RuntimeConfig::default();

    assert!(is_known_module_name("source.aya_dns"));
    assert!(!config.module_enabled("source.aya_dns"));
    assert!(is_known_module_name("source.aya_http"));
    assert!(!config.module_enabled("source.aya_http"));
    assert!(is_known_module_name("generator.dns_metrics"));
}

#[test]
fn runtime_config_rejects_unknown_top_level_fields() {
    assert_toml_rejects_unknown_field(
        r#"
        queue_capacity = 64
        queue_capcity = 128

        [[modules]]
        name = "source.synthetic_exec"
        enabled = true
        "#,
        "queue_capcity",
    );
}

#[test]
fn runtime_config_rejects_unknown_nested_fields() {
    assert_toml_rejects_unknown_field(
        r#"
        queue_capacity = 64

        [attribution.kubernetes]
        enabled = true
        namespace_allowlist = ["default"]
        namespace_alllowlist = ["typo"]

        [[modules]]
        name = "source.synthetic_exec"
        enabled = true
        "#,
        "namespace_alllowlist",
    );
}

#[test]
fn runtime_config_rejects_unknown_module_fields() {
    assert_toml_rejects_unknown_field(
        r#"
        queue_capacity = 64

        [[modules]]
        name = "source.synthetic_exec"
        enabled = true
        enabeld = false
        "#,
        "enabeld",
    );
}

#[test]
fn known_sinks_claim_only_json_stdout_as_concrete_registered_sink() {
    let sinks = KNOWN_MODULES
        .iter()
        .filter(|module| module.kind == ModuleKind::Sink)
        .map(|module| module.name)
        .collect::<Vec<_>>();

    assert_eq!(
        sinks,
        vec!["sink.json_stdout", "sink.prometheus_http", "sink.otlp_http"]
    );
    assert!(!is_known_module_name("sink.pyroscope"));
    assert!(!is_known_module_name("sink.pprof"));
}

#[test]
fn prometheus_http_sink_defaults_are_bounded_and_disabled() {
    let config = RuntimeConfig::default();

    assert!(!config.module_enabled("sink.prometheus_http"));
    assert!(!config.prometheus_http.enabled);
    assert_eq!(config.prometheus_http.bind_address, "0.0.0.0");
    assert_eq!(config.prometheus_http.port, 9090);
    assert_eq!(config.prometheus_http.max_metric_lines, 4096);
    assert!(config.prometheus_http.metrics_enabled);
    assert!(config.prometheus_http.profiles_enabled);
}

#[test]
fn prometheus_http_sink_config_is_validated_when_enabled() {
    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: String::new(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.bind_address must not be empty when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: " 127.0.0.1".to_string(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.bind_address must not have leading or trailing whitespace when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: "127.0.0.1 0.0.0.0".to_string(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.bind_address must not contain whitespace when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: "127.0.0.1\0".to_string(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.bind_address must not contain control characters when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: "a".repeat(PrometheusHttpConfig::MAX_BIND_ADDRESS_BYTES_LIMIT + 1),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "prometheus_http.bind_address must be at most {} bytes when sink.prometheus_http is enabled",
            PrometheusHttpConfig::MAX_BIND_ADDRESS_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: "127.0.0.1:9090".to_string(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.bind_address must not include a port because prometheus_http.port is configured separately",
    );

    assert!(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                bind_address: "[::1]".to_string(),
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        }
        .validate()
        .is_ok()
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                port: 0,
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.port must be greater than zero when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                max_metric_lines: 0,
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.max_metric_lines must be greater than zero when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                max_metric_lines: PrometheusHttpConfig::MAX_METRIC_LINES_LIMIT + 1,
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "prometheus_http.max_metric_lines must be less than or equal to {} when sink.prometheus_http is enabled",
            PrometheusHttpConfig::MAX_METRIC_LINES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("sink.prometheus_http"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                metrics_enabled: false,
                profiles_enabled: false,
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http must enable at least one signal family when sink.prometheus_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::disabled("sink.prometheus_http"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            prometheus_http: PrometheusHttpConfig {
                enabled: true,
                ..PrometheusHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "prometheus_http.enabled requires enabled sink.prometheus_http module",
    );
}

#[test]
fn otlp_http_sink_defaults_are_bounded_and_disabled() {
    let config = RuntimeConfig::default();

    assert!(!config.module_enabled("sink.otlp_http"));
    assert!(!config.otlp_http.enabled);
    assert_eq!(config.otlp_http.endpoint, "");
    assert_eq!(config.otlp_http.metrics_endpoint, "");
    assert_eq!(config.otlp_http.traces_endpoint, "");
    assert_eq!(config.otlp_http.profiles_endpoint, "");
    assert!(config.otlp_http.metrics_enabled);
    assert!(config.otlp_http.traces_enabled);
    assert!(config.otlp_http.profiles_enabled);
    assert_eq!(config.otlp_http.queue_capacity, 1024);
    assert_eq!(config.otlp_http.batch_size, 64);
    assert_eq!(config.otlp_http.timeout_millis, 3000);
    assert_eq!(config.otlp_http.max_retries, 2);
}

#[test]
fn otlp_http_sink_config_is_validated_when_enabled() {
    let enabled_modules = || {
        vec![
            ModuleConfig::enabled("source.synthetic_exec"),
            ModuleConfig::enabled("sink.otlp_http"),
        ]
    };

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: String::new(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.metrics_endpoint or otlp_http.endpoint is required when OTLP metrics are enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                metrics_enabled: false,
                traces_enabled: true,
                profiles_enabled: false,
                traces_endpoint: String::new(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.traces_endpoint or otlp_http.endpoint is required when OTLP traces are enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                metrics_enabled: false,
                traces_enabled: false,
                profiles_enabled: true,
                profiles_endpoint: String::new(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.profiles_endpoint or otlp_http.endpoint is required when OTLP profiles are enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                queue_capacity: 0,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.queue_capacity must be greater than zero when sink.otlp_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                queue_capacity: OtlpHttpConfig::MAX_QUEUE_CAPACITY_LIMIT + 1,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "otlp_http.queue_capacity must be less than or equal to {} when sink.otlp_http is enabled",
            OtlpHttpConfig::MAX_QUEUE_CAPACITY_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                batch_size: 0,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.batch_size must be greater than zero when sink.otlp_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                batch_size: OtlpHttpConfig::MAX_BATCH_SIZE_LIMIT + 1,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "otlp_http.batch_size must be less than or equal to {} when sink.otlp_http is enabled",
            OtlpHttpConfig::MAX_BATCH_SIZE_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                timeout_millis: 0,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.timeout_millis must be greater than zero when sink.otlp_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                timeout_millis: OtlpHttpConfig::MAX_TIMEOUT_MILLIS_LIMIT + 1,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "otlp_http.timeout_millis must be less than or equal to {} when sink.otlp_http is enabled",
            OtlpHttpConfig::MAX_TIMEOUT_MILLIS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                max_retries: OtlpHttpConfig::MAX_RETRIES_LIMIT + 1,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "otlp_http.max_retries must be less than or equal to {} when sink.otlp_http is enabled",
            OtlpHttpConfig::MAX_RETRIES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                metrics_enabled: false,
                traces_enabled: false,
                profiles_enabled: false,
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http must enable at least one signal family when sink.otlp_http is enabled",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "grpc://127.0.0.1:4317".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must start with http:// or https://",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: " http://127.0.0.1:4318".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must not contain whitespace",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/\0metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must not contain control characters",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must include a host after the scheme",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://[::1/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must include a host after the scheme",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http:///v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must include a host after the scheme",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://:4318/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.endpoint must include a host after the scheme",
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: format!(
                    "http://{}",
                    "a".repeat(OtlpHttpConfig::MAX_ENDPOINT_BYTES_LIMIT)
                ),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "otlp_http.endpoint must be at most {} bytes",
            OtlpHttpConfig::MAX_ENDPOINT_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            modules: enabled_modules(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                metrics_endpoint: "ftp://127.0.0.1:4318/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.metrics_endpoint must start with http:// or https://",
    );

    assert_invalid(
        RuntimeConfig {
            modules: vec![
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::disabled("sink.otlp_http"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "otlp_http.enabled requires enabled sink.otlp_http module",
    );
}

#[test]
fn otlp_http_sink_accepts_family_specific_and_fallback_endpoints() {
    let enabled_modules = vec![
        ModuleConfig::enabled("source.synthetic_exec"),
        ModuleConfig::enabled("sink.otlp_http"),
    ];

    assert!(
        RuntimeConfig {
            modules: enabled_modules.clone(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: String::new(),
                metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                traces_endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                profiles_endpoint: "http://127.0.0.1:4318/v1development/profiles".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        }
        .validate()
        .is_ok()
    );

    assert!(
        RuntimeConfig {
            modules: enabled_modules.clone(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://127.0.0.1:4318".to_string(),
                metrics_endpoint: "http://127.0.0.1:4319/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        }
        .validate()
        .is_ok()
    );

    assert!(
        RuntimeConfig {
            modules: enabled_modules.clone(),
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: String::new(),
                metrics_enabled: false,
                traces_enabled: true,
                profiles_enabled: false,
                traces_endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        }
        .validate()
        .is_ok()
    );

    assert!(
        RuntimeConfig {
            modules: enabled_modules,
            otlp_http: OtlpHttpConfig {
                enabled: true,
                endpoint: "http://[::1]:4318/v1/metrics".to_string(),
                ..OtlpHttpConfig::default()
            },
            ..RuntimeConfig::default()
        }
        .validate()
        .is_ok()
    );
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
        "unknown module 'generator.dns_typo'; known modules: source.aya_exec, source.aya_network, source.aya_dns, source.aya_http, source.aya_cpu_profile, source.host_resource, source.synthetic_exec, processor.container_attribution, generator.resource_metrics, generator.network_metrics, generator.dns_metrics, generator.trace_correlation, generator.request_correlation, generator.profiling, generator.dependency_graph, generator.runtime_security, sink.json_stdout, sink.prometheus_http, sink.otlp_http",
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
fn runtime_log_level_is_bounded() {
    assert_invalid(
        RuntimeConfig {
            log_level: String::new(),
            ..RuntimeConfig::default()
        },
        "log_level must not be empty",
    );

    assert_invalid(
        RuntimeConfig {
            log_level: " info".to_string(),
            ..RuntimeConfig::default()
        },
        "log_level must not have leading or trailing whitespace",
    );

    assert_invalid(
        RuntimeConfig {
            log_level: "info\nwarn".to_string(),
            ..RuntimeConfig::default()
        },
        "log_level must not contain control characters",
    );

    assert_invalid(
        RuntimeConfig {
            log_level: "x".repeat(RuntimeConfig::MAX_LOG_LEVEL_BYTES_LIMIT + 1),
            ..RuntimeConfig::default()
        },
        format!(
            "log_level must be at most {} bytes",
            RuntimeConfig::MAX_LOG_LEVEL_BYTES_LIMIT
        ),
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
fn runtime_queue_capacity_is_bounded() {
    assert_invalid(
        RuntimeConfig {
            queue_capacity: RuntimeConfig::MAX_QUEUE_CAPACITY_LIMIT + 1,
            ..RuntimeConfig::default()
        },
        format!(
            "queue_capacity must be less than or equal to {}",
            RuntimeConfig::MAX_QUEUE_CAPACITY_LIMIT
        ),
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
            max_derived_signals_per_input: RuntimeConfig::MAX_DERIVED_SIGNALS_PER_INPUT_LIMIT + 1,
            ..RuntimeConfig::default()
        },
        format!(
            "max_derived_signals_per_input must be less than or equal to {}",
            RuntimeConfig::MAX_DERIVED_SIGNALS_PER_INPUT_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            max_derived_signal_depth: 0,
            ..RuntimeConfig::default()
        },
        "max_derived_signal_depth must be greater than zero",
    );

    assert_invalid(
        RuntimeConfig {
            max_derived_signal_depth: RuntimeConfig::MAX_DERIVED_SIGNAL_DEPTH_LIMIT + 1,
            ..RuntimeConfig::default()
        },
        format!(
            "max_derived_signal_depth must be less than or equal to {}",
            RuntimeConfig::MAX_DERIVED_SIGNAL_DEPTH_LIMIT
        ),
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

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                procfs_root: PathBuf::from(format!(
                    "/{}",
                    "p".repeat(AttributionConfig::MAX_PATH_BYTES_LIMIT)
                )),
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.procfs_root must be at most {} bytes",
            AttributionConfig::MAX_PATH_BYTES_LIMIT
        ),
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

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    token_path: PathBuf::from(format!(
                        "/{}",
                        "t".repeat(KubernetesAttributionConfig::MAX_PATH_BYTES_LIMIT)
                    )),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.token_path must be at most {} bytes",
            KubernetesAttributionConfig::MAX_PATH_BYTES_LIMIT
        ),
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
fn kubernetes_attribution_limits_are_bounded() {
    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    max_response_bytes: KubernetesAttributionConfig::MAX_RESPONSE_BYTES_LIMIT + 1,
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.max_response_bytes must be less than or equal to {}",
            KubernetesAttributionConfig::MAX_RESPONSE_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    max_pods: KubernetesAttributionConfig::MAX_PODS_LIMIT + 1,
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.max_pods must be less than or equal to {}",
            KubernetesAttributionConfig::MAX_PODS_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    max_cache_entries: KubernetesAttributionConfig::MAX_CACHE_ENTRIES_LIMIT + 1,
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.max_cache_entries must be less than or equal to {}",
            KubernetesAttributionConfig::MAX_CACHE_ENTRIES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    max_labels_per_pod: KubernetesAttributionConfig::MAX_LABELS_PER_POD_LIMIT + 1,
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.max_labels_per_pod must be less than or equal to {}",
            KubernetesAttributionConfig::MAX_LABELS_PER_POD_LIMIT
        ),
    );
}

#[test]
fn kubernetes_attribution_selectors_are_validated() {
    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    label_allowlist: (0..=KubernetesAttributionConfig::MAX_SELECTOR_ENTRIES_LIMIT)
                        .map(|index| format!("label-{index}"))
                        .collect(),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.label_allowlist must contain at most {} entries",
            KubernetesAttributionConfig::MAX_SELECTOR_ENTRIES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec![
                        "n".repeat(KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT + 1),
                    ],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.namespace_allowlist entries must be at most {} bytes",
            KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec!["default".to_string(), " ".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.namespace_allowlist entries must not be empty",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec!["default\nprod".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.namespace_allowlist entries must not contain control characters",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec!["default prod".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.namespace_allowlist entries must not contain whitespace",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    label_allowlist: vec!["app".to_string(), "app".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.label_allowlist must not contain duplicate entry 'app'",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec!["default".to_string(), "default".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.namespace_allowlist must not contain duplicate entry 'default'",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    namespace_allowlist: vec!["default".to_string()],
                    namespace_denylist: vec!["default".to_string()],
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.namespace_denylist cannot contain 'default' because it is also allowed",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([("app".to_string(), String::new())]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.pod_label_selector value for 'app' must not be empty",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app\nrole".to_string(),
                        "checkout".to_string(),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.pod_label_selector keys must not contain control characters",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app role".to_string(),
                        "checkout".to_string(),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.pod_label_selector keys must not contain whitespace",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: (0
                        ..=KubernetesAttributionConfig::MAX_SELECTOR_ENTRIES_LIMIT)
                        .map(|index| (format!("label-{index}"), "value".to_string()))
                        .collect(),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.pod_label_selector must contain at most {} entries",
            KubernetesAttributionConfig::MAX_SELECTOR_ENTRIES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app".to_string(),
                        "v".repeat(KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT + 1),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "attribution.kubernetes.pod_label_selector value for 'app' must be at most {} bytes",
            KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT
        ),
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app".to_string(),
                        "checkout\tapi".to_string(),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.pod_label_selector value for 'app' must not contain control characters",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app".to_string(),
                        "checkout api".to_string(),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes.pod_label_selector value for 'app' must not contain whitespace",
    );

    assert_invalid(
        RuntimeConfig {
            attribution: AttributionConfig {
                kubernetes: KubernetesAttributionConfig {
                    pod_label_selector: BTreeMap::from([(
                        "app".to_string(),
                        "checkout".to_string(),
                    )]),
                    pod_label_exclude_selector: BTreeMap::from([(
                        "app".to_string(),
                        "checkout".to_string(),
                    )]),
                    ..KubernetesAttributionConfig::default()
                },
                ..AttributionConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "attribution.kubernetes pod label selector for 'app' cannot require and exclude the same value",
    );
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
                procfs_root: PathBuf::from(format!(
                    "/{}",
                    "r".repeat(ResourceSourceConfig::MAX_PATH_BYTES_LIMIT)
                )),
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.procfs_root must be at most {} bytes",
            ResourceSourceConfig::MAX_PATH_BYTES_LIMIT
        ),
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                sample_interval_millis: 0,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "resource_source.sample_interval_millis must be greater than zero",
    );
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                sample_interval_millis: ResourceSourceConfig::MAX_SAMPLE_INTERVAL_MILLIS_LIMIT + 1,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.sample_interval_millis must be less than or equal to {}",
            ResourceSourceConfig::MAX_SAMPLE_INTERVAL_MILLIS_LIMIT
        ),
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
                max_processes: ResourceSourceConfig::MAX_PROCESSES_LIMIT + 1,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.max_processes must be less than or equal to {}",
            ResourceSourceConfig::MAX_PROCESSES_LIMIT
        ),
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
                max_cgroups: ResourceSourceConfig::MAX_CGROUPS_LIMIT + 1,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.max_cgroups must be less than or equal to {}",
            ResourceSourceConfig::MAX_CGROUPS_LIMIT
        ),
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
                max_fds_per_process: ResourceSourceConfig::MAX_FDS_PER_PROCESS_LIMIT + 1,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.max_fds_per_process must be less than or equal to {}",
            ResourceSourceConfig::MAX_FDS_PER_PROCESS_LIMIT
        ),
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
    assert_invalid(
        RuntimeConfig {
            resource_source: ResourceSourceConfig {
                max_file_bytes: ResourceSourceConfig::MAX_FILE_BYTES_LIMIT + 1,
                ..ResourceSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_source.max_file_bytes must be less than or equal to {}",
            ResourceSourceConfig::MAX_FILE_BYTES_LIMIT
        ),
    );
}

#[test]
fn http_source_defaults_are_bounded() {
    let config = RuntimeConfig::default();

    assert_eq!(config.http_source.max_header_bytes, 8 * 1024);
    assert_eq!(config.http_source.max_request_line_bytes, 1024);
    assert_eq!(config.http_source.max_attributes, 8);
    assert_eq!(config.http_source.max_tracestate_bytes, 512);
}

#[test]
fn http_source_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_header_bytes: 0,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_header_bytes must be between 1 and 8192",
    );

    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_request_line_bytes: 0,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_request_line_bytes must be between 1 and 1024",
    );

    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_attributes: HttpSourceConfig::MAX_ATTRIBUTES_LIMIT + 1,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_attributes must be between 1 and 32",
    );

    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_tracestate_bytes: HttpSourceConfig::MAX_TRACESTATE_BYTES_LIMIT + 1,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_tracestate_bytes must be between 1 and 4096",
    );

    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 17,
                max_tracestate_bytes: 16,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_request_line_bytes must be less than or equal to http_source.max_header_bytes",
    );

    assert_invalid(
        RuntimeConfig {
            http_source: HttpSourceConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 16,
                max_tracestate_bytes: 17,
                ..HttpSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "http_source.max_tracestate_bytes must be less than or equal to http_source.max_header_bytes",
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

    assert_invalid(
        RuntimeConfig {
            resource_metrics: ResourceMetricsConfig {
                max_keys: ResourceMetricsConfig::MAX_KEYS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "resource_metrics.max_keys must be less than or equal to {}",
            ResourceMetricsConfig::MAX_KEYS_LIMIT
        ),
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
                max_metric_keys: NetworkMetricsConfig::MAX_METRIC_KEYS_LIMIT + 1,
                max_active_connections: 128,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "network_metrics.max_metric_keys must be less than or equal to {}",
            NetworkMetricsConfig::MAX_METRIC_KEYS_LIMIT
        ),
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

    assert_invalid(
        RuntimeConfig {
            network_metrics: NetworkMetricsConfig {
                max_metric_keys: 128,
                max_active_connections: NetworkMetricsConfig::MAX_ACTIVE_CONNECTIONS_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        },
        format!(
            "network_metrics.max_active_connections must be less than or equal to {}",
            NetworkMetricsConfig::MAX_ACTIVE_CONNECTIONS_LIMIT
        ),
    );
}

#[test]
fn runtime_security_kubernetes_api_endpoints_are_validated() {
    assert_invalid(
        RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![
                    NetworkEndpointConfig {
                        address: "10.96.0.1".to_string(),
                        port: 443,
                    };
                    RuntimeSecurityConfig::MAX_KUBERNETES_API_ENDPOINTS_LIMIT
                        + 1
                ],
            },
            ..RuntimeConfig::default()
        },
        format!(
            "runtime_security.kubernetes_api_endpoints must contain at most {} entries",
            RuntimeSecurityConfig::MAX_KUBERNETES_API_ENDPOINTS_LIMIT
        ),
    );

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
fn dns_source_defaults_are_bounded() {
    let config = RuntimeConfig::default();

    assert_eq!(config.dns_source.max_packet_bytes, 512);
    assert_eq!(config.dns_source.max_preview_bytes, 160);
}

#[test]
fn dns_source_limits_are_validated() {
    assert_invalid(
        RuntimeConfig {
            dns_source: DnsSourceConfig {
                max_packet_bytes: 0,
                ..DnsSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_source.max_packet_bytes must be between 12 and 512",
    );

    assert_invalid(
        RuntimeConfig {
            dns_source: DnsSourceConfig {
                max_packet_bytes: DnsSourceConfig::MAX_PACKET_BYTES_LIMIT + 1,
                ..DnsSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_source.max_packet_bytes must be between 12 and 512",
    );

    assert_invalid(
        RuntimeConfig {
            dns_source: DnsSourceConfig {
                max_preview_bytes: 0,
                ..DnsSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_source.max_preview_bytes must be between 1 and 160",
    );

    assert_invalid(
        RuntimeConfig {
            dns_source: DnsSourceConfig {
                max_preview_bytes: DnsSourceConfig::MAX_PREVIEW_BYTES_LIMIT + 1,
                ..DnsSourceConfig::default()
            },
            ..RuntimeConfig::default()
        },
        "dns_source.max_preview_bytes must be between 1 and 160",
    );

    assert_invalid(
        RuntimeConfig {
            dns_source: DnsSourceConfig {
                max_packet_bytes: DnsSourceConfig::MIN_PACKET_BYTES_LIMIT,
                max_preview_bytes: DnsSourceConfig::MIN_PACKET_BYTES_LIMIT + 1,
            },
            ..RuntimeConfig::default()
        },
        "dns_source.max_preview_bytes must be less than or equal to dns_source.max_packet_bytes",
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
                max_domains: DnsMetricsConfig::MAX_DOMAINS_LIMIT + 1,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "dns_metrics.max_domains must be less than or equal to {}",
            DnsMetricsConfig::MAX_DOMAINS_LIMIT
        ),
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
                max_counters: DnsMetricsConfig::MAX_COUNTERS_LIMIT + 1,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "dns_metrics.max_counters must be less than or equal to {}",
            DnsMetricsConfig::MAX_COUNTERS_LIMIT
        ),
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
                max_latencies: DnsMetricsConfig::MAX_LATENCIES_LIMIT + 1,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "dns_metrics.max_latencies must be less than or equal to {}",
            DnsMetricsConfig::MAX_LATENCIES_LIMIT
        ),
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

    assert_invalid(
        RuntimeConfig {
            dns_metrics: DnsMetricsConfig {
                max_edges: DnsMetricsConfig::MAX_EDGES_LIMIT + 1,
                ..DnsMetricsConfig::default()
            },
            ..RuntimeConfig::default()
        },
        format!(
            "dns_metrics.max_edges must be less than or equal to {}",
            DnsMetricsConfig::MAX_EDGES_LIMIT
        ),
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

        [dns_source]
        max_packet_bytes = 512
        max_preview_bytes = 160

        [http_source]
        max_header_bytes = 8192
        max_request_line_bytes = 1024
        max_attributes = 8
        max_tracestate_bytes = 512

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
fn omitted_optional_sections_use_serde_defaults() {
    let config: RuntimeConfig = toml::from_str(
        r#"
        [[modules]]
        name = "sink.json_stdout"
        enabled = true
        "#,
    )
    .expect("omitted optional config sections use serde defaults");

    assert_eq!(config.log_level, RuntimeConfig::default().log_level);
    assert_eq!(
        config.queue_capacity,
        RuntimeConfig::default().queue_capacity
    );
    assert_eq!(config.argv_capture, ArgvCaptureConfig::default());
    assert_eq!(config.attribution, AttributionConfig::default());
    assert_eq!(config.runtime_security, RuntimeSecurityConfig::default());
    assert_eq!(config.resource_source, ResourceSourceConfig::default());
    assert_eq!(config.dns_source, DnsSourceConfig::default());
    assert_eq!(config.http_source, HttpSourceConfig::default());
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
