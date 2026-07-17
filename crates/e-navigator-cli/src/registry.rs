use crate::args::SourceMode;
use crate::synthetic::SyntheticExecSource;
use async_trait::async_trait;
use e_navigator_core::{CoreResult, RuntimeConfig};
use e_navigator_generators::{
    DependencyGraphGenerator, DnsMetricsGenerator, NetworkMetricsGenerator, ProfilingGenerator,
    RequestCorrelationGenerator, ResourceMetricsGenerator, RuntimeSecurityGenerator,
    TraceCorrelationGenerator,
};
use e_navigator_processors::{
    ContainerAttributionProcessor, KubernetesMetadataCache, KubernetesMetadataProvider,
};
use e_navigator_runner::{ModuleRegistry, SourceHealthRegistry};
use e_navigator_sinks::{
    JsonStdoutSink, NativeTelemetryRegistry, NativeTelemetrySource, OtlpHttpSink,
    PrometheusHttpSink, PrometheusMetricLine,
};
use e_navigator_sources_ebpf_aya::{
    AyaCpuProfileSource, AyaDnsSource, AyaExecSource, AyaHttpSource, AyaNetworkSource,
    AyaProtocolSource, AyaTlsSource,
};
use e_navigator_sources_host::{HostResourceConfig, HostResourceSource};

pub(crate) fn build_registry(
    config: &RuntimeConfig,
    source: SourceMode,
    host: Option<String>,
) -> CoreResult<ModuleRegistry> {
    let mut registry = ModuleRegistry::new();
    let telemetry_registry = NativeTelemetryRegistry::default();
    telemetry_registry.register_source(std::sync::Arc::new(WorkloadControllerTelemetrySource));
    telemetry_registry.register_source(std::sync::Arc::new(AyaSourceTelemetrySource));
    telemetry_registry.register_source(std::sync::Arc::new(SourceSupervisorTelemetrySource {
        registry: registry.source_health_registry(),
    }));

    match source {
        SourceMode::Unified | SourceMode::AyaExec if config.module_enabled("source.aya_exec") => {
            registry = registry.with_source(Box::new(AyaExecSource::new(
                host.clone(),
                config.argv_capture.clone(),
                config.attribution.procfs_root.clone(),
            )));
        }
        SourceMode::Synthetic if config.module_enabled("source.synthetic_exec") => {
            registry = registry.with_source(Box::new(SyntheticExecSource { host: host.clone() }));
        }
        _ => {}
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.aya_network")
    {
        registry = registry.with_source(Box::new(AyaNetworkSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.aya_dns")
    {
        registry = registry.with_source(Box::new(AyaDnsSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
            config.dns_source.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.aya_http")
    {
        registry = registry.with_source(Box::new(AyaHttpSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
            config.http_source.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.aya_protocol")
    {
        registry = registry.with_source(Box::new(AyaProtocolSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
            config.protocol_source.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.aya_tls")
    {
        registry = registry.with_source(Box::new(AyaTlsSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
            config.tls_source.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaExec)
        && config.module_enabled("source.host_resource")
    {
        registry = registry.with_source(Box::new(HostResourceSource::with_host(
            host_resource_config(config),
            host.clone(),
        )));
    }

    if matches!(source, SourceMode::Unified | SourceMode::AyaCpuProfile)
        && config.cpu_profile_source.enabled
        && config.module_enabled("source.aya_cpu_profile")
    {
        registry = registry.with_source(Box::new(AyaCpuProfileSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
            config.cpu_profile_source.clone(),
        )));
    }

    if config.module_enabled("processor.container_attribution") {
        registry = registry.with_processor(Box::new(
            ContainerAttributionProcessor::with_kubernetes_provider(
                config.attribution.clone(),
                std::sync::Arc::new(SharedKubernetesMetadataProvider),
            ),
        ));
    }

    if config.module_enabled("generator.dependency_graph") {
        registry = registry.with_generator(Box::new(DependencyGraphGenerator::default()));
    }

    if config.module_enabled("generator.network_metrics") {
        registry = registry.with_generator(Box::new(NetworkMetricsGenerator::with_limits(
            config.network_metrics.max_metric_keys,
            config.network_metrics.max_active_connections,
        )));
    }

    if config.module_enabled("generator.resource_metrics") {
        registry = registry.with_generator(Box::new(ResourceMetricsGenerator::with_limits(
            config.resource_metrics.max_keys,
        )));
    }

    if config.module_enabled("generator.dns_metrics") {
        registry = registry.with_generator(Box::new(DnsMetricsGenerator::with_limits(
            config.dns_metrics.max_domains,
            config.dns_metrics.max_counters,
            config.dns_metrics.max_latencies,
            config.dns_metrics.max_edges,
        )));
    }

    if config.module_enabled("generator.trace_correlation") {
        registry = registry.with_generator(Box::new(TraceCorrelationGenerator::with_limits(
            config.trace_correlation.max_service_paths,
            config.trace_correlation.max_seen_interactions,
            config.trace_correlation.max_warnings,
        )));
    }

    if config.module_enabled("generator.request_correlation") {
        registry = registry.with_generator(Box::new(RequestCorrelationGenerator::with_options(
            config.request_correlation.max_seen_requests,
            config.request_correlation.max_warnings,
            config.request_correlation.generate_trace_ids,
        )));
    }

    if config.module_enabled("generator.profiling") {
        registry = registry.with_generator(Box::new(ProfilingGenerator::with_limits(
            config.profiling.max_windows,
            config.profiling.max_seen_samples,
            config.profiling.max_warnings,
            config.profiling.window_nanos,
        )));
    }

    if config.module_enabled("generator.runtime_security") {
        registry = registry.with_generator(Box::new(
            RuntimeSecurityGenerator::with_kubernetes_api_endpoints(kubernetes_api_endpoints(
                config,
            )),
        ));
    }

    if config.module_enabled("sink.json_stdout") {
        registry = registry.with_sink(Box::new(JsonStdoutSink));
    }

    if config.module_enabled("sink.prometheus_http") && config.prometheus_http.enabled {
        registry = registry.with_sink(Box::new(PrometheusHttpSink::bind_with_telemetry(
            config.prometheus_http.clone(),
            telemetry_registry.clone(),
        )?));
    }

    if config.module_enabled("sink.otlp_http") && config.otlp_http.enabled {
        registry = registry.with_sink(Box::new(OtlpHttpSink::new_with_telemetry(
            config.otlp_http.clone(),
            telemetry_registry,
        )?));
    }

    Ok(registry)
}

#[derive(Debug)]
struct SharedKubernetesMetadataProvider;

#[derive(Debug)]
struct WorkloadControllerTelemetrySource;

#[derive(Debug)]
struct AyaSourceTelemetrySource;

impl NativeTelemetrySource for AyaSourceTelemetrySource {
    fn prometheus_lines(&self) -> Vec<PrometheusMetricLine> {
        aya_source_telemetry_lines(
            e_navigator_sources_ebpf_aya::source_telemetry_snapshots().into_iter(),
        )
    }
}

fn aya_source_telemetry_lines(
    snapshots: impl Iterator<Item = e_navigator_sources_ebpf_aya::SourceTelemetrySnapshot>,
) -> Vec<PrometheusMetricLine> {
    snapshots
        .flat_map(|snapshot| {
            let labels = std::collections::BTreeMap::from([(
                "source".to_string(),
                snapshot.source.to_string(),
            )]);
            let metric = |name: &str, value: u64| PrometheusMetricLine {
                name: name.to_string(),
                labels: labels.clone(),
                value: value.to_string(),
            };
            [
                metric(
                    "e_navigator_ebpf_source_initialized",
                    u64::from(snapshot.initialized),
                ),
                metric(
                    "e_navigator_ebpf_source_decoded_samples_total",
                    snapshot.decoded_samples,
                ),
                metric(
                    "e_navigator_ebpf_source_invalid_samples_total",
                    snapshot.invalid_samples,
                ),
                metric(
                    "e_navigator_ebpf_source_sent_signals_total",
                    snapshot.sent_signals,
                ),
                metric(
                    "e_navigator_ebpf_source_send_failures_total",
                    snapshot.send_failures,
                ),
                metric(
                    "e_navigator_ebpf_source_lost_perf_events_total",
                    snapshot.lost_perf_events,
                ),
                metric(
                    "e_navigator_ebpf_source_diagnostic_matches_total",
                    snapshot.diagnostic_matches,
                ),
                metric(
                    "e_navigator_ebpf_source_diagnostic_filtered_total",
                    snapshot.diagnostic_filtered,
                ),
                metric(
                    "e_navigator_ebpf_source_diagnostic_exhausted_total",
                    snapshot.diagnostic_exhausted,
                ),
            ]
        })
        .collect()
}

#[derive(Debug)]
struct SourceSupervisorTelemetrySource {
    registry: SourceHealthRegistry,
}

impl NativeTelemetrySource for SourceSupervisorTelemetrySource {
    fn prometheus_lines(&self) -> Vec<PrometheusMetricLine> {
        self.registry
            .snapshots()
            .into_iter()
            .flat_map(|snapshot| {
                let labels = std::collections::BTreeMap::from([(
                    "source".to_string(),
                    snapshot.source.to_string(),
                )]);
                let metric = |name: &str, value: u64| PrometheusMetricLine {
                    name: name.to_string(),
                    labels: labels.clone(),
                    value: value.to_string(),
                };
                [
                    metric("e_navigator_source_configured", 1),
                    metric("e_navigator_source_running", u64::from(snapshot.running)),
                    metric("e_navigator_source_starts_total", snapshot.starts),
                    metric("e_navigator_source_clean_exits_total", snapshot.clean_exits),
                    metric("e_navigator_source_failures_total", snapshot.failures),
                    metric(
                        "e_navigator_source_last_transition_timestamp_seconds",
                        snapshot.last_transition_unix_seconds,
                    ),
                ]
            })
            .collect()
    }
}

impl NativeTelemetrySource for WorkloadControllerTelemetrySource {
    fn prometheus_lines(&self) -> Vec<PrometheusMetricLine> {
        let snapshot =
            e_navigator_sources_ebpf_aya::capture_filter::shared_telemetry().unwrap_or_default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let freshness = if snapshot.last_success_unix_seconds == 0 {
            0
        } else {
            now.saturating_sub(snapshot.last_success_unix_seconds)
        };
        let resource_relist_freshness = if snapshot.last_resource_relist_unix_seconds == 0 {
            0
        } else {
            now.saturating_sub(snapshot.last_resource_relist_unix_seconds)
        };
        let metric = |name: &str, value: u64| PrometheusMetricLine {
            name: name.to_string(),
            labels: std::collections::BTreeMap::new(),
            value: value.to_string(),
        };
        vec![
            metric(
                "e_navigator_kubernetes_controller_ready",
                u64::from(snapshot.last_success_unix_seconds > 0),
            ),
            metric(
                "e_navigator_kubernetes_controller_freshness_seconds",
                freshness,
            ),
            metric(
                "e_navigator_kubernetes_controller_resource_relist_freshness_seconds",
                resource_relist_freshness,
            ),
            metric("e_navigator_kubernetes_controller_pods", snapshot.pod_count),
            metric(
                "e_navigator_kubernetes_controller_services",
                snapshot.service_count,
            ),
            metric(
                "e_navigator_kubernetes_controller_endpoint_slices",
                snapshot.endpoint_slice_count,
            ),
            metric(
                "e_navigator_kubernetes_controller_relists_total",
                snapshot.relists,
            ),
            metric(
                "e_navigator_kubernetes_controller_relist_failures_total",
                snapshot.relist_failures,
            ),
            metric(
                "e_navigator_kubernetes_controller_watch_starts_total",
                snapshot.watch_starts,
            ),
            metric(
                "e_navigator_kubernetes_controller_watch_failures_total",
                snapshot.watch_failures,
            ),
            metric(
                "e_navigator_kubernetes_controller_expired_resource_versions_total",
                snapshot.expired_resource_versions,
            ),
            metric(
                "e_navigator_kubernetes_controller_reconciliations_total",
                snapshot.reconciliations,
            ),
            metric(
                "e_navigator_capture_filter_allowed_cgroups",
                snapshot.allowed_cgroups,
            ),
            metric(
                "e_navigator_capture_filter_denied_cgroups",
                snapshot.denied_cgroups,
            ),
            metric(
                "e_navigator_capture_filter_unresolved_cgroups",
                snapshot.unresolved_cgroups,
            ),
        ]
    }
}

#[async_trait]
impl KubernetesMetadataProvider for SharedKubernetesMetadataProvider {
    async fn refresh(
        &self,
        config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        let Some((_generation, pods, services, endpoint_slices)) =
            e_navigator_sources_ebpf_aya::capture_filter::shared_kubernetes_resources()
        else {
            return Err("shared Kubernetes workload controller is not initialized".to_string());
        };
        Ok(KubernetesMetadataCache::from_raw_resources(
            &pods,
            &services,
            &endpoint_slices,
            config,
        ))
    }
}

fn host_resource_config(config: &RuntimeConfig) -> HostResourceConfig {
    HostResourceConfig {
        procfs_root: config.resource_source.procfs_root.clone(),
        sysfs_root: config.resource_source.sysfs_root.clone(),
        cgroup_root: config.resource_source.cgroup_root.clone(),
        sample_interval_millis: config.resource_source.sample_interval_millis,
        max_processes: config.resource_source.max_processes,
        max_cgroups: config.resource_source.max_cgroups,
        max_fds_per_process: config.resource_source.max_fds_per_process,
        max_file_bytes: config.resource_source.max_file_bytes,
    }
}

pub(crate) fn node_name() -> Option<String> {
    std::env::var("NODE_NAME")
        .ok()
        .filter(|value| !value.is_empty())
}

fn kubernetes_api_endpoints(config: &RuntimeConfig) -> Vec<(String, u16)> {
    let mut endpoints: Vec<(String, u16)> = config
        .runtime_security
        .kubernetes_api_endpoints
        .iter()
        .map(|endpoint| (endpoint.address.clone(), endpoint.port))
        .collect();

    if let Some(host) = std::env::var("KUBERNETES_SERVICE_HOST")
        .ok()
        .filter(|value| !value.is_empty())
    {
        let port = std::env::var("KUBERNETES_SERVICE_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .unwrap_or(443);
        endpoints.push((host, port));
    }

    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::{NetworkEndpointConfig, RuntimeSecurityConfig};

    #[test]
    fn config_controls_static_module_registration() {
        let mut config = RuntimeConfig::default();
        for module in &mut config.modules {
            if module.name == "processor.container_attribution" {
                module.enabled = false;
            }
        }

        let registry = build_test_registry(&config, SourceMode::Synthetic);

        assert_eq!(registry.sources().len(), 1);
        assert_eq!(registry.processors().len(), 0);
        assert_eq!(registry.generators().len(), 8);
        assert_eq!(registry.sinks().len(), 1);

        let names = generator_names(&registry);
        assert_eq!(
            names,
            vec![
                "generator.dependency_graph",
                "generator.network_metrics",
                "generator.resource_metrics",
                "generator.dns_metrics",
                "generator.trace_correlation",
                "generator.request_correlation",
                "generator.profiling",
                "generator.runtime_security",
            ]
        );

        set_module_enabled(&mut config, "generator.trace_correlation", false);
        let registry = build_test_registry(&config, SourceMode::Synthetic);
        let names = generator_names(&registry);
        assert_eq!(
            names,
            vec![
                "generator.dependency_graph",
                "generator.network_metrics",
                "generator.resource_metrics",
                "generator.dns_metrics",
                "generator.request_correlation",
                "generator.profiling",
                "generator.runtime_security",
            ]
        );
    }

    #[test]
    fn workload_controller_telemetry_uses_fixed_native_metric_names() {
        let lines = WorkloadControllerTelemetrySource.prometheus_lines();
        let names = lines
            .iter()
            .map(|line| line.name.as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"e_navigator_kubernetes_controller_ready"));
        assert!(names.contains(&"e_navigator_kubernetes_controller_freshness_seconds"));
        assert!(
            names.contains(&"e_navigator_kubernetes_controller_resource_relist_freshness_seconds")
        );
        assert!(names.contains(&"e_navigator_capture_filter_unresolved_cgroups"));
        assert!(lines.iter().all(|line| line.labels.is_empty()));
    }

    #[test]
    fn source_supervisor_telemetry_is_bounded_by_registered_sources() {
        let config = RuntimeConfig::default();
        let registry = build_test_registry(&config, SourceMode::Synthetic);
        let lines = SourceSupervisorTelemetrySource {
            registry: registry.source_health_registry(),
        }
        .prometheus_lines();

        assert_eq!(lines.len(), 6);
        assert!(
            lines
                .iter()
                .all(|line| line.labels.get("source").map(String::as_str)
                    == Some("source.synthetic_exec"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.name == "e_navigator_source_running" && line.value == "0")
        );
    }

    #[test]
    fn aya_source_telemetry_uses_cumulative_fixed_metric_families() {
        let lines = aya_source_telemetry_lines(
            [e_navigator_sources_ebpf_aya::SourceTelemetrySnapshot {
                source: "source.aya_exec",
                initialized: true,
                decoded_samples: 3,
                invalid_samples: 1,
                sent_signals: 2,
                send_failures: 1,
                lost_perf_events: 4,
                diagnostic_matches: 1,
                diagnostic_filtered: 1,
                diagnostic_exhausted: 0,
            }]
            .into_iter(),
        );

        assert_eq!(lines.len(), 9);
        assert!(
            lines.iter().all(
                |line| line.labels.get("source").map(String::as_str) == Some("source.aya_exec")
            )
        );
        assert!(lines.iter().any(|line| {
            line.name == "e_navigator_ebpf_source_lost_perf_events_total" && line.value == "4"
        }));
        assert!(lines.iter().any(|line| {
            line.name == "e_navigator_ebpf_source_initialized" && line.value == "1"
        }));
    }

    #[test]
    fn aya_exec_source_mode_keeps_current_real_source_bundle() {
        let config = RuntimeConfig::default();
        let registry = build_test_registry(&config, SourceMode::AyaExec);

        assert_eq!(
            source_names(&registry),
            vec![
                "source.aya_exec",
                "source.aya_network",
                "source.host_resource"
            ]
        );
    }

    #[test]
    fn unified_source_mode_registers_general_capture_and_cpu_profiling() {
        let mut config = RuntimeConfig::default();
        config.cpu_profile_source.enabled = true;
        set_module_enabled(&mut config, "source.aya_dns", true);
        set_module_enabled(&mut config, "source.aya_http", true);
        set_module_enabled(&mut config, "source.aya_protocol", true);
        set_module_enabled(&mut config, "source.aya_tls", true);
        set_module_enabled(&mut config, "source.aya_cpu_profile", true);

        let registry = build_test_registry(&config, SourceMode::Unified);

        assert_eq!(
            source_names(&registry),
            vec![
                "source.aya_exec",
                "source.aya_network",
                "source.aya_dns",
                "source.aya_http",
                "source.aya_protocol",
                "source.aya_tls",
                "source.host_resource",
                "source.aya_cpu_profile",
            ]
        );
    }

    #[test]
    fn aya_exec_source_mode_registers_dns_source_when_explicitly_enabled() {
        let mut config = RuntimeConfig::default();
        set_module_enabled(&mut config, "source.aya_dns", true);

        let registry = build_test_registry(&config, SourceMode::AyaExec);

        assert_eq!(
            source_names(&registry),
            vec![
                "source.aya_exec",
                "source.aya_network",
                "source.aya_dns",
                "source.host_resource"
            ]
        );
    }

    #[test]
    fn aya_exec_source_mode_registers_http_source_when_explicitly_enabled() {
        let mut config = RuntimeConfig::default();
        set_module_enabled(&mut config, "source.aya_http", true);

        let registry = build_test_registry(&config, SourceMode::AyaExec);

        assert_eq!(
            source_names(&registry),
            vec![
                "source.aya_exec",
                "source.aya_network",
                "source.aya_http",
                "source.host_resource"
            ]
        );
    }

    #[test]
    fn cpu_profile_source_mode_registers_only_when_module_and_config_are_enabled() {
        let mut config = RuntimeConfig::default();
        config.cpu_profile_source.enabled = true;
        set_module_enabled(&mut config, "source.aya_exec", false);
        set_module_enabled(&mut config, "source.aya_network", false);
        set_module_enabled(&mut config, "source.host_resource", false);
        set_module_enabled(&mut config, "source.synthetic_exec", false);
        set_module_enabled(&mut config, "source.aya_cpu_profile", true);

        let registry = build_test_registry(&config, SourceMode::AyaCpuProfile);

        assert_eq!(source_names(&registry), vec!["source.aya_cpu_profile"]);

        set_module_enabled(&mut config, "source.aya_cpu_profile", false);
        let registry = build_test_registry(&config, SourceMode::AyaCpuProfile);

        assert!(source_names(&registry).is_empty());
    }

    #[test]
    fn synthetic_source_mode_does_not_register_real_sources() {
        let mut config = RuntimeConfig::default();
        config.cpu_profile_source.enabled = true;
        set_module_enabled(&mut config, "source.aya_cpu_profile", true);

        let registry = build_test_registry(&config, SourceMode::Synthetic);

        assert_eq!(source_names(&registry), vec!["source.synthetic_exec"]);
    }

    #[test]
    fn registry_registers_only_json_stdout_as_concrete_sink() {
        let config = RuntimeConfig::default();
        let registry = build_test_registry(&config, SourceMode::Synthetic);

        assert_eq!(sink_names(&registry), vec!["sink.json_stdout"]);
    }

    #[test]
    fn registry_registers_prometheus_http_sink_when_enabled() {
        let mut config = RuntimeConfig::default();
        set_module_enabled(&mut config, "sink.prometheus_http", true);
        config.prometheus_http.enabled = true;
        config.prometheus_http.bind_address = "127.0.0.1".to_string();
        config.prometheus_http.port = 0;

        let registry = build_test_registry(&config, SourceMode::Synthetic);

        assert_eq!(
            sink_names(&registry),
            vec!["sink.json_stdout", "sink.prometheus_http"]
        );
    }

    #[test]
    fn prometheus_bind_failure_is_returned_instead_of_panicking() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve local port");
        let mut config = RuntimeConfig::default();
        set_module_enabled(&mut config, "sink.prometheus_http", true);
        config.prometheus_http.enabled = true;
        config.prometheus_http.bind_address = "127.0.0.1".to_string();
        config.prometheus_http.port = listener.local_addr().expect("local address").port();

        let err = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()))
            .expect_err("occupied Prometheus port must fail registry construction");

        assert!(err.to_string().contains("sink.prometheus_http"));
    }

    #[tokio::test]
    async fn registry_registers_otlp_http_sink_when_enabled() {
        let mut config = RuntimeConfig::default();
        set_module_enabled(&mut config, "sink.otlp_http", true);
        config.otlp_http.enabled = true;
        config.otlp_http.endpoint = "http://127.0.0.1:4318/v1/metrics".to_string();

        let registry = build_test_registry(&config, SourceMode::Synthetic);

        assert_eq!(
            sink_names(&registry),
            vec!["sink.json_stdout", "sink.otlp_http"]
        );
    }

    #[test]
    fn configured_kubernetes_api_endpoints_feed_runtime_security_generator() {
        let config = RuntimeConfig {
            runtime_security: RuntimeSecurityConfig {
                kubernetes_api_endpoints: vec![NetworkEndpointConfig {
                    address: "10.96.0.1".to_string(),
                    port: 443,
                }],
            },
            ..RuntimeConfig::default()
        };

        assert!(kubernetes_api_endpoints(&config).contains(&("10.96.0.1".to_string(), 443)));
    }

    #[test]
    fn host_resource_config_preserves_runtime_resource_source_settings() {
        let mut config = RuntimeConfig::default();
        config.resource_source.procfs_root = "/host/proc".into();
        config.resource_source.sysfs_root = "/host/sys".into();
        config.resource_source.cgroup_root = "/host/cgroup".into();
        config.resource_source.sample_interval_millis = 7;
        config.resource_source.max_processes = 11;
        config.resource_source.max_cgroups = 13;
        config.resource_source.max_fds_per_process = 17;
        config.resource_source.max_file_bytes = 19;

        let source_config = host_resource_config(&config);

        assert_eq!(
            source_config.procfs_root,
            std::path::PathBuf::from("/host/proc")
        );
        assert_eq!(
            source_config.sysfs_root,
            std::path::PathBuf::from("/host/sys")
        );
        assert_eq!(
            source_config.cgroup_root,
            std::path::PathBuf::from("/host/cgroup")
        );
        assert_eq!(source_config.sample_interval_millis, 7);
        assert_eq!(source_config.max_processes, 11);
        assert_eq!(source_config.max_cgroups, 13);
        assert_eq!(source_config.max_fds_per_process, 17);
        assert_eq!(source_config.max_file_bytes, 19);
    }

    fn set_module_enabled(config: &mut RuntimeConfig, name: &str, enabled: bool) {
        let Some(module) = config.modules.iter_mut().find(|module| module.name == name) else {
            panic!("missing module {name}");
        };
        module.enabled = enabled;
    }

    fn build_test_registry(config: &RuntimeConfig, source: SourceMode) -> ModuleRegistry {
        build_registry(config, source, Some("node-a".to_string())).expect("registry builds")
    }

    fn source_names(registry: &ModuleRegistry) -> Vec<&'static str> {
        registry
            .sources()
            .iter()
            .map(|source| source.metadata().name)
            .collect()
    }

    fn generator_names(registry: &ModuleRegistry) -> Vec<String> {
        registry
            .generators()
            .iter()
            .map(|generator| generator.metadata().name.to_string())
            .collect()
    }

    fn sink_names(registry: &ModuleRegistry) -> Vec<&'static str> {
        registry
            .sinks()
            .iter()
            .map(|sink| sink.metadata().name)
            .collect()
    }
}
