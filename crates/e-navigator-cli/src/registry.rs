use crate::args::SourceMode;
use crate::synthetic::SyntheticExecSource;
use e_navigator_core::RuntimeConfig;
use e_navigator_generators::{
    DependencyGraphGenerator, DnsMetricsGenerator, GuaraCompatibilityGenerator,
    NetworkMetricsGenerator, ProfilingGenerator, RequestCorrelationGenerator,
    ResourceMetricsGenerator, RuntimeSecurityGenerator, TraceCorrelationGenerator,
};
use e_navigator_processors::ContainerAttributionProcessor;
use e_navigator_runner::ModuleRegistry;
use e_navigator_sinks::JsonStdoutSink;
use e_navigator_sources_ebpf_aya::{AyaCpuProfileSource, AyaExecSource, AyaNetworkSource};
use e_navigator_sources_host::{HostResourceConfig, HostResourceSource};

pub(crate) fn build_registry(
    config: &RuntimeConfig,
    source: SourceMode,
    host: Option<String>,
) -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();

    match source {
        SourceMode::AyaExec if config.module_enabled("source.aya_exec") => {
            registry = registry.with_source(Box::new(AyaExecSource::new(
                host.clone(),
                config.argv_capture.clone(),
                config.attribution.procfs_root.clone(),
            )));
        }
        SourceMode::AyaCpuProfile
            if config.cpu_profile_source.enabled
                && config.module_enabled("source.aya_cpu_profile") =>
        {
            registry = registry.with_source(Box::new(AyaCpuProfileSource::new(
                host.clone(),
                config.cpu_profile_source.clone(),
            )));
        }
        SourceMode::Synthetic if config.module_enabled("source.synthetic_exec") => {
            registry = registry.with_source(Box::new(SyntheticExecSource { host: host.clone() }));
        }
        _ => {}
    }

    if matches!(source, SourceMode::AyaExec) && config.module_enabled("source.aya_network") {
        registry = registry.with_source(Box::new(AyaNetworkSource::new(
            host.clone(),
            config.attribution.procfs_root.clone(),
        )));
    }

    if matches!(source, SourceMode::AyaExec) && config.module_enabled("source.host_resource") {
        registry = registry.with_source(Box::new(HostResourceSource::with_host(
            host_resource_config(config),
            host.clone(),
        )));
    }

    if config.module_enabled("processor.container_attribution") {
        registry = registry.with_processor(Box::new(ContainerAttributionProcessor::new(
            config.attribution.clone(),
        )));
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
        registry = registry.with_generator(Box::new(RequestCorrelationGenerator::with_limits(
            config.request_correlation.max_seen_requests,
            config.request_correlation.max_warnings,
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

    if config.module_enabled("generator.guara_compat") {
        registry = registry.with_generator(Box::new(GuaraCompatibilityGenerator::default()));
    }

    if config.module_enabled("sink.json_stdout") {
        registry = registry.with_sink(Box::new(JsonStdoutSink));
    }

    registry
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

        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));

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
        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));
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
    fn aya_exec_source_mode_keeps_current_real_source_bundle() {
        let config = RuntimeConfig::default();
        let registry = build_registry(&config, SourceMode::AyaExec, Some("node-a".to_string()));

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
    fn cpu_profile_source_mode_registers_only_when_module_and_config_are_enabled() {
        let mut config = RuntimeConfig::default();
        config.cpu_profile_source.enabled = true;
        set_module_enabled(&mut config, "source.aya_exec", false);
        set_module_enabled(&mut config, "source.aya_network", false);
        set_module_enabled(&mut config, "source.host_resource", false);
        set_module_enabled(&mut config, "source.synthetic_exec", false);
        set_module_enabled(&mut config, "source.aya_cpu_profile", true);

        let registry = build_registry(
            &config,
            SourceMode::AyaCpuProfile,
            Some("node-a".to_string()),
        );

        assert_eq!(source_names(&registry), vec!["source.aya_cpu_profile"]);

        set_module_enabled(&mut config, "source.aya_cpu_profile", false);
        let registry = build_registry(
            &config,
            SourceMode::AyaCpuProfile,
            Some("node-a".to_string()),
        );

        assert!(source_names(&registry).is_empty());
    }

    #[test]
    fn synthetic_source_mode_does_not_register_real_sources() {
        let mut config = RuntimeConfig::default();
        config.cpu_profile_source.enabled = true;
        set_module_enabled(&mut config, "source.aya_cpu_profile", true);

        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));

        assert_eq!(source_names(&registry), vec!["source.synthetic_exec"]);
    }

    #[test]
    fn registry_registers_only_json_stdout_as_concrete_sink() {
        let config = RuntimeConfig::default();
        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));

        assert_eq!(sink_names(&registry), vec!["sink.json_stdout"]);
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
