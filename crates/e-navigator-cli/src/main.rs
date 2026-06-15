use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, RuntimeConfig, Source};
use e_navigator_generators::{
    DependencyGraphGenerator, DnsMetricsGenerator, NetworkMetricsGenerator, ProfilingGenerator,
    RequestCorrelationGenerator, ResourceMetricsGenerator, RuntimeSecurityGenerator,
    TraceCorrelationGenerator,
};
use e_navigator_processors::ContainerAttributionProcessor;
use e_navigator_runner::{ModuleRegistry, Runner};
use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, ContainerContext, DnsQueryEvent, DnsQueryType,
    DnsResponseCode, DnsResponseEvent, ExecEvent, KubernetesContext, MetricAggregationWindow,
    NetworkAddressFamily, NetworkConnectionCloseEvent, NetworkConnectionFailureEvent,
    NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol, NodeCpuObservation,
    NodeDiskIoObservation, NodeFilesystemObservation, NodeLoadObservation, NodeMemoryObservation,
    ProcessExitEvent, ProcessResourceContext, ProcessResourceObservation, ProtocolKind,
    ProtocolRequestObservation, SignalEnvelope, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TracePeerContext, TraceSpanObservation,
};
use e_navigator_sinks::JsonStdoutSink;
use e_navigator_sources_ebpf_aya::{AyaExecSource, AyaNetworkSource};
use e_navigator_sources_host::{HostResourceConfig, HostResourceSource};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "e-navigator")]
#[command(about = "E-Navigator node agent")]
struct Args {
    #[arg(long, value_enum, default_value_t = SourceMode::AyaExec)]
    source: SourceMode,

    #[arg(long, env = "E_NAVIGATOR_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceMode {
    AyaExec,
    Synthetic,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = load_config(args.config.as_deref())?;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.log_level.clone())),
        )
        .init();

    let registry = build_registry(&config, args.source, node_name());

    Runner::new(config, registry)?.run().await?;
    Ok(())
}

fn load_config(path: Option<&std::path::Path>) -> anyhow::Result<RuntimeConfig> {
    match path {
        Some(path) => {
            let contents = std::fs::read_to_string(path)?;
            let config = toml::from_str::<RuntimeConfig>(&contents)?;
            config.validate().map_err(CoreError::InvalidConfig)?;
            Ok(config)
        }
        None => Ok(RuntimeConfig::default()),
    }
}

fn build_registry(
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
            )));
        }
        SourceMode::Synthetic if config.module_enabled("source.synthetic_exec") => {
            registry = registry.with_source(Box::new(SyntheticExecSource { host: host.clone() }));
        }
        _ => {}
    }

    if matches!(source, SourceMode::AyaExec) && config.module_enabled("source.aya_network") {
        registry = registry.with_source(Box::new(AyaNetworkSource::new(host.clone())));
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
        registry = registry.with_generator(Box::new(DnsMetricsGenerator::with_domain_limit(
            config.dns_metrics.max_domains,
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

fn node_name() -> Option<String> {
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

struct SyntheticExecSource {
    host: Option<String>,
}

#[async_trait]
impl Source<SignalEnvelope> for SyntheticExecSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.synthetic_exec", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let (container, kubernetes) = synthetic_attribution();
        let signal = SignalEnvelope::exec(
            "source.synthetic_exec",
            self.host.clone(),
            ExecEvent {
                pid: std::process::id(),
                ppid: None,
                uid: None,
                command: "sh".to_string(),
                executable: Some("/bin/sh".to_string()),
                arguments: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo synthetic".to_string(),
                ],
                cgroup_id: None,
                timestamp_unix_nanos: now_unix_nanos(),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );

        tx.send(signal)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let exit = SignalEnvelope::process_exit(
            "source.synthetic_exec",
            self.host.clone(),
            ProcessExitEvent {
                pid: std::process::id(),
                ppid: None,
                uid: None,
                command: "sh".to_string(),
                exit_code: Some(0),
                runtime_nanos: Some(1_000_000),
                timestamp_unix_nanos: now_unix_nanos(),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );

        tx.send(exit).await.map_err(|_| CoreError::PipelineClosed)?;

        let opened_at = now_unix_nanos();
        let open = SignalEnvelope::network_connection_open(
            "source.synthetic_exec",
            self.host.clone(),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: "203.0.113.10".to_string(),
                remote_port: 443,
                fd: Some(7),
                timestamp_unix_nanos: opened_at,
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        tx.send(open).await.map_err(|_| CoreError::PipelineClosed)?;

        let duration_nanos = 2_000_000;
        let close = SignalEnvelope::network_connection_close(
            "source.synthetic_exec",
            self.host.clone(),
            NetworkConnectionCloseEvent {
                process: NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: "203.0.113.10".to_string(),
                remote_port: 443,
                fd: Some(7),
                opened_at_unix_nanos: Some(opened_at),
                closed_at_unix_nanos: opened_at.saturating_add(duration_nanos),
                duration_nanos: Some(duration_nanos),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        tx.send(close)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let dns_query = SignalEnvelope::dns_query(
            "source.synthetic_exec",
            self.host.clone(),
            DnsQueryEvent {
                process: NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                },
                query_name: "api.example.com".to_string(),
                query_type: DnsQueryType::A,
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 1),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        tx.send(dns_query)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let dns_response = SignalEnvelope::dns_response(
            "source.synthetic_exec",
            self.host.clone(),
            DnsResponseEvent {
                process: NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                },
                query_name: "api.example.com".to_string(),
                query_type: DnsQueryType::A,
                response_code: DnsResponseCode::NoError,
                latency_nanos: Some(15_000),
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 15_001),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        tx.send(dns_response)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let trace_span = SignalEnvelope::trace_span_observation(
            "source.synthetic_exec",
            self.host.clone(),
            TraceSpanObservation {
                name: "synthetic checkout".to_string(),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: opened_at,
                end_unix_nanos: Some(opened_at.saturating_add(duration_nanos)),
                duration_nanos: Some(duration_nanos),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("synthetic-api".to_string()),
                process: Some(NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                }),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(TracePeerContext {
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: Some("api.example.com".to_string()),
                    workload: None,
                    container: None,
                }),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "true_trace_context".to_string(),
                }],
            },
        );
        tx.send(trace_span)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        for request in synthetic_protocol_request_signals(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ) {
            tx.send(request)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        let failure = SignalEnvelope::network_connection_failure(
            "source.synthetic_exec",
            self.host.clone(),
            NetworkConnectionFailureEvent {
                process: NetworkProcessIdentity {
                    pid: std::process::id(),
                    ppid: None,
                    uid: None,
                    command: "synthetic-api".to_string(),
                    executable: Some("/app/synthetic-api".to_string()),
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: "198.51.100.20".to_string(),
                remote_port: 5432,
                fd: Some(8),
                errno: 111,
                timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 30_000),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        tx.send(failure)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let resource_started = opened_at.saturating_add(duration_nanos + 20_000);
        for signal in
            synthetic_resource_signals(self.host.clone(), container, kubernetes, resource_started)
        {
            tx.send(signal)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

fn synthetic_protocol_request_signals(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    started: u64,
    duration_nanos: u64,
) -> Vec<SignalEnvelope> {
    let process = NetworkProcessIdentity {
        pid: std::process::id(),
        ppid: None,
        uid: None,
        command: "synthetic-api".to_string(),
        executable: Some("/app/synthetic-api".to_string()),
    };
    let peer = TracePeerContext {
        address: Some("203.0.113.10".to_string()),
        port: Some(443),
        domain: Some("api.example.com".to_string()),
        workload: None,
        container: None,
    };
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    vec![
        SignalEnvelope::protocol_request_observation(
            "source.synthetic_exec",
            host.clone(),
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started,
                end_unix_nanos: Some(started.saturating_add(duration_nanos)),
                duration_nanos: Some(duration_nanos),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                traceparent: Some(traceparent.to_string()),
                tracestate: Some("synthetic=value".to_string()),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("synthetic-api".to_string()),
                method: Some("GET".to_string()),
                status_code: Some(200),
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "http_trace_context_request".to_string(),
                }],
            },
        ),
        SignalEnvelope::protocol_request_observation(
            "source.synthetic_exec",
            host.clone(),
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started.saturating_add(duration_nanos + 10_000),
                end_unix_nanos: Some(started.saturating_add(duration_nanos + 11_000)),
                duration_nanos: Some(1_000),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: Some("00-bad".to_string()),
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Low,
                service_name: Some("synthetic-api".to_string()),
                method: Some("GET".to_string()),
                status_code: None,
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "malformed_trace_context_request".to_string(),
                }],
            },
        ),
        SignalEnvelope::protocol_request_observation(
            "source.synthetic_exec",
            host,
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started.saturating_add(duration_nanos + 20_000),
                end_unix_nanos: Some(started.saturating_add(duration_nanos + 21_000)),
                duration_nanos: Some(1_000),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: None,
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Low,
                service_name: Some("synthetic-api".to_string()),
                method: Some("POST".to_string()),
                status_code: None,
                process: Some(process),
                container: Some(container),
                kubernetes: Some(kubernetes),
                peer: Some(peer),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "missing_trace_context_request".to_string(),
                }],
            },
        ),
    ]
}

fn synthetic_resource_signals(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    started: u64,
) -> Vec<SignalEnvelope> {
    let window = MetricAggregationWindow {
        start_unix_nanos: started,
        end_unix_nanos: started.saturating_add(1_000),
    };
    let cgroup = CgroupResourceContext {
        cgroup_path: "/kubepods.slice/pod-synthetic/e-navigator.scope".to_string(),
        container: Some(container.clone()),
        kubernetes: Some(kubernetes.clone()),
    };
    let process = ProcessResourceContext {
        pid: std::process::id(),
        ppid: None,
        uid: None,
        command: "synthetic-api".to_string(),
        executable: Some("/app/synthetic-api".to_string()),
        container: Some(container.clone()),
        kubernetes: Some(kubernetes.clone()),
    };

    vec![
        SignalEnvelope::node_cpu_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeCpuObservation {
                metric_name: "system.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                user_nanos: 1_000_000_000,
                system_nanos: 500_000_000,
                idle_nanos: 8_000_000_000,
                iowait_nanos: 100_000_000,
                steal_nanos: 0,
                runnable_tasks: Some(2),
                blocked_tasks: Some(0),
            },
        ),
        SignalEnvelope::node_cpu_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeCpuObservation {
                metric_name: "system.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                window: MetricAggregationWindow {
                    start_unix_nanos: window.end_unix_nanos,
                    end_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                },
                user_nanos: 1_030_000_000,
                system_nanos: 520_000_000,
                idle_nanos: 8_040_000_000,
                iowait_nanos: 100_000_000,
                steal_nanos: 0,
                runnable_tasks: Some(2),
                blocked_tasks: Some(0),
            },
        ),
        SignalEnvelope::node_memory_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeMemoryObservation {
                metric_name: "system.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                mem_total_bytes: 8 * 1024 * 1024 * 1024,
                mem_available_bytes: Some(5 * 1024 * 1024 * 1024),
                mem_free_bytes: Some(4 * 1024 * 1024 * 1024),
                swap_total_bytes: Some(1024 * 1024 * 1024),
                swap_free_bytes: Some(1024 * 1024 * 1024),
            },
        ),
        SignalEnvelope::node_load_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeLoadObservation {
                metric_name: "system.cpu.load_average.1m".to_string(),
                unit: "1".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                load1: 0.25,
                load5: 0.5,
                load15: 0.75,
                runnable_tasks: Some(2),
                total_tasks: Some(200),
            },
        ),
        SignalEnvelope::node_filesystem_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeFilesystemObservation {
                metric_name: "system.filesystem.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                mount_point: "/var/lib/kubelet".to_string(),
                filesystem_type: Some("synthetic".to_string()),
                total_bytes: 100 * 1024 * 1024 * 1024,
                available_bytes: 60 * 1024 * 1024 * 1024,
            },
        ),
        SignalEnvelope::node_disk_io_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeDiskIoObservation {
                metric_name: "system.disk.io".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                device: "synthetic0".to_string(),
                reads_completed: 10,
                writes_completed: 20,
                read_bytes: 4096,
                written_bytes: 8192,
            },
        ),
        SignalEnvelope::node_disk_io_observation(
            "source.synthetic_exec",
            host.clone(),
            NodeDiskIoObservation {
                metric_name: "system.disk.io".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                window: MetricAggregationWindow {
                    start_unix_nanos: window.end_unix_nanos,
                    end_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                },
                device: "synthetic0".to_string(),
                reads_completed: 12,
                writes_completed: 23,
                read_bytes: 8192,
                written_bytes: 16_384,
            },
        ),
        SignalEnvelope::process_resource_observation(
            "source.synthetic_exec",
            host.clone(),
            ProcessResourceObservation {
                metric_name: "process.resource".to_string(),
                unit: "1".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                process,
                cpu_time_nanos: Some(10_000_000),
                memory_rss_bytes: Some(64 * 1024 * 1024),
                virtual_memory_bytes: Some(128 * 1024 * 1024),
                open_fds: Some(32),
                socket_count: Some(4),
                thread_count: Some(8),
            },
        ),
        SignalEnvelope::cgroup_cpu_observation(
            "source.synthetic_exec",
            host.clone(),
            CgroupCpuObservation {
                metric_name: "container.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                cgroup: cgroup.clone(),
                usage_nanos: Some(2_000_000_000),
                user_nanos: Some(1_500_000_000),
                system_nanos: Some(500_000_000),
                throttled_periods: Some(0),
                throttled_nanos: Some(0),
            },
        ),
        SignalEnvelope::cgroup_cpu_observation(
            "source.synthetic_exec",
            host.clone(),
            CgroupCpuObservation {
                metric_name: "container.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                window: MetricAggregationWindow {
                    start_unix_nanos: window.end_unix_nanos,
                    end_unix_nanos: window.end_unix_nanos.saturating_add(1_000),
                },
                cgroup: cgroup.clone(),
                usage_nanos: Some(2_060_000_000),
                user_nanos: Some(1_550_000_000),
                system_nanos: Some(510_000_000),
                throttled_periods: Some(0),
                throttled_nanos: Some(0),
            },
        ),
        SignalEnvelope::cgroup_memory_observation(
            "source.synthetic_exec",
            host.clone(),
            CgroupMemoryObservation {
                metric_name: "container.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                cgroup: cgroup.clone(),
                current_bytes: Some(128 * 1024 * 1024),
                peak_bytes: Some(160 * 1024 * 1024),
                max_bytes: Some(512 * 1024 * 1024),
            },
        ),
        SignalEnvelope::cgroup_pids_observation(
            "source.synthetic_exec",
            host.clone(),
            CgroupPidsObservation {
                metric_name: "container.process.count".to_string(),
                unit: "{process}".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window: window.clone(),
                cgroup: cgroup.clone(),
                process_count: Some(3),
                thread_count: Some(12),
                max_processes: Some(512),
            },
        ),
        SignalEnvelope::cgroup_file_descriptor_observation(
            "source.synthetic_exec",
            host,
            CgroupFileDescriptorObservation {
                metric_name: "container.file_descriptor.count".to_string(),
                unit: "{file_descriptor}".to_string(),
                timestamp_unix_nanos: window.end_unix_nanos,
                window,
                cgroup,
                open_fds: Some(64),
                socket_count: Some(6),
            },
        ),
    ]
}

fn synthetic_attribution() -> (ContainerContext, KubernetesContext) {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/name".to_string(),
        "e-navigator-smoke".to_string(),
    );

    (
        ContainerContext {
            container_id: "synthetic-container".to_string(),
            runtime: Some("synthetic".to_string()),
        },
        KubernetesContext {
            namespace: "e-navigator-system".to_string(),
            pod_name: "e-navigator-synthetic".to_string(),
            pod_uid: Some("synthetic-pod-uid".to_string()),
            container_name: Some("e-navigator".to_string()),
            node_name: node_name().or_else(|| Some("synthetic-node".to_string())),
            labels,
        },
    )
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::{NetworkEndpointConfig, RuntimeSecurityConfig, Source};
    use e_navigator_signals::SignalPayload;
    use tokio::sync::mpsc;

    #[test]
    fn config_controls_static_module_registration() {
        let mut config = RuntimeConfig::default();
        for module in &mut config.modules {
            if module.name == "processor.container_attribution" {
                module.enabled = false;
            }
        }

        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));

        assert_eq!(registry.sources.len(), 1);
        assert_eq!(registry.processors.len(), 0);
        assert_eq!(registry.generators.len(), 7);
        assert_eq!(registry.sinks.len(), 1);

        let generator_names = registry
            .generators
            .iter()
            .map(|generator| generator.metadata().name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            generator_names,
            vec![
                "generator.dependency_graph",
                "generator.network_metrics",
                "generator.resource_metrics",
                "generator.dns_metrics",
                "generator.trace_correlation",
                "generator.request_correlation",
                "generator.runtime_security",
            ]
        );

        for module in &mut config.modules {
            if module.name == "generator.trace_correlation" {
                module.enabled = false;
            }
        }
        let registry = build_registry(&config, SourceMode::Synthetic, Some("node-a".to_string()));
        let generator_names = registry
            .generators
            .iter()
            .map(|generator| generator.metadata().name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            generator_names,
            vec![
                "generator.dependency_graph",
                "generator.network_metrics",
                "generator.resource_metrics",
                "generator.dns_metrics",
                "generator.request_correlation",
                "generator.runtime_security",
            ]
        );
    }

    #[test]
    fn parses_toml_runtime_config() {
        let config = toml::from_str::<RuntimeConfig>(
            r#"
            log_level = "debug"
            queue_capacity = 64

            [[modules]]
            name = "source.synthetic_exec"
            enabled = true

            [[modules]]
            name = "sink.json_stdout"
            enabled = true
            "#,
        )
        .expect("config parses");

        assert_eq!(config.log_level, "debug");
        assert_eq!(config.queue_capacity, 64);
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(!config.module_enabled("processor.container_attribution"));
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

    #[tokio::test]
    async fn synthetic_source_emits_attributed_runtime_network_and_trace_fixtures() {
        let (tx, mut rx) = mpsc::channel(64);
        Box::new(SyntheticExecSource {
            host: Some("node-a".to_string()),
        })
        .run(tx)
        .await
        .expect("synthetic source succeeds");

        let mut signals = Vec::new();
        while let Some(signal) = rx.recv().await {
            signals.push(signal);
        }

        assert!(signals.len() >= 10);
        let SignalPayload::Exec(exec) = &signals[0].payload else {
            panic!("expected exec fixture");
        };
        assert!(exec.container.is_some());
        assert!(exec.kubernetes.is_some());

        let SignalPayload::ProcessExit(exit) = &signals[1].payload else {
            panic!("expected process exit fixture");
        };
        assert!(exit.container.is_some());
        assert!(exit.kubernetes.is_some());

        let SignalPayload::NetworkConnectionOpen(open) = &signals[2].payload else {
            panic!("expected network open fixture");
        };
        assert_eq!(open.remote_address, "203.0.113.10");
        assert!(open.container.is_some());
        assert!(open.kubernetes.is_some());

        let SignalPayload::NetworkConnectionClose(close) = &signals[3].payload else {
            panic!("expected network close fixture");
        };
        assert_eq!(close.remote_port, 443);
        assert_eq!(close.duration_nanos, Some(2_000_000));

        let SignalPayload::DnsQuery(query) = &signals[4].payload else {
            panic!("expected dns query fixture");
        };
        assert_eq!(query.query_name, "api.example.com");
        assert!(query.container.is_some());
        assert!(query.kubernetes.is_some());

        let SignalPayload::DnsResponse(response) = &signals[5].payload else {
            panic!("expected dns response fixture");
        };
        assert_eq!(response.query_name, "api.example.com");
        assert_eq!(response.latency_nanos, Some(15_000));

        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::TraceSpanObservation(span)
                if span.trace_id.as_deref() == Some("4bf92f3577b34da6a3ce929d0e0e4736")
                    && span.span_id.as_deref() == Some("00f067aa0ba902b7")
        )));
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::ProtocolRequestObservation(request)
                if request.traceparent.as_deref()
                    == Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                    && request.method.as_deref() == Some("GET")
                    && request.status_code == Some(200)
        )));
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::ProtocolRequestObservation(request)
                if request.traceparent.as_deref() == Some("00-bad")
                    && request.trace_id.is_none()
                    && request.span_id.is_none()
        )));
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::ProtocolRequestObservation(request)
                if request.traceparent.is_none()
                    && request.trace_id.is_none()
                    && request.span_id.is_none()
        )));
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::NetworkConnectionFailure(failure)
                if failure.remote_address == "198.51.100.20" && failure.errno == 111
        )));

        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NodeMemoryObservation(_)))
        );
        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NodeLoadObservation(_)))
        );
        assert!(
            signals.iter().any(|signal| matches!(
                signal.payload,
                SignalPayload::NodeFilesystemObservation(_)
            ))
        );
        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NodeDiskIoObservation(_)))
        );
        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::CgroupMemoryObservation(_)))
        );
        assert!(
            signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::CgroupPidsObservation(_)))
        );
        assert!(signals.iter().any(|signal| matches!(
            signal.payload,
            SignalPayload::CgroupFileDescriptorObservation(_)
        )));
    }
}
