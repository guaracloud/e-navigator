use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use e_navigator_core::{Generator, PrometheusHttpConfig, Sink};
use e_navigator_generators::{
    DependencyGraphGenerator, DnsMetricsGenerator, NetworkMetricsGenerator, ProfilingGenerator,
    RequestCorrelationGenerator, ResourceMetricsGenerator, RuntimeSecurityGenerator,
    TraceCorrelationGenerator,
};
use e_navigator_processors::container_attribution::KubernetesMetadataCache;
use e_navigator_profiling::model::{NormalizationLimits, parse_profile_fixture};
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    grpc::{parse_grpc_request_headers, parse_grpc_response_trailers},
    http::{parse_http_request, parse_http_response},
    kafka::{parse_kafka_api_versions_response, parse_kafka_produce_response, parse_kafka_request},
    mongodb::{parse_mongodb_message, parse_mongodb_response},
    mysql::{parse_mysql_command, parse_mysql_response},
    nats::{parse_nats_command, parse_nats_response},
    postgres::{parse_postgres_message, parse_postgres_response},
    redis::{parse_redis_command, parse_redis_response},
    trace_context::parse_traceparent,
};
use e_navigator_signals::{
    ContainerContext, DnsQueryEvent, DnsQueryType, DnsResponseCode, DnsResponseEvent, ExecEvent,
    KubernetesContext, MetricAggregationWindow, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkCounterMetric,
    NetworkProcessIdentity, NetworkProtocol, NodeCpuObservation, ProcessResourceContext,
    ProcessResourceObservation, ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
    ProfilingCorrelationKind, ProfilingFrame, ProfilingKind, ProfilingSessionObservation,
    ProfilingWarningObservation, ProtocolKind, ProtocolRequestObservation, RequestSpanObservation,
    SignalEnvelope, TraceAttribute, TraceConfidence, TraceCorrelationKind, TracePeerContext,
};
use e_navigator_sinks::{
    HttpExporterConfig, HttpJsonExporter, PrometheusHttpSink, format_otel_metric_record,
    format_otel_trace_record, format_pprof_profile, format_profile_record,
};
use e_navigator_sources_ebpf_aya::{
    cpu_profile::fuzz_decode_raw_cpu_profile_event, exec::fuzz_decode_raw_exec_event,
    network::fuzz_decode_raw_network_event,
};
use e_navigator_sources_host::{
    parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo, parse_process_stat,
};
use serde::Serialize;
use std::{cell::Cell, collections::BTreeMap};
use tokio::{runtime::Runtime, sync::mpsc};

fn bench_raw_aya_decoders(c: &mut Criterion) {
    let exec_bytes = vec![0x42; 4096];
    let network_bytes = vec![0x11; 1024];
    let cpu_profile_bytes = vec![0x7f; 1024];

    c.bench_function("aya_decode/exec_fuzz_harness", |b| {
        b.iter(|| fuzz_decode_raw_exec_event(black_box(&exec_bytes)))
    });
    c.bench_function("aya_decode/network_fuzz_harness", |b| {
        b.iter(|| fuzz_decode_raw_network_event(black_box(&network_bytes)))
    });
    c.bench_function("aya_decode/cpu_profile_fuzz_harness", |b| {
        b.iter(|| fuzz_decode_raw_cpu_profile_event(black_box(&cpu_profile_bytes)))
    });
}

fn bench_host_parsers(c: &mut Criterion) {
    let stat = "cpu  139755 0 33548 1852017 223 0 1417 0 0 0\nprocs_running 3\nprocs_blocked 0\n";
    let loadavg = "0.17 0.12 0.09 2/842 12345\n";
    let meminfo = "MemTotal:       32768000 kB\nMemFree:         1024000 kB\nMemAvailable:   24000000 kB\nSwapTotal:       8388608 kB\nSwapFree:        8388608 kB\n";
    let diskstats = "   8       0 sda 1024 0 2048 0 512 0 4096 0 0 0 0 0 0 0 0 0 0\n";
    let process_stat = "1234 (e-navigator) S 1 1 1 0 -1 4194560 100 0 0 0 25 9 0 0 20 0 8 0 123456 268435456 4096 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
    let process_status = "Name:\te-navigator\nUid:\t1000\t1000\t1000\t1000\nThreads:\t8\n";

    c.bench_function("host_parser/cpu_stat", |b| {
        b.iter(|| parse_cpu_stat(black_box(stat), 100, 1_000, 2_000).unwrap())
    });
    c.bench_function("host_parser/loadavg", |b| {
        b.iter(|| parse_loadavg(black_box(loadavg), 1_000, 2_000).unwrap())
    });
    c.bench_function("host_parser/meminfo", |b| {
        b.iter(|| parse_meminfo(black_box(meminfo), 1_000, 2_000).unwrap())
    });
    c.bench_function("host_parser/diskstats", |b| {
        b.iter(|| parse_diskstats(black_box(diskstats), 1_000, 2_000).unwrap())
    });
    c.bench_function("host_parser/process_stat", |b| {
        b.iter(|| {
            parse_process_stat(
                1234,
                black_box(process_stat),
                Some(process_status),
                100,
                4096,
                32,
                4,
                1_000,
                2_000,
            )
            .unwrap()
        })
    });
}

fn kafka_produce_response_fixture() -> Vec<u8> {
    let topic = b"bench-topic";
    let mut body = Vec::with_capacity(43);
    body.extend_from_slice(&42_i32.to_be_bytes());
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(
        &i16::try_from(topic.len())
            .expect("kafka benchmark topic fits in i16")
            .to_be_bytes(),
    );
    body.extend_from_slice(topic);
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&0_i32.to_be_bytes());
    body.extend_from_slice(&6_i16.to_be_bytes());
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&0_i32.to_be_bytes());

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(
        &i32::try_from(body.len())
            .expect("kafka benchmark body fits in i32")
            .to_be_bytes(),
    );
    frame.extend_from_slice(&body);
    frame
}

fn kubernetes_pod_list_fixture(pod_count: usize) -> String {
    let items = (0..pod_count)
        .map(|index| {
            format!(
                r#"{{
                  "metadata": {{
                    "name": "bench-pod-{index}",
                    "namespace": "e-navigator-bench",
                    "uid": "pod-uid-{index}",
                    "labels": {{
                      "app.kubernetes.io/name": "bench-app-{app_index}",
                      "app.kubernetes.io/component": "api",
                      "e-navigator.dev/bench": "true",
                      "cardinality.example/ignored": "{index}"
                    }}
                  }},
                  "spec": {{
                    "nodeName": "homelab-01"
                  }},
                  "status": {{
                    "podIP": "10.42.{octet_b}.{octet_c}",
                    "containerStatuses": [
                      {{
                        "name": "api",
                        "containerID": "containerd://container-{index}-api"
                      }}
                    ]
                  }}
                }}"#,
                app_index = index % 32,
                octet_b = (index / 254) + 1,
                octet_c = (index % 254) + 1,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"items":[{items}]}}"#)
}

fn bench_protocol_and_profiles(c: &mut Criterion) {
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let http = b"GET /api/orders HTTP/1.1\r\nHost: api.example.test\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTracestate: rojo=00f067aa0ba902b7\r\n\r\n";
    let http_response = b"HTTP/1.1 503 Service Unavailable\r\nServer: fixture\r\n\r\n";
    let grpc = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\n:authority: checkout.example.com:8443\ncontent-type: application/grpc+proto\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\ntracestate: vendor=value\n\n";
    let grpc_trailers = b"grpc-status: 13\ngrpc-message: internal%20detail\n\n";
    let mongodb =
        b"\x2e\0\0\0\x01\0\0\0\0\0\0\0\xdd\x07\0\0\0\0\0\0\0\x00\x19\0\0\0\x02find\0\x0a\0\0\0customers\0\0";
    let mongodb_response =
        b"<\0\0\0\x01\0\0\0\0\0\0\0\xdd\x07\0\0\0\0\0\0\0\x00'\0\0\0\x08ok\0\0\x10code\0\r\0\0\0\x02errmsg\0\x07\0\0\0secret\0\0";
    let kafka = b"\0\0\0\x1b\0\0\0\x08\0\0\0\x2a\0\x0cbench-clienttopic";
    let kafka_response = b"\0\0\0\x15\0\0\0\x2a\0#secret-api-list";
    let kafka_produce_response = kafka_produce_response_fixture();
    let mysql = b"\x18\0\0\0\x03select * from customers";
    let mysql_ok_response = b"\x05\0\0\0\0\0\0\x02\0";
    let nats = b"PUB orders.created 5\r\nhello\r\n";
    let nats_response = b"-ERR 'Authorization Violation'\r\n";
    let postgres = b"Q\0\0\0\x1cselect * from customers\0";
    let postgres_response = b"C\0\0\0\x0fINSERT 0 1\0";
    let redis = b"*2\r\n$3\r\nGET\r\n$16\r\ncustomer:pii:123\r\n";
    let redis_response = b"+OK password-reset-complete\r\n";
    let protocol_config = ProtocolExtractionConfig::default();
    let profile_fixture = r#"{
        "timestamp_unix_nanos": 1000,
        "profiling_kind": "cpu",
        "correlation_kind": "observed_profile_sample",
        "confidence": "medium",
        "sample_count": 7,
        "sampling_period_nanos": 20000000,
        "stack_frames": [
          {"symbol":"handler","module":"api","file":"src/main.rs","line":42},
          {"symbol":"tokio::runtime","module":"tokio","file":"runtime.rs","line":7}
        ],
        "process": {"pid": 42, "ppid": 1, "uid": 1000, "command": "api", "executable": "/usr/bin/api", "cgroup_id": 7},
        "attributes": [{"key":"profile.source","value":"fixture"}]
    }"#;
    let limits = NormalizationLimits::default();

    c.bench_function("protocol/traceparent_parse", |b| {
        b.iter(|| parse_traceparent(black_box(traceparent)).unwrap())
    });
    c.bench_function("protocol/http_fixture_parse", |b| {
        b.iter(|| parse_http_request(black_box(http), &protocol_config).unwrap())
    });
    c.bench_function("protocol/http_response_parse", |b| {
        b.iter(|| parse_http_response(black_box(http_response), &protocol_config).unwrap())
    });
    c.bench_function("protocol/grpc_request_headers_parse", |b| {
        b.iter(|| parse_grpc_request_headers(black_box(grpc), &protocol_config).unwrap())
    });
    c.bench_function("protocol/grpc_response_trailers_parse", |b| {
        b.iter(|| parse_grpc_response_trailers(black_box(grpc_trailers), &protocol_config).unwrap())
    });
    c.bench_function("protocol/kafka_request_parse", |b| {
        b.iter(|| parse_kafka_request(black_box(kafka), &protocol_config).unwrap())
    });
    c.bench_function("protocol/kafka_api_versions_response_parse", |b| {
        b.iter(|| {
            parse_kafka_api_versions_response(black_box(kafka_response), 0, &protocol_config)
                .unwrap()
        })
    });
    c.bench_function("protocol/kafka_produce_response_parse", |b| {
        b.iter(|| {
            parse_kafka_produce_response(
                black_box(kafka_produce_response.as_slice()),
                1,
                &protocol_config,
            )
            .unwrap()
        })
    });
    c.bench_function("protocol/mongodb_op_msg_parse", |b| {
        b.iter(|| parse_mongodb_message(black_box(mongodb), &protocol_config).unwrap())
    });
    c.bench_function("protocol/mongodb_error_response_parse", |b| {
        b.iter(|| parse_mongodb_response(black_box(mongodb_response), &protocol_config).unwrap())
    });
    c.bench_function("protocol/mysql_query_packet_parse", |b| {
        b.iter(|| parse_mysql_command(black_box(mysql), &protocol_config).unwrap())
    });
    c.bench_function("protocol/mysql_ok_response_parse", |b| {
        b.iter(|| parse_mysql_response(black_box(mysql_ok_response), &protocol_config).unwrap())
    });
    c.bench_function("protocol/nats_pub_command_parse", |b| {
        b.iter(|| parse_nats_command(black_box(nats), &protocol_config).unwrap())
    });
    c.bench_function("protocol/nats_error_response_parse", |b| {
        b.iter(|| parse_nats_response(black_box(nats_response), &protocol_config).unwrap())
    });
    c.bench_function("protocol/postgres_simple_query_parse", |b| {
        b.iter(|| parse_postgres_message(black_box(postgres), &protocol_config).unwrap())
    });
    c.bench_function("protocol/postgres_command_complete_response_parse", |b| {
        b.iter(|| parse_postgres_response(black_box(postgres_response), &protocol_config).unwrap())
    });
    c.bench_function("protocol/redis_resp_command_parse", |b| {
        b.iter(|| parse_redis_command(black_box(redis), &protocol_config).unwrap())
    });
    c.bench_function("protocol/redis_simple_response_parse", |b| {
        b.iter(|| parse_redis_response(black_box(redis_response), &protocol_config).unwrap())
    });
    c.bench_function("profiling/fixture_normalize", |b| {
        b.iter(|| parse_profile_fixture(black_box(profile_fixture), &limits).unwrap())
    });
}

fn bench_processors(c: &mut Criterion) {
    let pod_list = kubernetes_pod_list_fixture(512);
    let config = e_navigator_core::KubernetesAttributionConfig {
        max_pods: 512,
        max_cache_entries: 1024,
        max_labels_per_pod: 3,
        ..e_navigator_core::KubernetesAttributionConfig::default()
    };

    c.bench_function("processor/kubernetes_pod_list_cache_build", |b| {
        b.iter(|| {
            KubernetesMetadataCache::from_pod_list_json(black_box(pod_list.as_str()), &config)
                .unwrap()
        })
    });
}

fn bench_generators(c: &mut Criterion) {
    bench_generator(
        c,
        "generator/network_metrics",
        NetworkMetricsGenerator::with_limits(8192, 8192),
        network_signals(),
    );
    bench_network_flow_byte_aggregation(c);
    bench_generator(
        c,
        "generator/dns_metrics",
        DnsMetricsGenerator::with_limits(4096, 4096, 4096, 4096),
        dns_signals(),
    );
    bench_generator(
        c,
        "generator/resource_metrics",
        ResourceMetricsGenerator::with_limits(8192),
        resource_signals(),
    );
    bench_generator(
        c,
        "generator/dependency_graph",
        DependencyGraphGenerator::new(8192),
        network_signals(),
    );
    bench_generator(
        c,
        "generator/trace_correlation",
        TraceCorrelationGenerator::with_limits(8192, 8192, 4096),
        trace_signals(),
    );
    bench_generator(
        c,
        "generator/request_correlation",
        RequestCorrelationGenerator::with_limits(8192, 4096),
        request_signals(),
    );
    bench_generator(
        c,
        "generator/profiling",
        ProfilingGenerator::with_limits(8192, 8192, 4096, 30_000_000_000),
        profiling_signals(),
    );
    bench_generator(
        c,
        "generator/runtime_security",
        RuntimeSecurityGenerator::with_kubernetes_api_endpoints([("10.43.0.1".to_string(), 443)]),
        security_signals(),
    );
}

fn bench_generator<G>(
    c: &mut Criterion,
    name: &'static str,
    generator: G,
    signals: Vec<SignalEnvelope>,
) where
    G: Generator<SignalEnvelope> + 'static,
{
    let runtime = Runtime::new().unwrap();
    let (tx, mut rx) = mpsc::channel(1024);
    let index = Cell::new(0_usize);
    c.bench_function(name, |b| {
        b.iter(|| {
            let next = index.get().wrapping_add(1);
            index.set(next);
            let signal = &signals[next % signals.len()];
            runtime
                .block_on(generator.observe(black_box(signal), &tx))
                .unwrap();
            while rx.try_recv().is_ok() {}
        })
    });
}

fn bench_network_flow_byte_aggregation(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let generator = NetworkMetricsGenerator::with_limits(8192, 8192);
    let (tx, mut rx) = mpsc::channel(1024);
    let index = Cell::new(0_u64);

    c.bench_function("generator/network_flow_byte_aggregation", |b| {
        b.iter_batched(
            || {
                let next = index.get().wrapping_add(1);
                index.set(next);
                network_close_signal_for_destination(
                    10_000 + next,
                    format!("10.42.1.{}", (next % 64) + 1),
                    4_000 + (next % 64) as u16,
                    Some(100 + (next % 256) as i32),
                )
            },
            |signal| {
                runtime
                    .block_on(generator.observe(black_box(&signal), &tx))
                    .unwrap();
                while rx.try_recv().is_ok() {}
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_serialization_and_exporter(c: &mut Criterion) {
    let signal = network_open_signal(1_000);
    let runtime = Runtime::new().unwrap();
    c.bench_function("json/signal_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&signal)).unwrap())
    });

    let network_metric = network_flow_metric_signal();
    let request_error_span = request_error_span_signal();
    let profile = profiling_signals().remove(0);
    let profile_session = profile_session_signal();
    let profile_warning = profile_warning_signal();
    // Binding outside a Tokio runtime keeps this benchmark focused on sink
    // write formatting/storage without starting an HTTP server.
    let prometheus_sink = PrometheusHttpSink::bind(PrometheusHttpConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 0,
        max_metric_lines: 4096,
        metrics_enabled: true,
        profiles_enabled: true,
    })
    .unwrap();
    let prometheus_latest_sink = PrometheusHttpSink::bind(PrometheusHttpConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 0,
        max_metric_lines: 4096,
        metrics_enabled: true,
        profiles_enabled: false,
    })
    .unwrap();
    for index in 0..2048 {
        runtime
            .block_on(
                prometheus_latest_sink.write(&network_flow_metric_signal_named(&format!(
                    "network.bench.metric.{index}"
                ))),
            )
            .unwrap();
    }
    let prometheus_latest_update = network_flow_metric_signal_named("network.bench.metric.2047");
    c.bench_function("formatter/otel_network_flow_metric", |b| {
        b.iter(|| format_otel_metric_record(black_box(&network_metric)).unwrap())
    });
    c.bench_function("formatter/otel_protocol_error_trace_record", |b| {
        b.iter(|| format_otel_trace_record(black_box(&request_error_span)).unwrap())
    });
    c.bench_function("formatter/profile_record", |b| {
        b.iter(|| format_profile_record(black_box(&profile)).unwrap())
    });
    c.bench_function("formatter/pprof_profile_sample", |b| {
        b.iter(|| format_pprof_profile(black_box(&profile)).unwrap())
    });
    c.bench_function("formatter/prometheus_profile_session_write", |b| {
        b.iter(|| {
            runtime
                .block_on(prometheus_sink.write(black_box(&profile_session)))
                .unwrap()
        })
    });
    c.bench_function("formatter/prometheus_profile_warning_write", |b| {
        b.iter(|| {
            runtime
                .block_on(prometheus_sink.write(black_box(&profile_warning)))
                .unwrap()
        })
    });
    c.bench_function("formatter/prometheus_latest_metric_update_prefilled", |b| {
        b.iter(|| {
            runtime
                .block_on(prometheus_latest_sink.write(black_box(&prometheus_latest_update)))
                .unwrap()
        })
    });

    c.bench_function("exporter/bounded_queue_enqueue", |b| {
        b.iter_batched(
            || {
                HttpJsonExporter::new(HttpExporterConfig {
                    endpoint: "http://127.0.0.1:9".to_string(),
                    headers: Vec::new(),
                    batch_size: 16,
                    queue_capacity: 128,
                    timeout_millis: 1,
                    max_retries: 0,
                    tls_insecure_skip_verify: false,
                })
                .unwrap()
            },
            |mut exporter: HttpJsonExporter<ExportRecord>| {
                for value in 0..64 {
                    exporter.enqueue(ExportRecord { value });
                }
                black_box(exporter.counters())
            },
            BatchSize::SmallInput,
        )
    });
}

#[derive(Debug, Clone, Serialize)]
struct ExportRecord {
    value: u64,
}

fn network_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .flat_map(|index| {
            [
                network_open_signal(1_000 + index),
                network_close_signal(2_000 + index),
                network_failure_signal(3_000 + index),
            ]
        })
        .collect()
}

fn dns_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .flat_map(|index| {
            let query = format!("api-{index}.e-navigator-bench.svc.cluster.local");
            [
                SignalEnvelope::dns_query(
                    "source.synthetic",
                    Some("node-a".to_string()),
                    DnsQueryEvent {
                        process: process(),
                        query_name: query.clone(),
                        query_type: DnsQueryType::A,
                        transport_protocol: NetworkProtocol::Udp,
                        server_address: Some("10.43.0.10".to_string()),
                        server_port: Some(53),
                        timestamp_unix_nanos: 10_000 + index,
                        container: Some(container()),
                        kubernetes: Some(kubernetes("api")),
                    },
                ),
                SignalEnvelope::dns_response(
                    "source.synthetic",
                    Some("node-a".to_string()),
                    DnsResponseEvent {
                        process: process(),
                        query_name: query,
                        query_type: DnsQueryType::A,
                        response_code: DnsResponseCode::NoError,
                        latency_nanos: Some(750_000),
                        transport_protocol: NetworkProtocol::Udp,
                        server_address: Some("10.43.0.10".to_string()),
                        server_port: Some(53),
                        timestamp_unix_nanos: 10_500 + index,
                        container: Some(container()),
                        kubernetes: Some(kubernetes("api")),
                    },
                ),
            ]
        })
        .collect()
}

fn resource_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .flat_map(|index| {
            let window = window(1_000 + index, 2_000 + index);
            [
                SignalEnvelope::node_cpu_observation(
                    "source.host_resource",
                    Some("node-a".to_string()),
                    NodeCpuObservation {
                        metric_name: "system.cpu.time".to_string(),
                        unit: "ns".to_string(),
                        timestamp_unix_nanos: window.end_unix_nanos,
                        window: window.clone(),
                        user_nanos: 10_000 + index,
                        system_nanos: 2_000,
                        idle_nanos: 50_000,
                        iowait_nanos: 500,
                        steal_nanos: 0,
                        runnable_tasks: Some(2),
                        blocked_tasks: Some(0),
                    },
                ),
                SignalEnvelope::process_resource_observation(
                    "source.host_resource",
                    Some("node-a".to_string()),
                    ProcessResourceObservation {
                        metric_name: "process.resource".to_string(),
                        unit: "1".to_string(),
                        timestamp_unix_nanos: window.end_unix_nanos,
                        window,
                        process: ProcessResourceContext {
                            pid: 1000 + index as u32,
                            ppid: Some(1),
                            uid: Some(1000),
                            command: "api".to_string(),
                            executable: Some("/usr/bin/api".to_string()),
                            container: Some(container()),
                            kubernetes: Some(kubernetes("api")),
                        },
                        cpu_time_nanos: Some(9_000),
                        memory_rss_bytes: Some(64 * 1024 * 1024),
                        virtual_memory_bytes: Some(256 * 1024 * 1024),
                        open_fds: Some(32),
                        socket_count: Some(8),
                        thread_count: Some(12),
                    },
                ),
            ]
        })
        .collect()
}

fn trace_signals() -> Vec<SignalEnvelope> {
    let mut signals = network_signals();
    signals.extend(dns_signals());
    signals
}

fn request_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .map(|index| {
            SignalEnvelope::protocol_request_observation(
                "source.synthetic",
                Some("node-a".to_string()),
                ProtocolRequestObservation {
                    protocol: ProtocolKind::Http,
                    start_unix_nanos: 1_000 + index,
                    end_unix_nanos: Some(2_000 + index),
                    duration_nanos: Some(1_000),
                    trace_id: Some(format!("4bf92f3577b34da6a3ce929d0e0e{:04x}", index)),
                    span_id: Some(format!("00f067aa0ba9{:04x}", index)),
                    parent_span_id: None,
                    traceparent: None,
                    tracestate: None,
                    correlation_kind: TraceCorrelationKind::ProtocolObserved,
                    confidence: TraceConfidence::High,
                    service_name: Some("api".to_string()),
                    method: Some("GET".to_string()),
                    status_code: Some(200),
                    process: Some(process()),
                    container: Some(container()),
                    kubernetes: Some(kubernetes("api")),
                    peer: Some(TracePeerContext {
                        address: Some("10.43.12.22".to_string()),
                        port: Some(8080),
                        domain: Some("web.e-navigator-bench.svc.cluster.local".to_string()),
                        workload: Some(kubernetes("web")),
                        container: None,
                    }),
                    attributes: vec![TraceAttribute {
                        key: "http.route".to_string(),
                        value: "/orders".to_string(),
                    }],
                },
            )
        })
        .collect()
}

fn request_error_span_signal() -> SignalEnvelope {
    SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "mongodb command".to_string(),
            protocol: ProtocolKind::Mongodb,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("database-client".to_string()),
            method: Some("find".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes("database-client")),
            peer: Some(TracePeerContext {
                address: Some("10.43.12.30".to_string()),
                port: Some(27017),
                domain: Some("mongodb.e-navigator-bench.svc.cluster.local".to_string()),
                workload: Some(kubernetes("mongodb")),
                container: None,
            }),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "mongodb".to_string(),
                },
                TraceAttribute {
                    key: "db.response.status_code".to_string(),
                    value: "13".to_string(),
                },
                TraceAttribute {
                    key: "error.type".to_string(),
                    value: "13".to_string(),
                },
            ],
        },
    )
}

fn profiling_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .map(|index| {
            SignalEnvelope::profile_sample_observation(
                "source.aya_cpu_profile",
                Some("node-a".to_string()),
                ProfileSampleObservation {
                    timestamp_unix_nanos: 1_000 + index,
                    profiling_kind: ProfilingKind::Cpu,
                    correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                    confidence: ProfilingConfidence::Medium,
                    sample_count: 3,
                    sampling_period_nanos: Some(20_000_000),
                    stack_id: format!("stack:{index:016x}"),
                    stack_frames: vec![
                        ProfilingFrame {
                            symbol: Some("handler".to_string()),
                            module: Some("api".to_string()),
                            file: Some("src/main.rs".to_string()),
                            line: Some(42),
                        },
                        ProfilingFrame {
                            symbol: Some("tokio::runtime".to_string()),
                            module: Some("tokio".to_string()),
                            file: None,
                            line: None,
                        },
                    ],
                    process: Some(process()),
                    container: Some(container()),
                    kubernetes: Some(kubernetes("api")),
                    thread_id: Some(42),
                    thread_name: Some("worker".to_string()),
                    attributes: vec![ProfilingAttribute {
                        key: "profiling.source".to_string(),
                        value: "fixture".to_string(),
                    }],
                },
            )
        })
        .collect()
}

fn profile_session_signal() -> SignalEnvelope {
    SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingSessionObservation {
            window: window(1_000, 31_000),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:benchmark".to_string(),
            observed_sample_count: 256,
            dropped_sample_count: 4,
            distinct_stack_count: 64,
            sampling_period_nanos: Some(20_000_000),
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
            source: "source.aya_cpu_profile".to_string(),
            attributes: vec![ProfilingAttribute {
                key: "profiling.source".to_string(),
                value: "fixture".to_string(),
            }],
        },
    )
}

fn profile_warning_signal() -> SignalEnvelope {
    SignalEnvelope::profiling_warning_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingWarningObservation {
            warning_type: "dropped_profile_samples".to_string(),
            message: "profile samples were dropped by bounded aggregation".to_string(),
            timestamp_unix_nanos: 31_000,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::Medium,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
            attributes: vec![ProfilingAttribute {
                key: "profile.dropped_sample_count".to_string(),
                value: "4".to_string(),
            }],
        },
    )
}

fn security_signals() -> Vec<SignalEnvelope> {
    (0..128)
        .flat_map(|index| {
            [
                SignalEnvelope::exec(
                    "source.synthetic",
                    Some("node-a".to_string()),
                    ExecEvent {
                        pid: 2000 + index as u32,
                        ppid: Some(1),
                        uid: Some(1000),
                        command: "sh".to_string(),
                        executable: Some("/bin/sh".to_string()),
                        arguments: vec!["sh".to_string()],
                        cgroup_id: Some(7),
                        timestamp_unix_nanos: 1_000 + index,
                        container: Some(container()),
                        kubernetes: Some(kubernetes("api")),
                    },
                ),
                network_open_signal(2_000 + index),
            ]
        })
        .collect()
}

fn network_flow_metric_signal() -> SignalEnvelope {
    network_flow_metric_signal_named("network.flow.bytes")
}

fn network_flow_metric_signal_named(metric_name: &str) -> SignalEnvelope {
    SignalEnvelope::network_counter_metric(
        "generator.network_metrics",
        Some("node-a".to_string()),
        NetworkCounterMetric {
            metric_name: metric_name.to_string(),
            unit: "By".to_string(),
            value: 4096,
            window: window(1_000, 2_000),
            process: Some(process()),
            protocol: Some(NetworkProtocol::Tcp),
            address_family: Some(NetworkAddressFamily::Ipv4),
            local_address: None,
            local_port: None,
            remote_address: None,
            remote_port: None,
            errno: None,
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
        },
    )
}

fn network_open_signal(timestamp: u64) -> SignalEnvelope {
    SignalEnvelope::network_connection_open(
        "source.synthetic",
        Some("node-a".to_string()),
        NetworkConnectionOpenEvent {
            process: process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.42.0.10".to_string()),
            local_port: Some(41234),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(12),
            timestamp_unix_nanos: timestamp,
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
        },
    )
}

fn network_close_signal(timestamp: u64) -> SignalEnvelope {
    network_close_signal_for_destination(timestamp, "203.0.113.10".to_string(), 443, Some(12))
}

fn network_close_signal_for_destination(
    timestamp: u64,
    remote_address: String,
    remote_port: u16,
    fd: Option<i32>,
) -> SignalEnvelope {
    SignalEnvelope::network_connection_close(
        "source.synthetic",
        Some("node-a".to_string()),
        NetworkConnectionCloseEvent {
            process: process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.42.0.10".to_string()),
            local_port: Some(41234),
            remote_address,
            remote_port,
            fd,
            opened_at_unix_nanos: Some(timestamp.saturating_sub(500)),
            closed_at_unix_nanos: timestamp,
            duration_nanos: Some(500),
            bytes_sent: Some(512),
            bytes_received: Some(1536),
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
        },
    )
}

fn network_failure_signal(timestamp: u64) -> SignalEnvelope {
    SignalEnvelope::network_connection_failure(
        "source.synthetic",
        Some("node-a".to_string()),
        NetworkConnectionFailureEvent {
            process: process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            remote_address: "203.0.113.99".to_string(),
            remote_port: 443,
            fd: Some(13),
            errno: 111,
            timestamp_unix_nanos: timestamp,
            container: Some(container()),
            kubernetes: Some(kubernetes("api")),
        },
    )
}

fn process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 4242,
        ppid: Some(1),
        uid: Some(1000),
        command: "api".to_string(),
        executable: Some("/usr/bin/api".to_string()),
        cgroup_id: Some(7),
    }
}

fn container() -> ContainerContext {
    ContainerContext {
        container_id: "containerd://abc123".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes(app: &str) -> KubernetesContext {
    KubernetesContext {
        namespace: "e-navigator-bench".to_string(),
        pod_name: format!("{app}-7d9c9f6d7b-a1b2c"),
        pod_uid: Some(format!("pod-{app}")),
        container_name: Some(app.to_string()),
        node_name: Some("homelab-01".to_string()),
        labels: BTreeMap::from([("app.kubernetes.io/name".to_string(), app.to_string())]),
    }
}

fn window(start_unix_nanos: u64, end_unix_nanos: u64) -> MetricAggregationWindow {
    MetricAggregationWindow {
        start_unix_nanos,
        end_unix_nanos,
    }
}

criterion_group!(
    benches,
    bench_raw_aya_decoders,
    bench_host_parsers,
    bench_protocol_and_profiles,
    bench_processors,
    bench_generators,
    bench_serialization_and_exporter
);
criterion_main!(benches);
