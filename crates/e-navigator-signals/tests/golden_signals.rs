use e_navigator_core::Signal;
use e_navigator_signals::SignalEnvelope;
use std::collections::BTreeSet;

#[test]
fn golden_signal_families_round_trip_without_schema_drift() {
    let fixtures =
        serde_json::from_str::<Vec<serde_json::Value>>(include_str!("golden/signal_families.json"))
            .expect("golden signal fixtures parse");
    let mut seen = BTreeSet::new();

    for fixture in fixtures {
        let signal = serde_json::from_value::<SignalEnvelope>(fixture.clone())
            .expect("golden signal deserializes");
        let encoded = serde_json::to_value(&signal).expect("golden signal serializes");
        assert_eq!(encoded, fixture);
        seen.insert(signal.kind().to_string());
    }

    assert_eq!(
        seen,
        BTreeSet::from([
            "cgroup_cpu_observation".to_string(),
            "cgroup_file_descriptor_observation".to_string(),
            "cgroup_memory_observation".to_string(),
            "cgroup_pids_observation".to_string(),
            "dependency_edge".to_string(),
            "dns_counter_metric".to_string(),
            "dns_latency_metric".to_string(),
            "dns_query".to_string(),
            "dns_response".to_string(),
            "exec".to_string(),
            "extracted_trace_context_observation".to_string(),
            "network_connection_close".to_string(),
            "network_connection_failure".to_string(),
            "network_connection_open".to_string(),
            "network_counter_metric".to_string(),
            "network_duration_metric".to_string(),
            "network_flow_summary".to_string(),
            "network_gauge_metric".to_string(),
            "node_cpu_observation".to_string(),
            "node_disk_io_observation".to_string(),
            "node_filesystem_observation".to_string(),
            "node_load_observation".to_string(),
            "node_memory_observation".to_string(),
            "process_exit".to_string(),
            "process_lifecycle_duration".to_string(),
            "process_resource_observation".to_string(),
            "profile_sample_observation".to_string(),
            "profiling_session_observation".to_string(),
            "profiling_stack_trace_observation".to_string(),
            "profiling_warning_observation".to_string(),
            "protocol_request_observation".to_string(),
            "request_correlation_warning".to_string(),
            "request_span_observation".to_string(),
            "resource_counter_metric".to_string(),
            "resource_gauge_metric".to_string(),
            "runtime_security_finding".to_string(),
            "service_interaction_span_observation".to_string(),
            "trace_correlation_warning".to_string(),
            "trace_service_path_observation".to_string(),
            "trace_span_observation".to_string(),
        ])
    );
}
