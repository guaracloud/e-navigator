#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "integration tests use panic-oriented assertions for failed contracts"
)]

use std::collections::BTreeSet;
use std::process::Command;

#[test]
fn version_flag_reports_workspace_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--version")
        .output()
        .expect("run e-navigator version");

    assert!(
        output.status.success(),
        "version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output is utf8"),
        format!("e-navigator {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn validate_config_with_default_config_exits_without_running_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--source")
        .arg("synthetic")
        .arg("--validate-config")
        .output()
        .expect("run e-navigator validate-config");

    assert!(
        output.status.success(),
        "validate-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "validate-config should not emit synthetic signals"
    );
}

#[test]
fn validate_config_with_config_file_exits_without_running_source() {
    let path = temp_config_path("valid");
    std::fs::write(
        &path,
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
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--config")
        .arg(&path)
        .arg("--validate-config")
        .output()
        .expect("run e-navigator validate-config");
    let _ = std::fs::remove_file(path);

    assert!(
        output.status.success(),
        "validate-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "validate-config should not emit synthetic signals"
    );
}

#[test]
fn validate_config_with_invalid_config_fails_without_running_source() {
    let path = temp_config_path("invalid");
    std::fs::write(
        &path,
        r#"
        queue_capacity = 0

        [[modules]]
        name = "source.synthetic_exec"
        enabled = true

        [[modules]]
        name = "sink.json_stdout"
        enabled = true
        "#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--source")
        .arg("synthetic")
        .arg("--config")
        .arg(&path)
        .arg("--validate-config")
        .output()
        .expect("run e-navigator validate-config");
    let _ = std::fs::remove_file(path);

    assert!(
        !output.status.success(),
        "validate-config should reject invalid config"
    );
    assert!(
        output.stdout.is_empty(),
        "validate-config should not emit synthetic signals"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("queue_capacity must be greater than zero"),
        "stderr should explain validation failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn synthetic_run_emits_generated_contract_families() {
    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--source")
        .arg("synthetic")
        .output()
        .expect("run e-navigator synthetic");

    assert!(
        output.status.success(),
        "synthetic run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("synthetic output is utf8");
    for expected in [
        r#""kind":"exec""#,
        r#""kind":"process_exit""#,
        r#""kind":"network_connection_open""#,
        r#""kind":"network_connection_close""#,
        r#""kind":"network_connection_failure""#,
        r#""kind":"network_flow_warning""#,
        r#""kind":"dns_query""#,
        r#""kind":"dns_response""#,
        r#""kind":"protocol_request_observation""#,
        r#""kind":"trace_span_observation""#,
        r#""kind":"trace_correlation_warning""#,
        r#""kind":"request_span_observation""#,
        r#""kind":"request_correlation_warning""#,
        r#""kind":"profile_sample_observation""#,
        r#""kind":"profiling_session_observation""#,
        r#""kind":"profiling_warning_observation""#,
        r#""kind":"node_cpu_observation""#,
        r#""kind":"dependency_edge""#,
        r#""kind":"runtime_security_finding""#,
        r#""protocol":"grpc""#,
        r#""protocol":"kafka""#,
        r#""protocol":"mongodb""#,
        r#""protocol":"mysql""#,
        r#""protocol":"nats""#,
        r#""protocol":"postgresql""#,
        r#""protocol":"redis""#,
        r#""name":"grpc request""#,
        r#""name":"kafka request""#,
        r#""name":"mongodb command""#,
        r#""name":"mysql query""#,
        r#""name":"nats message""#,
        r#""name":"postgresql query""#,
        r#""name":"redis command""#,
        r#""value":"http_protocol_error""#,
        r#""value":"grpc_protocol_error""#,
        r#""value":"kafka_protocol_error""#,
        r#""value":"mongodb_protocol_error""#,
        r#""value":"mysql_protocol_error""#,
        r#""value":"nats_protocol_error""#,
        r#""value":"postgresql_protocol_error""#,
        r#""value":"redis_protocol_error""#,
        r#""status_code":503"#,
        r#""key":"rpc.grpc.status_code","value":"13""#,
        r#""key":"messaging.kafka.response.error_code","value":"35""#,
        r#""key":"messaging.nats.status_code","value":"ERR""#,
        r#""key":"db.response.status_code","value":"WRONGTYPE""#,
        r#""key":"error.type","value":"redis_wrongtype""#,
        r#""value":"malformed_trace_context_request""#,
        r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#,
        r#""duration_nanos":2000000"#,
        r#""warning_type":"missing_trace_context""#,
        r#""warning_type":"missing_attribution""#,
        r#""warning_type":"malformed_profile_fixture""#,
        r#""remote_address":"198.51.100.30""#,
        r#""errno":111"#,
        r#""rule_id":"runtime.shell_in_container""#,
        r#""rule_id":"network.unexpected_external_connection""#,
    ] {
        assert!(stdout.contains(expected), "missing {expected}");
    }
}

#[test]
fn synthetic_run_emits_expected_signal_kind_families() {
    let output = Command::new(env!("CARGO_BIN_EXE_e-navigator"))
        .arg("--source")
        .arg("synthetic")
        .output()
        .expect("run e-navigator synthetic");

    assert!(
        output.status.success(),
        "synthetic run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("synthetic output is utf8");
    let observed = stdout
        .lines()
        .map(|line| {
            let value = serde_json::from_str::<serde_json::Value>(line)
                .expect("synthetic signal line is json");
            value["kind"]
                .as_str()
                .expect("synthetic signal has kind")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        observed,
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
            "network_connection_close".to_string(),
            "network_connection_failure".to_string(),
            "network_connection_open".to_string(),
            "network_counter_metric".to_string(),
            "network_duration_metric".to_string(),
            "network_flow_summary".to_string(),
            "network_flow_warning".to_string(),
            "network_gauge_metric".to_string(),
            "node_cpu_observation".to_string(),
            "node_disk_io_observation".to_string(),
            "node_filesystem_observation".to_string(),
            "node_load_observation".to_string(),
            "node_memory_observation".to_string(),
            "process_exit".to_string(),
            "process_resource_observation".to_string(),
            "profile_sample_observation".to_string(),
            "profiling_session_observation".to_string(),
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

fn temp_config_path(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "e-navigator-cli-integration-{label}-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    path
}
