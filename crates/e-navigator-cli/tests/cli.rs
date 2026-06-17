use std::process::Command;

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
        r#""kind":"dns_query""#,
        r#""kind":"dns_response""#,
        r#""kind":"protocol_request_observation""#,
        r#""kind":"trace_span_observation""#,
        r#""kind":"request_span_observation""#,
        r#""kind":"request_correlation_warning""#,
        r#""kind":"profile_sample_observation""#,
        r#""kind":"profiling_session_observation""#,
        r#""kind":"profiling_warning_observation""#,
        r#""kind":"node_cpu_observation""#,
        r#""kind":"dependency_edge""#,
        r#""kind":"runtime_security_finding""#,
        r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#,
        r#""duration_nanos":2000000"#,
        r#""warning_type":"malformed_trace_context""#,
        r#""warning_type":"missing_trace_context""#,
        r#""warning_type":"malformed_profile_fixture""#,
        r#""errno":111"#,
        r#""rule_id":"runtime.shell_in_container""#,
        r#""rule_id":"network.unexpected_external_connection""#,
    ] {
        assert!(stdout.contains(expected), "missing {expected}");
    }
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
