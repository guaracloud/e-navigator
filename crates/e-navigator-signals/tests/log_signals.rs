#![allow(clippy::expect_used, reason = "fixture assertions")]
use e_navigator_signals::{SignalEnvelope, SignalKind};

#[test]
fn log_schema_round_trips_and_debug_does_not_disclose_body() {
    let value = serde_json::json!({
        "schema_version": 1, "kind": "application_log_observation",
        "source": "source.cri_logs", "host": "node-a",
        "payload": {"namespace":"default", "pod_name":"app", "pod_uid":"uid",
            "container_name":"web", "restart_count":0, "stream":"stdout",
            "timestamp":"2026-10-10T12:00:00.000000001Z", "observed_at_unix_nanos":1,
            "body":"private-test-body", "body_bytes":17, "truncated":false,
            "incomplete":false, "invalid_utf8":false}
    });
    let mut signal: SignalEnvelope = serde_json::from_value(value.clone()).expect("log schema");
    let (receipt, _accepted) = e_navigator_core::DurableReceipt::channel();
    signal.durable_receipt = Some(receipt);
    assert_eq!(serde_json::to_value(&signal).expect("encode"), value);
    let restored: SignalEnvelope = serde_json::from_value(value).expect("restore");
    assert!(restored.durable_receipt.is_none());
    assert!(!format!("{signal:?}").contains("durable_receipt"));
    assert_eq!(signal.signal_kind(), SignalKind::ApplicationLogObservation);
    assert!(!format!("{signal:?}").contains("private-test-body"));
}
