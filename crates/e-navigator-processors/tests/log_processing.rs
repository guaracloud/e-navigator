#![allow(clippy::unwrap_used, clippy::panic, reason = "fixture assertions")]
use e_navigator_core::{LogProcessingConfig, Processor};
use e_navigator_processors::LogProcessingProcessor;
use e_navigator_signals::{SignalEnvelope, SignalPayload};

fn observation(body: Option<&str>) -> SignalEnvelope {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,"kind":"application_log_observation","source":"source.cri_logs","host":"node-a",
        "payload":{"namespace":"default","pod_name":"app","pod_uid":"uid","container_name":"app",
        "restart_count":2,"stream":"stderr","timestamp":"2026-10-11T00:00:00.123456789Z",
        "observed_at_unix_nanos":100,"body":body,"body_bytes":100,"truncated":false,"incomplete":true,"invalid_utf8":false}
    })).unwrap()
}

#[tokio::test]
async fn redacts_before_export_and_preserves_instance_and_context() {
    let config = LogProcessingConfig {
        enabled: true,
        redact_values: vec!["literal-secret".into()],
        attribute_keys: vec!["request_id".into()],
        ..Default::default()
    };
    let processor = LogProcessingProcessor::new(config);
    let input = observation(Some(
        r#"{"message":"hello literal-secret\nstack frame","password":"hidden-secret","nested":{"authorization":"Bearer hidden"},"severity":"ERROR","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","request_id":"123","service.name":"forged"}"#,
    ));
    let output = processor.process(input).await.unwrap().unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    let body = log.body.as_deref().unwrap();
    for secret in ["literal-secret", "hidden-secret", "Bearer hidden"] {
        assert!(!body.contains(secret));
    }
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["message"], "hello [REDACTED]\nstack frame");
    assert!(parsed.get("password").is_none());
    let processed = log.processing.as_ref().unwrap();
    assert_eq!(processed.severity_text.as_deref(), Some("ERROR"));
    assert_eq!(
        processed.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(
        processed.attributes.get("request_id").map(String::as_str),
        Some("123")
    );
    assert_eq!((&log.pod_uid, log.restart_count), (&"uid".to_string(), 2));
    assert!(log.incomplete);
    assert!(!format!("{log:?}").contains("hidden"));
}

#[tokio::test]
async fn omitted_malformed_and_oversize_payloads_are_explicit_and_safe() {
    let processor = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        max_body_bytes: 64,
        ..Default::default()
    });
    for body in [None, Some("{broken secret"), Some(&"x".repeat(65))] {
        let output = processor.process(observation(body)).await.unwrap().unwrap();
        let SignalPayload::ApplicationLogObservation(log) = output.payload else {
            panic!("log")
        };
        assert!(log.body.is_none());
        assert!(log.processing.is_some());
    }
}

#[tokio::test]
async fn multiline_plaintext_and_invalid_context_are_bounded() {
    let processor = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        redact_values: vec!["secret".into()],
        ..Default::default()
    });
    let output = processor
        .process(observation(Some("panic secret\n  frame one\n  frame two")))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(
        log.body.as_deref(),
        Some("panic [REDACTED]\n  frame one\n  frame two")
    );
    let output = processor
        .process(observation(Some(
            r#"{"trace_id":"00000000000000000000000000000000","span_id":"00f067aa0ba902b7"}"#,
        )))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert!(log.processing.unwrap().trace_id.is_none());
}

#[tokio::test]
async fn literal_secrets_in_json_keys_and_numbers_are_removed() {
    let processor = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        redact_values: vec!["12345".into()],
        ..Default::default()
    });
    let output = processor
        .process(observation(Some(
            r#"{"account":12345,"12345-key":"value","array":["12345"]}"#,
        )))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    let encoded = serde_json::to_string(&log.body).unwrap();
    assert!(!encoded.contains("12345"));
}

#[tokio::test]
async fn redaction_expansion_and_line_limits_reject_without_retaining_fields() {
    for config in [
        LogProcessingConfig {
            enabled: true,
            max_body_bytes: 64,
            redact_values: vec!["x".into()],
            ..Default::default()
        },
        LogProcessingConfig {
            enabled: true,
            max_lines: 2,
            ..Default::default()
        },
    ] {
        let processor = LogProcessingProcessor::new(config);
        let output = processor
            .process(observation(Some("xxxxxxxx\nsecond\nthird")))
            .await
            .unwrap()
            .unwrap();
        let SignalPayload::ApplicationLogObservation(log) = output.payload else {
            panic!("log")
        };
        assert!(log.body.is_none());
        assert_eq!(
            log.processing.unwrap().outcome,
            e_navigator_signals::LogProcessingOutcome::BudgetRejected
        );
    }
}

#[tokio::test]
async fn workload_enrichment_uses_uid_and_never_current_runtime_identity() {
    use e_navigator_core::{AttributionConfig, capture_filter::RawPod};
    use e_navigator_processors::{ContainerAttributionProcessor, KubernetesMetadataCache};
    let pod = RawPod {
        namespace: "default".into(),
        pod_name: "app".into(),
        pod_uid: Some("uid".into()),
        node_name: Some("node-a".into()),
        pod_ip: None,
        workload_name: Some("checkout".into()),
        workload_type: Some("Deployment".into()),
        container_ids: vec!["current-container".into()],
        container_names: std::collections::BTreeMap::from([(
            "current-container".into(),
            "app".into(),
        )]),
        labels: Default::default(),
    };
    let config = AttributionConfig::default();
    let cache = KubernetesMetadataCache::from_raw_pods(&[pod], &config.kubernetes);
    let attribution = ContainerAttributionProcessor::with_cache(config, cache);
    let processing = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        ..Default::default()
    });
    let input = processing
        .process(observation(Some("crash-final")))
        .await
        .unwrap()
        .unwrap();
    let output = attribution.process(input.clone()).await.unwrap().unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(
        log.processing.unwrap().workload_name.as_deref(),
        Some("default/checkout")
    );
    let mut different_uid = input;
    if let SignalPayload::ApplicationLogObservation(log) = &mut different_uid.payload {
        log.pod_uid = "replacement-uid".into();
    }
    let output = attribution.process(different_uid).await.unwrap().unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert!(log.processing.unwrap().workload_name.is_none());
}

#[tokio::test]
async fn shared_sensitive_key_rules_and_decoded_json_multiline_budget_apply() {
    let processor = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        max_lines: 2,
        ..Default::default()
    });
    let output = processor
        .process(observation(Some(
            r#"{"message":"a\nb\nc","x-api-key":"secret","JWT":"private"}"#,
        )))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(
        log.processing.unwrap().outcome,
        e_navigator_signals::LogProcessingOutcome::BudgetRejected
    );
    assert!(log.body.is_none());
    let output = processor
        .process(observation(Some(
            r#"{"message":"ok","x-api-key":"private-key","JWT":"private-token"}"#,
        )))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(log.body.as_deref(), Some(r#"{"message":"ok"}"#));
}

#[tokio::test]
async fn malformed_keep_redacted_is_explicit_and_trace_only_context_is_preserved() {
    use e_navigator_core::LogParseFailure;
    let processor = LogProcessingProcessor::new(LogProcessingConfig {
        enabled: true,
        parse_failure: LogParseFailure::KeepRedacted,
        redact_values: vec!["secret".into()],
        ..Default::default()
    });
    let output = processor
        .process(observation(Some("{broken secret")))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(log.body.as_deref(), Some("{broken [REDACTED]"));
    assert_eq!(
        log.processing.unwrap().outcome,
        e_navigator_signals::LogProcessingOutcome::MalformedJson
    );
    let output = processor
        .process(observation(Some(
            r#"{"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}"#,
        )))
        .await
        .unwrap()
        .unwrap();
    let SignalPayload::ApplicationLogObservation(log) = output.payload else {
        panic!("log")
    };
    assert_eq!(
        log.processing.unwrap().trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
}
