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
            "dependency_edge".to_string(),
            "dns_response".to_string(),
            "exec".to_string(),
            "network_connection_open".to_string(),
            "node_memory_observation".to_string(),
            "profile_sample_observation".to_string(),
            "protocol_request_observation".to_string(),
            "trace_span_observation".to_string(),
        ])
    );
}
