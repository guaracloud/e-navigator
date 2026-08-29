#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Bounded generators that derive metrics, traces, topology, profiles, and findings.

use e_navigator_core::{CoreError, CoreResult};
use e_navigator_signals::SignalEnvelope;
use tokio::sync::mpsc;

mod bounded_fingerprints;
pub mod dependency_graph;
pub mod dns_metrics;
pub mod network_metrics;
mod otel_coexistence;
pub mod peer_flow_metrics;
pub mod profiling;
pub mod request_correlation;
pub mod resource_metrics;
pub mod runtime_security;
pub mod trace_correlation;

pub use dependency_graph::DependencyGraphGenerator;
pub use dns_metrics::DnsMetricsGenerator;
pub use network_metrics::NetworkMetricsGenerator;
pub use peer_flow_metrics::PeerFlowMetricsGenerator;
pub use profiling::ProfilingGenerator;
pub use request_correlation::RequestCorrelationGenerator;
pub use resource_metrics::ResourceMetricsGenerator;
pub use runtime_security::RuntimeSecurityGenerator;
pub use trace_correlation::TraceCorrelationGenerator;

async fn send_outputs(
    outputs: Vec<SignalEnvelope>,
    tx: &mpsc::Sender<SignalEnvelope>,
) -> CoreResult<()> {
    for output in outputs {
        tx.send(output)
            .await
            .map_err(|_| CoreError::PipelineClosed)?;
    }
    Ok(())
}
