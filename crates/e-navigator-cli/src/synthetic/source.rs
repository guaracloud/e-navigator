use super::{dns, exec, network, profiling, request, resource, synthetic_attribution, trace};
use crate::time::now_unix_nanos;
use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
use e_navigator_signals::SignalEnvelope;
use tokio::sync::mpsc;

#[derive(Debug)]
pub(crate) struct SyntheticExecSource {
    pub(crate) host: Option<String>,
}

#[async_trait]
impl Source<SignalEnvelope> for SyntheticExecSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new(super::source_name(), ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let (container, kubernetes) = synthetic_attribution();

        tx.send(exec::exec_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        tx.send(exec::process_exit_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        let opened_at = now_unix_nanos();
        tx.send(network::open_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        let duration_nanos = 2_000_000;
        tx.send(network::close_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        tx.send(dns::query_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        tx.send(dns::response_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        tx.send(trace::span_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        for signal in request::signals(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ) {
            tx.send(signal)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        for signal in profiling::signals(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at.saturating_add(duration_nanos + 25_000),
        ) {
            tx.send(signal)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        tx.send(network::failure_signal(
            self.host.clone(),
            container.clone(),
            kubernetes.clone(),
            opened_at,
            duration_nanos,
        ))
        .await
        .map_err(|_| CoreError::PipelineClosed)?;

        tx.send(network::flow_summary_signal(self.host.clone(), opened_at))
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

        let resource_started = opened_at.saturating_add(duration_nanos + 20_000);
        for signal in resource::signals(self.host.clone(), container, kubernetes, resource_started)
        {
            tx.send(signal)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Source;
    use e_navigator_signals::SignalPayload;
    use tokio::sync::mpsc;

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
                    && span.duration_nanos == Some(2_000_000)
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
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
                SignalPayload::NetworkFlowSummary(flow)
                if flow.bytes == 4096
                    && flow.source.kubernetes.as_ref().map(|k| k.namespace.as_str())
                        == Some("e-navigator-smoke")
        )));
        assert!(signals.iter().any(|signal| matches!(
            &signal.payload,
            SignalPayload::ProfilingWarningObservation(warning)
                if warning.warning_type == "malformed_profile_fixture"
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
