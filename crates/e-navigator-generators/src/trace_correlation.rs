use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata, Signal};
use e_navigator_signals::{
    ContainerContext, DependencyEdgeEvent, DependencyEndpoint, DnsResponseCode, DnsResponseEvent,
    KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkProcessIdentity, NetworkProtocol,
    ServiceInteractionSpanObservation, SignalEnvelope, SignalPayload, TraceAttribute,
    TraceConfidence, TraceCorrelationKind, TraceCorrelationWarning, TraceServicePathObservation,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_SERVICE_PATHS: usize = 4096;
const DEFAULT_MAX_SEEN_INTERACTIONS: usize = 8192;
const DEFAULT_MAX_WARNINGS: usize = 1024;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_DOMAIN_LABEL_BYTES: usize = 63;

#[derive(Debug)]
pub struct TraceCorrelationGenerator {
    max_service_paths: usize,
    max_seen_interactions: usize,
    max_warnings: usize,
    service_paths: Mutex<BTreeMap<PathKey, PathState>>,
    seen_interactions: Mutex<BoundedFingerprints<InteractionFingerprint>>,
    seen_warnings: Mutex<BoundedFingerprints<WarningFingerprint>>,
}

impl Default for TraceCorrelationGenerator {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_SERVICE_PATHS,
            DEFAULT_MAX_SEEN_INTERACTIONS,
            DEFAULT_MAX_WARNINGS,
        )
    }
}

impl TraceCorrelationGenerator {
    pub fn with_limits(
        max_service_paths: usize,
        max_seen_interactions: usize,
        max_warnings: usize,
    ) -> Self {
        Self {
            max_service_paths,
            max_seen_interactions,
            max_warnings,
            service_paths: Mutex::new(BTreeMap::new()),
            seen_interactions: Mutex::new(BoundedFingerprints::default()),
            seen_warnings: Mutex::new(BoundedFingerprints::default()),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for TraceCorrelationGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.trace_correlation", ModuleKind::Generator)
    }

    fn accepts(&self, signal: &SignalEnvelope) -> bool {
        matches!(
            &signal.payload,
            SignalPayload::NetworkConnectionClose(_)
                | SignalPayload::NetworkConnectionFailure(_)
                | SignalPayload::DependencyEdge(_)
                | SignalPayload::DnsResponse(_)
        )
    }

    fn observe_immediate(
        &self,
        signal: &SignalEnvelope,
    ) -> Option<CoreResult<Vec<SignalEnvelope>>> {
        Some(self.outputs_for_signal(signal))
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        for output in self.outputs_for_signal(signal)? {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl TraceCorrelationGenerator {
    fn outputs_for_signal(&self, signal: &SignalEnvelope) -> CoreResult<Vec<SignalEnvelope>> {
        let outputs = match &signal.payload {
            SignalPayload::NetworkConnectionClose(event) => {
                self.observe_network_close(signal, event)?
            }
            SignalPayload::NetworkConnectionFailure(event) => {
                self.observe_network_failure(signal, event)?
            }
            SignalPayload::DependencyEdge(event) => self.observe_dependency_edge(signal, event)?,
            SignalPayload::DnsResponse(event) => self.observe_dns_response(signal, event)?,
            _ => Vec::new(),
        };
        Ok(outputs)
    }

    fn observe_network_close(
        &self,
        signal: &SignalEnvelope,
        event: &NetworkConnectionCloseEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let fingerprint = InteractionFingerprint::from_close(event);
        if !self.mark_interaction_seen(fingerprint)? {
            return Ok(Vec::new());
        }

        let mut outputs = vec![SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            signal.host.clone(),
            ServiceInteractionSpanObservation {
                name: interaction_name(event.protocol),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: event
                    .opened_at_unix_nanos
                    .unwrap_or(event.closed_at_unix_nanos),
                end_unix_nanos: Some(event.closed_at_unix_nanos),
                duration_nanos: event.duration_nanos,
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: source_endpoint(
                    event.kubernetes.clone(),
                    event.container.clone(),
                    event.local_address.clone(),
                    event.local_port,
                ),
                destination: destination_endpoint(
                    event.remote_address.clone(),
                    Some(event.remote_port),
                    None,
                ),
                protocol: event.protocol,
                process: Some(event.process.clone()),
                error_type: None,
                attributes: network_attributes(event.protocol, event.address_family),
            },
        )];

        if missing_attribution(event.container.as_ref(), event.kubernetes.as_ref())
            && let Some(warning) = self.missing_attribution_warning(
                signal,
                event.closed_at_unix_nanos,
                TraceCorrelationKind::NetworkInferred,
                Some(event.process.clone()),
                TracePeerInput {
                    address: Some(event.remote_address.clone()),
                    port: Some(event.remote_port),
                    domain: None,
                },
            )?
        {
            outputs.push(warning);
        }

        Ok(outputs)
    }

    fn observe_network_failure(
        &self,
        signal: &SignalEnvelope,
        event: &NetworkConnectionFailureEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let fingerprint = InteractionFingerprint::from_failure(event);
        if !self.mark_interaction_seen(fingerprint)? {
            return Ok(Vec::new());
        }

        let mut attributes = network_attributes(event.protocol, event.address_family);
        attributes.push(TraceAttribute {
            key: "error.type".to_string(),
            value: format!("errno_{}", event.errno),
        });
        let mut outputs = vec![SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            signal.host.clone(),
            ServiceInteractionSpanObservation {
                name: interaction_name(event.protocol),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: event.timestamp_unix_nanos,
                end_unix_nanos: Some(event.timestamp_unix_nanos),
                duration_nanos: Some(0),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: source_endpoint(
                    event.kubernetes.clone(),
                    event.container.clone(),
                    None,
                    None,
                ),
                destination: destination_endpoint(
                    event.remote_address.clone(),
                    Some(event.remote_port),
                    None,
                ),
                protocol: event.protocol,
                process: Some(event.process.clone()),
                error_type: Some(format!("errno_{}", event.errno)),
                attributes,
            },
        )];

        if missing_attribution(event.container.as_ref(), event.kubernetes.as_ref())
            && let Some(warning) = self.missing_attribution_warning(
                signal,
                event.timestamp_unix_nanos,
                TraceCorrelationKind::NetworkInferred,
                Some(event.process.clone()),
                TracePeerInput {
                    address: Some(event.remote_address.clone()),
                    port: Some(event.remote_port),
                    domain: None,
                },
            )?
        {
            outputs.push(warning);
        }

        Ok(outputs)
    }

    fn observe_dependency_edge(
        &self,
        signal: &SignalEnvelope,
        event: &DependencyEdgeEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        Ok(self
            .update_service_path(
                signal.host.clone(),
                PathObservation {
                    source: event.source.clone(),
                    destination: event.destination.clone(),
                    protocol: event.protocol,
                    observations: PathObservationCount::Cumulative(event.observations),
                    first_seen_unix_nanos: event.first_seen_unix_nanos,
                    last_seen_unix_nanos: event.last_seen_unix_nanos,
                    correlation_kind: TraceCorrelationKind::DependencyInferred,
                    confidence: TraceConfidence::Low,
                    attributes: vec![TraceAttribute {
                        key: "trace.correlation.source".to_string(),
                        value: "dependency_edge".to_string(),
                    }],
                },
            )?
            .into_iter()
            .collect())
    }

    fn observe_dns_response(
        &self,
        signal: &SignalEnvelope,
        event: &DnsResponseEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        if event.response_code != DnsResponseCode::NoError {
            return Ok(Vec::new());
        }
        let Some(domain) = normalize_domain(&event.query_name) else {
            return Ok(Vec::new());
        };
        let observation = PathObservation {
            source: source_endpoint(
                event.kubernetes.clone(),
                event.container.clone(),
                None,
                None,
            ),
            destination: DependencyEndpoint {
                owner_name: None,
                owner_type: None,
                workload: None,
                container: None,
                address: None,
                port: None,
                domain: Some(domain),
            },
            protocol: event.transport_protocol,
            observations: PathObservationCount::Delta(1),
            first_seen_unix_nanos: event.timestamp_unix_nanos,
            last_seen_unix_nanos: event.timestamp_unix_nanos,
            correlation_kind: TraceCorrelationKind::DependencyInferred,
            confidence: TraceConfidence::Low,
            attributes: vec![TraceAttribute {
                key: "trace.correlation.source".to_string(),
                value: "dns_response".to_string(),
            }],
        };

        Ok(self
            .update_service_path(signal.host.clone(), observation)?
            .into_iter()
            .collect())
    }

    fn update_service_path(
        &self,
        host: Option<String>,
        observation: PathObservation,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let key = PathKey::from_observation(&observation);
        let mut paths = self.service_paths()?;
        if let Some(state) = paths.get_mut(&key) {
            let first_seen = state
                .first_seen_unix_nanos
                .min(observation.first_seen_unix_nanos);
            let last_seen = state
                .last_seen_unix_nanos
                .max(observation.last_seen_unix_nanos);
            let observations = match observation.observations {
                PathObservationCount::Cumulative(count) => state.observations.max(count),
                PathObservationCount::Delta(count) => {
                    if observation.first_seen_unix_nanos == state.last_seen_unix_nanos
                        && observation.last_seen_unix_nanos == state.last_seen_unix_nanos
                    {
                        state.observations
                    } else {
                        state.observations.saturating_add(count)
                    }
                }
            };
            if first_seen == state.first_seen_unix_nanos
                && last_seen == state.last_seen_unix_nanos
                && observations == state.observations
            {
                return Ok(None);
            }
            state.first_seen_unix_nanos = first_seen;
            state.last_seen_unix_nanos = last_seen;
            state.observations = observations;
            return Ok(Some(state.to_signal(host)));
        }

        if paths.len() >= self.max_service_paths {
            return Ok(None);
        }

        let state = PathState::from_observation(key.path_key.clone(), observation);
        let signal = state.to_signal(host);
        paths.insert(key, state);
        Ok(Some(signal))
    }

    fn mark_interaction_seen(&self, fingerprint: InteractionFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen_interactions()?;
        Ok(seen.insert_if_new(fingerprint, self.max_seen_interactions))
    }

    fn missing_attribution_warning(
        &self,
        signal: &SignalEnvelope,
        timestamp_unix_nanos: u64,
        correlation_kind: TraceCorrelationKind,
        process: Option<NetworkProcessIdentity>,
        peer: TracePeerInput,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let fingerprint = WarningFingerprint {
            source_signal_kind: signal.kind().to_string(),
            source_module: signal.source.clone(),
            timestamp_unix_nanos,
            peer: peer.clone(),
        };
        let mut seen = self.seen_warnings()?;
        if !seen.insert_if_new(fingerprint, self.max_warnings) {
            return Ok(None);
        }
        drop(seen);

        Ok(Some(SignalEnvelope::trace_correlation_warning(
            "generator.trace_correlation",
            signal.host.clone(),
            TraceCorrelationWarning {
                warning_type: "missing_attribution".to_string(),
                message: "trace correlation source signal has no container or Kubernetes context"
                    .to_string(),
                timestamp_unix_nanos,
                source_signal_kind: signal.kind().to_string(),
                source_module: signal.source.clone(),
                correlation_kind,
                process,
                container: None,
                kubernetes: None,
                peer: Some(peer.into_peer_context()),
            },
        )))
    }

    fn service_paths(&self) -> CoreResult<MutexGuard<'_, BTreeMap<PathKey, PathState>>> {
        self.service_paths.lock().map_err(module_error)
    }

    fn seen_interactions(
        &self,
    ) -> CoreResult<MutexGuard<'_, BoundedFingerprints<InteractionFingerprint>>> {
        self.seen_interactions.lock().map_err(module_error)
    }

    fn seen_warnings(&self) -> CoreResult<MutexGuard<'_, BoundedFingerprints<WarningFingerprint>>> {
        self.seen_warnings.lock().map_err(module_error)
    }
}

#[derive(Debug)]
struct BoundedFingerprints<T> {
    entries: BTreeSet<T>,
    insertion_order: VecDeque<T>,
}

impl<T> Default for BoundedFingerprints<T> {
    fn default() -> Self {
        Self {
            entries: BTreeSet::new(),
            insertion_order: VecDeque::new(),
        }
    }
}

impl<T> BoundedFingerprints<T>
where
    T: Clone + Ord,
{
    fn insert_if_new(&mut self, fingerprint: T, max_entries: usize) -> bool {
        if self.entries.contains(&fingerprint) {
            return false;
        }

        let max_entries = max_entries.max(1);
        while self.entries.len() >= max_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }

        self.insertion_order.push_back(fingerprint.clone());
        self.entries.insert(fingerprint);
        true
    }
}

#[derive(Debug, Clone)]
struct PathObservation {
    source: DependencyEndpoint,
    destination: DependencyEndpoint,
    protocol: NetworkProtocol,
    observations: PathObservationCount,
    first_seen_unix_nanos: u64,
    last_seen_unix_nanos: u64,
    correlation_kind: TraceCorrelationKind,
    confidence: TraceConfidence,
    attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy)]
enum PathObservationCount {
    Cumulative(u64),
    Delta(u64),
}

#[derive(Debug, Clone)]
struct PathState {
    path_key: String,
    source: DependencyEndpoint,
    destination: DependencyEndpoint,
    protocol: NetworkProtocol,
    observations: u64,
    first_seen_unix_nanos: u64,
    last_seen_unix_nanos: u64,
    correlation_kind: TraceCorrelationKind,
    confidence: TraceConfidence,
    attributes: Vec<TraceAttribute>,
}

impl PathState {
    fn from_observation(path_key: String, observation: PathObservation) -> Self {
        Self {
            path_key,
            source: observation.source,
            destination: observation.destination,
            protocol: observation.protocol,
            observations: observation.observations.initial_count(),
            first_seen_unix_nanos: observation.first_seen_unix_nanos,
            last_seen_unix_nanos: observation.last_seen_unix_nanos,
            correlation_kind: observation.correlation_kind,
            confidence: observation.confidence,
            attributes: observation.attributes,
        }
    }

    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::trace_service_path_observation(
            "generator.trace_correlation",
            host,
            TraceServicePathObservation {
                path_key: self.path_key.clone(),
                source: self.source.clone(),
                destination: self.destination.clone(),
                protocol: self.protocol,
                observations: self.observations,
                first_seen_unix_nanos: self.first_seen_unix_nanos,
                last_seen_unix_nanos: self.last_seen_unix_nanos,
                correlation_kind: self.correlation_kind,
                confidence: self.confidence,
                attributes: self.attributes.clone(),
            },
        )
    }
}

impl PathObservationCount {
    fn initial_count(self) -> u64 {
        match self {
            Self::Cumulative(count) | Self::Delta(count) => count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PathKey {
    path_key: String,
}

impl PathKey {
    fn from_observation(observation: &PathObservation) -> Self {
        let canonical_key = format!(
            "{}->{}",
            endpoint_label(
                &observation.source,
                observation.protocol,
                EndpointSide::Source,
            ),
            endpoint_label(
                &observation.destination,
                observation.protocol,
                EndpointSide::Destination,
            ),
        );
        Self {
            path_key: format!(
                "trace-path:{:016x}",
                stable_hash64(canonical_key.as_bytes())
            ),
        }
    }
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InteractionFingerprint {
    event_kind: &'static str,
    pid: u32,
    fd: Option<i32>,
    remote_address: String,
    remote_port: u16,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
    error_type: Option<String>,
}

impl InteractionFingerprint {
    fn from_close(event: &NetworkConnectionCloseEvent) -> Self {
        Self {
            event_kind: "network_connection_close",
            pid: event.process.pid,
            fd: event.fd,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
            start_unix_nanos: event
                .opened_at_unix_nanos
                .unwrap_or(event.closed_at_unix_nanos),
            end_unix_nanos: event.closed_at_unix_nanos,
            error_type: None,
        }
    }

    fn from_failure(event: &NetworkConnectionFailureEvent) -> Self {
        Self {
            event_kind: "network_connection_failure",
            pid: event.process.pid,
            fd: event.fd,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
            start_unix_nanos: event.timestamp_unix_nanos,
            end_unix_nanos: event.timestamp_unix_nanos,
            error_type: Some(format!("errno_{}", event.errno)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WarningFingerprint {
    source_signal_kind: String,
    source_module: String,
    timestamp_unix_nanos: u64,
    peer: TracePeerInput,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TracePeerInput {
    address: Option<String>,
    port: Option<u16>,
    domain: Option<String>,
}

impl TracePeerInput {
    fn into_peer_context(self) -> e_navigator_signals::TracePeerContext {
        e_navigator_signals::TracePeerContext {
            address: self.address,
            port: self.port,
            domain: self.domain,
            workload: None,
            container: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EndpointSide {
    Source,
    Destination,
}

fn source_endpoint(
    workload: Option<KubernetesContext>,
    container: Option<ContainerContext>,
    address: Option<String>,
    port: Option<u16>,
) -> DependencyEndpoint {
    DependencyEndpoint {
        owner_name: None,
        owner_type: None,
        workload,
        container,
        address,
        port,
        domain: None,
    }
}

fn destination_endpoint(
    address: String,
    port: Option<u16>,
    domain: Option<String>,
) -> DependencyEndpoint {
    DependencyEndpoint {
        owner_name: None,
        owner_type: None,
        workload: None,
        container: None,
        address: Some(address),
        port,
        domain,
    }
}

fn endpoint_label(
    endpoint: &DependencyEndpoint,
    protocol: NetworkProtocol,
    side: EndpointSide,
) -> String {
    if let Some(workload) = &endpoint.workload {
        let pod_identity = workload.pod_uid.as_deref().unwrap_or(&workload.pod_name);
        return format!(
            "{}/{}/{}",
            workload.namespace,
            pod_identity,
            workload.container_name.as_deref().unwrap_or("unknown")
        );
    }
    if let Some(domain) = &endpoint.domain {
        return format!(
            "{}:{}/{}",
            domain,
            endpoint
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            protocol_name(protocol)
        );
    }
    if let Some(address) = &endpoint.address {
        return format!(
            "{}:{}/{}",
            address,
            endpoint
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            protocol_name(protocol)
        );
    }
    match side {
        EndpointSide::Source => "unknown-source".to_string(),
        EndpointSide::Destination => "unknown-destination".to_string(),
    }
}

fn interaction_name(protocol: NetworkProtocol) -> String {
    format!("{} client", protocol_name(protocol))
}

fn network_attributes(
    protocol: NetworkProtocol,
    address_family: NetworkAddressFamily,
) -> Vec<TraceAttribute> {
    vec![
        TraceAttribute {
            key: "net.transport".to_string(),
            value: protocol_name(protocol).to_string(),
        },
        TraceAttribute {
            key: "network.type".to_string(),
            value: address_family_name(address_family).to_string(),
        },
        TraceAttribute {
            key: "trace.correlation.source".to_string(),
            value: "network_event".to_string(),
        },
    ]
}

fn protocol_name(protocol: NetworkProtocol) -> &'static str {
    match protocol {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
        _ => "other",
    }
}

fn address_family_name(address_family: NetworkAddressFamily) -> &'static str {
    match address_family {
        NetworkAddressFamily::Ipv4 => "ipv4",
        NetworkAddressFamily::Ipv6 => "ipv6",
        _ => "other",
    }
}

fn normalize_domain(raw_domain: &str) -> Option<String> {
    let domain = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > MAX_DOMAIN_BYTES {
        return None;
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > MAX_DOMAIN_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(domain_label_byte_allowed)
        {
            return None;
        }
    }
    Some(domain)
}

fn domain_label_byte_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn missing_attribution(
    container: Option<&ContainerContext>,
    kubernetes: Option<&KubernetesContext>,
) -> bool {
    container.is_none() && kubernetes.is_none()
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.trace_correlation".to_string(),
        message: err.to_string(),
    }
}
