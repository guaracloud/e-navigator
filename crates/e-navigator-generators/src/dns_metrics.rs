use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    DependencyEdgeEvent, DependencyEndpoint, DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent,
    DnsResponseCode, DnsResponseEvent, MetricAggregationWindow, NetworkProtocol, SignalEnvelope,
    SignalPayload,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
use tracing::warn;

const DEFAULT_MAX_DOMAINS: usize = 1024;
const DEFAULT_MAX_DNS_STATE_KEYS: usize = 4096;
const DNS_SUPPRESSION_FIRST_WARNINGS: u64 = 3;

#[derive(Debug)]
pub struct DnsMetricsGenerator {
    max_domains: usize,
    max_counters: usize,
    max_latencies: usize,
    max_edges: usize,
    domains: Mutex<BTreeSet<String>>,
    counters: Mutex<BTreeMap<CounterKey, CounterState>>,
    latencies: Mutex<BTreeMap<LatencyKey, LatencyState>>,
    edges: Mutex<BTreeMap<EdgeKey, EdgeState>>,
    seen_events: Mutex<BTreeSet<EventFingerprint>>,
    suppressed_counters: AtomicU64,
    suppressed_latencies: AtomicU64,
    suppressed_edges: AtomicU64,
}

impl Default for DnsMetricsGenerator {
    fn default() -> Self {
        Self::with_domain_limit(DEFAULT_MAX_DOMAINS)
    }
}

impl DnsMetricsGenerator {
    pub fn with_domain_limit(max_domains: usize) -> Self {
        Self::with_limits(
            max_domains,
            DEFAULT_MAX_DNS_STATE_KEYS,
            DEFAULT_MAX_DNS_STATE_KEYS,
            DEFAULT_MAX_DNS_STATE_KEYS,
        )
    }

    pub fn with_limits(
        max_domains: usize,
        max_counters: usize,
        max_latencies: usize,
        max_edges: usize,
    ) -> Self {
        Self {
            max_domains,
            max_counters,
            max_latencies,
            max_edges,
            domains: Mutex::new(BTreeSet::new()),
            counters: Mutex::new(BTreeMap::new()),
            latencies: Mutex::new(BTreeMap::new()),
            edges: Mutex::new(BTreeMap::new()),
            seen_events: Mutex::new(BTreeSet::new()),
            suppressed_counters: AtomicU64::new(0),
            suppressed_latencies: AtomicU64::new(0),
            suppressed_edges: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn suppression_counts(&self) -> DnsSuppressionCounts {
        DnsSuppressionCounts {
            counters: self.suppressed_counters.load(Ordering::Relaxed),
            latencies: self.suppressed_latencies.load(Ordering::Relaxed),
            edges: self.suppressed_edges.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for DnsMetricsGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.dns_metrics", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        if !self.mark_seen(signal)? {
            return Ok(());
        }

        let outputs = match &signal.payload {
            SignalPayload::DnsQuery(event) => self.observe_query(signal, event)?,
            SignalPayload::DnsResponse(event) => self.observe_response(signal, event)?,
            _ => Vec::new(),
        };

        for output in outputs {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl DnsMetricsGenerator {
    fn observe_query(
        &self,
        signal: &SignalEnvelope,
        event: &DnsQueryEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        Ok(self
            .update_counter(
                CounterKey::query(event, self.domain_label(&event.query_name)?),
                CounterTemplate::query(event, self.domain_label(&event.query_name)?),
                event.timestamp_unix_nanos,
                signal.host.clone(),
            )?
            .into_iter()
            .collect())
    }

    fn observe_response(
        &self,
        signal: &SignalEnvelope,
        event: &DnsResponseEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let domain = self.domain_label(&event.query_name)?;
        let mut outputs = Vec::new();
        if let Some(counter) = self.update_counter(
            CounterKey::response_code(event, domain.clone()),
            CounterTemplate::response_code(event, domain.clone()),
            event.timestamp_unix_nanos,
            signal.host.clone(),
        )? {
            outputs.push(counter);
        }
        if let Some(latency_nanos) = event.latency_nanos
            && let Some(latency) =
                self.update_latency(event, domain.clone(), latency_nanos, signal.host.clone())?
        {
            outputs.push(latency);
        }
        if event.response_code == DnsResponseCode::NoError
            && let Some(domain) = domain
            && let Some(edge) = self.update_edge(event, domain, signal.host.clone())?
        {
            outputs.push(edge);
        }

        Ok(outputs)
    }

    fn domain_label(&self, raw_domain: &str) -> CoreResult<Option<String>> {
        let Some(domain) = normalize_domain(raw_domain) else {
            return Ok(None);
        };
        let mut domains = self.domains()?;
        if domains.contains(&domain) {
            return Ok(Some(domain));
        }
        if domains.len() >= self.max_domains {
            return Ok(None);
        }
        domains.insert(domain.clone());
        Ok(Some(domain))
    }

    fn update_counter(
        &self,
        key: CounterKey,
        template: CounterTemplate,
        timestamp: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let mut counters = self.counters()?;
        if let Some(state) = counters.get_mut(&key) {
            state.value = state.value.saturating_add(1);
            state.window.start_unix_nanos = state.window.start_unix_nanos.min(timestamp);
            state.window.end_unix_nanos = state.window.end_unix_nanos.max(timestamp);
            return Ok(Some(state.to_signal(host)));
        }

        let state = CounterState {
            template,
            value: 1,
            window: MetricAggregationWindow {
                start_unix_nanos: timestamp,
                end_unix_nanos: timestamp,
            },
        };
        let signal = state.to_signal(host);
        if counters.len() >= self.max_counters {
            let suppressed_total = self.suppressed_counters.fetch_add(1, Ordering::Relaxed) + 1;
            warn_dns_suppression("counter", self.max_counters, suppressed_total);
            return Ok(None);
        }
        counters.insert(key, state);
        Ok(Some(signal))
    }

    fn update_latency(
        &self,
        event: &DnsResponseEvent,
        domain: Option<String>,
        latency_nanos: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let key = LatencyKey::from_response(event, domain.clone());
        let mut latencies = self.latencies()?;
        if let Some(state) = latencies.get_mut(&key) {
            state.count = state.count.saturating_add(1);
            state.sum_nanos = state.sum_nanos.saturating_add(latency_nanos);
            state.min_nanos = state.min_nanos.min(latency_nanos);
            state.max_nanos = state.max_nanos.max(latency_nanos);
            state.window.end_unix_nanos =
                state.window.end_unix_nanos.max(event.timestamp_unix_nanos);
            return Ok(Some(state.to_signal(host)));
        }

        let state = LatencyState {
            template: LatencyTemplate::from_response(event, domain),
            count: 1,
            sum_nanos: latency_nanos,
            min_nanos: latency_nanos,
            max_nanos: latency_nanos,
            window: MetricAggregationWindow {
                start_unix_nanos: event.timestamp_unix_nanos,
                end_unix_nanos: event.timestamp_unix_nanos,
            },
        };
        let signal = state.to_signal(host);
        if latencies.len() >= self.max_latencies {
            let suppressed_total = self.suppressed_latencies.fetch_add(1, Ordering::Relaxed) + 1;
            warn_dns_suppression("latency", self.max_latencies, suppressed_total);
            return Ok(None);
        }
        latencies.insert(key, state);
        Ok(Some(signal))
    }

    fn update_edge(
        &self,
        event: &DnsResponseEvent,
        domain: String,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let key = EdgeKey::from_response(event, &domain);
        let mut edges = self.edges()?;
        if let Some(state) = edges.get_mut(&key) {
            if state.last_seen_unix_nanos == event.timestamp_unix_nanos {
                return Ok(None);
            }
            state.observations = state.observations.saturating_add(1);
            state.last_seen_unix_nanos = state.last_seen_unix_nanos.max(event.timestamp_unix_nanos);
            return Ok(Some(state.to_signal(host)));
        }

        let state = EdgeState {
            source: DependencyEndpoint {
                workload: event.kubernetes.clone(),
                container: event.container.clone(),
                address: None,
                port: None,
                domain: None,
            },
            destination: DependencyEndpoint {
                workload: None,
                container: None,
                address: None,
                port: None,
                domain: Some(domain),
            },
            protocol: event.transport_protocol,
            observations: 1,
            first_seen_unix_nanos: event.timestamp_unix_nanos,
            last_seen_unix_nanos: event.timestamp_unix_nanos,
        };
        let signal = state.to_signal(host);
        if edges.len() >= self.max_edges {
            let suppressed_total = self.suppressed_edges.fetch_add(1, Ordering::Relaxed) + 1;
            warn_dns_suppression("dependency_edge", self.max_edges, suppressed_total);
            return Ok(None);
        }
        edges.insert(key, state);
        Ok(Some(signal))
    }

    fn mark_seen(&self, signal: &SignalEnvelope) -> CoreResult<bool> {
        let Some(fingerprint) = EventFingerprint::from_signal(signal) else {
            return Ok(true);
        };
        let mut seen_events = self.seen_events()?;
        if seen_events.contains(&fingerprint) {
            return Ok(false);
        }
        if seen_events.len() >= self.max_domains.saturating_mul(4).max(1)
            && let Some(first) = seen_events.iter().next().cloned()
        {
            seen_events.remove(&first);
        }
        seen_events.insert(fingerprint);
        Ok(true)
    }

    fn domains(&self) -> CoreResult<MutexGuard<'_, BTreeSet<String>>> {
        self.domains.lock().map_err(module_error)
    }

    fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<CounterKey, CounterState>>> {
        self.counters.lock().map_err(module_error)
    }

    fn latencies(&self) -> CoreResult<MutexGuard<'_, BTreeMap<LatencyKey, LatencyState>>> {
        self.latencies.lock().map_err(module_error)
    }

    fn edges(&self) -> CoreResult<MutexGuard<'_, BTreeMap<EdgeKey, EdgeState>>> {
        self.edges.lock().map_err(module_error)
    }

    fn seen_events(&self) -> CoreResult<MutexGuard<'_, BTreeSet<EventFingerprint>>> {
        self.seen_events.lock().map_err(module_error)
    }
}

fn warn_dns_suppression(state_type: &'static str, max_state_keys: usize, suppressed_total: u64) {
    if should_warn_dns_suppression(suppressed_total) {
        warn!(
            state_type,
            max_state_keys,
            suppressed_total,
            "dns metric state limit reached; suppressing new state keys"
        );
    }
}

fn should_warn_dns_suppression(suppressed_total: u64) -> bool {
    suppressed_total <= DNS_SUPPRESSION_FIRST_WARNINGS || suppressed_total.is_power_of_two()
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsSuppressionCounts {
    counters: u64,
    latencies: u64,
    edges: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CounterKey {
    metric_name: &'static str,
    workload: Option<String>,
    container: Option<String>,
    query_name: Option<String>,
    query_type: Option<e_navigator_signals::DnsQueryType>,
    response_code: Option<DnsResponseCode>,
    server_address: Option<String>,
    server_port: Option<u16>,
}

impl CounterKey {
    fn query(event: &DnsQueryEvent, domain: Option<String>) -> Self {
        Self {
            metric_name: "dns.query.count",
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            query_name: domain,
            query_type: Some(event.query_type),
            response_code: None,
            server_address: event.server_address.clone(),
            server_port: event.server_port,
        }
    }

    fn response_code(event: &DnsResponseEvent, domain: Option<String>) -> Self {
        Self {
            metric_name: "dns.response.code.count",
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            query_name: domain,
            query_type: Some(event.query_type),
            response_code: Some(event.response_code),
            server_address: event.server_address.clone(),
            server_port: event.server_port,
        }
    }
}

#[derive(Debug, Clone)]
struct CounterTemplate {
    metric_name: &'static str,
    unit: &'static str,
    query_name: Option<String>,
    query_type: Option<e_navigator_signals::DnsQueryType>,
    response_code: Option<DnsResponseCode>,
    server_address: Option<String>,
    server_port: Option<u16>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
}

impl CounterTemplate {
    fn query(event: &DnsQueryEvent, domain: Option<String>) -> Self {
        Self {
            metric_name: "dns.query.count",
            unit: "{query}",
            query_name: domain,
            query_type: Some(event.query_type),
            response_code: None,
            server_address: event.server_address.clone(),
            server_port: event.server_port,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }

    fn response_code(event: &DnsResponseEvent, domain: Option<String>) -> Self {
        Self {
            metric_name: "dns.response.code.count",
            unit: "{response}",
            query_name: domain,
            query_type: Some(event.query_type),
            response_code: Some(event.response_code),
            server_address: event.server_address.clone(),
            server_port: event.server_port,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct CounterState {
    template: CounterTemplate,
    value: u64,
    window: MetricAggregationWindow,
}

impl CounterState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::dns_counter_metric(
            "generator.dns_metrics",
            host,
            DnsCounterMetric {
                metric_name: self.template.metric_name.to_string(),
                unit: self.template.unit.to_string(),
                value: self.value,
                window: self.window.clone(),
                query_name: self.template.query_name.clone(),
                query_type: self.template.query_type,
                response_code: self.template.response_code,
                server_address: self.template.server_address.clone(),
                server_port: self.template.server_port,
                container: self.template.container.clone(),
                kubernetes: self.template.kubernetes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LatencyKey {
    workload: Option<String>,
    container: Option<String>,
    query_name: Option<String>,
    query_type: e_navigator_signals::DnsQueryType,
    response_code: DnsResponseCode,
}

impl LatencyKey {
    fn from_response(event: &DnsResponseEvent, domain: Option<String>) -> Self {
        Self {
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            query_name: domain,
            query_type: event.query_type,
            response_code: event.response_code,
        }
    }
}

#[derive(Debug, Clone)]
struct LatencyTemplate {
    query_name: Option<String>,
    query_type: Option<e_navigator_signals::DnsQueryType>,
    response_code: Option<DnsResponseCode>,
    server_address: Option<String>,
    server_port: Option<u16>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
}

impl LatencyTemplate {
    fn from_response(event: &DnsResponseEvent, domain: Option<String>) -> Self {
        Self {
            query_name: domain,
            query_type: Some(event.query_type),
            response_code: Some(event.response_code),
            server_address: event.server_address.clone(),
            server_port: event.server_port,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct LatencyState {
    template: LatencyTemplate,
    count: u64,
    sum_nanos: u64,
    min_nanos: u64,
    max_nanos: u64,
    window: MetricAggregationWindow,
}

impl LatencyState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::dns_latency_metric(
            "generator.dns_metrics",
            host,
            DnsLatencyMetric {
                metric_name: "dns.lookup.duration".to_string(),
                unit: "ns".to_string(),
                count: self.count,
                sum_nanos: self.sum_nanos,
                min_nanos: self.min_nanos,
                max_nanos: self.max_nanos,
                window: self.window.clone(),
                query_name: self.template.query_name.clone(),
                query_type: self.template.query_type,
                response_code: self.template.response_code,
                server_address: self.template.server_address.clone(),
                server_port: self.template.server_port,
                container: self.template.container.clone(),
                kubernetes: self.template.kubernetes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    workload: Option<String>,
    container: Option<String>,
    domain: String,
}

impl EdgeKey {
    fn from_response(event: &DnsResponseEvent, domain: &str) -> Self {
        Self {
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            domain: domain.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct EdgeState {
    source: DependencyEndpoint,
    destination: DependencyEndpoint,
    protocol: NetworkProtocol,
    observations: u64,
    first_seen_unix_nanos: u64,
    last_seen_unix_nanos: u64,
}

impl EdgeState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::dependency_edge(
            "generator.dns_metrics",
            host,
            DependencyEdgeEvent {
                source: self.source.clone(),
                destination: self.destination.clone(),
                protocol: self.protocol,
                observations: self.observations,
                first_seen_unix_nanos: self.first_seen_unix_nanos,
                last_seen_unix_nanos: self.last_seen_unix_nanos,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventFingerprint {
    kind: &'static str,
    query_name: String,
    query_type: e_navigator_signals::DnsQueryType,
    response_code: Option<DnsResponseCode>,
    timestamp: u64,
}

impl EventFingerprint {
    fn from_signal(signal: &SignalEnvelope) -> Option<Self> {
        match &signal.payload {
            SignalPayload::DnsQuery(event) => Some(Self {
                kind: "query",
                query_name: normalize_domain(&event.query_name)
                    .unwrap_or_else(|| event.query_name.clone()),
                query_type: event.query_type,
                response_code: None,
                timestamp: event.timestamp_unix_nanos,
            }),
            SignalPayload::DnsResponse(event) => Some(Self {
                kind: "response",
                query_name: normalize_domain(&event.query_name)
                    .unwrap_or_else(|| event.query_name.clone()),
                query_type: event.query_type,
                response_code: Some(event.response_code),
                timestamp: event.timestamp_unix_nanos,
            }),
            _ => None,
        }
    }
}

fn normalize_domain(raw_domain: &str) -> Option<String> {
    let domain = raw_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(domain)
}

fn workload_key(context: &e_navigator_signals::KubernetesContext) -> String {
    format!(
        "{}/{}/{}",
        context.namespace,
        context.pod_uid.as_deref().unwrap_or(&context.pod_name),
        context.container_name.as_deref().unwrap_or("")
    )
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.dns_metrics".to_string(),
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Generator;
    use e_navigator_signals::{
        ContainerContext, DependencyEdgeEvent, DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent,
        DnsQueryType, DnsResponseCode, DnsResponseEvent, KubernetesContext, NetworkProcessIdentity,
        NetworkProtocol, SignalEnvelope, SignalPayload,
    };
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn emits_dns_query_count_metric() {
        let generator = DnsMetricsGenerator::default();
        let query = dns_query_signal("API.Example.COM.", DnsQueryType::A, 100);

        let outputs = observe(&generator, &query).await;

        let metric = dns_counter(&outputs, "dns.query.count");
        assert_eq!(metric.value, 1);
        assert_eq!(metric.unit, "{query}");
        assert_eq!(metric.query_name.as_deref(), Some("api.example.com"));
        assert_eq!(metric.query_type, Some(DnsQueryType::A));
        assert_eq!(metric.container, Some(container_context()));
        assert_eq!(metric.kubernetes, Some(kubernetes_context()));
    }

    #[tokio::test]
    async fn emits_dns_response_code_counts_for_nxdomain_and_servfail() {
        let generator = DnsMetricsGenerator::default();
        let nxdomain = dns_response_signal("missing.example.com", DnsResponseCode::NxDomain, 100);
        let servfail = dns_response_signal("broken.example.com", DnsResponseCode::ServFail, 101);

        let nxdomain_outputs = observe(&generator, &nxdomain).await;
        let servfail_outputs = observe(&generator, &servfail).await;

        let nxdomain_metric = dns_counter(&nxdomain_outputs, "dns.response.code.count");
        let servfail_metric = dns_counter(&servfail_outputs, "dns.response.code.count");
        assert_eq!(
            nxdomain_metric.response_code,
            Some(DnsResponseCode::NxDomain)
        );
        assert_eq!(
            servfail_metric.response_code,
            Some(DnsResponseCode::ServFail)
        );
        assert_eq!(nxdomain_metric.value, 1);
        assert_eq!(servfail_metric.value, 1);
    }

    #[tokio::test]
    async fn emits_dns_lookup_latency_observation() {
        let generator = DnsMetricsGenerator::default();
        let response = dns_response_signal("api.example.com", DnsResponseCode::NoError, 115);

        let outputs = observe(&generator, &response).await;

        let latency = dns_latency(&outputs, "dns.lookup.duration");
        assert_eq!(latency.unit, "ns");
        assert_eq!(latency.count, 1);
        assert_eq!(latency.sum_nanos, 15_000);
        assert_eq!(latency.min_nanos, 15_000);
        assert_eq!(latency.max_nanos, 15_000);
        assert_eq!(latency.query_name.as_deref(), Some("api.example.com"));
    }

    #[tokio::test]
    async fn emits_domain_dependency_edge_for_successful_response() {
        let generator = DnsMetricsGenerator::default();
        let response = dns_response_signal("API.Example.COM.", DnsResponseCode::NoError, 115);

        let outputs = observe(&generator, &response).await;

        let edge = dependency_edge(&outputs);
        assert_eq!(edge.destination.domain.as_deref(), Some("api.example.com"));
        assert_eq!(edge.destination.address, None);
        assert_eq!(edge.observations, 1);
        assert_eq!(edge.first_seen_unix_nanos, 115);
        assert_eq!(edge.last_seen_unix_nanos, 115);
        assert_eq!(edge.source.workload, Some(kubernetes_context()));
        assert_eq!(edge.source.container, Some(container_context()));
    }

    #[tokio::test]
    async fn bounds_domain_cardinality() {
        let generator = DnsMetricsGenerator::with_domain_limit(1);
        let first = dns_query_signal("api.example.com", DnsQueryType::A, 100);
        let second = dns_query_signal("stripe.example.com", DnsQueryType::A, 101);

        let first_outputs = observe(&generator, &first).await;
        let second_outputs = observe(&generator, &second).await;

        assert_eq!(
            dns_counter(&first_outputs, "dns.query.count")
                .query_name
                .as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            dns_counter(&second_outputs, "dns.query.count").query_name,
            None
        );
    }

    #[tokio::test]
    async fn suppresses_duplicate_dependency_edges_for_identical_dns_responses() {
        let generator = DnsMetricsGenerator::default();
        let response = dns_response_signal("api.example.com", DnsResponseCode::NoError, 115);

        let first = observe(&generator, &response).await;
        let second = observe(&generator, &response).await;

        assert!(
            first
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::DependencyEdge(_)))
        );
        assert!(
            !second
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::DependencyEdge(_)))
        );
    }

    #[tokio::test]
    async fn bounds_counter_state_across_workload_container_and_server_dimensions() {
        let generator = DnsMetricsGenerator::with_limits(16, 1, 16, 16);
        let first = dns_query_with_dimensions(
            "api.example.com",
            "pod-a",
            "container-a",
            "10.0.0.10",
            53,
            100,
        );
        let second = dns_query_with_dimensions(
            "api.example.com",
            "pod-b",
            "container-b",
            "10.0.0.11",
            5353,
            101,
        );
        let repeat = dns_query_with_dimensions(
            "api.example.com",
            "pod-a",
            "container-a",
            "10.0.0.10",
            53,
            102,
        );

        let first_outputs = observe(&generator, &first).await;
        let second_outputs = observe(&generator, &second).await;
        let repeat_outputs = observe(&generator, &repeat).await;

        assert_eq!(dns_counter(&first_outputs, "dns.query.count").value, 1);
        assert!(
            !second_outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::DnsCounterMetric(_)))
        );
        assert_eq!(dns_counter(&repeat_outputs, "dns.query.count").value, 2);
        assert_eq!(generator.suppression_counts().counters, 1);
    }

    #[tokio::test]
    async fn bounds_latency_and_edge_state_for_high_cardinality_dns_responses() {
        let generator = DnsMetricsGenerator::with_limits(16, 16, 1, 1);
        let first = dns_response_with_dimensions(
            "api.example.com",
            "pod-a",
            "container-a",
            "10.0.0.10",
            53,
            100,
        );
        let second = dns_response_with_dimensions(
            "api.example.com",
            "pod-b",
            "container-b",
            "10.0.0.11",
            5353,
            101,
        );
        let repeat = dns_response_with_dimensions(
            "api.example.com",
            "pod-a",
            "container-a",
            "10.0.0.10",
            53,
            102,
        );

        let first_outputs = observe(&generator, &first).await;
        let second_outputs = observe(&generator, &second).await;
        let repeat_outputs = observe(&generator, &repeat).await;

        assert_eq!(dns_latency(&first_outputs, "dns.lookup.duration").count, 1);
        assert!(dependency_edge(&first_outputs).observations == 1);
        assert!(
            !second_outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::DnsLatencyMetric(_)))
        );
        assert!(
            !second_outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::DependencyEdge(_)))
        );
        assert_eq!(dns_latency(&repeat_outputs, "dns.lookup.duration").count, 2);
        assert_eq!(dependency_edge(&repeat_outputs).observations, 2);
        assert_eq!(generator.suppression_counts().latencies, 1);
        assert_eq!(generator.suppression_counts().edges, 1);
    }

    #[test]
    fn dns_suppression_warnings_are_bounded() {
        let warned: Vec<u64> = (1..=16)
            .filter(|suppressed_total| should_warn_dns_suppression(*suppressed_total))
            .collect();

        assert_eq!(warned, vec![1, 2, 3, 4, 8, 16]);
    }

    async fn observe(
        generator: &DnsMetricsGenerator,
        signal: &SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(8);
        generator
            .observe(signal, &tx)
            .await
            .expect("generator succeeds");
        drop(tx);

        let mut outputs = Vec::new();
        while let Some(output) = rx.recv().await {
            outputs.push(output);
        }
        outputs
    }

    fn dns_counter<'a>(outputs: &'a [SignalEnvelope], name: &str) -> &'a DnsCounterMetric {
        outputs
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::DnsCounterMetric(metric) if metric.metric_name == name => {
                    Some(metric)
                }
                _ => None,
            })
            .expect("dns counter exists")
    }

    fn dns_latency<'a>(outputs: &'a [SignalEnvelope], name: &str) -> &'a DnsLatencyMetric {
        outputs
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::DnsLatencyMetric(metric) if metric.metric_name == name => {
                    Some(metric)
                }
                _ => None,
            })
            .expect("dns latency exists")
    }

    fn dependency_edge(outputs: &[SignalEnvelope]) -> &DependencyEdgeEvent {
        outputs
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::DependencyEdge(edge) => Some(edge),
                _ => None,
            })
            .expect("dependency edge exists")
    }

    fn dns_query_signal(
        query_name: &str,
        query_type: DnsQueryType,
        timestamp: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::dns_query(
            "source.test",
            Some("node-a".to_string()),
            DnsQueryEvent {
                process: network_process(),
                query_name: query_name.to_string(),
                query_type,
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: timestamp,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn dns_response_signal(
        query_name: &str,
        response_code: DnsResponseCode,
        timestamp: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::dns_response(
            "source.test",
            Some("node-a".to_string()),
            DnsResponseEvent {
                process: network_process(),
                query_name: query_name.to_string(),
                query_type: DnsQueryType::A,
                response_code,
                latency_nanos: Some(15_000),
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: timestamp,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn dns_query_with_dimensions(
        query_name: &str,
        pod_name: &str,
        container_id: &str,
        server_address: &str,
        server_port: u16,
        timestamp: u64,
    ) -> SignalEnvelope {
        let mut signal = dns_query_signal(query_name, DnsQueryType::A, timestamp);
        let SignalPayload::DnsQuery(event) = &mut signal.payload else {
            panic!("expected dns query");
        };
        event.server_address = Some(server_address.to_string());
        event.server_port = Some(server_port);
        event.container = Some(ContainerContext {
            container_id: container_id.to_string(),
            runtime: Some("containerd".to_string()),
        });
        event.kubernetes = Some(kubernetes_context_with_pod(pod_name));
        signal
    }

    fn dns_response_with_dimensions(
        query_name: &str,
        pod_name: &str,
        container_id: &str,
        server_address: &str,
        server_port: u16,
        timestamp: u64,
    ) -> SignalEnvelope {
        let mut signal = dns_response_signal(query_name, DnsResponseCode::NoError, timestamp);
        let SignalPayload::DnsResponse(event) = &mut signal.payload else {
            panic!("expected dns response");
        };
        event.server_address = Some(server_address.to_string());
        event.server_port = Some(server_port);
        event.container = Some(ContainerContext {
            container_id: container_id.to_string(),
            runtime: Some("containerd".to_string()),
        });
        event.kubernetes = Some(kubernetes_context_with_pod(pod_name));
        signal
    }

    fn network_process() -> NetworkProcessIdentity {
        NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "api".to_string(),
            executable: Some("/app/api".to_string()),
            cgroup_id: None,
        }
    }

    fn container_context() -> ContainerContext {
        ContainerContext {
            container_id: "container-a".to_string(),
            runtime: Some("containerd".to_string()),
        }
    }

    fn kubernetes_context() -> KubernetesContext {
        kubernetes_context_with_pod("api-123")
    }

    fn kubernetes_context_with_pod(pod_name: &str) -> KubernetesContext {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "api".to_string());

        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: pod_name.to_string(),
            pod_uid: Some(format!("{pod_name}-uid")),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }
}
