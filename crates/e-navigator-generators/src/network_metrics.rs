use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    MetricAggregationWindow, NetworkConnectionCloseEvent, NetworkConnectionFailureEvent,
    NetworkConnectionOpenEvent, NetworkCounterMetric, NetworkDurationMetric, NetworkFlowDirection,
    NetworkFlowEndpoint, NetworkFlowSummaryEvent, NetworkFlowWarning, NetworkGaugeMetric,
    NetworkProcessIdentity, SignalEnvelope, SignalPayload,
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

const DEFAULT_MAX_METRIC_KEYS: usize = 4096;
const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 8192;
const NETWORK_SUPPRESSION_FIRST_WARNINGS: u64 = 3;

#[derive(Debug)]
pub struct NetworkMetricsGenerator {
    max_metric_keys: usize,
    max_active_connections: usize,
    counters: Mutex<BTreeMap<CounterKey, CounterState>>,
    durations: Mutex<BTreeMap<DurationKey, DurationState>>,
    active_connections: Mutex<BTreeMap<ActiveConnectionKey, ActiveConnectionState>>,
    active_counts: Mutex<BTreeMap<ActiveGaugeKey, ActiveGaugeState>>,
    seen_events: Mutex<BTreeSet<EventFingerprint>>,
    suppressed_counters: AtomicU64,
    suppressed_durations: AtomicU64,
    suppressed_active_connections: AtomicU64,
    suppressed_active_gauges: AtomicU64,
}

impl Default for NetworkMetricsGenerator {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_METRIC_KEYS, DEFAULT_MAX_ACTIVE_CONNECTIONS)
    }
}

impl NetworkMetricsGenerator {
    pub fn with_limits(max_metric_keys: usize, max_active_connections: usize) -> Self {
        Self {
            max_metric_keys,
            max_active_connections,
            counters: Mutex::new(BTreeMap::new()),
            durations: Mutex::new(BTreeMap::new()),
            active_connections: Mutex::new(BTreeMap::new()),
            active_counts: Mutex::new(BTreeMap::new()),
            seen_events: Mutex::new(BTreeSet::new()),
            suppressed_counters: AtomicU64::new(0),
            suppressed_durations: AtomicU64::new(0),
            suppressed_active_connections: AtomicU64::new(0),
            suppressed_active_gauges: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn suppression_counts(&self) -> NetworkSuppressionCounts {
        NetworkSuppressionCounts {
            counters: self.suppressed_counters.load(Ordering::Relaxed),
            durations: self.suppressed_durations.load(Ordering::Relaxed),
            active_connections: self.suppressed_active_connections.load(Ordering::Relaxed),
            active_gauges: self.suppressed_active_gauges.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for NetworkMetricsGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.network_metrics", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        if !self.mark_seen(signal)? {
            return Ok(());
        }

        let metrics = match &signal.payload {
            SignalPayload::NetworkConnectionOpen(event) => self.observe_open(signal, event)?,
            SignalPayload::NetworkConnectionClose(event) => self.observe_close(signal, event)?,
            SignalPayload::NetworkConnectionFailure(event) => {
                self.observe_failure(signal, event)?
            }
            _ => Vec::new(),
        };

        for metric in metrics {
            tx.send(metric)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl NetworkMetricsGenerator {
    fn observe_open(
        &self,
        signal: &SignalEnvelope,
        event: &NetworkConnectionOpenEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        if let Some(metric) = self.update_counter(
            CounterKey::connection_open(event),
            CounterTemplate::connection_open(event),
            event.timestamp_unix_nanos,
            signal.host.clone(),
        )? {
            metrics.push(metric);
        }
        if let Some(metric) = self.update_counter(
            CounterKey::protocol_open(event),
            CounterTemplate::protocol_open(event),
            event.timestamp_unix_nanos,
            signal.host.clone(),
        )? {
            metrics.push(metric);
        }
        if let Some(metric) = self.update_counter(
            CounterKey::traffic_destination(event),
            CounterTemplate::traffic_destination(event),
            event.timestamp_unix_nanos,
            signal.host.clone(),
        )? {
            metrics.push(metric);
        }
        if let Some(metric) = self.track_active_open(event, signal.host.clone())? {
            metrics.push(metric);
        }

        Ok(metrics)
    }

    fn observe_close(
        &self,
        signal: &SignalEnvelope,
        event: &NetworkConnectionCloseEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        if let Some(duration_nanos) = event.duration_nanos
            && let Some(metric) = self.update_duration(
                DurationKey::connection_duration(event),
                event,
                duration_nanos,
                signal.host.clone(),
            )?
        {
            metrics.push(metric);
        }
        if let Some(metric) = self.track_active_close(event, signal.host.clone())? {
            metrics.push(metric);
        }
        if let Some(summary) = flow_summary_from_close(signal, event) {
            metrics.push(summary);
        }
        if let Some(warning) = flow_warning_from_close(signal, event) {
            metrics.push(warning);
        }
        if event.kubernetes.is_some()
            && let Some(metric) = self.update_counter_by(
                CounterKey::flow_bytes(event),
                CounterTemplate::flow_bytes(event),
                event
                    .opened_at_unix_nanos
                    .unwrap_or(event.closed_at_unix_nanos),
                event.closed_at_unix_nanos,
                event
                    .bytes_sent
                    .unwrap_or(0)
                    .saturating_add(event.bytes_received.unwrap_or(0)),
                signal.host.clone(),
            )?
        {
            metrics.push(metric);
        }

        Ok(metrics)
    }

    fn observe_failure(
        &self,
        signal: &SignalEnvelope,
        event: &NetworkConnectionFailureEvent,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        Ok(self
            .update_counter(
                CounterKey::connection_failure(event),
                CounterTemplate::connection_failure(event),
                event.timestamp_unix_nanos,
                signal.host.clone(),
            )?
            .into_iter()
            .collect())
    }

    fn update_counter(
        &self,
        key: CounterKey,
        template: CounterTemplate,
        timestamp: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_counter_by(key, template, timestamp, timestamp, 1, host)
    }

    fn update_counter_by(
        &self,
        key: CounterKey,
        template: CounterTemplate,
        window_start: u64,
        window_end: u64,
        value: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        if value == 0 {
            return Ok(None);
        }
        let mut counters = self.counters()?;
        if let Some(state) = counters.get_mut(&key) {
            state.value = state.value.saturating_add(value);
            state.window.start_unix_nanos = state.window.start_unix_nanos.min(window_start);
            state.window.end_unix_nanos = state.window.end_unix_nanos.max(window_end);
            return Ok(Some(state.to_signal(host)));
        }

        if counters.len() >= self.max_metric_keys {
            let suppressed_total = self.suppressed_counters.fetch_add(1, Ordering::Relaxed) + 1;
            warn_network_suppression("counter", self.max_metric_keys, suppressed_total);
            return Ok(None);
        }

        let state = CounterState {
            template,
            value,
            window: MetricAggregationWindow {
                start_unix_nanos: window_start,
                end_unix_nanos: window_end,
            },
        };
        let signal = state.to_signal(host);
        counters.insert(key, state);
        Ok(Some(signal))
    }

    fn update_duration(
        &self,
        key: DurationKey,
        event: &NetworkConnectionCloseEvent,
        duration_nanos: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let window_start = event
            .opened_at_unix_nanos
            .unwrap_or(event.closed_at_unix_nanos);
        let mut durations = self.durations()?;
        if let Some(state) = durations.get_mut(&key) {
            state.count = state.count.saturating_add(1);
            state.sum_nanos = state.sum_nanos.saturating_add(duration_nanos);
            state.min_nanos = state.min_nanos.min(duration_nanos);
            state.max_nanos = state.max_nanos.max(duration_nanos);
            state.window.start_unix_nanos = state.window.start_unix_nanos.min(window_start);
            state.window.end_unix_nanos =
                state.window.end_unix_nanos.max(event.closed_at_unix_nanos);
            return Ok(Some(state.to_signal(host)));
        }

        if durations.len() >= self.max_metric_keys {
            let suppressed_total = self.suppressed_durations.fetch_add(1, Ordering::Relaxed) + 1;
            warn_network_suppression("duration", self.max_metric_keys, suppressed_total);
            return Ok(None);
        }

        let state = DurationState {
            template: DurationTemplate::connection_duration(event),
            count: 1,
            sum_nanos: duration_nanos,
            min_nanos: duration_nanos,
            max_nanos: duration_nanos,
            window: MetricAggregationWindow {
                start_unix_nanos: window_start,
                end_unix_nanos: event.closed_at_unix_nanos,
            },
        };
        let signal = state.to_signal(host);
        durations.insert(key, state);
        Ok(Some(signal))
    }

    fn track_active_open(
        &self,
        event: &NetworkConnectionOpenEvent,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let Some(connection_key) = ActiveConnectionKey::from_open(event) else {
            return Ok(None);
        };
        let gauge_key = ActiveGaugeKey::from_open(event);
        let mut active_connections = self.active_connections()?;
        if active_connections.contains_key(&connection_key) {
            return Ok(None);
        }
        if active_connections.len() >= self.max_active_connections {
            let suppressed_total = self
                .suppressed_active_connections
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            warn_network_suppression(
                "active_connection",
                self.max_active_connections,
                suppressed_total,
            );
            return Ok(None);
        }

        let state = ActiveConnectionState {
            gauge_key: gauge_key.clone(),
        };
        active_connections.insert(connection_key, state);
        drop(active_connections);

        self.update_active_gauge(
            gauge_key,
            ActiveGaugeTemplate::from_open(event),
            1,
            event.timestamp_unix_nanos,
            host,
        )
    }

    fn track_active_close(
        &self,
        event: &NetworkConnectionCloseEvent,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let Some(connection_key) = ActiveConnectionKey::from_close(event) else {
            return Ok(None);
        };
        let mut active_connections = self.active_connections()?;
        let Some(active_state) = active_connections.remove(&connection_key) else {
            return Ok(None);
        };
        drop(active_connections);

        self.update_active_gauge(
            active_state.gauge_key,
            ActiveGaugeTemplate::from_close(event),
            -1,
            event.closed_at_unix_nanos,
            host,
        )
    }

    fn update_active_gauge(
        &self,
        key: ActiveGaugeKey,
        template: ActiveGaugeTemplate,
        delta: i64,
        timestamp: u64,
        host: Option<String>,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let mut active_counts = self.active_counts()?;
        if let Some(state) = active_counts.get_mut(&key) {
            state.value = state.value.saturating_add(delta);
            if state.value < 0 {
                state.value = 0;
            }
            state.window.start_unix_nanos = state.window.start_unix_nanos.min(timestamp);
            state.window.end_unix_nanos = state.window.end_unix_nanos.max(timestamp);
            return Ok(Some(state.to_signal(host)));
        }

        if active_counts.len() >= self.max_metric_keys {
            let suppressed_total = self
                .suppressed_active_gauges
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            warn_network_suppression("active_gauge", self.max_metric_keys, suppressed_total);
            return Ok(None);
        }

        let state = ActiveGaugeState {
            template,
            value: delta.max(0),
            window: MetricAggregationWindow {
                start_unix_nanos: timestamp,
                end_unix_nanos: timestamp,
            },
        };
        let signal = state.to_signal(host);
        active_counts.insert(key, state);
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
        if seen_events.len() >= self.max_metric_keys.saturating_mul(4).max(1)
            && let Some(first) = seen_events.iter().next().cloned()
        {
            seen_events.remove(&first);
        }
        seen_events.insert(fingerprint);
        Ok(true)
    }

    fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<CounterKey, CounterState>>> {
        self.counters.lock().map_err(module_error)
    }

    fn durations(&self) -> CoreResult<MutexGuard<'_, BTreeMap<DurationKey, DurationState>>> {
        self.durations.lock().map_err(module_error)
    }

    fn active_connections(
        &self,
    ) -> CoreResult<MutexGuard<'_, BTreeMap<ActiveConnectionKey, ActiveConnectionState>>> {
        self.active_connections.lock().map_err(module_error)
    }

    fn active_counts(
        &self,
    ) -> CoreResult<MutexGuard<'_, BTreeMap<ActiveGaugeKey, ActiveGaugeState>>> {
        self.active_counts.lock().map_err(module_error)
    }

    fn seen_events(&self) -> CoreResult<MutexGuard<'_, BTreeSet<EventFingerprint>>> {
        self.seen_events.lock().map_err(module_error)
    }
}

fn flow_summary_from_close(
    signal: &SignalEnvelope,
    event: &NetworkConnectionCloseEvent,
) -> Option<SignalEnvelope> {
    event.kubernetes.as_ref()?;
    let bytes = event
        .bytes_sent
        .unwrap_or(0)
        .saturating_add(event.bytes_received.unwrap_or(0));
    if bytes == 0 {
        return None;
    }

    Some(SignalEnvelope::network_flow_summary(
        "generator.network_metrics",
        signal.host.clone(),
        NetworkFlowSummaryEvent {
            source: NetworkFlowEndpoint {
                address: event.local_address.clone(),
                port: event.local_port,
                owner_name: None,
                owner_type: None,
                container: event.container.clone(),
                kubernetes: event.kubernetes.clone(),
            },
            destination: NetworkFlowEndpoint {
                address: Some(event.remote_address.clone()),
                port: Some(event.remote_port),
                owner_name: None,
                owner_type: None,
                container: None,
                kubernetes: None,
            },
            protocol: event.protocol,
            address_family: event.address_family,
            bytes,
            packets: None,
            direction: NetworkFlowDirection::Egress,
            first_seen_unix_nanos: event
                .opened_at_unix_nanos
                .unwrap_or(event.closed_at_unix_nanos),
            last_seen_unix_nanos: event.closed_at_unix_nanos,
        },
    ))
}

fn flow_warning_from_close(
    signal: &SignalEnvelope,
    event: &NetworkConnectionCloseEvent,
) -> Option<SignalEnvelope> {
    let bytes = event
        .bytes_sent
        .unwrap_or(0)
        .saturating_add(event.bytes_received.unwrap_or(0));
    if bytes == 0 || (event.container.is_some() && event.kubernetes.is_some()) {
        return None;
    }

    Some(SignalEnvelope::network_flow_warning(
        "generator.network_metrics",
        signal.host.clone(),
        NetworkFlowWarning {
            warning_type: "missing_attribution".to_string(),
            message: "byte-counted network flow has incomplete source container or Kubernetes attribution".to_string(),
            timestamp_unix_nanos: event.closed_at_unix_nanos,
            source_signal_kind: "network_connection_close".to_string(),
            source_module: signal.source.clone(),
            protocol: event.protocol,
            address_family: event.address_family,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
            process: event.process.clone(),
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CounterKey {
    metric_name: &'static str,
    workload: Option<String>,
    container: Option<String>,
    protocol: Option<String>,
    address_family: Option<String>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    errno: Option<i32>,
}

impl CounterKey {
    fn connection_open(event: &NetworkConnectionOpenEvent) -> Self {
        metric_key("network.connection.open.count", event, None, true)
    }

    fn protocol_open(event: &NetworkConnectionOpenEvent) -> Self {
        metric_key("network.protocol.connection.open.count", event, None, false)
    }

    fn traffic_destination(event: &NetworkConnectionOpenEvent) -> Self {
        metric_key("network.traffic.destination.count", event, None, true)
    }

    fn connection_failure(event: &NetworkConnectionFailureEvent) -> Self {
        CounterKey {
            metric_name: "network.connection.failure.count",
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            protocol: Some(format!("{:?}", event.protocol)),
            address_family: Some(format!("{:?}", event.address_family)),
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            errno: Some(event.errno),
        }
    }

    fn flow_bytes(event: &NetworkConnectionCloseEvent) -> Self {
        CounterKey {
            metric_name: "network.flow.bytes",
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            protocol: Some(format!("{:?}", event.protocol)),
            address_family: Some(format!("{:?}", event.address_family)),
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            errno: None,
        }
    }
}

fn metric_key(
    metric_name: &'static str,
    event: &NetworkConnectionOpenEvent,
    errno: Option<i32>,
    include_destination: bool,
) -> CounterKey {
    CounterKey {
        metric_name,
        workload: event.kubernetes.as_ref().map(workload_key),
        container: event
            .container
            .as_ref()
            .map(|container| container.container_id.clone()),
        protocol: Some(format!("{:?}", event.protocol)),
        address_family: Some(format!("{:?}", event.address_family)),
        remote_address: include_destination.then(|| event.remote_address.clone()),
        remote_port: include_destination.then_some(event.remote_port),
        errno,
    }
}

#[derive(Debug, Clone)]
struct CounterTemplate {
    metric_name: &'static str,
    unit: &'static str,
    process: Option<NetworkProcessIdentity>,
    protocol: Option<e_navigator_signals::NetworkProtocol>,
    address_family: Option<e_navigator_signals::NetworkAddressFamily>,
    local_address: Option<String>,
    local_port: Option<u16>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    errno: Option<i32>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
}

impl CounterTemplate {
    fn connection_open(event: &NetworkConnectionOpenEvent) -> Self {
        counter_template("network.connection.open.count", event, None, true)
    }

    fn protocol_open(event: &NetworkConnectionOpenEvent) -> Self {
        counter_template("network.protocol.connection.open.count", event, None, false)
    }

    fn traffic_destination(event: &NetworkConnectionOpenEvent) -> Self {
        counter_template("network.traffic.destination.count", event, None, true)
    }

    fn connection_failure(event: &NetworkConnectionFailureEvent) -> Self {
        Self {
            metric_name: "network.connection.failure.count",
            unit: "{connection}",
            process: Some(event.process.clone()),
            protocol: Some(event.protocol),
            address_family: Some(event.address_family),
            local_address: None,
            local_port: None,
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            errno: Some(event.errno),
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }

    fn flow_bytes(event: &NetworkConnectionCloseEvent) -> Self {
        Self {
            metric_name: "network.flow.bytes",
            unit: "By",
            process: Some(event.process.clone()),
            protocol: Some(event.protocol),
            address_family: Some(event.address_family),
            local_address: event.local_address.clone(),
            local_port: event.local_port,
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            errno: None,
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }
}

fn counter_template(
    metric_name: &'static str,
    event: &NetworkConnectionOpenEvent,
    errno: Option<i32>,
    include_destination: bool,
) -> CounterTemplate {
    CounterTemplate {
        metric_name,
        unit: if metric_name == "network.traffic.destination.count" {
            "{observation}"
        } else {
            "{connection}"
        },
        process: Some(event.process.clone()),
        protocol: Some(event.protocol),
        address_family: Some(event.address_family),
        local_address: include_destination
            .then(|| event.local_address.clone())
            .flatten(),
        local_port: include_destination.then_some(event.local_port).flatten(),
        remote_address: include_destination.then(|| event.remote_address.clone()),
        remote_port: include_destination.then_some(event.remote_port),
        errno,
        container: event.container.clone(),
        kubernetes: event.kubernetes.clone(),
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
        SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            host,
            NetworkCounterMetric {
                metric_name: self.template.metric_name.to_string(),
                unit: self.template.unit.to_string(),
                value: self.value,
                window: self.window.clone(),
                process: self.template.process.clone(),
                protocol: self.template.protocol,
                address_family: self.template.address_family,
                local_address: self.template.local_address.clone(),
                local_port: self.template.local_port,
                remote_address: self.template.remote_address.clone(),
                remote_port: self.template.remote_port,
                errno: self.template.errno,
                container: self.template.container.clone(),
                kubernetes: self.template.kubernetes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DurationKey {
    workload: Option<String>,
    container: Option<String>,
    protocol: String,
    address_family: String,
    remote_address: String,
    remote_port: u16,
}

impl DurationKey {
    fn connection_duration(event: &NetworkConnectionCloseEvent) -> Self {
        Self {
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            protocol: format!("{:?}", event.protocol),
            address_family: format!("{:?}", event.address_family),
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
        }
    }
}

#[derive(Debug, Clone)]
struct DurationTemplate {
    process: Option<NetworkProcessIdentity>,
    protocol: Option<e_navigator_signals::NetworkProtocol>,
    address_family: Option<e_navigator_signals::NetworkAddressFamily>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
}

impl DurationTemplate {
    fn connection_duration(event: &NetworkConnectionCloseEvent) -> Self {
        Self {
            process: Some(event.process.clone()),
            protocol: Some(event.protocol),
            address_family: Some(event.address_family),
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct DurationState {
    template: DurationTemplate,
    count: u64,
    sum_nanos: u64,
    min_nanos: u64,
    max_nanos: u64,
    window: MetricAggregationWindow,
}

impl DurationState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::network_duration_metric(
            "generator.network_metrics",
            host,
            NetworkDurationMetric {
                metric_name: "network.connection.duration".to_string(),
                unit: "ns".to_string(),
                count: self.count,
                sum_nanos: self.sum_nanos,
                min_nanos: self.min_nanos,
                max_nanos: self.max_nanos,
                window: self.window.clone(),
                process: self.template.process.clone(),
                protocol: self.template.protocol,
                address_family: self.template.address_family,
                remote_address: self.template.remote_address.clone(),
                remote_port: self.template.remote_port,
                container: self.template.container.clone(),
                kubernetes: self.template.kubernetes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveConnectionKey {
    pid: u32,
    fd: i32,
    remote_address: String,
    remote_port: u16,
}

impl ActiveConnectionKey {
    fn from_open(event: &NetworkConnectionOpenEvent) -> Option<Self> {
        Some(Self {
            pid: event.process.pid,
            fd: event.fd?,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
        })
    }

    fn from_close(event: &NetworkConnectionCloseEvent) -> Option<Self> {
        Some(Self {
            pid: event.process.pid,
            fd: event.fd?,
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
        })
    }
}

#[derive(Debug, Clone)]
struct ActiveConnectionState {
    gauge_key: ActiveGaugeKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ActiveGaugeKey {
    workload: Option<String>,
    container: Option<String>,
    protocol: String,
    address_family: String,
    remote_address: String,
    remote_port: u16,
}

impl ActiveGaugeKey {
    fn from_open(event: &NetworkConnectionOpenEvent) -> Self {
        Self {
            workload: event.kubernetes.as_ref().map(workload_key),
            container: event
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            protocol: format!("{:?}", event.protocol),
            address_family: format!("{:?}", event.address_family),
            remote_address: event.remote_address.clone(),
            remote_port: event.remote_port,
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveGaugeTemplate {
    process: Option<NetworkProcessIdentity>,
    protocol: Option<e_navigator_signals::NetworkProtocol>,
    address_family: Option<e_navigator_signals::NetworkAddressFamily>,
    remote_address: Option<String>,
    remote_port: Option<u16>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
}

impl ActiveGaugeTemplate {
    fn from_open(event: &NetworkConnectionOpenEvent) -> Self {
        Self {
            process: Some(event.process.clone()),
            protocol: Some(event.protocol),
            address_family: Some(event.address_family),
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }

    fn from_close(event: &NetworkConnectionCloseEvent) -> Self {
        Self {
            process: Some(event.process.clone()),
            protocol: Some(event.protocol),
            address_family: Some(event.address_family),
            remote_address: Some(event.remote_address.clone()),
            remote_port: Some(event.remote_port),
            container: event.container.clone(),
            kubernetes: event.kubernetes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveGaugeState {
    template: ActiveGaugeTemplate,
    value: i64,
    window: MetricAggregationWindow,
}

impl ActiveGaugeState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::network_gauge_metric(
            "generator.network_metrics",
            host,
            NetworkGaugeMetric {
                metric_name: "network.connection.active".to_string(),
                unit: "{connection}".to_string(),
                value: self.value,
                window: self.window.clone(),
                process: self.template.process.clone(),
                protocol: self.template.protocol,
                address_family: self.template.address_family,
                remote_address: self.template.remote_address.clone(),
                remote_port: self.template.remote_port,
                container: self.template.container.clone(),
                kubernetes: self.template.kubernetes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EventFingerprint {
    kind: &'static str,
    pid: u32,
    fd: Option<i32>,
    remote_address: String,
    remote_port: u16,
    timestamp: u64,
    errno: Option<i32>,
}

impl EventFingerprint {
    fn from_signal(signal: &SignalEnvelope) -> Option<Self> {
        match &signal.payload {
            SignalPayload::NetworkConnectionOpen(event) => Some(Self {
                kind: "open",
                pid: event.process.pid,
                fd: event.fd,
                remote_address: event.remote_address.clone(),
                remote_port: event.remote_port,
                timestamp: event.timestamp_unix_nanos,
                errno: None,
            }),
            SignalPayload::NetworkConnectionClose(event) => Some(Self {
                kind: "close",
                pid: event.process.pid,
                fd: event.fd,
                remote_address: event.remote_address.clone(),
                remote_port: event.remote_port,
                timestamp: event.closed_at_unix_nanos,
                errno: None,
            }),
            SignalPayload::NetworkConnectionFailure(event) => Some(Self {
                kind: "failure",
                pid: event.process.pid,
                fd: event.fd,
                remote_address: event.remote_address.clone(),
                remote_port: event.remote_port,
                timestamp: event.timestamp_unix_nanos,
                errno: Some(event.errno),
            }),
            _ => None,
        }
    }
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
        module: "generator.network_metrics".to_string(),
        message: err.to_string(),
    }
}

fn warn_network_suppression(
    state_type: &'static str,
    max_state_keys: usize,
    suppressed_total: u64,
) {
    if should_warn_network_suppression(suppressed_total) {
        warn!(
            state_type,
            max_state_keys,
            suppressed_total,
            "network metric state limit reached; suppressing new state keys"
        );
    }
}

fn should_warn_network_suppression(suppressed_total: u64) -> bool {
    suppressed_total <= NETWORK_SUPPRESSION_FIRST_WARNINGS || suppressed_total.is_power_of_two()
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkSuppressionCounts {
    counters: u64,
    durations: u64,
    active_connections: u64,
    active_gauges: u64,
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Generator;
    use e_navigator_signals::{
        ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
        NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkCounterMetric,
        NetworkDurationMetric, NetworkGaugeMetric, NetworkProcessIdentity, NetworkProtocol,
        SignalEnvelope, SignalPayload,
    };
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn emits_open_connection_counter_metrics() {
        let generator = NetworkMetricsGenerator::default();
        let signal = network_open_signal("203.0.113.10", 443, 100, Some(7));

        let metrics = observe(&generator, &signal).await;

        let open = counter_metric(&metrics, "network.connection.open.count");
        assert_eq!(open.value, 1);
        assert_eq!(open.unit, "{connection}");
        assert_eq!(open.remote_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(open.remote_port, Some(443));
        assert_eq!(open.protocol, Some(NetworkProtocol::Tcp));
        assert_eq!(open.window.start_unix_nanos, 100);
        assert_eq!(open.window.end_unix_nanos, 100);
        assert_eq!(open.container, Some(container_context()));
        assert_eq!(open.kubernetes, Some(kubernetes_context()));
        assert!(counter_metric_exists(
            &metrics,
            "network.protocol.connection.open.count"
        ));
        assert!(counter_metric_exists(
            &metrics,
            "network.traffic.destination.count"
        ));
    }

    #[tokio::test]
    async fn emits_close_duration_metric() {
        let generator = NetworkMetricsGenerator::default();
        let close = network_close_signal("203.0.113.10", 443, 100, 700, Some(7));

        let metrics = observe(&generator, &close).await;

        let duration = duration_metric(&metrics, "network.connection.duration");
        assert_eq!(duration.unit, "ns");
        assert_eq!(duration.count, 1);
        assert_eq!(duration.sum_nanos, 600);
        assert_eq!(duration.min_nanos, 600);
        assert_eq!(duration.max_nanos, 600);
        assert_eq!(duration.window.start_unix_nanos, 100);
        assert_eq!(duration.window.end_unix_nanos, 700);
        assert_eq!(duration.container, Some(container_context()));
        assert_eq!(duration.kubernetes, Some(kubernetes_context()));
    }

    #[tokio::test]
    async fn emits_network_flow_summary_from_close_byte_counters() {
        let generator = NetworkMetricsGenerator::default();
        let close =
            network_close_signal_with_bytes("10.0.0.20", 5432, 100, 900, Some(7), 512, 1024);

        let outputs = observe(&generator, &close).await;
        let flow = network_flow_summary(&outputs);

        assert_eq!(flow.bytes, 1536);
        assert_eq!(flow.packets, None);
        assert_eq!(flow.protocol, NetworkProtocol::Tcp);
        assert_eq!(flow.address_family, NetworkAddressFamily::Ipv4);
        assert_eq!(flow.source.address.as_deref(), Some("10.0.0.5"));
        assert_eq!(flow.source.port, Some(43512));
        assert_eq!(flow.source.container, Some(container_context()));
        assert_eq!(flow.source.kubernetes, Some(kubernetes_context()));
        assert_eq!(flow.destination.address.as_deref(), Some("10.0.0.20"));
        assert_eq!(flow.destination.port, Some(5432));
        assert_eq!(flow.first_seen_unix_nanos, 100);
        assert_eq!(flow.last_seen_unix_nanos, 900);
    }

    #[tokio::test]
    async fn emits_native_flow_byte_counter_from_close_byte_counters() {
        let generator = NetworkMetricsGenerator::default();
        let close =
            network_close_signal_with_bytes("10.0.0.20", 5432, 100, 900, Some(7), 512, 1024);

        let outputs = observe(&generator, &close).await;
        let metric = counter_metric(&outputs, "network.flow.bytes");

        assert_eq!(metric.unit, "By");
        assert_eq!(metric.value, 1536);
        assert_eq!(metric.window.start_unix_nanos, 100);
        assert_eq!(metric.window.end_unix_nanos, 900);
        assert_eq!(metric.kubernetes, Some(kubernetes_context()));
        assert_eq!(metric.remote_address.as_deref(), Some("10.0.0.20"));
        assert_eq!(metric.remote_port, Some(5432));
    }

    #[tokio::test]
    async fn emits_network_flow_warning_when_byte_counters_lack_attribution() {
        let generator = NetworkMetricsGenerator::default();
        let mut close =
            network_close_signal_with_bytes("10.0.0.20", 5432, 100, 900, Some(7), 512, 1024);
        let SignalPayload::NetworkConnectionClose(event) = &mut close.payload else {
            panic!("expected network close");
        };
        event.container = None;
        event.kubernetes = None;

        let outputs = observe(&generator, &close).await;
        let warning = network_flow_warning(&outputs);

        assert_eq!(warning.warning_type, "missing_attribution");
        assert_eq!(warning.timestamp_unix_nanos, 900);
        assert_eq!(warning.source_signal_kind, "network_connection_close");
        assert_eq!(warning.source_module, "source.test");
        assert_eq!(warning.protocol, NetworkProtocol::Tcp);
        assert_eq!(warning.address_family, NetworkAddressFamily::Ipv4);
        assert_eq!(warning.remote_address, "10.0.0.20");
        assert_eq!(warning.remote_port, 5432);
        assert_eq!(warning.process, network_process());
        assert!(warning.container.is_none());
        assert!(warning.kubernetes.is_none());
        assert!(
            !outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NetworkFlowSummary(_)))
        );
        assert!(!counter_metric_exists(&outputs, "network.flow.bytes"));
    }

    #[tokio::test]
    async fn emits_network_flow_warning_for_partial_source_attribution() {
        let generator = NetworkMetricsGenerator::default();
        let mut close =
            network_close_signal_with_bytes("10.0.0.20", 5432, 100, 900, Some(7), 512, 1024);
        let SignalPayload::NetworkConnectionClose(event) = &mut close.payload else {
            panic!("expected network close");
        };
        event.container = None;

        let outputs = observe(&generator, &close).await;

        assert_eq!(
            network_flow_warning(&outputs).kubernetes,
            Some(kubernetes_context())
        );
        assert!(
            outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NetworkFlowSummary(_)))
        );
        assert!(counter_metric_exists(&outputs, "network.flow.bytes"));
    }

    #[tokio::test]
    async fn does_not_emit_network_flow_warning_without_byte_counters() {
        let generator = NetworkMetricsGenerator::default();
        let mut close = network_close_signal("10.0.0.20", 5432, 100, 900, Some(7));
        let SignalPayload::NetworkConnectionClose(event) = &mut close.payload else {
            panic!("expected network close");
        };
        event.container = None;
        event.kubernetes = None;

        let outputs = observe(&generator, &close).await;

        assert!(
            !outputs
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NetworkFlowWarning(_)))
        );
    }

    #[tokio::test]
    async fn emits_failure_counter_metric() {
        let generator = NetworkMetricsGenerator::default();
        let failure = network_failure_signal("203.0.113.10", 443, 111, 150);

        let metrics = observe(&generator, &failure).await;

        let failure = counter_metric(&metrics, "network.connection.failure.count");
        assert_eq!(failure.value, 1);
        assert_eq!(failure.errno, Some(111));
        assert_eq!(failure.remote_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(failure.remote_port, Some(443));
    }

    #[tokio::test]
    async fn accounts_for_active_connections() {
        let generator = NetworkMetricsGenerator::default();
        let open = network_open_signal("203.0.113.10", 443, 100, Some(7));
        let close = network_close_signal("203.0.113.10", 443, 100, 700, Some(7));

        let opened = observe(&generator, &open).await;
        let closed = observe(&generator, &close).await;

        assert_eq!(gauge_metric(&opened, "network.connection.active").value, 1);
        assert_eq!(gauge_metric(&closed, "network.connection.active").value, 0);
    }

    #[tokio::test]
    async fn deterministic_aggregation_updates_counter_values() {
        let first_generator = NetworkMetricsGenerator::default();
        let second_generator = NetworkMetricsGenerator::default();
        let first = network_open_signal("203.0.113.10", 443, 100, Some(7));
        let second = network_open_signal("203.0.113.10", 443, 101, Some(8));

        let first_outputs = observe_many(&first_generator, [&first, &second]).await;
        let second_outputs = observe_many(&second_generator, [&first, &second]).await;

        assert_eq!(first_outputs, second_outputs);
        let last_open = counter_metric(
            first_outputs
                .last()
                .expect("second observation emits metrics"),
            "network.connection.open.count",
        );
        assert_eq!(last_open.value, 2);
        assert_eq!(last_open.window.start_unix_nanos, 100);
        assert_eq!(last_open.window.end_unix_nanos, 101);
    }

    #[tokio::test]
    async fn bounded_metric_state_drops_new_keys_after_limit() {
        let generator = NetworkMetricsGenerator::with_limits(1, 8);

        let first = observe(
            &generator,
            &network_open_signal("203.0.113.10", 443, 100, Some(7)),
        )
        .await;
        let second = observe(
            &generator,
            &network_open_signal("203.0.113.11", 443, 101, Some(8)),
        )
        .await;

        assert!(counter_metric_exists(
            &first,
            "network.connection.open.count"
        ));
        assert!(!counter_metric_exists(
            &second,
            "network.connection.open.count"
        ));
        assert!(generator.suppression_counts().counters > 0);
    }

    #[tokio::test]
    async fn bounded_duration_state_counts_suppression_after_limit() {
        let generator = NetworkMetricsGenerator::with_limits(0, 8);

        let outputs = observe(
            &generator,
            &network_close_signal("203.0.113.10", 443, 100, 700, Some(7)),
        )
        .await;

        assert!(outputs.is_empty());
        assert_eq!(generator.suppression_counts().durations, 1);
    }

    #[tokio::test]
    async fn bounded_active_connection_state_counts_suppression_after_limit() {
        let generator = NetworkMetricsGenerator::with_limits(8, 0);

        let outputs = observe(
            &generator,
            &network_open_signal("203.0.113.10", 443, 100, Some(7)),
        )
        .await;

        assert!(!gauge_metric_exists(&outputs, "network.connection.active"));
        assert_eq!(generator.suppression_counts().active_connections, 1);
    }

    #[tokio::test]
    async fn bounded_active_gauge_state_counts_suppression_after_limit() {
        let generator = NetworkMetricsGenerator::with_limits(0, 8);

        let outputs = observe(
            &generator,
            &network_open_signal("203.0.113.10", 443, 100, Some(7)),
        )
        .await;

        assert!(outputs.is_empty());
        assert_eq!(generator.suppression_counts().active_gauges, 1);
    }

    #[test]
    fn network_suppression_warning_cadence_matches_dns_style() {
        assert!(should_warn_network_suppression(1));
        assert!(should_warn_network_suppression(2));
        assert!(should_warn_network_suppression(3));
        assert!(should_warn_network_suppression(4));
        assert!(!should_warn_network_suppression(5));
        assert!(should_warn_network_suppression(8));
    }

    #[tokio::test]
    async fn suppresses_duplicate_identical_observations() {
        let generator = NetworkMetricsGenerator::default();
        let signal = network_open_signal("203.0.113.10", 443, 100, Some(7));

        let first = observe(&generator, &signal).await;
        let second = observe(&generator, &signal).await;

        assert!(!first.is_empty());
        assert!(second.is_empty());
    }

    async fn observe(
        generator: &NetworkMetricsGenerator,
        signal: &SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(8);
        generator
            .observe(signal, &tx)
            .await
            .expect("generator succeeds");
        drop(tx);

        let mut metrics = Vec::new();
        while let Some(metric) = rx.recv().await {
            metrics.push(metric);
        }
        metrics
    }

    async fn observe_many<'a>(
        generator: &NetworkMetricsGenerator,
        signals: impl IntoIterator<Item = &'a SignalEnvelope>,
    ) -> Vec<Vec<SignalEnvelope>> {
        let mut outputs = Vec::new();
        for signal in signals {
            outputs.push(observe(generator, signal).await);
        }
        outputs
    }

    fn counter_metric<'a>(
        metrics: &'a [SignalEnvelope],
        metric_name: &str,
    ) -> &'a NetworkCounterMetric {
        metrics
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::NetworkCounterMetric(metric)
                    if metric.metric_name == metric_name =>
                {
                    Some(metric)
                }
                _ => None,
            })
            .expect("counter metric exists")
    }

    fn duration_metric<'a>(
        metrics: &'a [SignalEnvelope],
        metric_name: &str,
    ) -> &'a NetworkDurationMetric {
        metrics
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::NetworkDurationMetric(metric)
                    if metric.metric_name == metric_name =>
                {
                    Some(metric)
                }
                _ => None,
            })
            .expect("duration metric exists")
    }

    fn gauge_metric<'a>(
        metrics: &'a [SignalEnvelope],
        metric_name: &str,
    ) -> &'a NetworkGaugeMetric {
        metrics
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::NetworkGaugeMetric(metric) if metric.metric_name == metric_name => {
                    Some(metric)
                }
                _ => None,
            })
            .expect("gauge metric exists")
    }

    fn counter_metric_exists(metrics: &[SignalEnvelope], metric_name: &str) -> bool {
        metrics.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::NetworkCounterMetric(metric)
                    if metric.metric_name == metric_name
            )
        })
    }

    fn gauge_metric_exists(metrics: &[SignalEnvelope], metric_name: &str) -> bool {
        metrics.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::NetworkGaugeMetric(metric)
                    if metric.metric_name == metric_name
            )
        })
    }

    fn network_flow_summary(
        metrics: &[SignalEnvelope],
    ) -> &e_navigator_signals::NetworkFlowSummaryEvent {
        metrics
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::NetworkFlowSummary(flow) => Some(flow),
                _ => None,
            })
            .expect("network flow summary exists")
    }

    fn network_flow_warning(
        metrics: &[SignalEnvelope],
    ) -> &e_navigator_signals::NetworkFlowWarning {
        metrics
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::NetworkFlowWarning(warning) => Some(warning),
                _ => None,
            })
            .expect("network flow warning exists")
    }

    fn network_open_signal(
        remote_address: &str,
        remote_port: u16,
        timestamp: u64,
        fd: Option<i32>,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_open(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionOpenEvent {
                process: network_process(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: remote_address.to_string(),
                remote_port,
                fd,
                timestamp_unix_nanos: timestamp,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn network_close_signal(
        remote_address: &str,
        remote_port: u16,
        opened_at: u64,
        closed_at: u64,
        fd: Option<i32>,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_close(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionCloseEvent {
                process: network_process(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: remote_address.to_string(),
                remote_port,
                fd,
                opened_at_unix_nanos: Some(opened_at),
                closed_at_unix_nanos: closed_at,
                duration_nanos: Some(closed_at.saturating_sub(opened_at)),
                bytes_sent: None,
                bytes_received: None,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn network_close_signal_with_bytes(
        remote_address: &str,
        remote_port: u16,
        opened_at: u64,
        closed_at: u64,
        fd: Option<i32>,
        bytes_sent: u64,
        bytes_received: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_close(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionCloseEvent {
                process: network_process(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: remote_address.to_string(),
                remote_port,
                fd,
                opened_at_unix_nanos: Some(opened_at),
                closed_at_unix_nanos: closed_at,
                duration_nanos: Some(closed_at.saturating_sub(opened_at)),
                bytes_sent: Some(bytes_sent),
                bytes_received: Some(bytes_received),
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn network_failure_signal(
        remote_address: &str,
        remote_port: u16,
        errno: i32,
        timestamp: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_failure(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionFailureEvent {
                process: network_process(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: remote_address.to_string(),
                remote_port,
                fd: Some(7),
                errno,
                timestamp_unix_nanos: timestamp,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
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
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "api".to_string());

        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }
}
