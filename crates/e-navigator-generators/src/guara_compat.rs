use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    CompatibilityCounterMetric, MetricAggregationWindow, NetworkFlowEndpoint,
    NetworkFlowSummaryEvent, SignalEnvelope, SignalPayload,
};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
use tracing::warn;

pub const BEYLA_NETWORK_FLOW_BYTES_TOTAL: &str = "beyla_network_flow_bytes_total";
pub const PYROSCOPE_CPU_PROFILE_IDENTITY: &str = "process_cpu:cpu:nanoseconds:cpu:nanoseconds";

const DEFAULT_MAX_FLOW_SERIES: usize = 4096;
const SUPPRESSION_FIRST_WARNINGS: u64 = 3;

#[derive(Debug)]
pub struct GuaraCompatibilityGenerator {
    max_flow_series: usize,
    flow_totals: Mutex<BTreeMap<FlowSeriesKey, FlowSeriesState>>,
    dropped_platform_flows: AtomicU64,
    dropped_scope_flows: AtomicU64,
    dropped_cardinality_flows: AtomicU64,
}

impl Default for GuaraCompatibilityGenerator {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_FLOW_SERIES)
    }
}

impl GuaraCompatibilityGenerator {
    pub fn with_limits(max_flow_series: usize) -> Self {
        Self {
            max_flow_series,
            flow_totals: Mutex::new(BTreeMap::new()),
            dropped_platform_flows: AtomicU64::new(0),
            dropped_scope_flows: AtomicU64::new(0),
            dropped_cardinality_flows: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn drop_counts(&self) -> GuaraCompatibilityDropCounts {
        GuaraCompatibilityDropCounts {
            platform_flows: self.dropped_platform_flows.load(Ordering::Relaxed),
            scope_flows: self.dropped_scope_flows.load(Ordering::Relaxed),
            cardinality_flows: self.dropped_cardinality_flows.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for GuaraCompatibilityGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.guara_compat", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let Some(metric) = (match &signal.payload {
            SignalPayload::NetworkFlowSummary(flow) => self.observe_flow(signal, flow)?,
            _ => None,
        }) else {
            return Ok(());
        };

        tx.send(metric).await.map_err(|_| CoreError::PipelineClosed)
    }
}

impl GuaraCompatibilityGenerator {
    fn observe_flow(
        &self,
        signal: &SignalEnvelope,
        flow: &NetworkFlowSummaryEvent,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let Some(labels) = beyla_flow_labels(flow) else {
            self.dropped_platform_flows.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };

        if !flow_is_in_guara_scope(flow) {
            self.dropped_scope_flows.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let key = FlowSeriesKey {
            labels: labels.clone(),
        };
        let mut totals = self.flow_totals()?;
        if let Some(state) = totals.get_mut(&key) {
            state.value = state.value.saturating_add(flow.bytes);
            state.window.start_unix_nanos = state
                .window
                .start_unix_nanos
                .min(flow.first_seen_unix_nanos);
            state.window.end_unix_nanos =
                state.window.end_unix_nanos.max(flow.last_seen_unix_nanos);
            return Ok(Some(state.to_signal(signal.host.clone())));
        }

        if totals.len() >= self.max_flow_series.max(1) {
            let dropped_total = self
                .dropped_cardinality_flows
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            warn_compat_suppression(self.max_flow_series, dropped_total);
            return Ok(None);
        }

        let state = FlowSeriesState {
            labels,
            value: flow.bytes,
            window: MetricAggregationWindow {
                start_unix_nanos: flow.first_seen_unix_nanos,
                end_unix_nanos: flow.last_seen_unix_nanos,
            },
        };
        let metric = state.to_signal(signal.host.clone());
        totals.insert(key, state);
        Ok(Some(metric))
    }

    fn flow_totals(&self) -> CoreResult<MutexGuard<'_, BTreeMap<FlowSeriesKey, FlowSeriesState>>> {
        self.flow_totals.lock().map_err(module_error)
    }
}

pub fn beyla_flow_labels(flow: &NetworkFlowSummaryEvent) -> Option<BTreeMap<String, String>> {
    let src_namespace = flow.source.kubernetes.as_ref()?.namespace.clone();
    let dst_namespace = flow.destination.kubernetes.as_ref()?.namespace.clone();
    if !src_namespace.starts_with("proj-") && !dst_namespace.starts_with("proj-") {
        return None;
    }

    let src_owner_name = owner_name(&flow.source)?;
    let dst_owner_name = owner_name(&flow.destination)?;
    let src_owner_type = owner_type(&flow.source);
    let dst_owner_type = owner_type(&flow.destination);

    Some(BTreeMap::from([
        ("k8s_src_namespace".to_string(), src_namespace),
        ("k8s_src_owner_name".to_string(), src_owner_name),
        ("k8s_src_owner_type".to_string(), src_owner_type),
        ("k8s_dst_namespace".to_string(), dst_namespace),
        ("k8s_dst_owner_name".to_string(), dst_owner_name),
        ("k8s_dst_owner_type".to_string(), dst_owner_type),
    ]))
}

pub fn flow_is_in_guara_scope(flow: &NetworkFlowSummaryEvent) -> bool {
    endpoint_is_paid_tenant_source(&flow.source)
}

pub fn endpoint_is_paid_tenant_source(endpoint: &NetworkFlowEndpoint) -> bool {
    let Some(kubernetes) = endpoint.kubernetes.as_ref() else {
        return false;
    };
    if !kubernetes.namespace.starts_with("proj-") {
        return false;
    }
    if kubernetes
        .labels
        .get("guara.cloud/role")
        .map(String::as_str)
        == Some("build")
    {
        return false;
    }
    if kubernetes
        .labels
        .get("guara.cloud/catalog-slug")
        .is_some_and(|slug| !slug.is_empty())
    {
        return false;
    }

    matches!(
        kubernetes
            .labels
            .get("guara.cloud/tier")
            .map(String::as_str),
        Some("pro" | "business" | "enterprise")
    )
}

pub fn pyroscope_labels_for_endpoint(
    endpoint: &NetworkFlowEndpoint,
) -> Option<BTreeMap<String, String>> {
    let kubernetes = endpoint.kubernetes.as_ref()?;
    if !endpoint_is_paid_tenant_source(endpoint) {
        return None;
    }

    Some(BTreeMap::from([
        ("namespace".to_string(), kubernetes.namespace.clone()),
        ("service_name".to_string(), owner_name(endpoint)?),
        (
            "catalog_slug".to_string(),
            kubernetes
                .labels
                .get("guara.cloud/catalog-slug")
                .cloned()
                .unwrap_or_default(),
        ),
        ("pod".to_string(), kubernetes.pod_name.clone()),
        (
            "container".to_string(),
            kubernetes.container_name.clone().unwrap_or_default(),
        ),
        (
            "node".to_string(),
            kubernetes.node_name.clone().unwrap_or_default(),
        ),
        ("source".to_string(), "e-navigator".to_string()),
    ]))
}

fn owner_name(endpoint: &NetworkFlowEndpoint) -> Option<String> {
    if let Some(owner_name) = endpoint.owner_name.as_ref().filter(|name| !name.is_empty()) {
        return Some(owner_name.clone());
    }
    let kubernetes = endpoint.kubernetes.as_ref()?;
    kubernetes
        .labels
        .get("app.kubernetes.io/name")
        .or_else(|| kubernetes.labels.get("app"))
        .filter(|name| !name.is_empty())
        .cloned()
        .or_else(|| Some(kubernetes.pod_name.clone()))
}

fn owner_type(endpoint: &NetworkFlowEndpoint) -> String {
    endpoint
        .owner_type
        .as_ref()
        .filter(|owner_type| !owner_type.is_empty())
        .cloned()
        .unwrap_or_else(|| "deployment".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowSeriesKey {
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct FlowSeriesState {
    labels: BTreeMap<String, String>,
    value: u64,
    window: MetricAggregationWindow,
}

impl FlowSeriesState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::compatibility_counter_metric(
            "generator.guara_compat",
            host,
            CompatibilityCounterMetric {
                metric_name: BEYLA_NETWORK_FLOW_BYTES_TOTAL.to_string(),
                unit: "By".to_string(),
                value: self.value,
                window: self.window.clone(),
                labels: self.labels.clone(),
            },
        )
    }
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.guara_compat".to_string(),
        message: err.to_string(),
    }
}

fn warn_compat_suppression(max_flow_series: usize, dropped_total: u64) {
    if dropped_total <= SUPPRESSION_FIRST_WARNINGS || dropped_total.is_power_of_two() {
        warn!(
            max_flow_series,
            dropped_total,
            "Guara compatibility flow cardinality limit reached; dropping new flow series"
        );
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuaraCompatibilityDropCounts {
    platform_flows: u64,
    scope_flows: u64,
    cardinality_flows: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Generator;
    use e_navigator_signals::{
        KubernetesContext, NetworkAddressFamily, NetworkFlowDirection, NetworkProtocol,
    };
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn projects_beyla_network_flow_bytes_total_with_only_owner_labels() {
        let generator = GuaraCompatibilityGenerator::default();
        let signal = flow_signal(
            tenant_endpoint("api"),
            tenant_catalog_endpoint("redis"),
            2048,
        );

        let output = observe(&generator, &signal).await;
        let metric = compatibility_metric(&output);

        assert_eq!(metric.metric_name, BEYLA_NETWORK_FLOW_BYTES_TOTAL);
        assert_eq!(metric.unit, "By");
        assert_eq!(metric.value, 2048);
        assert_eq!(metric.labels["k8s_src_namespace"], "proj-paid");
        assert_eq!(metric.labels["k8s_src_owner_name"], "api");
        assert_eq!(metric.labels["k8s_src_owner_type"], "deployment");
        assert_eq!(metric.labels["k8s_dst_namespace"], "proj-paid");
        assert_eq!(metric.labels["k8s_dst_owner_name"], "redis");
        assert_eq!(metric.labels["k8s_dst_owner_type"], "statefulset");
        assert!(!metric.labels.contains_key("src_port"));
        assert!(!metric.labels.contains_key("dst_port"));
        assert!(!metric.labels.contains_key("src_address"));
        assert!(!metric.labels.contains_key("dst_address"));
    }

    #[tokio::test]
    async fn drops_platform_only_flows_before_export() {
        let generator = GuaraCompatibilityGenerator::default();
        let signal = flow_signal(platform_endpoint("api"), platform_endpoint("nats"), 1024);

        let output = observe(&generator, &signal).await;

        assert!(output.is_empty());
        assert_eq!(generator.drop_counts().platform_flows, 1);
    }

    #[tokio::test]
    async fn drops_catalog_sources_but_preserves_tenant_to_catalog_flows() {
        let generator = GuaraCompatibilityGenerator::default();
        let tenant_to_catalog = flow_signal(
            tenant_endpoint("api"),
            tenant_catalog_endpoint("redis"),
            512,
        );
        let catalog_to_tenant = flow_signal(
            tenant_catalog_endpoint("redis"),
            tenant_endpoint("api"),
            512,
        );

        let kept = observe(&generator, &tenant_to_catalog).await;
        let dropped = observe(&generator, &catalog_to_tenant).await;

        assert!(!kept.is_empty());
        assert!(dropped.is_empty());
        assert_eq!(generator.drop_counts().scope_flows, 1);
    }

    #[tokio::test]
    async fn bounds_flow_cardinality_with_drop_accounting() {
        let generator = GuaraCompatibilityGenerator::with_limits(1);
        let first = flow_signal(tenant_endpoint("api"), tenant_endpoint("worker"), 256);
        let second = flow_signal(tenant_endpoint("api"), tenant_endpoint("billing"), 256);

        assert!(!observe(&generator, &first).await.is_empty());
        assert!(observe(&generator, &second).await.is_empty());
        assert_eq!(generator.drop_counts().cardinality_flows, 1);
    }

    #[test]
    fn pyroscope_labels_match_guara_profile_identity_and_scope() {
        let labels = pyroscope_labels_for_endpoint(&tenant_endpoint("api")).expect("in scope");

        assert_eq!(
            PYROSCOPE_CPU_PROFILE_IDENTITY,
            "process_cpu:cpu:nanoseconds:cpu:nanoseconds"
        );
        assert_eq!(labels["namespace"], "proj-paid");
        assert_eq!(labels["service_name"], "api");
        assert_eq!(labels["catalog_slug"], "");
        assert_eq!(labels["pod"], "api-abc");
        assert_eq!(labels["container"], "app");
        assert_eq!(labels["node"], "node-a");
        assert_eq!(labels["source"], "e-navigator");
        assert!(pyroscope_labels_for_endpoint(&tenant_catalog_endpoint("redis")).is_none());
    }

    async fn observe(
        generator: &GuaraCompatibilityGenerator,
        signal: &SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(4);
        generator
            .observe(signal, &tx)
            .await
            .expect("generator succeeds");
        drop(tx);

        let mut output = Vec::new();
        while let Some(signal) = rx.recv().await {
            output.push(signal);
        }
        output
    }

    fn compatibility_metric(output: &[SignalEnvelope]) -> &CompatibilityCounterMetric {
        output
            .iter()
            .find_map(|signal| match &signal.payload {
                SignalPayload::CompatibilityCounterMetric(metric) => Some(metric),
                _ => None,
            })
            .expect("compatibility metric exists")
    }

    fn flow_signal(
        source: NetworkFlowEndpoint,
        destination: NetworkFlowEndpoint,
        bytes: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::network_flow_summary(
            "source.aya_network",
            Some("node-a".to_string()),
            NetworkFlowSummaryEvent {
                source,
                destination,
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                bytes,
                packets: Some(4),
                direction: NetworkFlowDirection::Egress,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 2_000,
            },
        )
    }

    fn tenant_endpoint(owner: &str) -> NetworkFlowEndpoint {
        NetworkFlowEndpoint {
            address: Some("10.0.0.10".to_string()),
            port: Some(8080),
            owner_name: Some(owner.to_string()),
            owner_type: Some("deployment".to_string()),
            container: None,
            kubernetes: Some(kubernetes("proj-paid", owner, None)),
        }
    }

    fn tenant_catalog_endpoint(owner: &str) -> NetworkFlowEndpoint {
        NetworkFlowEndpoint {
            address: Some("10.0.0.20".to_string()),
            port: Some(6379),
            owner_name: Some(owner.to_string()),
            owner_type: Some("statefulset".to_string()),
            container: None,
            kubernetes: Some(kubernetes("proj-paid", owner, Some(owner))),
        }
    }

    fn platform_endpoint(owner: &str) -> NetworkFlowEndpoint {
        NetworkFlowEndpoint {
            address: Some("10.0.1.10".to_string()),
            port: Some(8080),
            owner_name: Some(owner.to_string()),
            owner_type: Some("deployment".to_string()),
            container: None,
            kubernetes: Some(kubernetes("guara-system", owner, None)),
        }
    }

    fn kubernetes(namespace: &str, owner: &str, catalog_slug: Option<&str>) -> KubernetesContext {
        let mut labels = BTreeMap::from([
            ("app.kubernetes.io/name".to_string(), owner.to_string()),
            ("guara.cloud/tier".to_string(), "pro".to_string()),
        ]);
        if let Some(catalog_slug) = catalog_slug {
            labels.insert(
                "guara.cloud/catalog-slug".to_string(),
                catalog_slug.to_string(),
            );
        }

        KubernetesContext {
            namespace: namespace.to_string(),
            pod_name: format!("{owner}-abc"),
            pod_uid: Some(format!("{owner}-uid")),
            container_name: Some("app".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }
}
