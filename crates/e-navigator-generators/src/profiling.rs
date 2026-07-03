use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata, Signal};
use e_navigator_signals::{
    MetricAggregationWindow, ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
    ProfilingSessionObservation, ProfilingWarningObservation, SignalEnvelope, SignalPayload,
    is_sensitive_profiling_attribute_key,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_WINDOWS: usize = 4096;
const DEFAULT_MAX_SEEN_SAMPLES: usize = 8192;
const DEFAULT_MAX_WARNINGS: usize = 1024;
const DEFAULT_WINDOW_NANOS: u64 = 30_000_000_000;
const DEFAULT_MAX_STACK_IDS_PER_WINDOW: usize = 64;
const DEFAULT_MAX_SAMPLES_PER_WINDOW: u64 = 64;
const MAX_PROFILE_ATTRIBUTES: usize = 16;
const MAX_PROFILE_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_PROFILE_ATTRIBUTE_VALUE_BYTES: usize = 256;

#[derive(Debug)]
pub struct ProfilingGenerator {
    max_windows: usize,
    max_seen_samples: usize,
    max_warnings: usize,
    window_nanos: u64,
    max_stack_ids_per_window: usize,
    max_samples_per_window: u64,
    windows: Mutex<BTreeMap<WindowKey, WindowState>>,
    window_order: Mutex<BTreeSet<WindowOrderKey>>,
    seen_samples: Mutex<BTreeSet<SampleFingerprint>>,
    seen_warnings: Mutex<BTreeSet<WarningFingerprint>>,
}

impl Default for ProfilingGenerator {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_WINDOWS,
            DEFAULT_MAX_SEEN_SAMPLES,
            DEFAULT_MAX_WARNINGS,
            DEFAULT_WINDOW_NANOS,
        )
    }
}

impl ProfilingGenerator {
    pub fn with_limits(
        max_windows: usize,
        max_seen_samples: usize,
        max_warnings: usize,
        window_nanos: u64,
    ) -> Self {
        Self {
            max_windows,
            max_seen_samples,
            max_warnings,
            window_nanos: window_nanos.max(1),
            max_stack_ids_per_window: DEFAULT_MAX_STACK_IDS_PER_WINDOW,
            max_samples_per_window: DEFAULT_MAX_SAMPLES_PER_WINDOW,
            windows: Mutex::new(BTreeMap::new()),
            window_order: Mutex::new(BTreeSet::new()),
            seen_samples: Mutex::new(BTreeSet::new()),
            seen_warnings: Mutex::new(BTreeSet::new()),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for ProfilingGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.profiling", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let outputs = match &signal.payload {
            SignalPayload::ProfileSampleObservation(sample) => {
                self.observe_sample(signal, sample)?
            }
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

impl ProfilingGenerator {
    fn observe_sample(
        &self,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        if !self.mark_sample_seen(SampleFingerprint::from_signal(signal, sample))? {
            return Ok(Vec::new());
        }

        let mut outputs = Vec::new();
        if let Some(update) = self.update_window(signal, sample)? {
            let dropped_sample_count = update.dropped_sample_count;
            outputs.push(update.signal);
            if dropped_sample_count > 0
                && let Some(warning) =
                    self.dropped_samples_warning(signal, sample, dropped_sample_count)?
            {
                outputs.push(warning);
            }
        }
        if sample.container.is_none()
            && sample.kubernetes.is_none()
            && let Some(warning) = self.missing_attribution_warning(signal, sample)?
        {
            outputs.push(warning);
        }

        Ok(outputs)
    }

    fn update_window(
        &self,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
    ) -> CoreResult<Option<WindowUpdate>> {
        let window = window_for(sample.timestamp_unix_nanos, self.window_nanos);
        let key = WindowKey::from_sample(signal, sample, &window);
        let mut windows = self.windows()?;
        let mut window_order = self.window_order()?;
        if let Some(state) = windows.get_mut(&key) {
            let dropped_sample_count = state.update_from_sample(
                sample,
                self.max_stack_ids_per_window,
                self.max_samples_per_window,
            );
            state.confidence = state.confidence.min(sample.confidence);
            return Ok(Some(WindowUpdate {
                signal: state.to_signal(signal.host.clone()),
                dropped_sample_count,
            }));
        }

        if windows.len() >= self.max_windows.max(1)
            && let Some(oldest) = window_order.iter().next().cloned()
        {
            window_order.remove(&oldest);
            windows.remove(&oldest.key);
        }

        let state = WindowState::from_sample(
            key.profile_id.clone(),
            window,
            signal,
            sample,
            self.max_stack_ids_per_window,
            self.max_samples_per_window,
        );
        let dropped_sample_count = state.dropped_sample_count;
        let output = state.to_signal(signal.host.clone());
        window_order.insert(WindowOrderKey::new(&key));
        windows.insert(key, state);
        Ok(Some(WindowUpdate {
            signal: output,
            dropped_sample_count,
        }))
    }

    fn missing_attribution_warning(
        &self,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
    ) -> CoreResult<Option<SignalEnvelope>> {
        if !self.mark_warning_seen("missing_attribution", signal, sample)? {
            return Ok(None);
        }

        Ok(Some(SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            signal.host.clone(),
            ProfilingWarningObservation {
                warning_type: "missing_attribution".to_string(),
                message: "profile sample has no container or Kubernetes context".to_string(),
                timestamp_unix_nanos: sample.timestamp_unix_nanos,
                source_signal_kind: signal.kind().to_string(),
                source_module: signal.source.clone(),
                profiling_kind: sample.profiling_kind,
                correlation_kind: sample.correlation_kind,
                confidence: ProfilingConfidence::Low,
                process: sample.process.clone(),
                container: None,
                kubernetes: None,
                attributes: vec![ProfilingAttribute {
                    key: "profiling.warning.source".to_string(),
                    value: "profile_sample_observation".to_string(),
                }],
            },
        )))
    }

    fn dropped_samples_warning(
        &self,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
        dropped_sample_count: u64,
    ) -> CoreResult<Option<SignalEnvelope>> {
        if !self.mark_warning_seen("dropped_profile_samples", signal, sample)? {
            return Ok(None);
        }

        Ok(Some(SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            signal.host.clone(),
            ProfilingWarningObservation {
                warning_type: "dropped_profile_samples".to_string(),
                message: "profile samples were dropped by bounded aggregation".to_string(),
                timestamp_unix_nanos: sample.timestamp_unix_nanos,
                source_signal_kind: signal.kind().to_string(),
                source_module: signal.source.clone(),
                profiling_kind: sample.profiling_kind,
                correlation_kind: sample.correlation_kind,
                confidence: ProfilingConfidence::Medium,
                process: sample.process.clone(),
                container: sample.container.clone(),
                kubernetes: sample.kubernetes.clone(),
                attributes: vec![
                    ProfilingAttribute {
                        key: "profiling.warning.source".to_string(),
                        value: "profile_sample_observation".to_string(),
                    },
                    ProfilingAttribute {
                        key: "profile.dropped_sample_count".to_string(),
                        value: dropped_sample_count.to_string(),
                    },
                ],
            },
        )))
    }

    fn mark_warning_seen(
        &self,
        warning_type: &str,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
    ) -> CoreResult<bool> {
        let fingerprint = WarningFingerprint {
            warning_type: warning_type.to_string(),
            source_signal_kind: signal.kind().to_string(),
            source_module: signal.source.clone(),
            timestamp_unix_nanos: sample.timestamp_unix_nanos,
            stack_id: sample.stack_id.clone(),
        };
        let mut seen = self.seen_warnings()?;
        if seen.contains(&fingerprint) {
            return Ok(false);
        }
        if seen.len() >= self.max_warnings.max(1)
            && let Some(first) = seen.iter().next().cloned()
        {
            seen.remove(&first);
        }
        seen.insert(fingerprint);
        Ok(true)
    }

    fn mark_sample_seen(&self, fingerprint: SampleFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen_samples()?;
        if seen.contains(&fingerprint) {
            return Ok(false);
        }
        if seen.len() >= self.max_seen_samples.max(1)
            && let Some(first) = seen.iter().next().cloned()
        {
            seen.remove(&first);
        }
        seen.insert(fingerprint);
        Ok(true)
    }

    fn windows(&self) -> CoreResult<MutexGuard<'_, BTreeMap<WindowKey, WindowState>>> {
        self.windows.lock().map_err(module_error)
    }

    fn window_order(&self) -> CoreResult<MutexGuard<'_, BTreeSet<WindowOrderKey>>> {
        self.window_order.lock().map_err(module_error)
    }

    fn seen_samples(&self) -> CoreResult<MutexGuard<'_, BTreeSet<SampleFingerprint>>> {
        self.seen_samples.lock().map_err(module_error)
    }

    fn seen_warnings(&self) -> CoreResult<MutexGuard<'_, BTreeSet<WarningFingerprint>>> {
        self.seen_warnings.lock().map_err(module_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WindowKey {
    source: String,
    host: Option<String>,
    pid: Option<u32>,
    process_uid: Option<u32>,
    container_id: Option<String>,
    kubernetes_namespace: Option<String>,
    pod_uid: Option<String>,
    container_name: Option<String>,
    profiling_kind: &'static str,
    correlation_kind: &'static str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
    profile_id: String,
}

impl WindowKey {
    fn from_sample(
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
        window: &MetricAggregationWindow,
    ) -> Self {
        let canonical = format!(
            "source:{}|host:{}|pid:{}|uid:{}|container:{}|namespace:{}|pod:{}|k8s_container:{}|kind:{}|correlation:{}|start:{}|end:{}",
            signal.source,
            signal
                .host
                .as_deref()
                .map(optional_str)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .process
                .as_ref()
                .map(|process| process.pid)
                .map(optional_u32)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .process
                .as_ref()
                .and_then(|process| process.uid)
                .map(optional_u32)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .container
                .as_ref()
                .map(|container| container.container_id.as_str())
                .map(optional_str)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .kubernetes
                .as_ref()
                .map(|kubernetes| kubernetes.namespace.as_str())
                .map(optional_str)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .kubernetes
                .as_ref()
                .and_then(|kubernetes| kubernetes.pod_uid.as_deref())
                .map(optional_str)
                .unwrap_or_else(|| "none".to_string()),
            sample
                .kubernetes
                .as_ref()
                .and_then(|kubernetes| kubernetes.container_name.as_deref())
                .map(optional_str)
                .unwrap_or_else(|| "none".to_string()),
            profiling_kind_name(sample.profiling_kind),
            correlation_kind_name(sample.correlation_kind),
            window.start_unix_nanos,
            window.end_unix_nanos
        );
        Self {
            source: signal.source.clone(),
            host: signal.host.clone(),
            pid: sample.process.as_ref().map(|process| process.pid),
            process_uid: sample.process.as_ref().and_then(|process| process.uid),
            container_id: sample
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            kubernetes_namespace: sample
                .kubernetes
                .as_ref()
                .map(|kubernetes| kubernetes.namespace.clone()),
            pod_uid: sample
                .kubernetes
                .as_ref()
                .and_then(|kubernetes| kubernetes.pod_uid.clone()),
            container_name: sample
                .kubernetes
                .as_ref()
                .and_then(|kubernetes| kubernetes.container_name.clone()),
            profiling_kind: profiling_kind_name(sample.profiling_kind),
            correlation_kind: correlation_kind_name(sample.correlation_kind),
            start_unix_nanos: window.start_unix_nanos,
            end_unix_nanos: window.end_unix_nanos,
            profile_id: format!("profile:{:016x}", stable_hash64(canonical.as_bytes())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WindowOrderKey {
    end_unix_nanos: u64,
    start_unix_nanos: u64,
    key: WindowKey,
}

impl WindowOrderKey {
    fn new(key: &WindowKey) -> Self {
        Self {
            end_unix_nanos: key.end_unix_nanos,
            start_unix_nanos: key.start_unix_nanos,
            key: key.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct WindowUpdate {
    signal: SignalEnvelope,
    dropped_sample_count: u64,
}

#[derive(Debug, Clone)]
struct WindowState {
    profile_id: String,
    window: MetricAggregationWindow,
    observed_sample_count: u64,
    dropped_sample_count: u64,
    stack_ids: BTreeSet<String>,
    profiling_kind: e_navigator_signals::ProfilingKind,
    correlation_kind: e_navigator_signals::ProfilingCorrelationKind,
    confidence: ProfilingConfidence,
    sampling_period_nanos: Option<u64>,
    process: Option<e_navigator_signals::NetworkProcessIdentity>,
    container: Option<e_navigator_signals::ContainerContext>,
    kubernetes: Option<e_navigator_signals::KubernetesContext>,
    source: String,
    attributes: Vec<ProfilingAttribute>,
}

impl WindowState {
    fn from_sample(
        profile_id: String,
        window: MetricAggregationWindow,
        signal: &SignalEnvelope,
        sample: &ProfileSampleObservation,
        max_stack_ids_per_window: usize,
        max_samples_per_window: u64,
    ) -> Self {
        let mut stack_ids = BTreeSet::new();
        if max_stack_ids_per_window > 0 {
            stack_ids.insert(sample.stack_id.clone());
        }
        let observed_sample_count = sample.sample_count.min(max_samples_per_window);
        let dropped_sample_count = sample.sample_count.saturating_sub(observed_sample_count);
        Self {
            profile_id,
            window,
            observed_sample_count,
            dropped_sample_count,
            stack_ids,
            profiling_kind: sample.profiling_kind,
            correlation_kind: sample.correlation_kind,
            confidence: sample.confidence,
            sampling_period_nanos: sample.sampling_period_nanos,
            process: sample.process.clone(),
            container: sample.container.clone(),
            kubernetes: sample.kubernetes.clone(),
            source: signal.source.clone(),
            attributes: bounded_attributes(&sample.attributes),
        }
    }

    fn update_from_sample(
        &mut self,
        sample: &ProfileSampleObservation,
        max_stack_ids_per_window: usize,
        max_samples_per_window: u64,
    ) -> u64 {
        let remaining = max_samples_per_window.saturating_sub(self.observed_sample_count);
        let accepted = sample.sample_count.min(remaining);
        let dropped_sample_count = sample.sample_count.saturating_sub(accepted);
        self.observed_sample_count = self.observed_sample_count.saturating_add(accepted);
        self.dropped_sample_count = self
            .dropped_sample_count
            .saturating_add(dropped_sample_count);

        if self.stack_ids.contains(&sample.stack_id)
            || self.stack_ids.len() < max_stack_ids_per_window
        {
            self.stack_ids.insert(sample.stack_id.clone());
        }

        if self.process.is_none() {
            self.process = sample.process.clone();
        }
        if self.container.is_none() {
            self.container = sample.container.clone();
        }
        if self.kubernetes.is_none() {
            self.kubernetes = sample.kubernetes.clone();
        }
        if self.sampling_period_nanos.is_none() {
            self.sampling_period_nanos = sample.sampling_period_nanos;
        }
        dropped_sample_count
    }

    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::profiling_session_observation(
            "generator.profiling",
            host,
            ProfilingSessionObservation {
                window: self.window.clone(),
                profiling_kind: self.profiling_kind,
                correlation_kind: self.correlation_kind,
                confidence: self.confidence,
                profile_id: self.profile_id.clone(),
                observed_sample_count: self.observed_sample_count,
                dropped_sample_count: self.dropped_sample_count,
                distinct_stack_count: self.stack_ids.len() as u64,
                sampling_period_nanos: self.sampling_period_nanos,
                process: self.process.clone(),
                container: self.container.clone(),
                kubernetes: self.kubernetes.clone(),
                source: self.source.clone(),
                attributes: self.attributes.clone(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SampleFingerprint {
    source: String,
    host: Option<String>,
    timestamp_unix_nanos: u64,
    pid: Option<u32>,
    stack_id: String,
    profiling_kind: &'static str,
    correlation_kind: &'static str,
    thread_id: Option<u64>,
    sample_count: u64,
    sampling_period_nanos: Option<u64>,
    container_id: Option<String>,
    pod_uid: Option<String>,
}

impl SampleFingerprint {
    fn from_signal(signal: &SignalEnvelope, sample: &ProfileSampleObservation) -> Self {
        Self {
            source: signal.source.clone(),
            host: signal.host.clone(),
            timestamp_unix_nanos: sample.timestamp_unix_nanos,
            pid: sample.process.as_ref().map(|process| process.pid),
            stack_id: sample.stack_id.clone(),
            profiling_kind: profiling_kind_name(sample.profiling_kind),
            correlation_kind: correlation_kind_name(sample.correlation_kind),
            thread_id: sample.thread_id,
            sample_count: sample.sample_count,
            sampling_period_nanos: sample.sampling_period_nanos,
            container_id: sample
                .container
                .as_ref()
                .map(|container| container.container_id.clone()),
            pod_uid: sample
                .kubernetes
                .as_ref()
                .and_then(|kubernetes| kubernetes.pod_uid.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WarningFingerprint {
    warning_type: String,
    source_signal_kind: String,
    source_module: String,
    timestamp_unix_nanos: u64,
    stack_id: String,
}

fn window_for(timestamp_unix_nanos: u64, window_nanos: u64) -> MetricAggregationWindow {
    let start_unix_nanos = timestamp_unix_nanos / window_nanos * window_nanos;
    MetricAggregationWindow {
        start_unix_nanos,
        end_unix_nanos: start_unix_nanos.saturating_add(window_nanos),
    }
}

fn bounded_attributes(attributes: &[ProfilingAttribute]) -> Vec<ProfilingAttribute> {
    let mut attributes = attributes
        .iter()
        .filter(|attribute| {
            !is_sensitive_profiling_attribute_key(&attribute.key)
                && attribute.key.len() <= MAX_PROFILE_ATTRIBUTE_KEY_BYTES
                && attribute.value.len() <= MAX_PROFILE_ATTRIBUTE_VALUE_BYTES
        })
        .cloned()
        .collect::<Vec<_>>();
    attributes.sort();
    attributes.truncate(MAX_PROFILE_ATTRIBUTES);
    attributes
}

fn profiling_kind_name(kind: e_navigator_signals::ProfilingKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => "cpu",
        e_navigator_signals::ProfilingKind::Memory => "memory",
        e_navigator_signals::ProfilingKind::Lock => "lock",
        e_navigator_signals::ProfilingKind::Unknown => "unknown",
        _ => "unknown",
    }
}

fn correlation_kind_name(kind: e_navigator_signals::ProfilingCorrelationKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample => {
            "observed_profile_sample"
        }
        e_navigator_signals::ProfilingCorrelationKind::Synthetic => "synthetic",
        e_navigator_signals::ProfilingCorrelationKind::RuntimeInferred => "runtime_inferred",
        _ => "unknown",
    }
}

fn optional_str(value: &str) -> String {
    format!("some:{value}")
}

fn optional_u32(value: u32) -> String {
    format!("some:{value}")
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.profiling".to_string(),
        message: err.to_string(),
    }
}
