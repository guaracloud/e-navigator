#[cfg(any(target_os = "linux", test))]
use e_navigator_core::{CpuProfileBackpressure, CpuProfileSourceConfig};
#[cfg(any(target_os = "linux", test))]
use e_navigator_profiling::model::{NormalizationLimits, RawProfileFrame, RawProfileSample};
#[cfg(any(target_os = "linux", test))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingKind, SignalEnvelope,
};

#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_CPU_PROFILE_MAX_FRAMES: usize = 4;

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawCpuProfileEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub sample_count: u64,
    pub timestamp_unix_nanos: u64,
    pub command: [u8; 16],
    pub frame_count: u32,
    pub instruction_pointers: [u64; RAW_CPU_PROFILE_MAX_FRAMES],
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn raw_cpu_profile_to_signal(
    bytes: &[u8],
    host: Option<String>,
    config: &CpuProfileSourceConfig,
) -> Option<SignalEnvelope> {
    raw_cpu_profile_to_signal_with_clock(bytes, host, config, now_unix_nanos())
}

#[cfg(any(target_os = "linux", test))]
fn raw_cpu_profile_to_signal_with_clock(
    bytes: &[u8],
    host: Option<String>,
    config: &CpuProfileSourceConfig,
    observed_unix_nanos: u64,
) -> Option<SignalEnvelope> {
    if bytes.len() < core::mem::size_of::<RawCpuProfileEvent>() {
        return None;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawCpuProfileEvent>()) };
    if raw.sample_count == 0 {
        return None;
    }
    let frame_count = (raw.frame_count as usize).min(RAW_CPU_PROFILE_MAX_FRAMES);
    let stack_frames = raw
        .instruction_pointers
        .iter()
        .copied()
        .take(frame_count)
        .filter(|ip| *ip != 0)
        .map(|ip| RawProfileFrame {
            symbol: Some(format!("ip:{ip:016x}")),
            module: None,
            file: None,
            line: None,
        })
        .collect::<Vec<_>>();
    let timestamp_unix_nanos = if raw.timestamp_unix_nanos == 0 {
        observed_unix_nanos
    } else {
        raw.timestamp_unix_nanos
    };
    let sample = RawProfileSample {
        timestamp_unix_nanos,
        profiling_kind: ProfilingKind::Cpu,
        correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
        confidence: ProfilingConfidence::Medium,
        sample_count: raw.sample_count,
        sampling_period_nanos: Some(sample_period_nanos(config.sample_frequency_hz)),
        stack_frames,
        process: Some(NetworkProcessIdentity {
            pid: raw.pid,
            ppid: None,
            uid: Some(raw.uid),
            command: bytes_to_string(&raw.command),
            executable: None,
        }),
        container: None,
        kubernetes: None,
        thread_id: (raw.tid != 0).then_some(u64::from(raw.tid)),
        thread_name: None,
        attributes: vec![
            ProfilingAttribute {
                key: "profiling.sample.frequency_hz".to_string(),
                value: config.sample_frequency_hz.to_string(),
            },
            ProfilingAttribute {
                key: "profiling.source".to_string(),
                value: "aya_perf_event".to_string(),
            },
        ],
    };
    let limits = NormalizationLimits {
        max_frames_per_stack: config.max_frames_per_sample,
        max_symbol_bytes: config.max_symbol_bytes,
        max_module_bytes: config.max_module_bytes,
        max_file_bytes: config.max_file_bytes,
        max_samples_per_window: config.max_samples_per_batch as u64,
        ..NormalizationLimits::default()
    };
    sample.normalize(&limits).ok().map(|sample| {
        SignalEnvelope::profile_sample_observation("source.aya_cpu_profile", host, sample)
    })
}

#[cfg(test)]
fn decode_cpu_profile_batch(
    events: &[&[u8]],
    host: Option<String>,
    config: &CpuProfileSourceConfig,
    observed_unix_nanos: u64,
) -> Vec<SignalEnvelope> {
    events
        .iter()
        .take(config.max_samples_per_batch)
        .filter_map(|event| {
            raw_cpu_profile_to_signal_with_clock(event, host.clone(), config, observed_unix_nanos)
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn send_with_backpressure(
    tx: &tokio::sync::mpsc::Sender<SignalEnvelope>,
    signal: SignalEnvelope,
    backpressure: CpuProfileBackpressure,
) -> bool {
    match backpressure {
        CpuProfileBackpressure::DropNewest => tx.try_send(signal).is_ok(),
        CpuProfileBackpressure::Wait => tx.blocking_send(signal).is_ok(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn sample_period_nanos(sample_frequency_hz: u32) -> u64 {
    1_000_000_000_u64 / u64::from(sample_frequency_hz.max(1))
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(any(target_os = "linux", test))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{raw_cpu_profile_to_signal, send_with_backpressure};
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::perf::{PerfEvent as PerfBufferEvent, PerfEventArray},
        programs::perf_event::{
            PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
        },
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, CpuProfileBackpressure, CpuProfileSourceConfig, ModuleKind,
        ModuleMetadata, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, warn};

    #[derive(Debug, Clone)]
    pub struct AyaCpuProfileSource {
        host: Option<String>,
        config: CpuProfileSourceConfig,
    }

    impl AyaCpuProfileSource {
        pub fn new(host: Option<String>, config: CpuProfileSourceConfig) -> Self {
            Self { host, config }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaCpuProfileSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_cpu_profile", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            let program: &mut PerfEvent = ebpf
                .program_mut("sample_cpu_profile")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_cpu_profile".to_string(),
                    message: "missing sample_cpu_profile program".to_string(),
                })?
                .try_into()
                .map_err(module_error)?;
            program.load().map_err(module_error)?;
            let perf_type = PerfEventConfig::Software(SoftwareEvent::CpuClock);
            let sample_policy = SamplePolicy::Frequency(self.config.sample_frequency_hz.into());
            let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
            for cpu in cpus.iter().copied().take(self.config.max_active_targets) {
                program
                    .attach(
                        perf_type,
                        PerfEventScope::AllProcessesOneCpu { cpu },
                        sample_policy,
                        true,
                    )
                    .map_err(module_error)?;
            }

            let mut perf_array =
                PerfEventArray::try_from(ebpf.take_map("CPU_PROFILE_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_cpu_profile".to_string(),
                        message: "missing CPU_PROFILE_EVENTS map".to_string(),
                    }
                })?)
                .map_err(module_error)?;

            for cpu_id in cpus {
                let mut buffer = perf_array.open(cpu_id, None).map_err(module_error)?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let config = self.config.clone();
                let backpressure = config.backpressure;
                let reader_shutdown = shutdown.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        let mut accepted = 0_usize;
                        buffer.for_each(|event| {
                            if closed || accepted >= config.max_samples_per_batch {
                                return;
                            }

                            match event {
                                PerfBufferEvent::Sample { head, tail } => {
                                    if !tail.is_empty() {
                                        warn!("dropped wrapped cpu profile perf event sample");
                                        return;
                                    }
                                    let Some(signal) =
                                        raw_cpu_profile_to_signal(head, host.clone(), &config)
                                    else {
                                        return;
                                    };
                                    accepted += 1;
                                    if !send_with_backpressure(&cpu_tx, signal, backpressure) {
                                        if matches!(backpressure, CpuProfileBackpressure::Wait) {
                                            closed = true;
                                        } else {
                                            warn!("dropped cpu profile sample due to backpressure");
                                        }
                                    }
                                }
                                PerfBufferEvent::Lost { count } => {
                                    warn!(count, "lost cpu profile perf events");
                                }
                            }
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }));
            }

            debug!("aya cpu profile source attached");
            tokio::signal::ctrl_c().await.map_err(module_error)?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    #[derive(Clone)]
    struct ReaderShutdown {
        stopped: Arc<AtomicBool>,
    }

    impl ReaderShutdown {
        fn new() -> Self {
            Self {
                stopped: Arc::new(AtomicBool::new(false)),
            }
        }

        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }

        fn is_stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }
    }

    impl Drop for ReaderShutdown {
        fn drop(&mut self) {
            self.stop();
        }
    }

    async fn join_reader_handles(handles: Vec<JoinHandle<()>>) -> CoreResult<()> {
        for handle in handles {
            handle.await.map_err(module_error)?;
        }

        Ok(())
    }

    fn bump_memlock_rlimit() {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
        if ret != 0 {
            debug!("failed to raise RLIMIT_MEMLOCK");
        }
    }

    fn module_error(err: impl ToString) -> CoreError {
        CoreError::ModuleFailed {
            module: "source.aya_cpu_profile".to_string(),
            message: err.to_string(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{
        CoreError, CoreResult, CpuProfileSourceConfig, ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Clone)]
    pub struct AyaCpuProfileSource {
        host: Option<String>,
        _config: CpuProfileSourceConfig,
    }

    impl AyaCpuProfileSource {
        pub fn new(host: Option<String>, config: CpuProfileSourceConfig) -> Self {
            Self {
                host,
                _config: config,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaCpuProfileSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_cpu_profile", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_cpu_profile".to_string(),
                message: format!(
                    "Aya CPU profile source requires Linux, eBPF, and perf-event support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaCpuProfileSource;

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::{CpuProfileSourceConfig, Signal};
    use e_navigator_signals::{
        ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind, SignalPayload,
    };

    #[test]
    fn decodes_valid_observed_cpu_sample() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 3,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 2,
            instruction_pointers: [0xabc, 0xdef, 0, 0],
        };

        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
        )
        .expect("raw profile event decodes");

        assert_eq!(signal.source, "source.aya_cpu_profile");
        assert_eq!(signal.kind(), "profile_sample_observation");
        let SignalPayload::ProfileSampleObservation(sample) = signal.payload else {
            panic!("expected profile sample");
        };
        assert_eq!(sample.timestamp_unix_nanos, 1_000);
        assert_eq!(sample.profiling_kind, ProfilingKind::Cpu);
        assert_eq!(
            sample.correlation_kind,
            ProfilingCorrelationKind::ObservedProfileSample
        );
        assert_eq!(sample.confidence, ProfilingConfidence::Medium);
        assert_eq!(sample.sample_count, 3);
        assert_eq!(sample.sampling_period_nanos, Some(10_000_000));
        assert_eq!(sample.process.expect("process").pid, 42);
        assert_eq!(sample.thread_id, Some(43));
        assert_eq!(sample.stack_frames.len(), 2);
        assert_eq!(
            sample.stack_frames[0].symbol.as_deref(),
            Some("ip:0000000000000abc")
        );
        assert!(
            sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.source"
                    && attribute.value == "aya_perf_event")
        );
    }

    #[test]
    fn missing_stack_remains_empty_without_inventing_frames() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 1,
            timestamp_unix_nanos: 0,
            command: fixed_command("api"),
            frame_count: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };

        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
        )
        .expect("raw profile event decodes");
        let SignalPayload::ProfileSampleObservation(sample) = signal.payload else {
            panic!("expected profile sample");
        };

        assert_eq!(sample.timestamp_unix_nanos, 10_000);
        assert!(sample.stack_frames.is_empty());
        assert!(sample.stack_id.starts_with("stack:"));
    }

    #[test]
    fn oversized_stack_is_truncated_to_configured_frame_limit() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: RAW_CPU_PROFILE_MAX_FRAMES as u32,
            instruction_pointers: [0x1, 0x2, 0x3, 0x4],
        };
        let config = CpuProfileSourceConfig {
            max_frames_per_sample: 2,
            ..source_config()
        };

        let signal =
            raw_cpu_profile_to_signal_with_clock(raw_as_bytes(&raw), None, &config, 10_000)
                .expect("raw profile event decodes");
        let SignalPayload::ProfileSampleObservation(sample) = signal.payload else {
            panic!("expected profile sample");
        };

        assert_eq!(sample.stack_frames.len(), 2);
        assert!(
            sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.truncated"
                    && attribute.value == "true")
        );
    }

    #[test]
    fn malformed_event_is_rejected() {
        assert!(
            raw_cpu_profile_to_signal_with_clock(&[1, 2, 3], None, &source_config(), 10_000)
                .is_none()
        );
    }

    #[test]
    fn deterministic_output_for_same_observed_sample() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 2,
            instruction_pointers: [0xabc, 0xdef, 0, 0],
        };

        let first = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
        )
        .expect("first sample decodes");
        let second = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
        )
        .expect("second sample decodes");

        assert_eq!(first, second);
    }

    #[test]
    fn max_samples_per_batch_bounds_decode_batch() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };
        let config = CpuProfileSourceConfig {
            max_samples_per_batch: 2,
            ..source_config()
        };
        let decoded = decode_cpu_profile_batch(
            &[raw_as_bytes(&raw), raw_as_bytes(&raw), raw_as_bytes(&raw)],
            Some("node-a".to_string()),
            &config,
            10_000,
        );

        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn drop_newest_backpressure_drops_when_pipeline_queue_is_full() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };
        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
        )
        .expect("raw profile event decodes");
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        assert!(send_with_backpressure(
            &tx,
            signal.clone(),
            e_navigator_core::CpuProfileBackpressure::DropNewest
        ));
        assert!(!send_with_backpressure(
            &tx,
            signal,
            e_navigator_core::CpuProfileBackpressure::DropNewest
        ));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    fn source_config() -> CpuProfileSourceConfig {
        CpuProfileSourceConfig {
            enabled: true,
            sample_frequency_hz: 100,
            ..CpuProfileSourceConfig::default()
        }
    }

    fn fixed_command(value: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = value.as_bytes();
        let len = bytes.len().min(command.len().saturating_sub(1));
        command[..len].copy_from_slice(&bytes[..len]);
        command
    }

    fn raw_as_bytes(raw: &RawCpuProfileEvent) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(raw).cast::<u8>(),
                core::mem::size_of::<RawCpuProfileEvent>(),
            )
        }
    }
}
