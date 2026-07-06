#[cfg(any(target_os = "linux", test))]
use e_navigator_core::CpuProfileBackpressure;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_core::CpuProfileSourceConfig;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_profiling::model::{NormalizationLimits, RawProfileFrame, RawProfileSample};
#[cfg(any(target_os = "linux", test))]
use e_navigator_profiling::symbolize::{ElfSymbolTable, ProcessModuleMap};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingKind, SignalEnvelope,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_CPU_PROFILE_MAX_FRAMES: usize = 128;

/// The in-kernel capture buffer was filled to the configured frame limit,
/// so the sampled stack may continue past the deepest captured frame.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_CPU_PROFILE_FLAG_TRUNCATED: u32 = 1;

/// The kernel could not translate the pid into the symbolization pid
/// namespace (the sampled process's active namespace differs), so the
/// event carries the root-namespace pid and userspace must verify the pid
/// against procfs before attributing frames to it.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED: u32 = 2;

/// The stack was produced by the in-kernel DWARF/CFI unwinder rather
/// than frame-pointer walking; bits 8..16 of `flags` carry the stop
/// reason.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_CPU_PROFILE_FLAG_DWARF: u32 = 4;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_UNWIND_STOP_SHIFT: u32 = 8;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_UNWIND_STOP_MASK: u32 = 0xff;

/// Human-readable DWARF stop reason for the sample attribute; reasons
/// other than `complete` and `depth` mean the tail of the stack was
/// lost and are additionally counted into a periodic warning.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn unwind_stop_reason(flags: u32) -> Option<(&'static str, bool)> {
    if flags & RAW_CPU_PROFILE_FLAG_DWARF == 0 {
        return None;
    }
    let (name, incomplete) = match (flags >> RAW_UNWIND_STOP_SHIFT) & RAW_UNWIND_STOP_MASK {
        1 => ("complete", false),
        2 => ("no_mapping", true),
        3 => ("no_rule", true),
        4 => ("read_fault", true),
        5 => ("bad_frame", true),
        6 => ("depth", false),
        7 => ("tail_limit", true),
        _ => ("unknown", true),
    };
    Some((name, incomplete))
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawCpuProfileEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub sample_count: u64,
    pub timestamp_unix_nanos: u64,
    pub command: [u8; 16],
    pub frame_count: u32,
    pub flags: u32,
    pub instruction_pointers: [u64; RAW_CPU_PROFILE_MAX_FRAMES],
}

/// A decoded CPU profile sample plus capture-side accounting that the
/// signal envelope alone does not expose to the reader loop.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct DecodedCpuProfileSample {
    pub signal: SignalEnvelope,
    /// True when the kernel filled the configured frame budget and the
    /// stack may be deeper than what was captured.
    pub capture_truncated: bool,
    /// True when the sample's untranslated pid failed procfs identity
    /// verification and frames were left as raw addresses.
    pub pid_unverified: bool,
    /// True when a DWARF unwind stopped before the outermost frame for
    /// a reason other than the configured depth budget.
    pub dwarf_incomplete: bool,
}

/// Resolves a captured instruction pointer for a pid into a stack frame.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) trait FrameResolver {
    fn resolve(&mut self, pid: u32, ip: u64) -> RawProfileFrame;

    /// Confirms that `pid`/`tid` in the resolver's procfs view refer to
    /// the sampled thread (matching thread comm). Resolvers that never
    /// consult procfs have nothing to mis-attribute and accept every pid.
    fn verify_thread(&mut self, _pid: u32, _tid: u32, _command: &str) -> bool {
        true
    }
}

/// Fallback resolver that carries the raw instruction pointer as a hex
/// symbol without module attribution.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Default)]
pub(crate) struct RawAddressResolver;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl FrameResolver for RawAddressResolver {
    fn resolve(&mut self, _pid: u32, ip: u64) -> RawProfileFrame {
        RawProfileFrame {
            symbol: Some(format!("ip:{ip:016x}")),
            module: None,
            file: None,
            line: None,
            module_offset: None,
        }
    }
}

/// procfs-backed symbolizer: resolves instruction pointers to module and
/// module-relative offset from `/proc/<pid>/maps`, with best-effort local
/// ELF symbol-table name resolution. Per-pid maps and per-module symbol
/// tables are cached with bounded capacity.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub(crate) struct ProcfsSymbolizer {
    procfs_root: std::path::PathBuf,
    resolve_symbols: bool,
    max_cached_pids: usize,
    max_cached_modules: usize,
    maps: std::collections::BTreeMap<u32, ProcessModuleMap>,
    symbols: std::collections::BTreeMap<String, Option<ElfSymbolTable>>,
    /// Cached thread comms for untranslated pids, keyed by (pid, tid);
    /// `None` records an unreadable thread. Bounded like the other caches;
    /// like them it can go stale on pid reuse, which at worst withholds or
    /// restores symbolization for later samples of a reused pid.
    thread_comms: std::collections::BTreeMap<(u32, u32), Option<String>>,
}

#[cfg(any(target_os = "linux", test))]
impl ProcfsSymbolizer {
    const MAX_MODULE_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

    pub(crate) fn new(procfs_root: std::path::PathBuf, resolve_symbols: bool) -> Self {
        Self {
            procfs_root,
            resolve_symbols,
            max_cached_pids: 1024,
            max_cached_modules: 512,
            maps: std::collections::BTreeMap::new(),
            symbols: std::collections::BTreeMap::new(),
            thread_comms: std::collections::BTreeMap::new(),
        }
    }

    fn process_map(&mut self, pid: u32) -> &ProcessModuleMap {
        if !self.maps.contains_key(&pid) {
            if self.maps.len() >= self.max_cached_pids
                && let Some(&oldest) = self.maps.keys().next()
            {
                self.maps.remove(&oldest);
            }
            let path = self.procfs_root.join(pid.to_string()).join("maps");
            let parsed = std::fs::read_to_string(&path)
                .map(|contents| ProcessModuleMap::parse_maps(&contents))
                .unwrap_or_default();
            self.maps.insert(pid, parsed);
        }
        self.maps.get(&pid).expect("map inserted above")
    }

    fn symbol_name(&mut self, module: &str, offset: u64) -> Option<String> {
        if !self.resolve_symbols {
            return None;
        }
        if !self.symbols.contains_key(module) {
            if self.symbols.len() >= self.max_cached_modules
                && let Some(oldest) = self.symbols.keys().next().cloned()
            {
                self.symbols.remove(&oldest);
            }
            let table = self.load_symbol_table(module);
            self.symbols.insert(module.to_string(), table);
        }
        self.symbols
            .get(module)
            .and_then(|table| table.as_ref())
            .and_then(|table| table.resolve(offset))
            .map(ToString::to_string)
    }

    fn thread_comm(&mut self, pid: u32, tid: u32) -> Option<&str> {
        if !self.thread_comms.contains_key(&(pid, tid)) {
            if self.thread_comms.len() >= self.max_cached_pids
                && let Some(&oldest) = self.thread_comms.keys().next()
            {
                self.thread_comms.remove(&oldest);
            }
            let comm_path = self
                .procfs_root
                .join(pid.to_string())
                .join("task")
                .join(tid.to_string())
                .join("comm");
            let comm = std::fs::read_to_string(&comm_path)
                .ok()
                .map(|comm| comm.trim_end_matches('\n').to_string());
            self.thread_comms.insert((pid, tid), comm);
        }
        self.thread_comms
            .get(&(pid, tid))
            .and_then(|comm| comm.as_deref())
    }

    fn load_symbol_table(&self, module: &str) -> Option<ElfSymbolTable> {
        let metadata = std::fs::metadata(module).ok()?;
        if metadata.len() > Self::MAX_MODULE_IMAGE_BYTES {
            return None;
        }
        let image = std::fs::read(module).ok()?;
        let table = ElfSymbolTable::parse(&image);
        (!table.is_empty()).then_some(table)
    }
}

#[cfg(any(target_os = "linux", test))]
impl FrameResolver for ProcfsSymbolizer {
    fn resolve(&mut self, pid: u32, ip: u64) -> RawProfileFrame {
        let Some(location) = self.process_map(pid).resolve(ip) else {
            return RawAddressResolver.resolve(pid, ip);
        };
        let symbol = self
            .symbol_name(&location.module, location.module_offset)
            .unwrap_or_else(|| format!("{}+{:#x}", location.module, location.module_offset));
        RawProfileFrame {
            symbol: Some(symbol),
            module: Some(location.module),
            file: None,
            line: None,
            module_offset: Some(location.module_offset),
        }
    }

    fn verify_thread(&mut self, pid: u32, tid: u32, command: &str) -> bool {
        self.thread_comm(pid, tid) == Some(command)
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn raw_cpu_profile_to_signal(
    bytes: &[u8],
    host: Option<String>,
    config: &CpuProfileSourceConfig,
    resolver: &mut impl FrameResolver,
) -> Option<DecodedCpuProfileSample> {
    raw_cpu_profile_to_signal_with_clock(bytes, host, config, now_unix_nanos(), resolver)
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_cpu_profile_to_signal_with_clock(
    bytes: &[u8],
    host: Option<String>,
    config: &CpuProfileSourceConfig,
    observed_unix_nanos: u64,
    resolver: &mut impl FrameResolver,
) -> Option<DecodedCpuProfileSample> {
    if bytes.len() < core::mem::size_of::<RawCpuProfileEvent>() {
        return None;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawCpuProfileEvent>()) };
    if raw.sample_count == 0 {
        return None;
    }
    let capture_truncated = raw.flags & RAW_CPU_PROFILE_FLAG_TRUNCATED != 0;
    let command = bytes_to_string(&raw.command);
    // An untranslated pid may belong to an unrelated same-numbered process
    // in the symbolization procfs view; only symbolize it after the
    // resolver confirms the thread identity there.
    let pid_unverified = raw.flags & RAW_CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED != 0
        && !resolver.verify_thread(raw.pid, raw.tid, &command);
    let frame_count = (raw.frame_count as usize).min(RAW_CPU_PROFILE_MAX_FRAMES);
    let stack_frames = raw
        .instruction_pointers
        .iter()
        .copied()
        .take(frame_count)
        .filter(|ip| *ip != 0)
        .enumerate()
        .map(|(index, ip)| {
            // Frames past the sampled leaf hold return addresses, which
            // point one instruction past the call; resolve the call site
            // so functions ending flush against a neighbor do not get
            // the neighbor's name.
            let resolve_ip = if index == 0 { ip } else { ip.wrapping_sub(1) };
            if pid_unverified {
                RawAddressResolver.resolve(raw.pid, resolve_ip)
            } else {
                resolver.resolve(raw.pid, resolve_ip)
            }
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
            command: command.clone(),
            executable: None,
            cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
        }),
        container: None,
        kubernetes: None,
        thread_id: (raw.tid != 0).then_some(u64::from(raw.tid)),
        thread_name: None,
        attributes: {
            let mut attributes = vec![
                ProfilingAttribute {
                    key: "profiling.sample.frequency_hz".to_string(),
                    value: config.sample_frequency_hz.to_string(),
                },
                ProfilingAttribute {
                    key: "profiling.source".to_string(),
                    value: "aya_perf_event".to_string(),
                },
            ];
            if capture_truncated {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.capture_truncated".to_string(),
                    value: "true".to_string(),
                });
            }
            if pid_unverified {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.pid_ns".to_string(),
                    value: "unverified".to_string(),
                });
            }
            attributes.push(ProfilingAttribute {
                key: "profiling.stack.unwind".to_string(),
                value: if raw.flags & RAW_CPU_PROFILE_FLAG_DWARF != 0 {
                    "dwarf".to_string()
                } else {
                    "fp".to_string()
                },
            });
            if let Some((reason, _)) = unwind_stop_reason(raw.flags) {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.dwarf_stop".to_string(),
                    value: reason.to_string(),
                });
            }
            attributes
        },
    };
    let limits = NormalizationLimits {
        max_frames_per_stack: config.max_frames_per_sample,
        max_symbol_bytes: config.max_symbol_bytes,
        max_module_bytes: config.max_module_bytes,
        max_file_bytes: config.max_file_bytes,
        max_samples_per_window: config.max_samples_per_batch as u64,
        ..NormalizationLimits::default()
    };
    sample
        .normalize(&limits)
        .ok()
        .map(|sample| DecodedCpuProfileSample {
            signal: SignalEnvelope::profile_sample_observation(
                "source.aya_cpu_profile",
                host,
                sample,
            ),
            capture_truncated,
            pid_unverified,
            dwarf_incomplete: unwind_stop_reason(raw.flags)
                .is_some_and(|(_, incomplete)| incomplete),
        })
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_raw_cpu_profile_event(bytes: &[u8]) -> bool {
    const MAX_FUZZ_BYTES: usize = 2048;

    let bytes = &bytes[..bytes.len().min(MAX_FUZZ_BYTES)];
    let config = CpuProfileSourceConfig {
        enabled: true,
        max_active_targets: 4,
        max_frames_per_sample: RAW_CPU_PROFILE_MAX_FRAMES,
        max_samples_per_batch: 4,
        max_symbol_bytes: 64,
        max_module_bytes: 64,
        max_file_bytes: 64,
        ..CpuProfileSourceConfig::default()
    };

    raw_cpu_profile_to_signal_with_clock(bytes, None, &config, 1_000, &mut RawAddressResolver)
        .is_some()
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
            raw_cpu_profile_to_signal_with_clock(
                event,
                host.clone(),
                config,
                observed_unix_nanos,
                &mut RawAddressResolver,
            )
            .map(|decoded| decoded.signal)
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
        CpuProfileBackpressure::StopSource => tx.try_send(signal).is_ok(),
    }
}

/// Sizes each per-CPU perf ring to hold roughly 250ms of samples (2.5x the
/// 100ms reader poll interval) including perf record framing, rounded up to
/// a power of two as the perf mmap API requires, bounded to keep per-CPU
/// memory predictable. Overflow past this budget is dropped by the kernel
/// and accounted as lost perf events.
#[cfg(any(target_os = "linux", test))]
fn cpu_profile_perf_pages(sample_frequency_hz: u32, event_bytes: usize) -> usize {
    const PERF_RECORD_OVERHEAD_BYTES: usize = 64;
    const PAGE_BYTES: usize = 4096;
    let samples_per_window = (sample_frequency_hz.max(1) as usize).div_ceil(4);
    let bytes = samples_per_window * (event_bytes + PERF_RECORD_OVERHEAD_BYTES);
    bytes.div_ceil(PAGE_BYTES).next_power_of_two().clamp(4, 64)
}

#[cfg(any(target_os = "linux", test))]
fn bounded_cpu_targets(cpus: &[u32], max_active_targets: usize) -> Vec<u32> {
    cpus.iter()
        .copied()
        .take(max_active_targets)
        .collect::<Vec<_>>()
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn sample_period_nanos(sample_frequency_hz: u32) -> u64 {
    1_000_000_000_u64 / u64::from(sample_frequency_hz.max(1))
}

/// Source-layer CPU profile sample drop accounting: kernel perf-buffer
/// losses and userspace backpressure drops, neither of which is visible to
/// the aggregation-layer dropped-sample count.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
pub(crate) struct CpuProfileDropCounters {
    lost_perf_events: std::sync::atomic::AtomicU64,
    backpressure_dropped: std::sync::atomic::AtomicU64,
    truncated_stacks: std::sync::atomic::AtomicU64,
    pid_unverified_samples: std::sync::atomic::AtomicU64,
    dwarf_incomplete_samples: std::sync::atomic::AtomicU64,
}

#[cfg(any(target_os = "linux", test))]
impl CpuProfileDropCounters {
    pub(crate) fn record_lost_perf_events(&self, count: u64) {
        self.lost_perf_events
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn record_backpressure_drop(&self) {
        self.backpressure_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn record_truncated_stack(&self) {
        self.truncated_stacks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn record_pid_unverified_sample(&self) {
        self.pid_unverified_samples
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn record_dwarf_incomplete_sample(&self) {
        self.dwarf_incomplete_samples
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Atomically reads and resets all counters, returning
    /// (lost_perf_events, backpressure_dropped, truncated_stacks,
    /// pid_unverified_samples, dwarf_incomplete_samples) since the last
    /// drain.
    pub(crate) fn drain(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.lost_perf_events
                .swap(0, std::sync::atomic::Ordering::Relaxed),
            self.backpressure_dropped
                .swap(0, std::sync::atomic::Ordering::Relaxed),
            self.truncated_stacks
                .swap(0, std::sync::atomic::Ordering::Relaxed),
            self.pid_unverified_samples
                .swap(0, std::sync::atomic::Ordering::Relaxed),
            self.dwarf_incomplete_samples
                .swap(0, std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Builds a bounded profiling warning reporting source-layer sample drops.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn source_drop_warning(
    host: Option<String>,
    lost_perf_events: u64,
    backpressure_dropped: u64,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    use e_navigator_signals::{
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind,
        ProfilingWarningObservation,
    };
    SignalEnvelope::profiling_warning_observation(
        "source.aya_cpu_profile",
        host,
        ProfilingWarningObservation {
            warning_type: "source_dropped_samples".to_string(),
            message: "cpu profile samples dropped before aggregation".to_string(),
            timestamp_unix_nanos,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            attributes: vec![
                ProfilingAttribute {
                    key: "profiling.dropped.lost_perf_events".to_string(),
                    value: lost_perf_events.to_string(),
                },
                ProfilingAttribute {
                    key: "profiling.dropped.backpressure".to_string(),
                    value: backpressure_dropped.to_string(),
                },
            ],
        },
    )
}

/// Builds a bounded profiling warning reporting samples whose processes
/// live outside the symbolization pid namespace and therefore carry raw
/// addresses instead of symbolized frames.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn pid_unverified_warning(
    host: Option<String>,
    foreign_samples: u64,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    use e_navigator_signals::{
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind,
        ProfilingWarningObservation,
    };
    SignalEnvelope::profiling_warning_observation(
        "source.aya_cpu_profile",
        host,
        ProfilingWarningObservation {
            warning_type: "pid_unverified_samples".to_string(),
            message: "cpu samples from processes outside the symbolization pid namespace \
                      carry raw addresses"
                .to_string(),
            timestamp_unix_nanos,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            attributes: vec![ProfilingAttribute {
                key: "profiling.stack.pid_unverified_samples".to_string(),
                value: foreign_samples.to_string(),
            }],
        },
    )
}

/// Builds a bounded profiling warning reporting DWARF unwinds that
/// stopped before the outermost frame (missing rules, unreadable stack
/// memory, or implausible frames), losing the tail of those stacks.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn dwarf_incomplete_warning(
    host: Option<String>,
    incomplete_samples: u64,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    use e_navigator_signals::{
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind,
        ProfilingWarningObservation,
    };
    SignalEnvelope::profiling_warning_observation(
        "source.aya_cpu_profile",
        host,
        ProfilingWarningObservation {
            warning_type: "dwarf_unwind_incomplete".to_string(),
            message: "dwarf unwinds stopped before a provably outermost frame; stack tails may be missing"
                .to_string(),
            timestamp_unix_nanos,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            attributes: vec![ProfilingAttribute {
                key: "profiling.stack.dwarf_incomplete_samples".to_string(),
                value: incomplete_samples.to_string(),
            }],
        },
    )
}

/// Builds a bounded profiling warning reporting that captured stacks hit
/// the configured in-kernel frame limit and may be deeper than captured.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn stack_truncation_warning(
    host: Option<String>,
    truncated_stacks: u64,
    frame_limit: usize,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    use e_navigator_signals::{
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind,
        ProfilingWarningObservation,
    };
    SignalEnvelope::profiling_warning_observation(
        "source.aya_cpu_profile",
        host,
        ProfilingWarningObservation {
            warning_type: "stack_depth_capped".to_string(),
            message: "captured cpu stacks reached the configured frame limit and may be deeper"
                .to_string(),
            timestamp_unix_nanos,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            attributes: vec![
                ProfilingAttribute {
                    key: "profiling.stack.truncated_samples".to_string(),
                    value: truncated_stacks.to_string(),
                },
                ProfilingAttribute {
                    key: "profiling.stack.frame_limit".to_string(),
                    value: frame_limit.to_string(),
                },
            ],
        },
    )
}

/// Builds a bounded profiling warning reporting that CPU sampling coverage
/// is capped below the online CPU count.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn coverage_gap_warning(
    host: Option<String>,
    online_cpus: usize,
    active_cpus: usize,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    use e_navigator_signals::{
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind,
        ProfilingWarningObservation,
    };
    SignalEnvelope::profiling_warning_observation(
        "source.aya_cpu_profile",
        host,
        ProfilingWarningObservation {
            warning_type: "coverage_capped".to_string(),
            message: "cpu profile sampling covers fewer cpus than are online".to_string(),
            timestamp_unix_nanos,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            attributes: vec![
                ProfilingAttribute {
                    key: "profiling.coverage.online_cpus".to_string(),
                    value: online_cpus.to_string(),
                },
                ProfilingAttribute {
                    key: "profiling.coverage.active_cpus".to_string(),
                    value: active_cpus.to_string(),
                },
            ],
        },
    )
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{
        bounded_cpu_targets, cpu_profile_perf_pages, raw_cpu_profile_to_signal,
        send_with_backpressure,
    };
    use crate::cpu_unwind::{
        UnwindMapSink, UnwindModuleSpan, UnwindProcMappings, UnwindRowAbi, UnwindTableManager,
    };
    use crate::perf_sample::perf_sample_bytes;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, MapData, ProgramArray as AyaProgramArray,
            perf::{PerfEvent as PerfBufferEvent, PerfEventArray},
        },
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
        procfs_root: std::path::PathBuf,
        config: CpuProfileSourceConfig,
    }

    impl AyaCpuProfileSource {
        pub fn new(
            host: Option<String>,
            procfs_root: std::path::PathBuf,
            config: CpuProfileSourceConfig,
        ) -> Self {
            Self {
                host,
                procfs_root,
                config,
            }
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
            let drop_counters = std::sync::Arc::new(super::CpuProfileDropCounters::default());
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;
            populate_frame_limit(&mut ebpf, &self.config)?;
            populate_pid_namespace(&mut ebpf, &self.procfs_root);
            if self.config.dwarf_unwind {
                setup_dwarf_unwinder(&mut ebpf)?;
            }

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
            let active_cpus = bounded_cpu_targets(&cpus, self.config.max_active_targets);
            if active_cpus.len() < cpus.len() {
                let uncovered = cpus.len() - active_cpus.len();
                warn!(
                    online_cpus = cpus.len(),
                    active_cpus = active_cpus.len(),
                    uncovered,
                    "cpu profile coverage is capped by max_active_targets; some cpus are unsampled"
                );
                let warning = super::coverage_gap_warning(
                    self.host.clone(),
                    cpus.len(),
                    active_cpus.len(),
                    super::now_unix_nanos(),
                );
                let _ = tx.send(warning).await;
            }
            for cpu in active_cpus.iter().copied() {
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

            let perf_pages = cpu_profile_perf_pages(
                self.config.sample_frequency_hz,
                core::mem::size_of::<super::RawCpuProfileEvent>(),
            );
            for cpu_id in active_cpus {
                let mut buffer = perf_array
                    .open(cpu_id, Some(perf_pages))
                    .map_err(module_error)?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let config = self.config.clone();
                let backpressure = config.backpressure;
                let reader_shutdown = shutdown.clone();
                let drop_counters = drop_counters.clone();
                let mut resolver = super::ProcfsSymbolizer::new(
                    self.procfs_root.clone(),
                    config.resolve_symbol_names,
                );
                let symbolize = config.symbolize;

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    while !reader_shutdown.is_stopped() {
                        let mut accepted = 0_usize;
                        let mut exit = ReaderExit::Stopped;
                        buffer.for_each(|event| {
                            if matches!(exit, ReaderExit::BackpressureStop)
                                || accepted >= config.max_samples_per_batch
                            {
                                return;
                            }

                            match event {
                                PerfBufferEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail);
                                    let decoded = if symbolize {
                                        raw_cpu_profile_to_signal(
                                            bytes.as_ref(),
                                            host.clone(),
                                            &config,
                                            &mut resolver,
                                        )
                                    } else {
                                        raw_cpu_profile_to_signal(
                                            bytes.as_ref(),
                                            host.clone(),
                                            &config,
                                            &mut super::RawAddressResolver,
                                        )
                                    };
                                    let Some(decoded) = decoded else {
                                        return;
                                    };
                                    if decoded.capture_truncated {
                                        drop_counters.record_truncated_stack();
                                    }
                                    if decoded.pid_unverified {
                                        drop_counters.record_pid_unverified_sample();
                                    }
                                    if decoded.dwarf_incomplete {
                                        drop_counters.record_dwarf_incomplete_sample();
                                    }
                                    let signal = decoded.signal;
                                    accepted += 1;
                                    if !send_with_backpressure(&cpu_tx, signal, backpressure) {
                                        if matches!(
                                            backpressure,
                                            CpuProfileBackpressure::StopSource
                                        ) {
                                            reader_shutdown.stop();
                                            exit = ReaderExit::BackpressureStop;
                                        } else {
                                            drop_counters.record_backpressure_drop();
                                            warn!("dropped cpu profile sample due to backpressure");
                                        }
                                    }
                                }
                                PerfBufferEvent::Lost { count } => {
                                    drop_counters.record_lost_perf_events(count);
                                    warn!(count, "lost cpu profile perf events");
                                }
                            }
                        });

                        if matches!(exit, ReaderExit::BackpressureStop) {
                            return ReaderExit::BackpressureStop;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    ReaderExit::Stopped
                }));
            }

            if self.config.dwarf_unwind {
                let refresher_shutdown = shutdown.clone();
                let mut sink = EbpfUnwindSink::take_from(&mut ebpf)?;
                let mut manager = UnwindTableManager::new(
                    self.procfs_root.clone(),
                    self.config.max_unwind_processes,
                );
                reader_handles.push(tokio::task::spawn_blocking(move || {
                    // Populate immediately, then re-scan on the same
                    // cadence as the TLS library rescan.
                    loop {
                        let stats = manager.refresh(&mut sink);
                        debug!(?stats, "dwarf unwind table refresh");
                        if stats.processes_skipped_limit > 0
                            || stats.modules_skipped_row_budget > 0
                            || stats.modules_skipped_module_budget > 0
                        {
                            warn!(
                                skipped_processes = stats.processes_skipped_limit,
                                skipped_modules_rows = stats.modules_skipped_row_budget,
                                skipped_modules_budget = stats.modules_skipped_module_budget,
                                "dwarf unwind coverage is capped; uncovered processes fall \
                                 back to frame-pointer unwinding"
                            );
                        }
                        for _ in 0..150 {
                            if refresher_shutdown.is_stopped() {
                                return ReaderExit::Stopped;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }));
            }

            {
                let emitter_shutdown = shutdown.clone();
                let emitter_counters = drop_counters.clone();
                let emitter_tx = tx.clone();
                let emitter_host = self.host.clone();
                let frame_limit = self.config.max_frames_per_sample;
                reader_handles.push(tokio::task::spawn_blocking(move || {
                    while !emitter_shutdown.is_stopped() {
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        let (lost, dropped, truncated, foreign, dwarf_incomplete) =
                            emitter_counters.drain();
                        if lost > 0 || dropped > 0 {
                            let warning = super::source_drop_warning(
                                emitter_host.clone(),
                                lost,
                                dropped,
                                super::now_unix_nanos(),
                            );
                            if emitter_tx.blocking_send(warning).is_err() {
                                return ReaderExit::Stopped;
                            }
                        }
                        if truncated > 0 {
                            let warning = super::stack_truncation_warning(
                                emitter_host.clone(),
                                truncated,
                                frame_limit,
                                super::now_unix_nanos(),
                            );
                            if emitter_tx.blocking_send(warning).is_err() {
                                return ReaderExit::Stopped;
                            }
                        }
                        if foreign > 0 {
                            let warning = super::pid_unverified_warning(
                                emitter_host.clone(),
                                foreign,
                                super::now_unix_nanos(),
                            );
                            if emitter_tx.blocking_send(warning).is_err() {
                                return ReaderExit::Stopped;
                            }
                        }
                        if dwarf_incomplete > 0 {
                            let warning = super::dwarf_incomplete_warning(
                                emitter_host.clone(),
                                dwarf_incomplete,
                                super::now_unix_nanos(),
                            );
                            if emitter_tx.blocking_send(warning).is_err() {
                                return ReaderExit::Stopped;
                            }
                        }
                    }
                    ReaderExit::Stopped
                }));
            }
            debug!("aya cpu profile source attached");
            let reader_results = join_reader_handles(reader_handles);
            tokio::pin!(reader_results);
            tokio::select! {
                result = &mut reader_results => result,
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(module_error)?;
                    shutdown.stop();
                    reader_results.await
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReaderExit {
        Stopped,
        BackpressureStop,
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

    async fn join_reader_handles(handles: Vec<JoinHandle<ReaderExit>>) -> CoreResult<()> {
        let mut backpressure_stopped = false;
        for handle in handles {
            if matches!(
                handle.await.map_err(module_error)?,
                ReaderExit::BackpressureStop
            ) {
                backpressure_stopped = true;
            }
        }

        if backpressure_stopped {
            return Err(CoreError::ModuleFailed {
                module: "source.aya_cpu_profile".to_string(),
                message: "cpu profile source stopped due to pipeline backpressure".to_string(),
            });
        }

        Ok(())
    }

    fn populate_frame_limit(ebpf: &mut Ebpf, config: &CpuProfileSourceConfig) -> CoreResult<()> {
        let map =
            ebpf.map_mut("CPU_PROFILE_FRAME_LIMIT")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_cpu_profile".to_string(),
                    message: "missing CPU_PROFILE_FRAME_LIMIT map".to_string(),
                })?;
        let mut limit: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(module_error)?;
        let frames = config
            .max_frames_per_sample
            .clamp(1, super::RAW_CPU_PROFILE_MAX_FRAMES) as u32;
        limit.set(0, frames, 0).map_err(module_error)?;
        Ok(())
    }

    /// Loads the tail-called DWARF unwind program and registers it in
    /// the program array the sampler jumps through.
    fn setup_dwarf_unwinder(ebpf: &mut Ebpf) -> CoreResult<()> {
        let program: &mut PerfEvent = ebpf
            .program_mut("cpu_profile_unwind")
            .ok_or_else(|| CoreError::ModuleFailed {
                module: "source.aya_cpu_profile".to_string(),
                message: "missing cpu_profile_unwind program".to_string(),
            })?
            .try_into()
            .map_err(module_error)?;
        program.load().map_err(module_error)?;
        let program_fd = program
            .fd()
            .map_err(module_error)?
            .try_clone()
            .map_err(module_error)?;
        let map = ebpf
            .map_mut("CPU_PROFILE_PROGS")
            .ok_or_else(|| CoreError::ModuleFailed {
                module: "source.aya_cpu_profile".to_string(),
                message: "missing CPU_PROFILE_PROGS map".to_string(),
            })?;
        let mut programs: AyaProgramArray<&mut MapData> =
            AyaProgramArray::try_from(map).map_err(module_error)?;
        programs.set(0, &program_fd, 0).map_err(module_error)?;
        Ok(())
    }

    /// eBPF-map-backed sink for the unwind table manager.
    struct EbpfUnwindSink {
        rows: AyaArray<aya::maps::MapData, UnwindRowAbi>,
        modules: AyaHashMap<aya::maps::MapData, u32, UnwindModuleSpan>,
        processes: AyaHashMap<aya::maps::MapData, u32, UnwindProcMappings>,
    }

    impl EbpfUnwindSink {
        fn take_from(ebpf: &mut Ebpf) -> CoreResult<Self> {
            let take = |ebpf: &mut Ebpf, name: &str| {
                ebpf.take_map(name).ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_cpu_profile".to_string(),
                    message: format!("missing {name} map"),
                })
            };
            Ok(Self {
                rows: AyaArray::try_from(take(ebpf, "UNWIND_ROWS")?).map_err(module_error)?,
                modules: AyaHashMap::try_from(take(ebpf, "UNWIND_MODULES")?)
                    .map_err(module_error)?,
                processes: AyaHashMap::try_from(take(ebpf, "UNWIND_PROC_MAPPINGS")?)
                    .map_err(module_error)?,
            })
        }
    }

    impl UnwindMapSink for EbpfUnwindSink {
        fn write_rows(&mut self, row_start: u32, rows: &[UnwindRowAbi]) -> bool {
            for (index, row) in rows.iter().enumerate() {
                let position = row_start.saturating_add(index as u32);
                if self.rows.set(position, row, 0).is_err() {
                    return false;
                }
            }
            true
        }

        fn write_module(&mut self, module_id: u32, span: UnwindModuleSpan) -> bool {
            self.modules.insert(module_id, span, 0).is_ok()
        }

        fn write_process(&mut self, pid: u32, mappings: &UnwindProcMappings) -> bool {
            self.processes.insert(pid, mappings, 0).is_ok()
        }

        fn remove_process(&mut self, pid: u32) {
            let _ = self.processes.remove(&pid);
        }
    }

    /// Points the in-kernel pid translation at the pid namespace of the
    /// procfs view used for symbolization (the namespace of that view's
    /// pid 1). Best-effort: when the namespace cannot be identified the
    /// map stays zeroed, translation stays off, and behavior matches the
    /// pre-translation agent.
    fn populate_pid_namespace(ebpf: &mut Ebpf, procfs_root: &std::path::Path) {
        use std::os::linux::fs::MetadataExt;

        let ns_path = procfs_root.join("1").join("ns").join("pid");
        let metadata = match std::fs::metadata(&ns_path) {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    path = %ns_path.display(),
                    %err,
                    "cannot identify symbolization pid namespace; \
                     cross-namespace samples may carry unresolvable pids"
                );
                return;
            }
        };
        let Some(map) = ebpf.map_mut("CPU_PROFILE_PIDNS") else {
            warn!("missing CPU_PROFILE_PIDNS map; pid namespace translation disabled");
            return;
        };
        let Ok(mut pidns) = AyaArray::<&mut MapData, u64>::try_from(map) else {
            warn!("CPU_PROFILE_PIDNS map has unexpected shape; pid namespace translation disabled");
            return;
        };
        if pidns.set(0, metadata.st_dev(), 0).is_err()
            || pidns.set(1, metadata.st_ino(), 0).is_err()
        {
            warn!("failed to record pid namespace; pid namespace translation disabled");
        }
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
        _procfs_root: std::path::PathBuf,
        _config: CpuProfileSourceConfig,
    }

    impl AyaCpuProfileSource {
        pub fn new(
            host: Option<String>,
            procfs_root: std::path::PathBuf,
            config: CpuProfileSourceConfig,
        ) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
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
            cgroup_id: 7,
            sample_count: 3,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 2,
            flags: 0,
            instruction_pointers: padded_pointers(&[0xabc, 0xdef, 0, 0]),
        };

        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes")
        .signal;

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
        let process = sample.process.expect("process");
        assert_eq!(process.pid, 42);
        assert_eq!(process.cgroup_id, Some(7));
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
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 0,
            command: fixed_command("api"),
            frame_count: 0,
            flags: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };

        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes")
        .signal;
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
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: RAW_CPU_PROFILE_MAX_FRAMES as u32,
            flags: 0,
            instruction_pointers: padded_pointers(&[0x1, 0x2, 0x3, 0x4]),
        };
        let config = CpuProfileSourceConfig {
            max_frames_per_sample: 2,
            ..source_config()
        };

        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &config,
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes")
        .signal;
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
    fn procfs_symbolizer_reads_maps_from_root() {
        let dir = std::env::temp_dir().join(format!("e-nav-symtest-{}", std::process::id()));
        let pid_dir = dir.join("777");
        std::fs::create_dir_all(&pid_dir).expect("create procfs dir");
        std::fs::write(
            pid_dir.join("maps"),
            "55f000000000-55f000010000 r-xp 00001000 fd:00 100 /usr/bin/app\n",
        )
        .expect("write maps");

        let mut symbolizer = ProcfsSymbolizer::new(dir.clone(), false);
        let frame = symbolizer.resolve(777, 0x55f000000500);
        assert_eq!(frame.module.as_deref(), Some("/usr/bin/app"));
        assert_eq!(frame.module_offset, Some(0x1500));
        // An unmapped ip falls back to a raw hex symbol.
        let fallback = symbolizer.resolve(777, 0x10);
        assert_eq!(fallback.module, None);
        assert!(fallback.symbol.as_deref().unwrap().starts_with("ip:"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn procfs_symbolizer_resolves_module_and_offset() {
        struct FixedMapResolver;
        impl FrameResolver for FixedMapResolver {
            fn resolve(&mut self, _pid: u32, ip: u64) -> RawProfileFrame {
                let map = e_navigator_profiling::symbolize::ProcessModuleMap::parse_maps(
                    "55f000000000-55f000010000 r-xp 00001000 fd:00 100 /usr/bin/app\n",
                );
                match map.resolve(ip) {
                    Some(location) => RawProfileFrame {
                        symbol: Some(format!("{}+{:#x}", location.module, location.module_offset)),
                        module: Some(location.module),
                        file: None,
                        line: None,
                        module_offset: Some(location.module_offset),
                    },
                    None => RawAddressResolver.resolve(0, ip),
                }
            }
        }

        let raw = RawCpuProfileEvent {
            pid: 4242,
            tid: 4243,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("app"),
            frame_count: 1,
            flags: 0,
            instruction_pointers: {
                let mut pointers = [0_u64; RAW_CPU_PROFILE_MAX_FRAMES];
                pointers[0] = 0x55f000000500;
                pointers
            },
        };
        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut FixedMapResolver,
        )
        .expect("symbolized sample decodes")
        .signal;
        let SignalPayload::ProfileSampleObservation(sample) = signal.payload else {
            panic!("expected profile sample");
        };
        assert_eq!(sample.stack_frames.len(), 1);
        let frame = &sample.stack_frames[0];
        assert_eq!(frame.module.as_deref(), Some("/usr/bin/app"));
        assert_eq!(frame.module_offset, Some(0x1500));
        assert_eq!(frame.symbol.as_deref(), Some("/usr/bin/app+0x1500"));
    }

    #[test]
    fn coverage_gap_warning_reports_cpu_counts() {
        let signal = coverage_gap_warning(None, 16, 8, 1_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "coverage_capped");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.coverage.online_cpus"
            && attribute.value == "16"));
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.coverage.active_cpus"
            && attribute.value == "8"));
    }

    #[test]
    fn drop_counters_accumulate_and_drain() {
        let counters = CpuProfileDropCounters::default();
        counters.record_lost_perf_events(3);
        counters.record_lost_perf_events(2);
        counters.record_backpressure_drop();
        counters.record_truncated_stack();
        counters.record_truncated_stack();
        counters.record_pid_unverified_sample();
        counters.record_dwarf_incomplete_sample();
        assert_eq!(counters.drain(), (5, 1, 2, 1, 1));
        // Draining resets all counters.
        assert_eq!(counters.drain(), (0, 0, 0, 0, 0));
    }

    #[test]
    fn source_drop_warning_reports_bounded_counts() {
        let signal = source_drop_warning(Some("node-a".to_string()), 7, 4, 12_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "source_dropped_samples");
        assert_eq!(warning.source_module, "source.aya_cpu_profile");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.dropped.lost_perf_events"
            && attribute.value == "7"));
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.dropped.backpressure"
            && attribute.value == "4"));
    }

    #[test]
    fn malformed_event_is_rejected() {
        assert!(
            raw_cpu_profile_to_signal_with_clock(
                &[1, 2, 3],
                None,
                &source_config(),
                10_000,
                &mut RawAddressResolver,
            )
            .is_none()
        );
    }

    #[test]
    fn zero_sample_count_is_rejected() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 0,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 1,
            flags: 0,
            instruction_pointers: padded_pointers(&[0xabc, 0, 0, 0]),
        };

        assert!(
            raw_cpu_profile_to_signal_with_clock(
                raw_as_bytes(&raw),
                None,
                &source_config(),
                10_000,
                &mut RawAddressResolver,
            )
            .is_none()
        );
    }

    #[test]
    fn deterministic_output_for_same_observed_sample() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 2,
            flags: 0,
            instruction_pointers: padded_pointers(&[0xabc, 0xdef, 0, 0]),
        };

        let first = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("first sample decodes")
        .signal;
        let second = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("second sample decodes")
        .signal;

        assert_eq!(first, second);
    }

    #[test]
    fn max_samples_per_batch_bounds_decode_batch() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 0,
            flags: 0,
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
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 0,
            flags: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };
        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes")
        .signal;
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

    #[test]
    fn stop_source_backpressure_does_not_block_on_full_queue() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 0,
            flags: 0,
            instruction_pointers: [0; RAW_CPU_PROFILE_MAX_FRAMES],
        };
        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes")
        .signal;
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        assert!(send_with_backpressure(
            &tx,
            signal.clone(),
            e_navigator_core::CpuProfileBackpressure::StopSource
        ));
        assert!(!send_with_backpressure(
            &tx,
            signal,
            e_navigator_core::CpuProfileBackpressure::StopSource
        ));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn capture_truncated_flag_sets_attribute_and_accounting() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 4,
            flags: RAW_CPU_PROFILE_FLAG_TRUNCATED,
            instruction_pointers: padded_pointers(&[0x1, 0x2, 0x3, 0x4]),
        };

        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes");
        assert!(decoded.capture_truncated);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert!(sample.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.capture_truncated"
            && attribute.value == "true"));
    }

    #[test]
    fn untruncated_capture_carries_no_truncation_attribute() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 2,
            flags: 0,
            instruction_pointers: padded_pointers(&[0x1, 0x2]),
        };

        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("raw profile event decodes");
        assert!(!decoded.capture_truncated);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert!(
            !sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.capture_truncated")
        );
    }

    #[test]
    fn stack_truncation_warning_reports_count_and_limit() {
        let signal = stack_truncation_warning(Some("node-a".to_string()), 9, 64, 12_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "stack_depth_capped");
        assert_eq!(warning.source_module, "source.aya_cpu_profile");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.truncated_samples"
            && attribute.value == "9"));
        assert!(
            warning
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.frame_limit"
                    && attribute.value == "64")
        );
    }

    #[test]
    fn perf_page_budget_scales_with_frequency_and_stays_bounded() {
        let event_bytes = core::mem::size_of::<RawCpuProfileEvent>();
        // Low frequencies keep a small floor.
        assert_eq!(cpu_profile_perf_pages(1, event_bytes), 4);
        // The default 49hz fits ~250ms of 1088-byte samples.
        let default_pages = cpu_profile_perf_pages(49, event_bytes);
        assert!(default_pages.is_power_of_two());
        assert!((4..=64).contains(&default_pages));
        // Extreme frequencies clamp instead of growing unbounded.
        assert_eq!(cpu_profile_perf_pages(999, event_bytes), 64);
    }

    struct VerdictResolver {
        verified: bool,
    }

    impl FrameResolver for VerdictResolver {
        fn resolve(&mut self, _pid: u32, _ip: u64) -> RawProfileFrame {
            RawProfileFrame {
                symbol: Some("resolved_fn".to_string()),
                module: Some("/usr/bin/app".to_string()),
                file: None,
                line: None,
                module_offset: Some(0x10),
            }
        }

        fn verify_thread(&mut self, _pid: u32, _tid: u32, _command: &str) -> bool {
            self.verified
        }
    }

    #[test]
    fn untranslated_pid_failing_verification_keeps_raw_addresses() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 1,
            flags: RAW_CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED,
            instruction_pointers: padded_pointers(&[0xabc]),
        };

        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut VerdictResolver { verified: false },
        )
        .expect("raw profile event decodes");
        assert!(decoded.pid_unverified);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert_eq!(
            sample.stack_frames[0].symbol.as_deref(),
            Some("ip:0000000000000abc")
        );
        assert_eq!(sample.stack_frames[0].module, None);
        assert!(
            sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.pid_ns"
                    && attribute.value == "unverified")
        );
    }

    #[test]
    fn untranslated_pid_passing_verification_symbolizes_normally() {
        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 1,
            flags: RAW_CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED,
            instruction_pointers: padded_pointers(&[0xabc]),
        };

        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut VerdictResolver { verified: true },
        )
        .expect("raw profile event decodes");
        assert!(!decoded.pid_unverified);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert_eq!(
            sample.stack_frames[0].symbol.as_deref(),
            Some("resolved_fn")
        );
        assert!(
            !sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.pid_ns")
        );
    }

    #[test]
    fn procfs_symbolizer_verifies_thread_comm() {
        let dir = std::env::temp_dir().join(format!("e-nav-commtest-{}", std::process::id()));
        let task_dir = dir.join("900").join("task").join("901");
        std::fs::create_dir_all(&task_dir).expect("create task dir");
        std::fs::write(task_dir.join("comm"), "worker\n").expect("write comm");

        let mut symbolizer = ProcfsSymbolizer::new(dir.clone(), false);
        assert!(symbolizer.verify_thread(900, 901, "worker"));
        assert!(!symbolizer.verify_thread(900, 901, "other"));
        // Missing pid/tid fails closed.
        assert!(!symbolizer.verify_thread(900, 999, "worker"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pid_unverified_warning_reports_count() {
        let signal = pid_unverified_warning(Some("node-a".to_string()), 5, 12_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "pid_unverified_samples");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.pid_unverified_samples"
            && attribute.value == "5"));
    }

    #[test]
    fn return_address_frames_resolve_the_call_site() {
        struct RecordingResolver {
            requested: Vec<u64>,
        }
        impl FrameResolver for RecordingResolver {
            fn resolve(&mut self, _pid: u32, ip: u64) -> RawProfileFrame {
                self.requested.push(ip);
                RawAddressResolver.resolve(0, ip)
            }
        }

        let raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 3,
            flags: 0,
            instruction_pointers: padded_pointers(&[0x1000, 0x2000, 0x3000]),
        };
        let mut resolver = RecordingResolver {
            requested: Vec::new(),
        };
        raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut resolver,
        )
        .expect("raw profile event decodes");

        // Leaf frame resolves as sampled; return addresses resolve one
        // byte back into the call instruction.
        assert_eq!(resolver.requested, vec![0x1000, 0x1fff, 0x2fff]);
    }

    #[test]
    fn unwind_mode_and_stop_reason_are_attributed() {
        let mut raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("api"),
            frame_count: 1,
            flags: 0,
            instruction_pointers: padded_pointers(&[0xabc]),
        };

        // Frame-pointer sample: fp mode, no dwarf stop attribute.
        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("fp sample decodes");
        assert!(!decoded.dwarf_incomplete);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert!(
            sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.unwind"
                    && attribute.value == "fp")
        );
        assert!(
            !sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.dwarf_stop")
        );

        // Complete DWARF unwind: dwarf mode, complete stop, not counted.
        raw.flags = RAW_CPU_PROFILE_FLAG_DWARF | (1 << RAW_UNWIND_STOP_SHIFT);
        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("dwarf sample decodes");
        assert!(!decoded.dwarf_incomplete);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert!(sample.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.unwind"
            && attribute.value == "dwarf"));
        assert!(sample.attributes.iter().any(|attribute| {
            attribute.key == "profiling.stack.dwarf_stop" && attribute.value == "complete"
        }));

        // A missing rule loses the stack tail and is counted.
        raw.flags = RAW_CPU_PROFILE_FLAG_DWARF | (3 << RAW_UNWIND_STOP_SHIFT);
        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut RawAddressResolver,
        )
        .expect("incomplete dwarf sample decodes");
        assert!(decoded.dwarf_incomplete);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        assert!(sample.attributes.iter().any(|attribute| {
            attribute.key == "profiling.stack.dwarf_stop" && attribute.value == "no_rule"
        }));
    }

    #[test]
    fn dwarf_incomplete_warning_reports_count() {
        let signal = dwarf_incomplete_warning(Some("node-a".to_string()), 6, 12_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "dwarf_unwind_incomplete");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.dwarf_incomplete_samples"
            && attribute.value == "6"));
    }

    #[test]
    fn cpu_reader_targets_are_bounded_by_active_target_limit() {
        assert_eq!(bounded_cpu_targets(&[0, 1, 2, 3], 2), vec![0, 1]);
        assert_eq!(bounded_cpu_targets(&[0, 1], 4), vec![0, 1]);
    }

    #[test]
    fn raw_cpu_profile_event_layout_size_matches_ebpf_abi() {
        assert_eq!(core::mem::size_of::<RawCpuProfileEvent>(), 1088);
    }

    fn padded_pointers(values: &[u64]) -> [u64; RAW_CPU_PROFILE_MAX_FRAMES] {
        let mut pointers = [0_u64; RAW_CPU_PROFILE_MAX_FRAMES];
        pointers[..values.len()].copy_from_slice(values);
        pointers
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
