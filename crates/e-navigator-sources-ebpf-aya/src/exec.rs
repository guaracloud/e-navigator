#[cfg(any(target_os = "linux", test))]
use e_navigator_core::ArgvCaptureConfig;

#[cfg(any(target_os = "linux", test))]
const RAW_MAX_ARGS: usize = ArgvCaptureConfig::MAX_ARGS_LIMIT;
#[cfg(any(target_os = "linux", test))]
const RAW_ARG_LEN: usize = 64;
#[cfg(any(target_os = "linux", test))]
const RAW_ARG_BYTES: usize = RAW_MAX_ARGS * RAW_ARG_LEN;
#[cfg(any(target_os = "linux", test))]
const EXECUTABLE_LEN: usize = 256;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(any(target_os = "linux", test))]
const EXEC_EVENT_SOURCE_SYSCALL_ENTER: u32 = 1;
#[cfg(any(target_os = "linux", test))]
const EXEC_EVENT_SOURCE_SCHED_EXEC: u32 = 2;
#[cfg(any(target_os = "linux", test))]
const MAX_PENDING_EXEC_ATTEMPTS: usize = 4096;
#[cfg(any(target_os = "linux", test))]
const PENDING_EXEC_MAX_AGE_NANOS: u64 = 5_000_000_000;

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy)]
struct RawExecEvent {
    pid: u32,
    uid: u32,
    argument_count: u32,
    event_source: u32,
    event_monotonic_nanos: u64,
    cgroup_id: u64,
    command: [u8; 16],
    executable: [u8; EXECUTABLE_LEN],
    arguments: [[u8; RAW_ARG_LEN]; RAW_MAX_ARGS],
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedArguments {
    arguments: Vec<String>,
    truncated: bool,
    bytes: usize,
}

#[cfg(any(target_os = "linux", test))]
fn captured_arguments_from_raw(
    raw_arguments: &[[u8; RAW_ARG_LEN]; RAW_MAX_ARGS],
    raw_count: u32,
    config: &ArgvCaptureConfig,
) -> CapturedArguments {
    if !config.enabled {
        return CapturedArguments {
            arguments: Vec::new(),
            truncated: false,
            bytes: 0,
        };
    }

    let mut arguments = Vec::new();
    let raw_count = raw_count as usize;
    let requested_count = raw_count.min(RAW_MAX_ARGS).min(config.max_args);
    let max_bytes = config.max_bytes.min(RAW_ARG_BYTES);
    let mut bytes = 0;
    let mut truncated = raw_count > requested_count;

    for raw in raw_arguments.iter().take(requested_count) {
        if bytes >= max_bytes {
            truncated = true;
            break;
        }

        let value = bytes_to_string(raw);
        if value.is_empty() {
            continue;
        }

        let remaining = max_bytes - bytes;
        if value.len() > remaining {
            let mut end = remaining;
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            arguments.push(value[..end].to_string());
            bytes += end;
            truncated = true;
            break;
        }

        bytes += value.len();
        arguments.push(value);
    }

    CapturedArguments {
        arguments,
        truncated,
        bytes,
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
struct ExecEventNormalizer {
    pending: std::collections::BTreeMap<u32, PendingExecAttempt>,
    order: std::collections::VecDeque<u32>,
}

#[cfg(any(target_os = "linux", test))]
impl ExecEventNormalizer {
    fn normalize(
        &mut self,
        raw: RawExecEvent,
        host: Option<String>,
        argv_capture: &ArgvCaptureConfig,
        procfs_root: &std::path::Path,
    ) -> ExecDecodeResult {
        match raw.event_source {
            EXEC_EVENT_SOURCE_SYSCALL_ENTER => {
                self.store_pending(raw, argv_capture);
                ExecDecodeResult::Pending
            }
            EXEC_EVENT_SOURCE_SCHED_EXEC => ExecDecodeResult::Emitted(Box::new(
                self.success_signal(raw, host, argv_capture, procfs_root),
            )),
            _ => ExecDecodeResult::Invalid,
        }
    }

    fn store_pending(&mut self, raw: RawExecEvent, argv_capture: &ArgvCaptureConfig) {
        if !self.pending.contains_key(&raw.pid) {
            self.order.push_back(raw.pid);
        }
        let captured =
            captured_arguments_from_raw(&raw.arguments, raw.argument_count, argv_capture);
        self.pending.insert(
            raw.pid,
            PendingExecAttempt {
                event_monotonic_nanos: raw.event_monotonic_nanos,
                executable: bytes_to_string(&raw.executable),
                captured,
            },
        );
        self.evict_overflow();
    }

    fn success_signal(
        &mut self,
        raw: RawExecEvent,
        host: Option<String>,
        argv_capture: &ArgvCaptureConfig,
        procfs_root: &std::path::Path,
    ) -> e_navigator_signals::SignalEnvelope {
        let pending = self.take_fresh_pending(raw.pid, raw.event_monotonic_nanos);
        raw_to_success_signal(raw, pending, host, argv_capture, procfs_root)
    }

    fn take_fresh_pending(
        &mut self,
        pid: u32,
        success_monotonic_nanos: u64,
    ) -> Option<PendingExecAttempt> {
        let pending = self.pending.remove(&pid)?;
        self.remove_ordered_pid(pid);
        let age = success_monotonic_nanos.saturating_sub(pending.event_monotonic_nanos);
        (age <= PENDING_EXEC_MAX_AGE_NANOS).then_some(pending)
    }

    fn evict_overflow(&mut self) {
        while self.pending.len() > MAX_PENDING_EXEC_ATTEMPTS {
            let Some(pid) = self.order.pop_front() else {
                break;
            };
            self.pending.remove(&pid);
        }
    }

    fn remove_ordered_pid(&mut self, pid: u32) {
        if let Some(index) = self
            .order
            .iter()
            .position(|ordered_pid| *ordered_pid == pid)
        {
            self.order.remove(index);
        }
    }

    #[cfg(test)]
    fn retained_pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    fn retained_order_len(&self) -> usize {
        self.order.len()
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
enum ExecDecodeResult {
    Pending,
    Emitted(Box<e_navigator_signals::SignalEnvelope>),
    Invalid,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingExecAttempt {
    event_monotonic_nanos: u64,
    executable: String,
    captured: CapturedArguments,
}

#[cfg(any(target_os = "linux", test))]
fn raw_to_success_signal(
    raw: RawExecEvent,
    pending: Option<PendingExecAttempt>,
    host: Option<String>,
    argv_capture: &ArgvCaptureConfig,
    procfs_root: &std::path::Path,
) -> e_navigator_signals::SignalEnvelope {
    let task_comm = bytes_to_string(&raw.command);
    let sched_executable = bytes_to_string(&raw.executable);
    let executable = pending
        .as_ref()
        .map(|pending| pending.executable.clone())
        .filter(|executable| !executable.is_empty())
        .or_else(|| (!sched_executable.is_empty()).then_some(sched_executable));
    let arguments = pending
        .map(|pending| pending.captured.arguments)
        .unwrap_or_else(|| {
            captured_arguments_from_raw(&raw.arguments, raw.argument_count, argv_capture).arguments
        });
    let command = executable.clone().unwrap_or(task_comm.clone());
    let container = crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid);

    e_navigator_signals::SignalEnvelope::exec(
        "source.aya_exec",
        host,
        e_navigator_signals::ExecEvent {
            pid: raw.pid,
            ppid: None,
            uid: Some(raw.uid),
            command,
            executable,
            arguments,
            cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
            timestamp_unix_nanos: now_unix_nanos(),
            container,
            kubernetes: None,
        },
    )
}

#[cfg(any(target_os = "linux", test))]
fn raw_to_signal(
    bytes: &[u8],
    host: Option<String>,
    argv_capture: &ArgvCaptureConfig,
    procfs_root: &std::path::Path,
    exec_normalizer: &std::sync::Mutex<ExecEventNormalizer>,
) -> ExecDecodeResult {
    if bytes.len() < core::mem::size_of::<RawExecEvent>() {
        return ExecDecodeResult::Invalid;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) };
    exec_normalizer
        .lock()
        .map(|mut normalizer| normalizer.normalize(raw, host, argv_capture, procfs_root))
        .unwrap_or(ExecDecodeResult::Invalid)
}

#[cfg(target_os = "linux")]
mod platform {
    use crate::diagnostics::{DiagnosticSampleDecision, SourceDiagnostics};
    use crate::perf_sample::perf_sample_bytes;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::Array,
        maps::perf::{PerfEvent, PerfEventArray},
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{
        ArgvCaptureConfig, CoreError, CoreResult, ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_signals::{
        ContainerContext, KubernetesContext, ProcessExitEvent, SignalEnvelope, SignalPayload,
    };
    use std::{
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{debug, info, warn};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawExitEvent {
        pid: u32,
        uid: u32,
        cgroup_id: u64,
        command: [u8; 16],
    }

    #[derive(Debug, Default)]
    pub struct AyaExecSource {
        host: Option<String>,
        argv_capture: ArgvCaptureConfig,
        procfs_root: PathBuf,
    }

    impl AyaExecSource {
        pub fn new(
            host: Option<String>,
            argv_capture: ArgvCaptureConfig,
            procfs_root: PathBuf,
        ) -> Self {
            Self {
                host,
                argv_capture,
                procfs_root,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaExecSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_exec", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let argv_capture = self.argv_capture.clone();
            let diagnostics = SourceDiagnostics::from_env();
            let telemetry = Arc::new(SourceTelemetry::new("source.aya_exec"));
            let exec_normalizer = Arc::new(Mutex::new(super::ExecEventNormalizer::default()));

            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;

            configure_argv_capture(&mut ebpf, argv_capture.enabled)?;

            let program: &mut TracePoint = ebpf
                .program_mut("tracepoint_execve")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing tracepoint_execve program".to_string(),
                })?
                .try_into()
                .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            program.load().map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
            program
                .attach("syscalls", "sys_enter_execve")
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let execveat_program: &mut TracePoint = ebpf
                .program_mut("tracepoint_execveat")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing tracepoint_execveat program".to_string(),
                })?
                .try_into()
                .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            execveat_program
                .load()
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            execveat_program
                .attach("syscalls", "sys_enter_execveat")
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let process_exec_program: &mut TracePoint = ebpf
                .program_mut("tracepoint_process_exec")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing tracepoint_process_exec program".to_string(),
                })?
                .try_into()
                .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            process_exec_program
                .load()
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            process_exec_program
                .attach("sched", "sched_process_exec")
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let exit_program: &mut TracePoint = ebpf
                .program_mut("tracepoint_process_exit")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: "missing tracepoint_process_exit program".to_string(),
                })?
                .try_into()
                .map_err(|err: aya::programs::ProgramError| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            exit_program.load().map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
            exit_program
                .attach("sched", "sched_process_exit")
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let mut perf_array =
                PerfEventArray::try_from(ebpf.take_map("EXEC_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_exec".to_string(),
                        message: "missing EXEC_EVENTS map".to_string(),
                    }
                })?)
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let mut exit_perf_array =
                PerfEventArray::try_from(ebpf.take_map("EXIT_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_exec".to_string(),
                        message: "missing EXIT_EVENTS map".to_string(),
                    }
                })?)
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;

            let cpus = online_cpus().map_err(|(_, err)| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;

            for cpu_id in &cpus {
                let mut buffer = perf_array
                    .open(*cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                    .map_err(|err| CoreError::ModuleFailed {
                        module: "source.aya_exec".to_string(),
                        message: err.to_string(),
                    })?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let argv_capture = argv_capture.clone();
                let procfs_root = self.procfs_root.clone();
                let exec_normalizer = exec_normalizer.clone();
                let reader_shutdown = shutdown.clone();
                let diagnostics = diagnostics.clone();
                let telemetry = telemetry.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail);
                                    match super::raw_to_signal(
                                        bytes.as_ref(),
                                        host.clone(),
                                        &argv_capture,
                                        &procfs_root,
                                        &exec_normalizer,
                                    ) {
                                        super::ExecDecodeResult::Emitted(signal) => {
                                            telemetry.record_decoded_sample();
                                            let diagnostic_decision =
                                                log_signal_diagnostic(&diagnostics, &signal);
                                            telemetry
                                                .record_diagnostic_decision(diagnostic_decision);
                                            if cpu_tx.blocking_send(*signal).is_err() {
                                                telemetry.record_send_failure();
                                                closed = true;
                                            } else {
                                                telemetry.record_sent_signal();
                                            }
                                        }
                                        super::ExecDecodeResult::Pending => {}
                                        super::ExecDecodeResult::Invalid => {
                                            telemetry.record_invalid_sample();
                                        }
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    telemetry.record_lost_perf_events(count);
                                    warn!(count, "lost exec perf events");
                                }
                            }
                            telemetry.maybe_log_summary();
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(
                            super::PERF_READER_POLL_INTERVAL_MS,
                        ));
                    }
                }));
            }

            for cpu_id in &cpus {
                let mut buffer = exit_perf_array
                    .open(*cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                    .map_err(|err| CoreError::ModuleFailed {
                        module: "source.aya_exec".to_string(),
                        message: err.to_string(),
                    })?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let procfs_root = self.procfs_root.clone();
                let reader_shutdown = shutdown.clone();
                let diagnostics = diagnostics.clone();
                let telemetry = telemetry.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail);
                                    if let Some(signal) = raw_exit_to_signal(
                                        bytes.as_ref(),
                                        host.clone(),
                                        &procfs_root,
                                    ) {
                                        telemetry.record_decoded_sample();
                                        let diagnostic_decision =
                                            log_signal_diagnostic(&diagnostics, &signal);
                                        telemetry.record_diagnostic_decision(diagnostic_decision);
                                        if cpu_tx.blocking_send(signal).is_err() {
                                            telemetry.record_send_failure();
                                            closed = true;
                                        } else {
                                            telemetry.record_sent_signal();
                                        }
                                    } else {
                                        telemetry.record_invalid_sample();
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    telemetry.record_lost_perf_events(count);
                                    warn!(count, "lost process exit perf events");
                                }
                            }
                            telemetry.maybe_log_summary();
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(
                            super::PERF_READER_POLL_INTERVAL_MS,
                        ));
                    }
                }));
            }

            if diagnostics.enabled() {
                info!(
                    source = "source.aya_exec",
                    remaining_samples = diagnostics.remaining_samples(),
                    filtered_preview_remaining_samples =
                        diagnostics.remaining_filtered_preview_samples(),
                    "source diagnostics enabled"
                );
            }
            debug!("aya exec source attached");
            tokio::signal::ctrl_c()
                .await
                .map_err(|err| CoreError::ModuleFailed {
                    module: "source.aya_exec".to_string(),
                    message: err.to_string(),
                })?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    fn log_signal_diagnostic(
        diagnostics: &SourceDiagnostics,
        signal: &SignalEnvelope,
    ) -> DiagnosticSampleDecision {
        match &signal.payload {
            SignalPayload::Exec(event) => {
                let executable = event.executable.as_deref().unwrap_or_default();
                let mut filter_values = Vec::with_capacity(event.arguments.len() + 2);
                filter_values.push(event.command.as_str());
                filter_values.push(executable);
                filter_values.extend(event.arguments.iter().map(String::as_str));
                let decision = diagnostics.sample_decision_for(&filter_values);
                if decision != DiagnosticSampleDecision::Matched {
                    if decision == DiagnosticSampleDecision::Filtered
                        && diagnostics.try_acquire_filtered_preview()
                    {
                        let logged_filter_values =
                            diagnostics.redact_values(filter_values.iter().copied());
                        info!(
                            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                            source = "source.aya_exec",
                            raw_event = "exec",
                            diagnostic_decision = "filtered",
                            filter_values = ?logged_filter_values,
                            pid = event.pid,
                            uid = ?event.uid,
                            command = %diagnostics.redact_value(&event.command),
                            executable = ?diagnostics.redact_optional_value(event.executable.as_deref()),
                            arguments = ?diagnostics.redact_values(event.arguments.iter().map(String::as_str)),
                            argument_count = event.arguments.len(),
                            cgroup_id = ?diagnostics.redact_optional_u64(event.cgroup_id),
                            container_id = ?diagnostics.redact_optional_value(container_id(&event.container)),
                            container_runtime = ?container_runtime(&event.container),
                            kubernetes_namespace = ?diagnostics.redact_optional_value(kubernetes_namespace(&event.kubernetes)),
                            kubernetes_pod_name = ?diagnostics.redact_optional_value(kubernetes_pod_name(&event.kubernetes)),
                            kubernetes_pod_uid = ?diagnostics.redact_optional_value(kubernetes_pod_uid(&event.kubernetes)),
                            kubernetes_container_name = ?diagnostics.redact_optional_value(kubernetes_container_name(&event.kubernetes)),
                            "source diagnostic raw event filtered"
                        );
                    }
                    return decision;
                }

                info!(
                    target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                    source = "source.aya_exec",
                    raw_event = "exec",
                    pid = event.pid,
                    uid = ?event.uid,
                    command = %diagnostics.redact_value(&event.command),
                    executable = ?diagnostics.redact_optional_value(event.executable.as_deref()),
                    arguments = ?diagnostics.redact_values(event.arguments.iter().map(String::as_str)),
                    argument_count = event.arguments.len(),
                    cgroup_id = ?diagnostics.redact_optional_u64(event.cgroup_id),
                    container_id = ?diagnostics.redact_optional_value(container_id(&event.container)),
                    container_runtime = ?container_runtime(&event.container),
                    kubernetes_namespace = ?diagnostics.redact_optional_value(kubernetes_namespace(&event.kubernetes)),
                    kubernetes_pod_name = ?diagnostics.redact_optional_value(kubernetes_pod_name(&event.kubernetes)),
                    kubernetes_pod_uid = ?diagnostics.redact_optional_value(kubernetes_pod_uid(&event.kubernetes)),
                    kubernetes_container_name = ?diagnostics.redact_optional_value(kubernetes_container_name(&event.kubernetes)),
                    "source diagnostic raw event decoded"
                );
                DiagnosticSampleDecision::Matched
            }
            SignalPayload::ProcessExit(event) => {
                let filter_values = [event.command.as_str()];
                let decision = diagnostics.sample_decision_for(&filter_values);
                if decision != DiagnosticSampleDecision::Matched {
                    if decision == DiagnosticSampleDecision::Filtered
                        && diagnostics.try_acquire_filtered_preview()
                    {
                        let logged_filter_values =
                            diagnostics.redact_values(filter_values.iter().copied());
                        info!(
                            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                            source = "source.aya_exec",
                            raw_event = "process_exit",
                            diagnostic_decision = "filtered",
                            filter_values = ?logged_filter_values,
                            pid = event.pid,
                            uid = ?event.uid,
                            command = %diagnostics.redact_value(&event.command),
                            cgroup_id = ?diagnostics.redact_optional_u64(event.cgroup_id),
                            container_id = ?diagnostics.redact_optional_value(container_id(&event.container)),
                            container_runtime = ?container_runtime(&event.container),
                            kubernetes_namespace = ?diagnostics.redact_optional_value(kubernetes_namespace(&event.kubernetes)),
                            kubernetes_pod_name = ?diagnostics.redact_optional_value(kubernetes_pod_name(&event.kubernetes)),
                            kubernetes_pod_uid = ?diagnostics.redact_optional_value(kubernetes_pod_uid(&event.kubernetes)),
                            kubernetes_container_name = ?diagnostics.redact_optional_value(kubernetes_container_name(&event.kubernetes)),
                            "source diagnostic raw event filtered"
                        );
                    }
                    return decision;
                }

                info!(
                    target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                    source = "source.aya_exec",
                    raw_event = "process_exit",
                    pid = event.pid,
                    uid = ?event.uid,
                    command = %diagnostics.redact_value(&event.command),
                    cgroup_id = ?diagnostics.redact_optional_u64(event.cgroup_id),
                    container_id = ?diagnostics.redact_optional_value(container_id(&event.container)),
                    container_runtime = ?container_runtime(&event.container),
                    kubernetes_namespace = ?diagnostics.redact_optional_value(kubernetes_namespace(&event.kubernetes)),
                    kubernetes_pod_name = ?diagnostics.redact_optional_value(kubernetes_pod_name(&event.kubernetes)),
                    kubernetes_pod_uid = ?diagnostics.redact_optional_value(kubernetes_pod_uid(&event.kubernetes)),
                    kubernetes_container_name = ?diagnostics.redact_optional_value(kubernetes_container_name(&event.kubernetes)),
                    "source diagnostic raw event decoded"
                );
                DiagnosticSampleDecision::Matched
            }
            _ => DiagnosticSampleDecision::Disabled,
        }
    }

    fn container_id(container: &Option<ContainerContext>) -> Option<&str> {
        container
            .as_ref()
            .map(|container| container.container_id.as_str())
    }

    fn container_runtime(container: &Option<ContainerContext>) -> Option<&str> {
        container
            .as_ref()
            .and_then(|container| container.runtime.as_deref())
    }

    fn kubernetes_namespace(kubernetes: &Option<KubernetesContext>) -> Option<&str> {
        kubernetes
            .as_ref()
            .map(|kubernetes| kubernetes.namespace.as_str())
    }

    fn kubernetes_pod_name(kubernetes: &Option<KubernetesContext>) -> Option<&str> {
        kubernetes
            .as_ref()
            .map(|kubernetes| kubernetes.pod_name.as_str())
    }

    fn kubernetes_pod_uid(kubernetes: &Option<KubernetesContext>) -> Option<&str> {
        kubernetes
            .as_ref()
            .and_then(|kubernetes| kubernetes.pod_uid.as_deref())
    }

    fn kubernetes_container_name(kubernetes: &Option<KubernetesContext>) -> Option<&str> {
        kubernetes
            .as_ref()
            .and_then(|kubernetes| kubernetes.container_name.as_deref())
    }

    fn raw_exit_to_signal(
        bytes: &[u8],
        host: Option<String>,
        procfs_root: &std::path::Path,
    ) -> Option<SignalEnvelope> {
        if bytes.len() < core::mem::size_of::<RawExitEvent>() {
            return None;
        }

        let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawExitEvent>()) };
        let command = super::bytes_to_string(&raw.command);
        let container = crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid);

        Some(SignalEnvelope::process_exit(
            "source.aya_exec",
            host,
            ProcessExitEvent {
                pid: raw.pid,
                ppid: None,
                uid: Some(raw.uid),
                command,
                cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
                exit_code: None,
                runtime_nanos: None,
                timestamp_unix_nanos: super::now_unix_nanos(),
                container,
                kubernetes: None,
            },
        ))
    }

    fn configure_argv_capture(ebpf: &mut Ebpf, enabled: bool) -> CoreResult<()> {
        let mut map = Array::try_from(ebpf.map_mut("ARGV_CAPTURE_ENABLED").ok_or_else(|| {
            CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: "missing ARGV_CAPTURE_ENABLED map".to_string(),
            }
        })?)
        .map_err(|err| CoreError::ModuleFailed {
            module: "source.aya_exec".to_string(),
            message: err.to_string(),
        })?;

        map.set(0, u32::from(enabled), 0)
            .map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })
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
            handle.await.map_err(|err| CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: err.to_string(),
            })?;
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
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{
        ArgvCaptureConfig, CoreError, CoreResult, ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaExecSource {
        host: Option<String>,
        _argv_capture: ArgvCaptureConfig,
        _procfs_root: std::path::PathBuf,
    }

    impl AyaExecSource {
        pub fn new(
            host: Option<String>,
            argv_capture: ArgvCaptureConfig,
            procfs_root: std::path::PathBuf,
        ) -> Self {
            Self {
                host,
                _argv_capture: argv_capture,
                _procfs_root: procfs_root,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaExecSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_exec", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_exec".to_string(),
                message: format!(
                    "Aya exec source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaExecSource;

#[cfg(any(target_os = "linux", test))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::ArgvCaptureConfig;

    #[test]
    fn command_bytes_convert_to_string() {
        let mut command = [0_u8; 16];
        command[..4].copy_from_slice(b"bash");
        assert_eq!(bytes_to_string(&command), "bash");
    }

    #[test]
    fn argv_capture_can_be_disabled() {
        let raw = raw_argument_slots(["/bin/sh", "-c", "echo hello"]);
        let config = ArgvCaptureConfig {
            enabled: false,
            max_args: 8,
            max_bytes: 512,
        };

        let captured = captured_arguments_from_raw(&raw, 3, &config);

        assert!(captured.arguments.is_empty());
        assert!(!captured.truncated);
        assert_eq!(captured.bytes, 0);
    }

    #[test]
    fn argv_capture_is_bounded_by_count_and_bytes() {
        let raw = raw_argument_slots(["/bin/bash", "-lc", "curl http://example.invalid"]);
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 2,
            max_bytes: 12,
        };

        let captured = captured_arguments_from_raw(&raw, 3, &config);

        assert_eq!(
            captured.arguments,
            vec!["/bin/bash".to_string(), "-lc".to_string()]
        );
        assert!(captured.truncated);
        assert_eq!(captured.bytes, 12);
    }

    #[test]
    fn unix_timestamp_is_not_epoch_placeholder() {
        assert!(now_unix_nanos() > 0);
    }

    #[test]
    fn perf_reader_settings_are_bounded_for_short_bursts() {
        assert!((16..=128).contains(&PERF_BUFFER_PAGE_COUNT));
        assert!((10..=50).contains(&PERF_READER_POLL_INTERVAL_MS));
    }

    #[test]
    fn normalizer_emits_once_for_syscall_entry_and_sched_success() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");
        let entry = raw_exec_event(
            42,
            EXEC_EVENT_SOURCE_SYSCALL_ENTER,
            10,
            "/bin/sh",
            ["sh", "-c", "echo ok"],
        );
        let success = raw_exec_event(42, EXEC_EVENT_SOURCE_SCHED_EXEC, 20, "", []);

        assert_pending(normalizer.normalize(entry, None, &config, procfs_root));
        let signal = emitted_signal(normalizer.normalize(success, None, &config, procfs_root));

        let e_navigator_signals::SignalPayload::Exec(event) = signal.payload else {
            panic!("expected exec payload");
        };
        assert_eq!(event.pid, 42);
        assert_eq!(event.executable.as_deref(), Some("/bin/sh"));
        assert_eq!(event.arguments, vec!["sh", "-c", "echo ok"]);
    }

    #[test]
    fn normalizer_does_not_emit_failed_exec_attempts() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");
        let entry = raw_exec_event(
            42,
            EXEC_EVENT_SOURCE_SYSCALL_ENTER,
            10,
            "/missing/binary",
            ["/missing/binary"],
        );

        assert_pending(normalizer.normalize(entry, None, &config, procfs_root));
        assert_eq!(normalizer.retained_pending_len(), 1);
        assert_eq!(normalizer.retained_order_len(), 1);
    }

    #[test]
    fn normalizer_discards_stale_pending_argv() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");
        let entry = raw_exec_event(
            42,
            EXEC_EVENT_SOURCE_SYSCALL_ENTER,
            10,
            "/missing/binary",
            ["--password=stale"],
        );
        let success = raw_exec_event(
            42,
            EXEC_EVENT_SOURCE_SCHED_EXEC,
            10 + PENDING_EXEC_MAX_AGE_NANOS + 1,
            "",
            [],
        );

        assert_pending(normalizer.normalize(entry, None, &config, procfs_root));
        let signal = emitted_signal(normalizer.normalize(success, None, &config, procfs_root));

        let e_navigator_signals::SignalPayload::Exec(event) = signal.payload else {
            panic!("expected exec payload");
        };
        assert!(event.arguments.is_empty());
        assert_eq!(normalizer.retained_pending_len(), 0);
        assert_eq!(normalizer.retained_order_len(), 0);
    }

    #[test]
    fn normalizer_successful_exec_stream_does_not_retain_ordering_state() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");

        for pid in 1..=MAX_PENDING_EXEC_ATTEMPTS as u32 + 128 {
            let entry = raw_exec_event(
                pid,
                EXEC_EVENT_SOURCE_SYSCALL_ENTER,
                u64::from(pid),
                "/bin/sh",
                ["sh"],
            );
            let success = raw_exec_event(
                pid,
                EXEC_EVENT_SOURCE_SCHED_EXEC,
                u64::from(pid) + 1,
                "",
                [],
            );

            assert_pending(normalizer.normalize(entry, None, &config, procfs_root));
            let _signal = emitted_signal(normalizer.normalize(success, None, &config, procfs_root));
        }

        assert_eq!(normalizer.retained_pending_len(), 0);
        assert_eq!(normalizer.retained_order_len(), 0);
    }

    #[test]
    fn normalizer_overflow_evicts_oldest_pending_and_ordering_entries() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");

        for pid in 1..=MAX_PENDING_EXEC_ATTEMPTS as u32 + 2 {
            let entry = raw_exec_event(
                pid,
                EXEC_EVENT_SOURCE_SYSCALL_ENTER,
                u64::from(pid),
                "/bin/sh",
                ["sh"],
            );
            assert_pending(normalizer.normalize(entry, None, &config, procfs_root));
        }

        assert_eq!(normalizer.retained_pending_len(), MAX_PENDING_EXEC_ATTEMPTS);
        assert_eq!(normalizer.retained_order_len(), MAX_PENDING_EXEC_ATTEMPTS);
        assert!(!normalizer.pending.contains_key(&1));
        assert!(!normalizer.pending.contains_key(&2));
        assert_eq!(normalizer.order.front().copied(), Some(3));
    }

    #[test]
    fn normalizer_duplicate_pid_updates_without_growing_ordering_state() {
        let mut normalizer = ExecEventNormalizer::default();
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");
        let first = raw_exec_event(42, EXEC_EVENT_SOURCE_SYSCALL_ENTER, 10, "/bin/old", ["old"]);
        let second = raw_exec_event(42, EXEC_EVENT_SOURCE_SYSCALL_ENTER, 20, "/bin/new", ["new"]);
        let success = raw_exec_event(42, EXEC_EVENT_SOURCE_SCHED_EXEC, 21, "", []);

        assert_pending(normalizer.normalize(first, None, &config, procfs_root));
        assert_pending(normalizer.normalize(second, None, &config, procfs_root));
        assert_eq!(normalizer.retained_pending_len(), 1);
        assert_eq!(normalizer.retained_order_len(), 1);

        let signal = emitted_signal(normalizer.normalize(success, None, &config, procfs_root));

        let e_navigator_signals::SignalPayload::Exec(event) = signal.payload else {
            panic!("expected exec payload");
        };
        assert_eq!(event.executable.as_deref(), Some("/bin/new"));
        assert_eq!(event.arguments, vec!["new"]);
        assert_eq!(normalizer.retained_pending_len(), 0);
        assert_eq!(normalizer.retained_order_len(), 0);
    }

    #[test]
    fn raw_to_signal_classifies_pending_emitted_and_invalid_exec_samples() {
        let normalizer = std::sync::Mutex::new(ExecEventNormalizer::default());
        let config = ArgvCaptureConfig {
            enabled: true,
            max_args: 8,
            max_bytes: 512,
        };
        let procfs_root = std::path::Path::new("/proc/does-not-exist-for-e-navigator-test");
        let entry = raw_exec_event(42, EXEC_EVENT_SOURCE_SYSCALL_ENTER, 10, "/bin/sh", ["sh"]);
        let success = raw_exec_event(42, EXEC_EVENT_SOURCE_SCHED_EXEC, 11, "", []);
        let unknown = raw_exec_event(7, 99, 12, "", []);

        assert_pending(raw_to_signal(
            &raw_exec_event_bytes(&entry),
            None,
            &config,
            procfs_root,
            &normalizer,
        ));
        let _signal = emitted_signal(raw_to_signal(
            &raw_exec_event_bytes(&success),
            None,
            &config,
            procfs_root,
            &normalizer,
        ));
        assert_invalid(raw_to_signal(
            &raw_exec_event_bytes(&unknown),
            None,
            &config,
            procfs_root,
            &normalizer,
        ));
        assert_invalid(raw_to_signal(
            &[0_u8; 4],
            None,
            &config,
            procfs_root,
            &normalizer,
        ));
    }

    fn raw_argument_slots<const N: usize>(values: [&str; N]) -> [[u8; RAW_ARG_LEN]; RAW_MAX_ARGS] {
        let mut slots = [[0_u8; RAW_ARG_LEN]; RAW_MAX_ARGS];
        for (slot, value) in slots.iter_mut().zip(values) {
            let bytes = value.as_bytes();
            let copy_len = bytes.len().min(RAW_ARG_LEN.saturating_sub(1));
            slot[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        slots
    }

    fn raw_exec_event<const N: usize>(
        pid: u32,
        event_source: u32,
        event_monotonic_nanos: u64,
        executable: &str,
        arguments: [&str; N],
    ) -> RawExecEvent {
        let mut executable_bytes = [0_u8; EXECUTABLE_LEN];
        let executable_raw = executable.as_bytes();
        let executable_len = executable_raw.len().min(EXECUTABLE_LEN.saturating_sub(1));
        executable_bytes[..executable_len].copy_from_slice(&executable_raw[..executable_len]);

        RawExecEvent {
            pid,
            uid: 1000,
            argument_count: arguments.len() as u32,
            event_source,
            event_monotonic_nanos,
            cgroup_id: 0,
            command: fixed_command("sh"),
            executable: executable_bytes,
            arguments: raw_argument_slots(arguments),
        }
    }

    fn fixed_command(value: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = value.as_bytes();
        let copy_len = bytes.len().min(command.len().saturating_sub(1));
        command[..copy_len].copy_from_slice(&bytes[..copy_len]);
        command
    }

    fn raw_exec_event_bytes(raw: &RawExecEvent) -> Vec<u8> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(raw).cast::<u8>(),
                core::mem::size_of::<RawExecEvent>(),
            )
        };
        bytes.to_vec()
    }

    fn assert_pending(result: ExecDecodeResult) {
        match result {
            ExecDecodeResult::Pending => {}
            ExecDecodeResult::Emitted(_) => panic!("expected pending exec sample"),
            ExecDecodeResult::Invalid => panic!("expected pending exec sample"),
        }
    }

    fn assert_invalid(result: ExecDecodeResult) {
        match result {
            ExecDecodeResult::Invalid => {}
            ExecDecodeResult::Pending => panic!("expected invalid exec sample"),
            ExecDecodeResult::Emitted(_) => panic!("expected invalid exec sample"),
        }
    }

    fn emitted_signal(result: ExecDecodeResult) -> e_navigator_signals::SignalEnvelope {
        match result {
            ExecDecodeResult::Emitted(signal) => *signal,
            ExecDecodeResult::Pending => panic!("expected emitted exec signal"),
            ExecDecodeResult::Invalid => panic!("expected emitted exec signal"),
        }
    }
}
