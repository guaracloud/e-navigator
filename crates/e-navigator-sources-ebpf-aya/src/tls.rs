//! Uprobe-based TLS plaintext capture source (`source.aya_tls`).
//!
//! This is library-boundary interception: uprobes on the userspace TLS
//! read/write calls (OpenSSL/BoringSSL `SSL_read`/`SSL_write`, GnuTLS
//! `gnutls_record_recv`/`gnutls_record_send`) copy the plaintext the
//! application already holds. It is NOT on-the-wire decryption. Captured
//! plaintext shares the `RawProtocolDataEvent` layout with the cleartext
//! protocol source and is routed through the same bounded stream reassembler,
//! parsers, and request/response matcher.

#[cfg(target_os = "linux")]
const TLS_PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(target_os = "linux")]
const TLS_PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(target_os = "linux")]
const TLS_RAW_SAMPLE_CHANNEL_CAPACITY: usize = 1024;

/// Builds a protocol-source configuration that reuses the existing stream
/// registry for the stream-framed protocols carried over TLS. HTTP/1 ports
/// are handled separately and are intentionally excluded here.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn stream_protocol_config(
    config: &e_navigator_core::TlsSourceConfig,
) -> e_navigator_core::ProtocolSourceConfig {
    e_navigator_core::ProtocolSourceConfig {
        http1_ports: config.http1_ports.clone(),
        http2_ports: config.http2_ports.clone(),
        kafka_ports: config.kafka_ports.clone(),
        mongodb_ports: config.mongodb_ports.clone(),
        mysql_ports: config.mysql_ports.clone(),
        nats_ports: config.nats_ports.clone(),
        postgresql_ports: config.postgresql_ports.clone(),
        redis_ports: config.redis_ports.clone(),
        max_buffered_bytes_per_connection: config.max_buffered_bytes_per_connection,
        max_tracked_connections: config.max_tracked_connections,
        max_attributes: config.max_attributes,
        ..e_navigator_core::ProtocolSourceConfig::default()
    }
}

/// The remote ports whose decrypted plaintext is framed by the stream
/// registry (all configured TLS protocol ports, HTTP/1 included).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn stream_capture_ports(config: &e_navigator_core::TlsSourceConfig) -> Vec<u16> {
    let mut ports = Vec::new();
    for list in [
        &config.http1_ports,
        &config.http2_ports,
        &config.kafka_ports,
        &config.mongodb_ports,
        &config.mysql_ports,
        &config.nats_ports,
        &config.postgresql_ports,
        &config.redis_ports,
    ] {
        for port in list {
            if *port != 0 && !ports.contains(port) {
                ports.push(*port);
            }
        }
    }
    ports
}

#[cfg(target_os = "linux")]
mod platform {
    use crate::diagnostics::SourceDiagnostics;
    use crate::perf_sample::perf_sample_bytes;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, perf::PerfEventArray},
        programs::{TracePoint, UProbe, uprobe::UProbeScope},
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, Source, TlsSourceConfig,
    };
    use e_navigator_signals::SignalEnvelope;
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, info, warn};

    /// One uprobe/uretprobe program paired with the exported symbol it hooks.
    struct UprobeBinding {
        program: &'static str,
        symbol: &'static str,
    }

    const OPENSSL_BINDINGS: &[UprobeBinding] = &[
        UprobeBinding {
            program: "uprobe_ssl_set_fd",
            symbol: "SSL_set_fd",
        },
        UprobeBinding {
            program: "uprobe_ssl_write_enter",
            symbol: "SSL_write",
        },
        UprobeBinding {
            program: "uretprobe_ssl_write_exit",
            symbol: "SSL_write",
        },
        UprobeBinding {
            program: "uprobe_ssl_read_enter",
            symbol: "SSL_read",
        },
        UprobeBinding {
            program: "uretprobe_ssl_read_exit",
            symbol: "SSL_read",
        },
        // OpenSSL 3 length-in-out-parameter variants (used by, for example,
        // CPython's _ssl). Absent on older OpenSSL and BoringSSL, which are
        // then accounted by the attach count.
        UprobeBinding {
            program: "uprobe_ssl_write_ex_enter",
            symbol: "SSL_write_ex",
        },
        UprobeBinding {
            program: "uretprobe_ssl_write_ex_exit",
            symbol: "SSL_write_ex",
        },
        UprobeBinding {
            program: "uprobe_ssl_read_ex_enter",
            symbol: "SSL_read_ex",
        },
        UprobeBinding {
            program: "uretprobe_ssl_read_ex_exit",
            symbol: "SSL_read_ex",
        },
    ];

    const GNUTLS_BINDINGS: &[UprobeBinding] = &[
        UprobeBinding {
            program: "uprobe_gnutls_transport_set_ptr",
            symbol: "gnutls_transport_set_ptr",
        },
        UprobeBinding {
            program: "uprobe_gnutls_record_send_enter",
            symbol: "gnutls_record_send",
        },
        UprobeBinding {
            program: "uretprobe_gnutls_record_send_exit",
            symbol: "gnutls_record_send",
        },
        UprobeBinding {
            program: "uprobe_gnutls_record_recv_enter",
            symbol: "gnutls_record_recv",
        },
        UprobeBinding {
            program: "uretprobe_gnutls_record_recv_exit",
            symbol: "gnutls_record_recv",
        },
    ];

    #[derive(Debug, Default)]
    pub struct AyaTlsSource {
        host: Option<String>,
        procfs_root: PathBuf,
        config: TlsSourceConfig,
    }

    impl AyaTlsSource {
        pub fn new(host: Option<String>, procfs_root: PathBuf, config: TlsSourceConfig) -> Self {
            Self {
                host,
                procfs_root,
                config,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaTlsSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_tls", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let diagnostics = SourceDiagnostics::from_env();
            let telemetry = Arc::new(SourceTelemetry::new("source.aya_tls"));
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            populate_capture_ports(&mut ebpf, &self.config)?;
            populate_capture_limit(&mut ebpf, &self.config)?;

            // Connection tuples come from the same connect/accept tracepoints
            // the cleartext protocol source uses; the uprobes resolve their
            // TLS handle to an fd and reuse those tuples.
            for (program, category, name) in [
                (
                    "tracepoint_protocol_connect_enter",
                    "syscalls",
                    "sys_enter_connect",
                ),
                (
                    "tracepoint_protocol_connect_exit",
                    "syscalls",
                    "sys_exit_connect",
                ),
                (
                    "tracepoint_protocol_close_enter",
                    "syscalls",
                    "sys_enter_close",
                ),
                (
                    "tracepoint_http_accept_enter",
                    "syscalls",
                    "sys_enter_accept",
                ),
                ("tracepoint_http_accept_exit", "syscalls", "sys_exit_accept"),
                (
                    "tracepoint_http_accept4_enter",
                    "syscalls",
                    "sys_enter_accept4",
                ),
                (
                    "tracepoint_http_accept4_exit",
                    "syscalls",
                    "sys_exit_accept4",
                ),
            ] {
                attach_tracepoint(&mut ebpf, program, category, name)?;
            }

            let libraries = discover_tls_libraries(&self.procfs_root);
            if libraries.openssl.is_empty() && libraries.gnutls.is_empty() {
                warn!(
                    source = "source.aya_tls",
                    "no OpenSSL/BoringSSL or GnuTLS libraries found in process maps; \
                     TLS capture will produce nothing until a TLS workload starts"
                );
            }
            let openssl_attached = attach_uprobes(&mut ebpf, OPENSSL_BINDINGS, &libraries.openssl);
            let gnutls_attached = attach_uprobes(&mut ebpf, GNUTLS_BINDINGS, &libraries.gnutls);
            info!(
                source = "source.aya_tls",
                openssl_libraries = libraries.openssl.len(),
                openssl_probes_attached = openssl_attached,
                gnutls_libraries = libraries.gnutls.len(),
                gnutls_probes_attached = gnutls_attached,
                "attached TLS uprobes"
            );
            let mut perf_array = PerfEventArray::try_from(
                ebpf.take_map("TLS_DATA_EVENTS")
                    .ok_or_else(|| module_message("missing TLS_DATA_EVENTS map"))?,
            )
            .map_err(module_error)?;

            let (sample_tx, mut sample_rx) =
                mpsc::channel::<Vec<u8>>(super::TLS_RAW_SAMPLE_CHANNEL_CAPACITY);

            let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
            for cpu_id in cpus {
                let mut buffer = perf_array
                    .open(cpu_id, Some(super::TLS_PERF_BUFFER_PAGE_COUNT))
                    .map_err(module_error)?;
                let reader_shutdown = shutdown.clone();
                let telemetry = telemetry.clone();
                let sample_tx = sample_tx.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;
                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }
                            match event {
                                aya::maps::perf::PerfEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail).into_owned();
                                    if sample_tx.blocking_send(bytes).is_err() {
                                        closed = true;
                                    }
                                }
                                aya::maps::perf::PerfEvent::Lost { count } => {
                                    telemetry.record_lost_perf_events(count);
                                    warn!(count, "lost TLS data perf events");
                                }
                            }
                        });
                        if closed {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(
                            super::TLS_PERF_READER_POLL_INTERVAL_MS,
                        ));
                    }
                }));
            }
            drop(sample_tx);

            let decoder_host = self.host.clone();
            let decoder_procfs_root = self.procfs_root.clone();
            let decoder_config = super::stream_protocol_config(&self.config);
            let decoder_shutdown = shutdown.clone();
            let decoder_telemetry = telemetry.clone();
            let _ = &diagnostics;
            reader_handles.push(tokio::task::spawn_blocking(move || {
                let mut registry = crate::protocol::ProtocolStreamRegistry::new(
                    decoder_host,
                    decoder_procfs_root,
                    &decoder_config,
                );
                let mut signals = Vec::new();

                while let Some(bytes) = sample_rx.blocking_recv() {
                    if decoder_shutdown.is_stopped() {
                        return;
                    }
                    signals.clear();
                    match registry.handle_event(&bytes, now_unix_nanos(), &mut signals) {
                        Ok(()) => {
                            decoder_telemetry.record_decoded_sample();
                            for signal in signals.drain(..) {
                                if tx.blocking_send(signal).is_err() {
                                    decoder_telemetry.record_send_failure();
                                    return;
                                }
                                decoder_telemetry.record_sent_signal();
                            }
                        }
                        Err(_) => {
                            decoder_telemetry.record_invalid_sample();
                        }
                    }
                    decoder_telemetry.maybe_log_summary();
                }
            }));

            debug!("aya tls source attached");
            tokio::signal::ctrl_c().await.map_err(module_error)?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    /// The OpenSSL/BoringSSL and GnuTLS shared objects mapped into any process.
    #[derive(Debug, Default)]
    struct DiscoveredTlsLibraries {
        openssl: Vec<PathBuf>,
        gnutls: Vec<PathBuf>,
    }

    /// Scans `/proc/<pid>/maps` for mapped TLS shared objects, returning the
    /// unique absolute paths so each distinct library version is probed.
    fn discover_tls_libraries(procfs_root: &Path) -> DiscoveredTlsLibraries {
        const MAX_SCANNED_PROCESSES: usize = 4096;
        let mut openssl = BTreeSet::new();
        let mut gnutls = BTreeSet::new();

        let Ok(entries) = std::fs::read_dir(procfs_root) else {
            return DiscoveredTlsLibraries::default();
        };
        let mut scanned = 0;
        for entry in entries.flatten() {
            if scanned >= MAX_SCANNED_PROCESSES {
                break;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            scanned += 1;
            let maps_path = entry.path().join("maps");
            let Ok(contents) = std::fs::read_to_string(&maps_path) else {
                continue;
            };
            for line in contents.lines() {
                let Some(path) = line.split_once(" /").map(|(_, rest)| rest) else {
                    continue;
                };
                let path = format!("/{path}");
                if let Some(basename) = Path::new(&path).file_name().and_then(|name| name.to_str())
                {
                    if basename.starts_with("libssl.so") {
                        openssl.insert(PathBuf::from(&path));
                    } else if basename.starts_with("libgnutls.so") {
                        gnutls.insert(PathBuf::from(&path));
                    }
                }
            }
        }

        DiscoveredTlsLibraries {
            openssl: openssl.into_iter().collect(),
            gnutls: gnutls.into_iter().collect(),
        }
    }

    /// Loads each program once and attaches it to every discovered library
    /// exporting its symbol. Libraries missing a symbol (for example a
    /// BoringSSL build without `SSL_set_fd`) are accounted by the lower count,
    /// never silently assumed present. Returns the number of successful
    /// (program, library) attachments.
    fn attach_uprobes(ebpf: &mut Ebpf, bindings: &[UprobeBinding], libraries: &[PathBuf]) -> usize {
        let mut attached = 0;
        for binding in bindings {
            let program: &mut UProbe = match ebpf
                .program_mut(binding.program)
                .and_then(|program| program.try_into().ok())
            {
                Some(program) => program,
                None => {
                    warn!(program = binding.program, "missing TLS uprobe program");
                    continue;
                }
            };
            if let Err(err) = program.load() {
                warn!(program = binding.program, error = %err, "failed to load TLS uprobe");
                continue;
            }
            for library in libraries {
                match program.attach(binding.symbol, library, UProbeScope::AllProcesses) {
                    Ok(_) => attached += 1,
                    Err(err) => {
                        debug!(
                            program = binding.program,
                            symbol = binding.symbol,
                            library = %library.display(),
                            error = %err,
                            "TLS symbol not attachable in library; accounting as unsupported"
                        );
                    }
                }
            }
        }
        attached
    }

    fn populate_capture_ports(ebpf: &mut Ebpf, config: &TlsSourceConfig) -> CoreResult<()> {
        let map = ebpf
            .map_mut("TLS_CAPTURE_PORTS")
            .ok_or_else(|| module_message("missing TLS_CAPTURE_PORTS map"))?;
        let mut ports: AyaHashMap<&mut MapData, u16, u32> =
            AyaHashMap::try_from(map).map_err(module_error)?;
        for port in super::stream_capture_ports(config) {
            ports.insert(port, 1, 0).map_err(module_error)?;
        }
        Ok(())
    }

    fn populate_capture_limit(ebpf: &mut Ebpf, config: &TlsSourceConfig) -> CoreResult<()> {
        let map = ebpf
            .map_mut("TLS_CAPTURE_LIMIT")
            .ok_or_else(|| module_message("missing TLS_CAPTURE_LIMIT map"))?;
        let mut limit: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(module_error)?;
        let capture_bytes = config.capture_bytes_per_call.clamp(
            TlsSourceConfig::MIN_CAPTURE_BYTES_PER_CALL,
            TlsSourceConfig::MAX_CAPTURE_BYTES_PER_CALL,
        ) as u32;
        limit.set(0, capture_bytes, 0).map_err(module_error)?;
        Ok(())
    }

    fn attach_tracepoint(
        ebpf: &mut Ebpf,
        program_name: &'static str,
        category: &'static str,
        name: &'static str,
    ) -> CoreResult<()> {
        let program: &mut TracePoint = ebpf
            .program_mut(program_name)
            .ok_or_else(|| module_message(&format!("missing {program_name} program")))?
            .try_into()
            .map_err(module_error)?;
        program.load().map_err(module_error)?;
        program.attach(category, name).map_err(module_error)?;
        Ok(())
    }

    fn now_unix_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
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
            module: "source.aya_tls".to_string(),
            message: err.to_string(),
        }
    }

    fn module_message(message: &str) -> CoreError {
        CoreError::ModuleFailed {
            module: "source.aya_tls".to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, Source, TlsSourceConfig,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaTlsSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
        _config: TlsSourceConfig,
    }

    impl AyaTlsSource {
        pub fn new(
            host: Option<String>,
            procfs_root: std::path::PathBuf,
            config: TlsSourceConfig,
        ) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
                _config: config,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaTlsSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_tls", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_tls".to_string(),
                message: format!(
                    "Aya TLS source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaTlsSource;

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::TlsSourceConfig;

    #[test]
    fn stream_capture_ports_includes_http1_and_dedupes() {
        let config = TlsSourceConfig {
            http1_ports: vec![443, 443],
            http2_ports: vec![8443],
            redis_ports: vec![6380],
            ..TlsSourceConfig::default()
        };
        let ports = stream_capture_ports(&config);
        assert!(ports.contains(&443));
        assert!(ports.contains(&8443));
        assert!(ports.contains(&6380));
        assert_eq!(ports.iter().filter(|port| **port == 443).count(), 1);
    }

    #[test]
    fn stream_protocol_config_maps_tls_ports() {
        let config = TlsSourceConfig {
            http1_ports: vec![443],
            http2_ports: vec![8443],
            postgresql_ports: vec![5433],
            max_attributes: 5,
            ..TlsSourceConfig::default()
        };
        let protocol = stream_protocol_config(&config);
        assert_eq!(protocol.http1_ports, vec![443]);
        assert_eq!(protocol.http2_ports, vec![8443]);
        assert_eq!(protocol.postgresql_ports, vec![5433]);
        assert_eq!(protocol.max_attributes, 5);
        // Cleartext defaults must not leak into the TLS-derived config.
        assert!(protocol.kafka_ports.is_empty());
        assert!(protocol.redis_ports.is_empty());
    }
}
