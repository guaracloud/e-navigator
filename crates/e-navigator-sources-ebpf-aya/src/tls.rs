//! Uprobe-based TLS plaintext capture source (`source.aya_tls`).
//!
//! This is library-boundary interception: uprobes on the userspace TLS
//! read/write calls (version-gated OpenSSL `SSL_read`/`SSL_write`, GnuTLS
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
/// How often to rescan process maps for newly loaded TLS libraries.
#[cfg(target_os = "linux")]
const TLS_LIBRARY_RESCAN_SECS: u64 = 15;
#[cfg(target_os = "linux")]
const TLS_MAX_SCANNED_PROCESSES: usize = 4096;
#[cfg(target_os = "linux")]
const TLS_MAX_DISCOVERED_LIBRARIES: usize = 1024;
#[cfg(target_os = "linux")]
const TLS_MAX_TRACKED_LIBRARY_IDENTITIES: usize = 4096;
#[cfg(target_os = "linux")]
const TLS_MAX_LIBRARY_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(target_os = "linux")]
const TLS_ATTACHMENT_WARNING_LIMIT: usize = 64;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsLibraryKind {
    OpenSsl1_1,
    OpenSsl3,
    GnuTls30,
}

#[cfg(target_os = "linux")]
impl TlsLibraryKind {
    const fn label(self) -> &'static str {
        match self {
            Self::OpenSsl1_1 => "openssl_1_1",
            Self::OpenSsl3 => "openssl_3",
            Self::GnuTls30 => "gnutls_30",
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsLibraryClassification {
    Supported(TlsLibraryKind),
    UnsupportedOpenSsl,
    UnsupportedGnuTls,
}

#[cfg(any(target_os = "linux", test))]
fn classify_tls_library_basename(basename: &str) -> Option<TlsLibraryClassification> {
    let versioned_name = |prefix: &str| {
        basename == prefix
            || basename
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('.'))
    };
    if versioned_name("libssl.so.1.1") {
        Some(TlsLibraryClassification::Supported(
            TlsLibraryKind::OpenSsl1_1,
        ))
    } else if versioned_name("libssl.so.3") {
        Some(TlsLibraryClassification::Supported(
            TlsLibraryKind::OpenSsl3,
        ))
    } else if basename.starts_with("libssl.so") {
        Some(TlsLibraryClassification::UnsupportedOpenSsl)
    } else if versioned_name("libgnutls.so.30") {
        Some(TlsLibraryClassification::Supported(
            TlsLibraryKind::GnuTls30,
        ))
    } else if basename.starts_with("libgnutls.so") {
        Some(TlsLibraryClassification::UnsupportedGnuTls)
    } else {
        None
    }
}

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
    use crate::diagnostics::{DiagnosticSampleDecision, SourceDiagnostics};
    use crate::perf_sample::InlineSample;
    use crate::reader_shutdown::ReaderShutdown;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, perf::PerfEventArray},
        programs::{TracePoint, UProbe, uprobe::UProbeLinkId, uprobe::UProbeScope},
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, Source, TlsSourceConfig,
    };
    use e_navigator_signals::SignalEnvelope;
    use object::{Architecture, BinaryFormat, Object, ObjectSymbol};
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::{Path, PathBuf},
        sync::Arc,
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
            program: "uprobe_ssl_set_fd_enter",
            symbol: "SSL_set_fd",
        },
        UprobeBinding {
            program: "uretprobe_ssl_set_fd_exit",
            symbol: "SSL_set_fd",
        },
        UprobeBinding {
            program: "uprobe_ssl_set_rfd_enter",
            symbol: "SSL_set_rfd",
        },
        UprobeBinding {
            program: "uretprobe_ssl_set_rfd_exit",
            symbol: "SSL_set_rfd",
        },
        UprobeBinding {
            program: "uprobe_ssl_set_wfd_enter",
            symbol: "SSL_set_wfd",
        },
        UprobeBinding {
            program: "uretprobe_ssl_set_wfd_exit",
            symbol: "SSL_set_wfd",
        },
        UprobeBinding {
            program: "uprobe_ssl_free",
            symbol: "SSL_free",
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
        // Length-in-out-parameter variants used by OpenSSL 1.1.1 and 3.x.
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
            program: "uprobe_gnutls_transport_set_int2",
            symbol: "gnutls_transport_set_int2",
        },
        UprobeBinding {
            program: "uprobe_gnutls_deinit",
            symbol: "gnutls_deinit",
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

            load_uprobe_programs(&mut ebpf, OPENSSL_BINDINGS);
            load_uprobe_programs(&mut ebpf, GNUTLS_BINDINGS);
            let mut seen_libraries: BTreeSet<(u64, u64)> = BTreeSet::new();
            let mut terminal_libraries: BTreeSet<(u64, u64)> = BTreeSet::new();
            let mut warning_budget = super::TLS_ATTACHMENT_WARNING_LIMIT;
            warn!(
                source = "source.aya_tls",
                "TLS plaintext capture is limited to dynamically linked OpenSSL 1.1.1/3.x and \
                 GnuTLS ABI 30 using standard socket descriptors; Go crypto/tls, rustls, \
                 statically bundled Node TLS, JVM JSSE, BoringSSL, custom BIOs, and custom \
                 GnuTLS transports are not captured"
            );
            let libraries = discover_tls_libraries(&self.procfs_root);
            telemetry.record_optional_rescan();
            telemetry.record_optional_capacity_rejections(
                libraries
                    .skipped_processes
                    .saturating_add(libraries.skipped_libraries),
            );
            let attachment = attach_discovered_libraries(
                &mut ebpf,
                &libraries.libraries,
                &mut seen_libraries,
                &mut terminal_libraries,
                &telemetry,
                &mut warning_budget,
            );
            if attachment.ready_libraries == 0 {
                warn!(
                    source = "source.aya_tls",
                    "no complete, supported TLS library attachment is ready yet; supported \
                     libraries are rescanned periodically"
                );
            }
            info!(
                source = "source.aya_tls",
                ready_libraries = attachment.ready_libraries,
                unsupported_libraries = attachment.unsupported_libraries,
                attachment_failures = attachment.attachment_failures,
                probes_attached = attachment.probes_attached,
                skipped_processes = libraries.skipped_processes,
                skipped_libraries = libraries.skipped_libraries,
                "completed TLS library discovery"
            );
            if let Some(handle) =
                crate::capture_filter::attach_capture_filter(&mut ebpf, "source.aya_tls", {
                    let shutdown = shutdown.clone();
                    move || shutdown.is_stopped()
                })?
            {
                reader_handles.push(handle);
            }

            let mut perf_array = PerfEventArray::try_from(
                ebpf.take_map("TLS_DATA_EVENTS")
                    .ok_or_else(|| module_message("missing TLS_DATA_EVENTS map"))?,
            )
            .map_err(module_error)?;

            let (sample_tx, mut sample_rx) =
                mpsc::channel::<InlineSample>(super::TLS_RAW_SAMPLE_CHANNEL_CAPACITY);

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
                                    let Some(sample) = InlineSample::from_perf(head, tail) else {
                                        telemetry.record_lost_perf_events(1);
                                        return;
                                    };
                                    if sample_tx.blocking_send(sample).is_err() {
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
            let decoder_diagnostics = diagnostics.clone();
            reader_handles.push(tokio::task::spawn_blocking(move || {
                let mut registry = crate::protocol::ProtocolStreamRegistry::new_with_source(
                    decoder_host,
                    decoder_procfs_root,
                    &decoder_config,
                    "source.aya_tls",
                );
                let mut signals = Vec::new();

                while let Some(sample) = sample_rx.blocking_recv() {
                    if decoder_shutdown.is_stopped() {
                        return;
                    }
                    signals.clear();
                    let result =
                        registry.handle_event(sample.as_bytes(), now_unix_nanos(), &mut signals);
                    let diagnostic_decision = log_tls_sample_diagnostic(
                        &decoder_diagnostics,
                        sample.as_bytes(),
                        registry.counters(),
                        registry.tracked_connections(),
                        signals.len(),
                        result.err(),
                    );
                    decoder_telemetry.record_diagnostic_decision(diagnostic_decision);
                    match result {
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

            if diagnostics.enabled() {
                info!(
                    source = "source.aya_tls",
                    remaining_samples = diagnostics.remaining_samples(),
                    "source diagnostics enabled"
                );
            }

            telemetry.mark_initialized();
            debug!("aya tls source attached");
            // TLS libraries mapped by processes that start after the agent are
            // picked up on this cadence, so late-starting workloads are not
            // silently missed.
            let rescan_interval = std::time::Duration::from_secs(super::TLS_LIBRARY_RESCAN_SECS);
            loop {
                tokio::select! {
                    result = crate::shutdown::signal() => {
                        result.map_err(module_error)?;
                        break;
                    }
                    _ = tokio::time::sleep(rescan_interval) => {
                        let libraries = discover_tls_libraries(&self.procfs_root);
                        telemetry.record_optional_rescan();
                        telemetry.record_optional_capacity_rejections(
                            libraries.skipped_processes.saturating_add(libraries.skipped_libraries),
                        );
                        let attachment = attach_discovered_libraries(
                            &mut ebpf,
                            &libraries.libraries,
                            &mut seen_libraries,
                            &mut terminal_libraries,
                            &telemetry,
                            &mut warning_budget,
                        );
                        if !attachment.is_empty()
                            || libraries.skipped_processes > 0
                            || libraries.skipped_libraries > 0
                        {
                            info!(
                                source = "source.aya_tls",
                                ready_libraries = attachment.ready_libraries,
                                unsupported_libraries = attachment.unsupported_libraries,
                                attachment_failures = attachment.attachment_failures,
                                probes_attached = attachment.probes_attached,
                                skipped_processes = libraries.skipped_processes,
                                skipped_libraries = libraries.skipped_libraries,
                                "completed periodic TLS library discovery"
                            );
                        }
                    }
                }
            }
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    #[derive(Debug)]
    struct DiscoveredTlsLibrary {
        identity: (u64, u64),
        path: PathBuf,
        basename: String,
        classification: super::TlsLibraryClassification,
    }

    /// Version-classified OpenSSL and GnuTLS shared objects mapped into any
    /// process, plus explicit capacity diagnostics for a bounded scan.
    #[derive(Debug, Default)]
    struct DiscoveredTlsLibraries {
        libraries: Vec<DiscoveredTlsLibrary>,
        skipped_processes: usize,
        skipped_libraries: usize,
    }

    /// Scans `/proc/<pid>/maps` for mapped TLS shared objects. Library
    /// paths are resolved through `<procfs>/<pid>/root/<path>` so files in
    /// other mount namespaces (container workloads) are attachable, and
    /// deduplicated by (device, inode) so each distinct library file is
    /// considered exactly once no matter how many processes map it.
    fn discover_tls_libraries(procfs_root: &Path) -> DiscoveredTlsLibraries {
        let mut libraries = BTreeMap::new();
        let mut skipped_processes = 0_usize;
        let mut skipped_libraries = 0_usize;

        let Ok(entries) = std::fs::read_dir(procfs_root) else {
            return DiscoveredTlsLibraries::default();
        };
        let mut scanned = 0;
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            if scanned >= super::TLS_MAX_SCANNED_PROCESSES {
                skipped_processes = skipped_processes.saturating_add(1);
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
                let Some(basename) = Path::new(&path).file_name().and_then(|name| name.to_str())
                else {
                    continue;
                };
                let Some(classification) = super::classify_tls_library_basename(basename) else {
                    continue;
                };
                let resolved = entry.path().join("root").join(path.trim_start_matches('/'));
                let Ok(metadata) = std::fs::metadata(&resolved) else {
                    continue;
                };
                use std::os::linux::fs::MetadataExt;
                let identity = (metadata.st_dev(), metadata.st_ino());
                if libraries.contains_key(&identity) {
                    continue;
                }
                if libraries.len() >= super::TLS_MAX_DISCOVERED_LIBRARIES {
                    skipped_libraries = skipped_libraries.saturating_add(1);
                    continue;
                }
                libraries.insert(
                    identity,
                    DiscoveredTlsLibrary {
                        identity,
                        path: resolved,
                        basename: basename.to_string(),
                        classification,
                    },
                );
            }
        }

        DiscoveredTlsLibraries {
            libraries: libraries.into_values().collect(),
            skipped_processes,
            skipped_libraries,
        }
    }

    /// Loads each uprobe program once so it can later be attached to any
    /// number of library files. Loading is separate from attaching because a
    /// program is attached to every discovered library and re-attached to
    /// libraries that appear after startup.
    fn load_uprobe_programs(ebpf: &mut Ebpf, bindings: &[UprobeBinding]) {
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
            }
        }
    }

    #[derive(Debug, Default)]
    struct AttachmentSummary {
        ready_libraries: usize,
        unsupported_libraries: usize,
        attachment_failures: usize,
        probes_attached: usize,
        capacity_rejections: usize,
    }

    impl AttachmentSummary {
        fn is_empty(&self) -> bool {
            self.ready_libraries == 0
                && self.unsupported_libraries == 0
                && self.attachment_failures == 0
                && self.probes_attached == 0
                && self.capacity_rejections == 0
        }
    }

    fn attach_discovered_libraries(
        ebpf: &mut Ebpf,
        libraries: &[DiscoveredTlsLibrary],
        seen_identities: &mut BTreeSet<(u64, u64)>,
        terminal_identities: &mut BTreeSet<(u64, u64)>,
        telemetry: &SourceTelemetry,
        warning_budget: &mut usize,
    ) -> AttachmentSummary {
        let mut summary = AttachmentSummary::default();
        for library in libraries {
            if terminal_identities.contains(&library.identity) {
                continue;
            }
            if !seen_identities.contains(&library.identity)
                && seen_identities.len() >= super::TLS_MAX_TRACKED_LIBRARY_IDENTITIES
            {
                summary.capacity_rejections = summary.capacity_rejections.saturating_add(1);
                telemetry.record_optional_capacity_rejections(1);
                warn_tls_attachment(
                    warning_budget,
                    &library.basename,
                    "tracked TLS library identity capacity exhausted",
                );
                continue;
            }
            if seen_identities.insert(library.identity) {
                telemetry.record_optional_target_discovered();
            }

            let kind = match library.classification {
                super::TlsLibraryClassification::Supported(kind) => kind,
                super::TlsLibraryClassification::UnsupportedOpenSsl => {
                    terminal_identities.insert(library.identity);
                    summary.unsupported_libraries = summary.unsupported_libraries.saturating_add(1);
                    telemetry.record_optional_target_unsupported();
                    warn_tls_attachment(
                        warning_budget,
                        &library.basename,
                        "unsupported or unversioned OpenSSL-compatible ABI; skipped fail-closed",
                    );
                    continue;
                }
                super::TlsLibraryClassification::UnsupportedGnuTls => {
                    terminal_identities.insert(library.identity);
                    summary.unsupported_libraries = summary.unsupported_libraries.saturating_add(1);
                    telemetry.record_optional_target_unsupported();
                    warn_tls_attachment(
                        warning_budget,
                        &library.basename,
                        "unsupported or unversioned GnuTLS ABI; skipped fail-closed",
                    );
                    continue;
                }
            };

            let bindings = bindings_for_kind(kind);
            if let Err(reason) = validate_library_image(&library.path, kind, bindings) {
                terminal_identities.insert(library.identity);
                summary.unsupported_libraries = summary.unsupported_libraries.saturating_add(1);
                summary.attachment_failures = summary.attachment_failures.saturating_add(1);
                telemetry.record_optional_target_unsupported();
                telemetry.record_optional_attachment_failure();
                warn_tls_attachment(warning_budget, &library.basename, &reason);
                continue;
            }
            match attach_library_transaction(ebpf, &library.path, kind, bindings) {
                Ok(attached) => {
                    terminal_identities.insert(library.identity);
                    summary.ready_libraries = summary.ready_libraries.saturating_add(1);
                    summary.probes_attached = summary.probes_attached.saturating_add(attached);
                    telemetry.record_optional_target_ready();
                    telemetry.record_optional_probe_attachments(attached);
                }
                Err(reason) => {
                    summary.attachment_failures = summary.attachment_failures.saturating_add(1);
                    telemetry.record_optional_attachment_failure();
                    warn_tls_attachment(warning_budget, &library.basename, &reason);
                }
            }
        }
        summary
    }

    fn bindings_for_kind(kind: super::TlsLibraryKind) -> &'static [UprobeBinding] {
        match kind {
            super::TlsLibraryKind::OpenSsl1_1 | super::TlsLibraryKind::OpenSsl3 => OPENSSL_BINDINGS,
            super::TlsLibraryKind::GnuTls30 => GNUTLS_BINDINGS,
        }
    }

    fn attach_library_transaction(
        ebpf: &mut Ebpf,
        library: &Path,
        kind: super::TlsLibraryKind,
        bindings: &'static [UprobeBinding],
    ) -> Result<usize, String> {
        let mut links: Vec<(&'static str, UProbeLinkId)> = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let Some(program): Option<&mut UProbe> = ebpf
                .program_mut(binding.program)
                .and_then(|program| program.try_into().ok())
            else {
                rollback_uprobe_links(ebpf, links);
                return Err(format!("missing loaded uprobe program {}", binding.program));
            };
            let result = program.attach(binding.symbol, library, UProbeScope::AllProcesses);
            match result {
                Ok(link_id) => links.push((binding.program, link_id)),
                Err(err) => {
                    rollback_uprobe_links(ebpf, links);
                    return Err(format!(
                        "{} attachment failed for {}: {err}",
                        binding.symbol,
                        kind.label()
                    ));
                }
            }
        }
        Ok(links.len())
    }

    fn rollback_uprobe_links(ebpf: &mut Ebpf, links: Vec<(&'static str, UProbeLinkId)>) {
        for (program_name, link_id) in links {
            let Some(program): Option<&mut UProbe> = ebpf
                .program_mut(program_name)
                .and_then(|program| program.try_into().ok())
            else {
                continue;
            };
            if let Err(err) = program.detach(link_id) {
                warn!(
                    program = program_name,
                    error = %err,
                    "failed to roll back incomplete TLS uprobe attachment"
                );
            }
        }
    }

    fn validate_library_image(
        library: &Path,
        kind: super::TlsLibraryKind,
        bindings: &[UprobeBinding],
    ) -> Result<(), String> {
        let metadata = std::fs::metadata(library)
            .map_err(|err| format!("{} metadata unavailable: {err}", kind.label()))?;
        if metadata.len() == 0 || metadata.len() > super::TLS_MAX_LIBRARY_BYTES {
            return Err(format!(
                "{} image size {} is outside the supported 1..={} byte range",
                kind.label(),
                metadata.len(),
                super::TLS_MAX_LIBRARY_BYTES
            ));
        }
        let image = std::fs::read(library)
            .map_err(|err| format!("{} image unreadable: {err}", kind.label()))?;
        let object = object::File::parse(image.as_slice())
            .map_err(|err| format!("{} image is not a valid object: {err}", kind.label()))?;
        if object.format() != BinaryFormat::Elf || !object.is_64() {
            return Err(format!(
                "{} image is not a supported 64-bit ELF object",
                kind.label()
            ));
        }
        let expected_architecture = match std::env::consts::ARCH {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            other => {
                return Err(format!(
                    "agent architecture {other} is unsupported for TLS uprobes"
                ));
            }
        };
        if object.architecture() != expected_architecture {
            return Err(format!(
                "{} architecture {:?} does not match agent architecture {:?}",
                kind.label(),
                object.architecture(),
                expected_architecture
            ));
        }

        let mut required = bindings
            .iter()
            .map(|binding| binding.symbol)
            .collect::<BTreeSet<_>>();
        for symbol in object.dynamic_symbols() {
            if symbol.is_undefined() {
                continue;
            }
            if let Ok(name) = symbol.name() {
                required.remove(name);
            }
        }
        if required.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} image lacks required exported symbols: {}",
                kind.label(),
                required.into_iter().collect::<Vec<_>>().join(",")
            ))
        }
    }

    fn warn_tls_attachment(warning_budget: &mut usize, basename: &str, reason: &str) {
        if *warning_budget == 0 {
            return;
        }
        *warning_budget -= 1;
        warn!(
            source = "source.aya_tls",
            library = basename,
            reason,
            remaining_attachment_warnings = *warning_budget,
            "TLS library is not capture-ready"
        );
    }

    fn log_tls_sample_diagnostic(
        diagnostics: &SourceDiagnostics,
        bytes: &[u8],
        counters: crate::protocol::ProtocolRegistryCounters,
        tracked_connections: usize,
        emitted_signals: usize,
        error: Option<crate::protocol::RawProtocolDecodeError>,
    ) -> DiagnosticSampleDecision {
        if !diagnostics.enabled() {
            return DiagnosticSampleDecision::Disabled;
        }
        let raw = (bytes.len() >= core::mem::size_of::<crate::protocol::RawProtocolDataEvent>())
            .then(|| unsafe {
                core::ptr::read_unaligned(
                    bytes
                        .as_ptr()
                        .cast::<crate::protocol::RawProtocolDataEvent>(),
                )
            });
        let command = raw
            .map(|raw| {
                let end = raw
                    .command
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(raw.command.len());
                String::from_utf8_lossy(&raw.command[..end]).into_owned()
            })
            .unwrap_or_default();
        let reason = error.map_or("decoded", |error| error.reason_name());
        let decision = diagnostics.sample_decision_for(&[command.as_str(), reason]);
        if decision != DiagnosticSampleDecision::Matched {
            return decision;
        }
        info!(
            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
            source = "source.aya_tls",
            raw_event = "tls_protocol_data_sample",
            result = reason,
            pid = ?raw.map(|raw| raw.pid),
            command = ?diagnostics.redact_optional_value((!command.is_empty()).then_some(command.as_str())),
            fd = ?raw.map(|raw| raw.fd),
            direction = ?raw.map(|raw| raw.direction),
            role = ?raw.map(|raw| raw.role),
            remote_port = ?raw.map(|raw| u16::from_be(raw.remote_port_be)),
            local_port = ?raw.map(|raw| u16::from_be(raw.local_port_be)),
            payload_len = ?raw.map(|raw| raw.payload_len),
            payload_total_len = ?raw.map(|raw| raw.payload_total_len),
            payload_offset = ?raw.map(|raw| raw.payload_offset),
            payload_captured_len = ?raw.map(|raw| raw.payload_captured_len),
            emitted_signals,
            tracked_connections,
            unparsed_frames = counters.unparsed_frames,
            truncated_frames = counters.truncated_frames,
            matched_responses = counters.matched_responses,
            orphan_responses = counters.orphan_responses,
            unparsed_responses = counters.unparsed_responses,
            segment_gaps = counters.segment_gaps,
            "source diagnostic TLS sample processed"
        );
        DiagnosticSampleDecision::Matched
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

    #[test]
    fn tls_library_versions_are_classified_fail_closed() {
        assert_eq!(
            classify_tls_library_basename("libssl.so.1.1"),
            Some(TlsLibraryClassification::Supported(
                TlsLibraryKind::OpenSsl1_1
            ))
        );
        assert_eq!(
            classify_tls_library_basename("libssl.so.3.4.0"),
            Some(TlsLibraryClassification::Supported(
                TlsLibraryKind::OpenSsl3
            ))
        );
        assert_eq!(
            classify_tls_library_basename("libgnutls.so.30.42.0"),
            Some(TlsLibraryClassification::Supported(
                TlsLibraryKind::GnuTls30
            ))
        );
        assert_eq!(
            classify_tls_library_basename("libssl.so"),
            Some(TlsLibraryClassification::UnsupportedOpenSsl)
        );
        assert_eq!(
            classify_tls_library_basename("libssl.so.4"),
            Some(TlsLibraryClassification::UnsupportedOpenSsl)
        );
        assert_eq!(
            classify_tls_library_basename("libgnutls.so.31"),
            Some(TlsLibraryClassification::UnsupportedGnuTls)
        );
        assert_eq!(classify_tls_library_basename("libcrypto.so.3"), None);
    }
}
