//! Bounded decoding and Linux attachment support for Go `crypto/tls` uprobes.

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};

const GO_BUILD_INFO_MAGIC: &[u8; 14] = b"\xff Go buildinf:";
const GO_BUILD_INFO_HEADER_BYTES: usize = 32;
const GO_BUILD_INFO_ALIGNMENT: usize = 16;
const GO_BUILD_INFO_INLINE_FLAG: u8 = 0x2;
const GO_BUILD_VERSION_MAX_BYTES: usize = 64;
const GO_TLS_MAX_FUNCTION_BYTES: usize = 1024 * 1024;
const GO_TLS_MAX_RETURN_SITES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoTlsLayout {
    pub(crate) sysfd_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoBuildVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) patch: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoBuildInfoError {
    MissingMagic,
    TruncatedHeader,
    LegacyPointerEncoding,
    InvalidVersionLength,
    InvalidVersionUtf8,
    UnsupportedVersionSyntax,
    UnsupportedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoReturnDecodeError {
    EmptyFunction,
    FunctionTooLarge,
    InvalidInstruction { offset: usize },
    MissingReturn,
    TooManyReturns,
}

pub(crate) fn parse_go_build_info(
    data: &[u8],
) -> Result<(GoBuildVersion, GoTlsLayout), GoBuildInfoError> {
    let Some(header_offset) = data
        .chunks(GO_BUILD_INFO_ALIGNMENT)
        .position(|chunk| chunk.starts_with(GO_BUILD_INFO_MAGIC))
        .map(|index| index.saturating_mul(GO_BUILD_INFO_ALIGNMENT))
    else {
        return Err(GoBuildInfoError::MissingMagic);
    };
    let header_end = header_offset.saturating_add(GO_BUILD_INFO_HEADER_BYTES);
    let Some(header) = data.get(header_offset..header_end) else {
        return Err(GoBuildInfoError::TruncatedHeader);
    };
    if header[15] & GO_BUILD_INFO_INLINE_FLAG == 0 {
        return Err(GoBuildInfoError::LegacyPointerEncoding);
    }

    let payload = data
        .get(header_end..)
        .ok_or(GoBuildInfoError::InvalidVersionLength)?;
    let (version_len, prefix_len) =
        decode_bounded_uvarint(payload).ok_or(GoBuildInfoError::InvalidVersionLength)?;
    let version_len =
        usize::try_from(version_len).map_err(|_| GoBuildInfoError::InvalidVersionLength)?;
    if version_len == 0 || version_len > GO_BUILD_VERSION_MAX_BYTES {
        return Err(GoBuildInfoError::InvalidVersionLength);
    }
    let start = prefix_len;
    let end = start
        .checked_add(version_len)
        .ok_or(GoBuildInfoError::InvalidVersionLength)?;
    let version = core::str::from_utf8(
        payload
            .get(start..end)
            .ok_or(GoBuildInfoError::InvalidVersionLength)?,
    )
    .map_err(|_| GoBuildInfoError::InvalidVersionUtf8)?;
    let version = parse_go_version(version)?;
    let layout = layout_for_version(version)?;
    Ok((version, layout))
}

fn decode_bounded_uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index.saturating_add(1)));
        }
        shift = shift.saturating_add(7);
    }
    None
}

fn parse_go_version(version: &str) -> Result<GoBuildVersion, GoBuildInfoError> {
    let Some(numbers) = version.strip_prefix("go") else {
        return Err(GoBuildInfoError::UnsupportedVersionSyntax);
    };
    let mut parts = numbers.split('.');
    let major = parse_version_component(parts.next())?;
    let minor = parse_version_component(parts.next())?;
    let patch = match parts.next() {
        Some(value) => parse_version_component(Some(value))?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(GoBuildInfoError::UnsupportedVersionSyntax);
    }
    Ok(GoBuildVersion {
        major,
        minor,
        patch,
    })
}

fn parse_version_component(value: Option<&str>) -> Result<u16, GoBuildInfoError> {
    let Some(value) = value else {
        return Err(GoBuildInfoError::UnsupportedVersionSyntax);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GoBuildInfoError::UnsupportedVersionSyntax);
    }
    value
        .parse::<u16>()
        .map_err(|_| GoBuildInfoError::UnsupportedVersionSyntax)
}

fn layout_for_version(version: GoBuildVersion) -> Result<GoTlsLayout, GoBuildInfoError> {
    if version.major != 1 || !(24..=26).contains(&version.minor) {
        return Err(GoBuildInfoError::UnsupportedVersion);
    }

    // Go 1.24 through 1.26 keep `internal/poll.FD.Sysfd` immediately after
    // the 16-byte `fdMutex`. The remaining path reached from
    // `net.(*netFD).Read`/`Write` starts at the method receiver itself.
    Ok(GoTlsLayout { sysfd_offset: 16 })
}

pub(crate) fn decode_go_amd64_return_offsets(
    function: &[u8],
) -> Result<Vec<u64>, GoReturnDecodeError> {
    if function.is_empty() {
        return Err(GoReturnDecodeError::EmptyFunction);
    }
    if function.len() > GO_TLS_MAX_FUNCTION_BYTES {
        return Err(GoReturnDecodeError::FunctionTooLarge);
    }

    let mut decoder = Decoder::new(64, function, DecoderOptions::NONE);
    let mut returns = Vec::new();
    while decoder.can_decode() {
        let offset = decoder.position();
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(GoReturnDecodeError::InvalidInstruction { offset });
        }
        if instruction.mnemonic() == Mnemonic::Ret {
            if returns.len() >= GO_TLS_MAX_RETURN_SITES {
                return Err(GoReturnDecodeError::TooManyReturns);
            }
            returns.push(u64::try_from(offset).unwrap_or(u64::MAX));
        }
    }
    if returns.is_empty() {
        return Err(GoReturnDecodeError::MissingReturn);
    }
    Ok(returns)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{
        GO_TLS_MAX_FUNCTION_BYTES, GoBuildVersion, GoTlsLayout, decode_go_amd64_return_offsets,
        parse_go_build_info,
    };
    use crate::source_telemetry::SourceTelemetry;
    use aya::{
        Ebpf,
        maps::{HashMap as AyaHashMap, MapData},
        programs::{UProbe, uprobe::UProbeLinkId, uprobe::UProbeScope},
    };
    use object::{
        Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::{Path, PathBuf},
    };
    use tracing::{info, warn};

    const GO_TLS_MAX_SCANNED_PROCESSES: usize = 4096;
    const GO_TLS_MAX_DISCOVERED_EXECUTABLES: usize = 1024;
    const GO_TLS_MAX_TRACKED_IDENTITIES: usize = 4096;
    const GO_TLS_MAX_CONFIGURED_PROCESSES: usize = 4096;
    const GO_TLS_MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    const GO_TLS_MAX_BUILD_INFO_BYTES: usize = 1024 * 1024;
    const GO_TLS_WARNING_LIMIT: usize = 64;

    const GO_TLS_PROGRAMS: &[&str] = &[
        "uprobe_go_tls_read_enter",
        "uprobe_go_tls_read_exit",
        "uprobe_go_tls_write_enter",
        "uprobe_go_tls_write_exit",
        "uprobe_go_netfd_read_enter",
        "uprobe_go_netfd_write_enter",
    ];

    const GO_TLS_READ: &str = "crypto/tls.(*Conn).Read";
    const GO_TLS_WRITE: &str = "crypto/tls.(*Conn).Write";
    const GO_NETFD_READ: &str = "net.(*netFD).Read";
    const GO_NETFD_WRITE: &str = "net.(*netFD).Write";

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct GoTlsLayoutAbi {
        pub(crate) sysfd_offset: u32,
        pub(crate) reserved: u32,
    }

    // SAFETY: `GoTlsLayoutAbi` is `repr(C)`, contains only two `u32` fields,
    // has no invalid bit patterns, pointers, references, or padding that is
    // read semantically, and exactly mirrors the eBPF map value layout.
    unsafe impl aya::Pod for GoTlsLayoutAbi {}

    impl From<GoTlsLayout> for GoTlsLayoutAbi {
        fn from(layout: GoTlsLayout) -> Self {
            Self {
                sysfd_offset: layout.sysfd_offset,
                reserved: 0,
            }
        }
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct GoTlsRescanSummary {
        pub(crate) ready_executables: usize,
        pub(crate) unsupported_executables: usize,
        pub(crate) attachment_failures: usize,
        pub(crate) probes_attached: usize,
        pub(crate) configured_processes: usize,
        pub(crate) capacity_rejections: usize,
        pub(crate) skipped_processes: usize,
        pub(crate) skipped_executables: usize,
    }

    impl GoTlsRescanSummary {
        pub(crate) fn is_empty(self) -> bool {
            self.ready_executables == 0
                && self.unsupported_executables == 0
                && self.attachment_failures == 0
                && self.probes_attached == 0
                && self.configured_processes == 0
                && self.capacity_rejections == 0
                && self.skipped_processes == 0
                && self.skipped_executables == 0
        }
    }

    #[derive(Debug)]
    struct DiscoveredGoExecutable {
        identity: (u64, u64),
        path: PathBuf,
        basename: String,
        pids: Vec<u32>,
    }

    #[derive(Debug, Default)]
    struct DiscoveredGoExecutables {
        executables: Vec<DiscoveredGoExecutable>,
        skipped_processes: usize,
        skipped_executables: usize,
    }

    #[derive(Debug, Clone, Copy)]
    struct ReadyGoExecutable {
        version: GoBuildVersion,
        layout: GoTlsLayoutAbi,
    }

    #[derive(Debug, Clone, Copy)]
    struct ProbeAttachment {
        program: &'static str,
        file_offset: u64,
    }

    #[derive(Debug)]
    struct ValidatedGoExecutable {
        version: GoBuildVersion,
        layout: GoTlsLayoutAbi,
        attachments: Vec<ProbeAttachment>,
    }

    #[derive(Debug)]
    enum ExecutableValidation {
        NotGo,
        Unavailable(String),
        Unsupported(String),
        Ready(ValidatedGoExecutable),
    }

    pub(crate) struct GoTlsRuntime {
        process_layouts: AyaHashMap<MapData, u32, GoTlsLayoutAbi>,
        ready: BTreeMap<(u64, u64), ReadyGoExecutable>,
        terminal: BTreeSet<(u64, u64)>,
        seen_go: BTreeSet<(u64, u64)>,
        active_pids: BTreeSet<u32>,
        warning_budget: usize,
    }

    impl core::fmt::Debug for GoTlsRuntime {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("GoTlsRuntime")
                .field("ready", &self.ready.len())
                .field("terminal", &self.terminal.len())
                .field("seen_go", &self.seen_go.len())
                .field("active_pids", &self.active_pids.len())
                .field("warning_budget", &self.warning_budget)
                .finish_non_exhaustive()
        }
    }

    impl GoTlsRuntime {
        pub(crate) fn initialize(ebpf: &mut Ebpf) -> Result<Self, String> {
            for name in GO_TLS_PROGRAMS {
                let program: &mut UProbe = ebpf
                    .program_mut(name)
                    .and_then(|program| program.try_into().ok())
                    .ok_or_else(|| format!("missing Go TLS uprobe program {name}"))?;
                program
                    .load()
                    .map_err(|error| format!("failed to load Go TLS uprobe {name}: {error}"))?;
            }

            let map = ebpf
                .take_map("GO_TLS_PROCESS_LAYOUTS")
                .ok_or_else(|| "missing GO_TLS_PROCESS_LAYOUTS map".to_string())?;
            let process_layouts = AyaHashMap::try_from(map)
                .map_err(|error| format!("invalid GO_TLS_PROCESS_LAYOUTS map: {error}"))?;
            Ok(Self {
                process_layouts,
                ready: BTreeMap::new(),
                terminal: BTreeSet::new(),
                seen_go: BTreeSet::new(),
                active_pids: BTreeSet::new(),
                warning_budget: GO_TLS_WARNING_LIMIT,
            })
        }

        pub(crate) fn rescan(
            &mut self,
            ebpf: &mut Ebpf,
            procfs_root: &Path,
            telemetry: &SourceTelemetry,
        ) -> GoTlsRescanSummary {
            let discovered = discover_go_executables(procfs_root);
            let mut summary = GoTlsRescanSummary {
                skipped_processes: discovered.skipped_processes,
                skipped_executables: discovered.skipped_executables,
                ..GoTlsRescanSummary::default()
            };
            telemetry.record_optional_capacity_rejections(
                discovered
                    .skipped_processes
                    .saturating_add(discovered.skipped_executables),
            );

            let mut desired = BTreeMap::new();
            for executable in &discovered.executables {
                if let Some(ready) = self.ready.get(&executable.identity).copied() {
                    add_desired_processes(&mut desired, executable, ready.layout, &mut summary);
                    continue;
                }
                if self.terminal.contains(&executable.identity) {
                    continue;
                }
                if !self.seen_go.contains(&executable.identity)
                    && self.seen_go.len() >= GO_TLS_MAX_TRACKED_IDENTITIES
                {
                    summary.capacity_rejections = summary.capacity_rejections.saturating_add(1);
                    self.warn_attachment(
                        &executable.basename,
                        "tracked Go executable identity capacity exhausted",
                    );
                    continue;
                }

                match validate_go_executable(&executable.path) {
                    ExecutableValidation::NotGo => {
                        self.terminal.insert(executable.identity);
                    }
                    ExecutableValidation::Unavailable(reason) => {
                        summary.attachment_failures = summary.attachment_failures.saturating_add(1);
                        telemetry.record_optional_attachment_failure();
                        self.warn_attachment(&executable.basename, &reason);
                    }
                    ExecutableValidation::Unsupported(reason) => {
                        if self.seen_go.insert(executable.identity) {
                            telemetry.record_optional_target_discovered();
                        }
                        self.terminal.insert(executable.identity);
                        summary.unsupported_executables =
                            summary.unsupported_executables.saturating_add(1);
                        telemetry.record_optional_target_unsupported();
                        self.warn_attachment(&executable.basename, &reason);
                    }
                    ExecutableValidation::Ready(validated) => {
                        if self.seen_go.insert(executable.identity) {
                            telemetry.record_optional_target_discovered();
                        }
                        match attach_executable_transaction(
                            ebpf,
                            &executable.path,
                            &validated.attachments,
                        ) {
                            Ok(attached) => {
                                let ready = ReadyGoExecutable {
                                    version: validated.version,
                                    layout: validated.layout,
                                };
                                self.ready.insert(executable.identity, ready);
                                summary.ready_executables =
                                    summary.ready_executables.saturating_add(1);
                                summary.probes_attached =
                                    summary.probes_attached.saturating_add(attached);
                                telemetry.record_optional_target_ready();
                                telemetry.record_optional_probe_attachments(attached);
                                add_desired_processes(
                                    &mut desired,
                                    executable,
                                    ready.layout,
                                    &mut summary,
                                );
                                info!(
                                    source = "source.aya_tls",
                                    executable = executable.basename,
                                    go_version = ready.version.label(),
                                    probes_attached = attached,
                                    "Go crypto/tls executable is capture-ready"
                                );
                            }
                            Err(reason) => {
                                summary.attachment_failures =
                                    summary.attachment_failures.saturating_add(1);
                                telemetry.record_optional_attachment_failure();
                                self.warn_attachment(&executable.basename, &reason);
                            }
                        }
                    }
                }
            }

            let desired_pids = desired.keys().copied().collect::<BTreeSet<_>>();
            let stale = self
                .active_pids
                .difference(&desired_pids)
                .copied()
                .collect::<Vec<_>>();
            for pid in stale {
                if let Err(error) = self.process_layouts.remove(&pid) {
                    summary.attachment_failures = summary.attachment_failures.saturating_add(1);
                    telemetry.record_optional_attachment_failure();
                    self.warn_attachment(
                        "process-layout-map",
                        &format!("failed to remove stale Go TLS process {pid}: {error}"),
                    );
                }
                self.active_pids.remove(&pid);
            }

            for (pid, layout) in desired {
                if self.active_pids.contains(&pid) {
                    continue;
                }
                match self.process_layouts.insert(pid, layout, 0) {
                    Ok(()) => {
                        self.active_pids.insert(pid);
                        summary.configured_processes =
                            summary.configured_processes.saturating_add(1);
                    }
                    Err(error) => {
                        summary.attachment_failures = summary.attachment_failures.saturating_add(1);
                        telemetry.record_optional_attachment_failure();
                        self.warn_attachment(
                            "process-layout-map",
                            &format!("failed to configure Go TLS process {pid}: {error}"),
                        );
                    }
                }
            }
            telemetry.record_optional_capacity_rejections(summary.capacity_rejections);
            summary
        }

        fn warn_attachment(&mut self, executable: &str, reason: &str) {
            if self.warning_budget == 0 {
                return;
            }
            self.warning_budget = self.warning_budget.saturating_sub(1);
            warn!(
                source = "source.aya_tls",
                executable,
                reason,
                remaining_go_tls_warnings = self.warning_budget,
                "Go crypto/tls executable is not capture-ready"
            );
        }
    }

    impl GoBuildVersion {
        fn label(self) -> String {
            format!("go{}.{}.{}", self.major, self.minor, self.patch)
        }
    }

    fn add_desired_processes(
        desired: &mut BTreeMap<u32, GoTlsLayoutAbi>,
        executable: &DiscoveredGoExecutable,
        layout: GoTlsLayoutAbi,
        summary: &mut GoTlsRescanSummary,
    ) {
        for pid in &executable.pids {
            if desired.len() >= GO_TLS_MAX_CONFIGURED_PROCESSES && !desired.contains_key(pid) {
                summary.capacity_rejections = summary.capacity_rejections.saturating_add(1);
                continue;
            }
            desired.insert(*pid, layout);
        }
    }

    fn discover_go_executables(procfs_root: &Path) -> DiscoveredGoExecutables {
        let Ok(entries) = std::fs::read_dir(procfs_root) else {
            return DiscoveredGoExecutables::default();
        };
        let mut executables: BTreeMap<(u64, u64), DiscoveredGoExecutable> = BTreeMap::new();
        let mut skipped_processes = 0_usize;
        let mut skipped_executables = 0_usize;
        let mut scanned = 0_usize;

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            if scanned >= GO_TLS_MAX_SCANNED_PROCESSES {
                skipped_processes = skipped_processes.saturating_add(1);
                continue;
            }
            scanned = scanned.saturating_add(1);
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let exe_link = entry.path().join("exe");
            let Ok(target) = std::fs::read_link(&exe_link) else {
                continue;
            };
            if target.as_os_str().to_string_lossy().ends_with(" (deleted)") {
                continue;
            }
            let resolved = if target.is_absolute() {
                entry
                    .path()
                    .join("root")
                    .join(target.strip_prefix("/").unwrap_or(target.as_path()))
            } else {
                entry.path().join(&target)
            };
            let Ok(metadata) = std::fs::metadata(&exe_link) else {
                continue;
            };
            use std::os::linux::fs::MetadataExt;
            let identity = (metadata.st_dev(), metadata.st_ino());
            if let Some(executable) = executables.get_mut(&identity) {
                if executable.pids.len() < GO_TLS_MAX_CONFIGURED_PROCESSES {
                    executable.pids.push(pid);
                } else {
                    skipped_processes = skipped_processes.saturating_add(1);
                }
                continue;
            }
            if executables.len() >= GO_TLS_MAX_DISCOVERED_EXECUTABLES {
                skipped_executables = skipped_executables.saturating_add(1);
                continue;
            }
            let basename = target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("go-executable")
                .to_string();
            executables.insert(
                identity,
                DiscoveredGoExecutable {
                    identity,
                    path: resolved,
                    basename,
                    pids: vec![pid],
                },
            );
        }

        DiscoveredGoExecutables {
            executables: executables.into_values().collect(),
            skipped_processes,
            skipped_executables,
        }
    }

    fn validate_go_executable(path: &Path) -> ExecutableValidation {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return ExecutableValidation::Unavailable(format!(
                    "executable metadata unavailable: {error}"
                ));
            }
        };
        if metadata.len() == 0 {
            return ExecutableValidation::NotGo;
        }
        if metadata.len() > GO_TLS_MAX_EXECUTABLE_BYTES {
            return ExecutableValidation::Unsupported(format!(
                "executable size {} is outside the supported 1..={GO_TLS_MAX_EXECUTABLE_BYTES} byte range",
                metadata.len()
            ));
        }
        let image = match std::fs::read(path) {
            Ok(image) => image,
            Err(error) => {
                return ExecutableValidation::Unavailable(format!(
                    "executable image is unreadable: {error}"
                ));
            }
        };
        let object = match object::File::parse(image.as_slice()) {
            Ok(object) => object,
            Err(_) => return ExecutableValidation::NotGo,
        };
        let Some(build_info) = object.section_by_name(".go.buildinfo") else {
            return ExecutableValidation::NotGo;
        };
        let build_info = match build_info.data() {
            Ok(data) if data.len() <= GO_TLS_MAX_BUILD_INFO_BYTES => data,
            Ok(data) => {
                return ExecutableValidation::Unsupported(format!(
                    ".go.buildinfo size {} exceeds {GO_TLS_MAX_BUILD_INFO_BYTES} bytes",
                    data.len()
                ));
            }
            Err(error) => {
                return ExecutableValidation::Unsupported(format!(
                    ".go.buildinfo is unreadable: {error}"
                ));
            }
        };
        let (version, layout) = match parse_go_build_info(build_info) {
            Ok(value) => value,
            Err(error) => {
                return ExecutableValidation::Unsupported(format!(
                    "unsupported or malformed Go build info ({error:?})"
                ));
            }
        };
        if object.format() != BinaryFormat::Elf || !object.is_64() {
            return ExecutableValidation::Unsupported(
                "Go TLS uprobes require a 64-bit ELF executable".to_string(),
            );
        }
        if object.architecture() != Architecture::X86_64 || std::env::consts::ARCH != "x86_64" {
            return ExecutableValidation::Unsupported(format!(
                "Go TLS ABI support is limited to linux/x86_64; executable={:?}, agent={}",
                object.architecture(),
                std::env::consts::ARCH
            ));
        }

        let mut attachments = Vec::new();
        for (symbol, entry_program, return_program) in [
            (
                GO_TLS_READ,
                "uprobe_go_tls_read_enter",
                Some("uprobe_go_tls_read_exit"),
            ),
            (
                GO_TLS_WRITE,
                "uprobe_go_tls_write_enter",
                Some("uprobe_go_tls_write_exit"),
            ),
            (GO_NETFD_READ, "uprobe_go_netfd_read_enter", None),
            (GO_NETFD_WRITE, "uprobe_go_netfd_write_enter", None),
        ] {
            let location = match resolve_exact_text_symbol(&object, symbol) {
                Ok(location) => location,
                Err(reason) => return ExecutableValidation::Unsupported(reason),
            };
            attachments.push(ProbeAttachment {
                program: entry_program,
                file_offset: location.file_offset,
            });
            if let Some(return_program) = return_program {
                let relative_returns = match decode_go_amd64_return_offsets(location.bytes) {
                    Ok(returns) => returns,
                    Err(error) => {
                        return ExecutableValidation::Unsupported(format!(
                            "{symbol} return-site decode failed ({error:?})"
                        ));
                    }
                };
                for relative in relative_returns {
                    let Some(file_offset) = location.file_offset.checked_add(relative) else {
                        return ExecutableValidation::Unsupported(format!(
                            "{symbol} return-site file offset overflowed"
                        ));
                    };
                    attachments.push(ProbeAttachment {
                        program: return_program,
                        file_offset,
                    });
                }
            }
        }

        ExecutableValidation::Ready(ValidatedGoExecutable {
            version,
            layout: layout.into(),
            attachments,
        })
    }

    #[derive(Debug, Clone, Copy)]
    struct TextSymbolLocation<'data> {
        file_offset: u64,
        bytes: &'data [u8],
    }

    fn resolve_exact_text_symbol<'data>(
        object: &object::File<'data>,
        required: &str,
    ) -> Result<TextSymbolLocation<'data>, String> {
        let mut matches = object.symbols().filter(|symbol| {
            !symbol.is_undefined()
                && symbol.kind() == SymbolKind::Text
                && symbol.name().ok() == Some(required)
        });
        let Some(symbol) = matches.next() else {
            return Err(format!(
                "required static Go symbol {required} is absent; stripped binaries fail closed"
            ));
        };
        if matches.next().is_some() {
            return Err(format!("required Go symbol {required} is ambiguous"));
        }
        let size = usize::try_from(symbol.size())
            .map_err(|_| format!("{required} size does not fit usize"))?;
        if size == 0 || size > GO_TLS_MAX_FUNCTION_BYTES {
            return Err(format!(
                "{required} size {size} is outside 1..={GO_TLS_MAX_FUNCTION_BYTES}"
            ));
        }
        let section_index = symbol
            .section_index()
            .ok_or_else(|| format!("{required} has no containing section"))?;
        let section = object
            .section_by_index(section_index)
            .map_err(|error| format!("{required} section is unavailable: {error}"))?;
        if section.kind() != SectionKind::Text {
            return Err(format!("{required} is not in a text section"));
        }
        let bytes = section
            .data_range(symbol.address(), symbol.size())
            .map_err(|error| format!("{required} bytes are unreadable: {error}"))?
            .ok_or_else(|| format!("{required} bytes fall outside its section"))?;
        let (section_file_offset, _) = section
            .file_range()
            .ok_or_else(|| format!("{required} section has no file range"))?;
        let relative = symbol
            .address()
            .checked_sub(section.address())
            .ok_or_else(|| format!("{required} address precedes its section"))?;
        let file_offset = section_file_offset
            .checked_add(relative)
            .ok_or_else(|| format!("{required} file offset overflowed"))?;
        Ok(TextSymbolLocation { file_offset, bytes })
    }

    fn attach_executable_transaction(
        ebpf: &mut Ebpf,
        executable: &Path,
        attachments: &[ProbeAttachment],
    ) -> Result<usize, String> {
        let mut links: Vec<(&'static str, UProbeLinkId)> = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let Some(program): Option<&mut UProbe> = ebpf
                .program_mut(attachment.program)
                .and_then(|program| program.try_into().ok())
            else {
                rollback_links(ebpf, links);
                return Err(format!(
                    "missing loaded Go TLS uprobe program {}",
                    attachment.program
                ));
            };
            match program.attach(
                attachment.file_offset,
                executable,
                UProbeScope::AllProcesses,
            ) {
                Ok(link_id) => links.push((attachment.program, link_id)),
                Err(error) => {
                    rollback_links(ebpf, links);
                    return Err(format!(
                        "{} attach at file offset {:#x} failed: {error}",
                        attachment.program, attachment.file_offset
                    ));
                }
            }
        }
        Ok(links.len())
    }

    fn rollback_links(ebpf: &mut Ebpf, links: Vec<(&'static str, UProbeLinkId)>) {
        for (program_name, link_id) in links {
            let Some(program): Option<&mut UProbe> = ebpf
                .program_mut(program_name)
                .and_then(|program| program.try_into().ok())
            else {
                continue;
            };
            if let Err(error) = program.detach(link_id) {
                warn!(
                    source = "source.aya_tls",
                    program = program_name,
                    error = %error,
                    "failed to roll back incomplete Go TLS uprobe attachment"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use platform::GoTlsRuntime;

#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_go_build_info(data: &[u8]) -> usize {
    parse_go_build_info(data)
        .map(|(version, layout)| {
            usize::from(version.major)
                .saturating_add(usize::from(version.minor))
                .saturating_add(usize::from(version.patch))
                .saturating_add(layout.sysfd_offset as usize)
        })
        .unwrap_or(0)
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_go_amd64_returns(data: &[u8]) -> usize {
    decode_go_amd64_return_offsets(data)
        .map(|offsets| offsets.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn inline_build_info(version: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; GO_BUILD_INFO_HEADER_BYTES];
        bytes[..GO_BUILD_INFO_MAGIC.len()].copy_from_slice(GO_BUILD_INFO_MAGIC);
        bytes[14] = 8;
        bytes[15] = GO_BUILD_INFO_INLINE_FLAG;
        bytes.push(u8::try_from(version.len()).unwrap_or(u8::MAX));
        bytes.extend_from_slice(version);
        bytes
    }

    #[test]
    fn supported_go_versions_select_the_audited_layout() {
        for (version, expected) in [
            (
                b"go1.24.0".as_slice(),
                GoBuildVersion {
                    major: 1,
                    minor: 24,
                    patch: 0,
                },
            ),
            (
                b"go1.25.9",
                GoBuildVersion {
                    major: 1,
                    minor: 25,
                    patch: 9,
                },
            ),
            (
                b"go1.26.4",
                GoBuildVersion {
                    major: 1,
                    minor: 26,
                    patch: 4,
                },
            ),
        ] {
            assert_eq!(
                parse_go_build_info(&inline_build_info(version)),
                Ok((expected, GoTlsLayout { sysfd_offset: 16 }))
            );
        }
    }

    #[test]
    fn unsupported_or_prerelease_go_versions_fail_closed() {
        for version in [
            b"go1.23.12".as_slice(),
            b"go1.27.0",
            b"go1.26rc1",
            b"devel go1.27-deadbeef",
        ] {
            assert!(parse_go_build_info(&inline_build_info(version)).is_err());
        }
    }

    #[test]
    fn amd64_decoder_finds_every_near_return() {
        let function = [0x55, 0x48, 0x89, 0xe5, 0xc3, 0x90, 0xc2, 0x08, 0x00];
        assert_eq!(decode_go_amd64_return_offsets(&function), Ok(vec![4, 6]));
    }

    #[test]
    fn amd64_decoder_rejects_unbounded_or_returnless_input() {
        assert_eq!(
            decode_go_amd64_return_offsets(&[]),
            Err(GoReturnDecodeError::EmptyFunction)
        );
        assert_eq!(
            decode_go_amd64_return_offsets(&[0x90]),
            Err(GoReturnDecodeError::MissingReturn)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_build_info_never_escapes_version_and_layout_bounds(data in prop::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok((version, layout)) = parse_go_build_info(&data) {
                prop_assert_eq!(version.major, 1);
                prop_assert!((24..=26).contains(&version.minor));
                prop_assert_eq!(layout.sysfd_offset, 16);
            }
        }

        #[test]
        fn arbitrary_instruction_stream_returns_sorted_in_bounds_offsets(data in prop::collection::vec(any::<u8>(), 0..8192)) {
            if let Ok(offsets) = decode_go_amd64_return_offsets(&data) {
                prop_assert!(!offsets.is_empty());
                prop_assert!(offsets.len() <= GO_TLS_MAX_RETURN_SITES);
                prop_assert!(offsets.windows(2).all(|window| window[0] < window[1]));
                prop_assert!(offsets.iter().all(|offset| (*offset as usize) < data.len()));
            }
        }
    }
}
