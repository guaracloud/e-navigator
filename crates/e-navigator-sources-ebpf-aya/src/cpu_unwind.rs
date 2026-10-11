//! Userspace side of the in-kernel DWARF unwinder: builds `.eh_frame`
//! unwind tables for running processes and ships them to the eBPF maps
//! (`UNWIND_ROWS` / `UNWIND_MODULES` / `UNWIND_PROC_MAPPINGS`).
//!
//! Module files are read through `<procfs>/<pid>/root/<path>` so tables
//! resolve correctly across mount namespaces, cached by (device, inode).
//! Every bound - row pool, mapping count, process count - degrades with
//! counters, never silently.

#[cfg(any(target_os = "linux", test))]
use e_navigator_profiling::symbolize::ProcessModuleMap;
#[cfg(any(target_os = "linux", test))]
use e_navigator_profiling::unwind::{
    CfaRule, ElfUnwindTable, FpRule, LoadSegment, RaRule, parse_load_segments,
};

/// Mirrors the eBPF row pool size; the manager never allocates past it.
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_ROW_POOL: u32 = 262_144;
// Must stay a power of two and match the eBPF side; the in-kernel
// mapping lookup masks the index with `UNWIND_MAX_MAPPINGS - 1`.
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_MAX_MAPPINGS: usize = 32;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_MAX_MODULES: usize = 512;

/// Row rule kinds shared with the eBPF program.
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_CFA_INVALID: u8 = 0;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_CFA_SP: u8 = 1;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_CFA_FP: u8 = 2;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_CFA_UNSUPPORTED: u8 = 3;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_RA_CFA_OFFSET: u8 = 0;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_RA_LINK_REGISTER: u8 = 1;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_RA_UNDEFINED: u8 = 2;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_RA_UNSUPPORTED: u8 = 3;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_FP_PRESERVED: u8 = 0;
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_FP_CFA_OFFSET: u8 = 1;

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnwindRowAbi {
    pub pc: u64,
    pub cfa_kind: u8,
    pub ra_kind: u8,
    pub fp_kind: u8,
    pub _pad: u8,
    pub cfa_off: i32,
    pub ra_off: i32,
    pub fp_off: i32,
}

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnwindMapping {
    pub start: u64,
    pub end: u64,
    pub bias: u64,
    pub module_id: u32,
    pub _pad: u32,
}

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct UnwindProcMappings {
    pub generation: u64,
    pub count: u32,
    pub _pad: u32,
    pub entries: [UnwindMapping; UNWIND_MAX_MAPPINGS],
}

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProfileGenerationAbi {
    pub generation: u64,
    pub pending_mappings: u64,
}

#[cfg(any(target_os = "linux", test))]
impl ProfileGenerationAbi {
    pub(crate) fn usable(self) -> Option<u64> {
        (self.pending_mappings == 0 && self.generation != 0).then_some(self.generation)
    }
}

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnwindModuleSpan {
    pub row_start: u32,
    pub row_len: u32,
}

#[cfg(target_os = "linux")]
mod pod {
    unsafe impl aya::Pod for super::ProfileGenerationAbi {}
    unsafe impl aya::Pod for super::UnwindRowAbi {}
    unsafe impl aya::Pod for super::UnwindProcMappings {}
    unsafe impl aya::Pod for super::UnwindModuleSpan {}
    unsafe impl aya::Pod for super::PyProcInfoAbi {}
}

/// CPython walk parameters shipped to the eBPF program. Offsets are
/// version-specific; see [`py311_proc_info`] and [`py312_proc_info`] for
/// their provenance.
#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PyProcInfoAbi {
    pub generation: u64,
    pub runtime_addr: u64,
    pub pid_ns_dev: u64,
    pub pid_ns_ino: u64,
    pub interpreters_head: u16,
    pub threads_head: u16,
    pub tstate_next: u16,
    pub tstate_native_thread_id: u16,
    pub tstate_cframe: u16,
    pub cframe_current_frame: u16,
    pub iframe_code: u16,
    pub iframe_previous: u16,
    pub iframe_owner: u16,
    pub _pad: [u16; 3],
}

/// Kernel-side CPython 3.11 struct offsets, measured with offsetof()
/// against CPython 3.11.13 headers (Py_BUILD_CORE, 64-bit, non-debug
/// build; python:3.11.13-bookworm). Non-standard builds that shift these
/// offsets fail the in-kernel walk with explicit py_stop accounting.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn py311_proc_info(
    runtime_addr: u64,
    pid_ns_dev: u64,
    pid_ns_ino: u64,
) -> PyProcInfoAbi {
    PyProcInfoAbi {
        generation: 0,
        runtime_addr,
        pid_ns_dev,
        pid_ns_ino,
        interpreters_head: 40,
        threads_head: 16,
        tstate_next: 8,
        tstate_native_thread_id: 160,
        tstate_cframe: 56,
        cframe_current_frame: 8,
        iframe_code: 32,
        iframe_previous: 48,
        iframe_owner: 69,
        _pad: [0; 3],
    }
}

/// Kernel-side CPython 3.12 struct offsets, measured with offsetof()
/// against CPython 3.12.13 headers (Py_BUILD_CORE, 64-bit, non-debug
/// build; python:3.12-bookworm). Non-standard builds that shift these
/// offsets fail the in-kernel walk with explicit py_stop accounting.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn py312_proc_info(
    runtime_addr: u64,
    pid_ns_dev: u64,
    pid_ns_ino: u64,
) -> PyProcInfoAbi {
    PyProcInfoAbi {
        generation: 0,
        runtime_addr,
        pid_ns_dev,
        pid_ns_ino,
        interpreters_head: 40,
        threads_head: 72,
        tstate_next: 8,
        tstate_native_thread_id: 144,
        tstate_cframe: 56,
        cframe_current_frame: 0,
        iframe_code: 0,
        iframe_previous: 8,
        iframe_owner: 70,
        _pad: [0; 3],
    }
}

/// Userspace-side CPython 3.11 code-object and unicode offsets, same
/// provenance as [`py311_proc_info`].
#[cfg(any(target_os = "linux", test))]
pub(crate) mod py311 {
    pub(crate) const CODE_FILENAME: u64 = 112;
    pub(crate) const CODE_NAME: u64 = 120;
    pub(crate) const CODE_QUALNAME: u64 = 128;
    pub(crate) const CODE_FIRSTLINENO: u64 = 72;
    /// CPython 3.11 retains the legacy `wstr` pointer in PyASCIIObject,
    /// so compact-ASCII payload bytes begin at offset 48.
    pub(crate) const UNICODE_DATA: u64 = 48;
    pub(crate) const UNICODE_LENGTH: u64 = 16;
    pub(crate) const UNICODE_STATE: u64 = 32;
}

/// Userspace-side CPython 3.12 code-object and unicode offsets, same
/// provenance as [`py312_proc_info`].
#[cfg(any(target_os = "linux", test))]
pub(crate) mod py312 {
    pub(crate) const CODE_FILENAME: u64 = 112;
    pub(crate) const CODE_NAME: u64 = 120;
    pub(crate) const CODE_QUALNAME: u64 = 128;
    pub(crate) const CODE_FIRSTLINENO: u64 = 68;
    /// Compact-ASCII string payload starts after the PyASCIIObject
    /// header; `state` bit 5 = compact, bit 6 = ascii, bits 2..5 kind.
    pub(crate) const UNICODE_DATA: u64 = 40;
    pub(crate) const UNICODE_LENGTH: u64 = 16;
    pub(crate) const UNICODE_STATE: u64 = 32;
}

/// Bounded, thread-safe recency set of pids the sampler has observed on-CPU.
/// Reader threads refresh a pid's sequence on every sample. New pids evict the
/// least recently sampled pid at capacity, so an old, still-alive process
/// cannot permanently prevent a new workload from receiving unwind coverage.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub(crate) struct HotPidTracker {
    inner: std::sync::Mutex<HotPidState>,
    capacity: usize,
    membership_revision: std::sync::atomic::AtomicU64,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
struct HotPidState {
    sequence: u64,
    last_seen: std::collections::BTreeMap<u32, u64>,
}

#[cfg(any(target_os = "linux", test))]
impl HotPidTracker {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(HotPidState::default()),
            capacity: capacity.max(1),
            membership_revision: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Records a sampled pid and evicts the least-recently sampled entry when
    /// a new pid arrives at capacity.
    pub(crate) fn record(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        if let Ok(mut state) = self.inner.lock() {
            let is_new = !state.last_seen.contains_key(&pid);
            state.sequence = state.sequence.wrapping_add(1);
            if state.sequence == 0 {
                // Impossibly rare in practice, but keep ordering valid across
                // wraparound instead of allowing old entries to look newest.
                let mut ordered = state
                    .last_seen
                    .iter()
                    .map(|(pid, sequence)| (*pid, *sequence))
                    .collect::<Vec<_>>();
                ordered.sort_unstable_by_key(|(pid, sequence)| (*sequence, *pid));
                for (index, (pid, _)) in ordered.into_iter().enumerate() {
                    state.last_seen.insert(pid, index as u64 + 1);
                }
                state.sequence = state.last_seen.len() as u64 + 1;
            }
            if !state.last_seen.contains_key(&pid)
                && state.last_seen.len() >= self.capacity
                && let Some(stale) = state
                    .last_seen
                    .iter()
                    .min_by_key(|(pid, sequence)| (**sequence, **pid))
                    .map(|(pid, _)| *pid)
            {
                state.last_seen.remove(&stale);
            }
            let sequence = state.sequence;
            state.last_seen.insert(pid, sequence);
            if is_new {
                self.membership_revision
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> std::collections::BTreeSet<u32> {
        self.inner
            .lock()
            .map(|state| state.last_seen.keys().copied().collect())
            .unwrap_or_default()
    }

    fn ordered_snapshot(&self) -> Vec<u32> {
        let Ok(state) = self.inner.lock() else {
            return Vec::new();
        };
        let mut entries = state
            .last_seen
            .iter()
            .map(|(pid, sequence)| (*pid, *sequence))
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(pid, sequence)| (std::cmp::Reverse(*sequence), *pid));
        entries.into_iter().map(|(pid, _)| pid).collect()
    }

    pub(crate) fn membership_revision(&self) -> u64 {
        self.membership_revision
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drops pids that no longer exist so the bounded set tracks live,
    /// recently-sampled processes rather than accumulating dead ones.
    pub(crate) fn retain_alive(&self, alive: &std::collections::BTreeSet<u32>) {
        if let Ok(mut state) = self.inner.lock() {
            let previous_len = state.last_seen.len();
            state.last_seen.retain(|pid, _| alive.contains(pid));
            if state.last_seen.len() != previous_len {
                self.membership_revision
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Destination for unwind-table writes; the platform implementation
/// wraps the eBPF maps, tests collect writes in memory.
#[cfg(any(target_os = "linux", test))]
pub(crate) trait UnwindMapSink {
    fn process_generation(&mut self, pid: u32) -> Option<u64>;
    fn write_rows(&mut self, row_start: u32, rows: &[UnwindRowAbi]) -> bool;
    fn write_module(&mut self, module_id: u32, span: UnwindModuleSpan) -> bool;
    fn write_process(&mut self, pid: u32, mappings: &UnwindProcMappings) -> bool;
    fn remove_process(&mut self, pid: u32);
    fn write_python_process(&mut self, pid: u32, info: &PyProcInfoAbi) -> bool;
    fn remove_python_process(&mut self, pid: u32);
}

/// Degradation accounting for one refresh pass.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnwindRefreshStats {
    pub processes_registered: usize,
    pub processes_skipped_limit: usize,
    pub modules_loaded: usize,
    pub modules_without_tables: usize,
    pub modules_skipped_row_budget: usize,
    pub modules_skipped_module_budget: usize,
    pub tables_truncated: usize,
    pub mappings_skipped_per_process_limit: usize,
    pub python_registered: usize,
    pub python_unsupported_version: usize,
    pub python_unvalidated_builds: usize,
    pub process_identity_changes: usize,
    pub maps_rejected: usize,
    pub modules_skipped_size: usize,
    pub tracked_processes: usize,
    pub cached_modules: usize,
    pub cached_rows: usize,
}

/// Per-module handle returned to the process-mapping builder.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct ModuleRecord {
    module_id: u32,
    segments: [LoadSegment; 4],
    segment_count: usize,
}

/// A module's parsed unwind rows, kept in userspace so files are read
/// and parsed once per immutable file identity. Published row positions
/// remain fixed for the source lifetime.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct ParsedModule {
    module_id: u32,
    rows: Vec<UnwindRowAbi>,
    segments: [LoadSegment; 4],
    segment_count: usize,
}

/// Builds and maintains per-process unwind tables.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub(crate) struct UnwindTableManager {
    procfs_root: std::path::PathBuf,
    max_processes: usize,
    max_module_bytes: u64,
    row_pool: u32,
    row_cursor: u32,
    next_module_id: u32,
    cached_rows: usize,
    /// (st_dev, st_ino) -> parsed module rows; `None` records a file
    /// that has no usable table so it is not re-parsed every pass.
    parsed: std::collections::BTreeMap<ModuleIdentity, Option<ParsedModule>>,
    /// Immutable row-pool placements. Published slots are never reused while
    /// a kernel walker can still hold a reference to them.
    assigned: std::collections::BTreeMap<ModuleIdentity, u32>,
    /// (st_dev, st_ino) -> `_PyRuntime` link-time address and load
    /// segments of a supported CPython module; `None` records absence.
    python_runtimes: std::collections::BTreeMap<ModuleIdentity, Option<PyRuntimeRecord>>,
    python_builds: Vec<e_navigator_core::CpuProfilePythonBuild>,
    registered_pids: std::collections::BTreeSet<u32>,
    registered_py_pids: std::collections::BTreeSet<u32>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct PyRuntimeRecord {
    minor: u32,
    runtime_vaddr: u64,
    segments: [LoadSegment; 4],
    segment_count: usize,
}

/// A build descriptor attests the compiled layouts; paths and perf-map
/// names never establish interpreter support.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatedPythonImage {
    pub minor: u32,
    pub runtime_vaddr: u64,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn validated_python_image(
    image: &[u8],
    builds: &[e_navigator_core::CpuProfilePythonBuild],
) -> Option<ValidatedPythonImage> {
    use object::{Object, ObjectSection, ObjectSymbol};
    let file = object::File::parse(image).ok()?;
    if file.format() != object::BinaryFormat::Elf || !file.is_64() || !file.is_little_endian() {
        return None;
    }
    let architecture = match file.architecture() {
        object::Architecture::X86_64 => "x86_64",
        object::Architecture::Aarch64 => "aarch64",
        _ => return None,
    };
    let build_id = file.build_id().ok()??;
    let build = builds.iter().find(|build| {
        build.architecture == architecture
            && build.build_id.len() == build_id.len() * 2
            && build
                .build_id
                .as_bytes()
                .chunks_exact(2)
                .zip(build_id)
                .all(|(hex, byte)| {
                    let digit = |value: u8| match value {
                        b'0'..=b'9' => Some(value - b'0'),
                        b'a'..=b'f' => Some(value - b'a' + 10),
                        _ => None,
                    };
                    digit(hex[0])
                        .zip(digit(hex[1]))
                        .is_some_and(|(high, low)| high * 16 + low == *byte)
                })
    })?;
    let (minor, version) = match build.version.as_str() {
        "3.11.13" => (11, 0x030b0df0u32),
        "3.12.13" => (12, 0x030c0df0u32),
        _ => return None,
    };
    let mut runtime_vaddr = None;
    let mut actual_version = None;
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.is_undefined() {
            continue;
        }
        match symbol.name().ok()? {
            "_Py_RefTotal" | "Py_GetObjects" => return None,
            "_PyRuntime" => runtime_vaddr = Some(symbol.address()),
            "Py_Version" => {
                let section = file.section_by_index(symbol.section_index()?).ok()?;
                let bytes: [u8; 4] = section
                    .data_range(symbol.address(), 4)
                    .ok()??
                    .try_into()
                    .ok()?;
                actual_version = Some(u32::from_le_bytes(bytes));
            }
            _ => {}
        }
    }
    let runtime_vaddr = runtime_vaddr.filter(|address| *address != 0)?;
    (actual_version == Some(version)).then_some(ValidatedPythonImage {
        minor,
        runtime_vaddr,
    })
}

#[cfg(any(target_os = "linux", test))]
impl UnwindTableManager {
    const MAX_SEGMENTS_PER_MODULE: usize = 4;

    pub(crate) fn new(procfs_root: std::path::PathBuf, max_processes: usize) -> Self {
        Self {
            procfs_root,
            max_processes,
            // Whole-image parses dominate refresh memory; images past
            // this bound (typically large static Go binaries, which keep
            // frame pointers and unwind fine without tables) fall back
            // to frame-pointer unwinding, counted below.
            max_module_bytes: 64 * 1024 * 1024,
            row_pool: UNWIND_ROW_POOL,
            row_cursor: 0,
            next_module_id: 0,
            cached_rows: 0,
            parsed: std::collections::BTreeMap::new(),
            assigned: std::collections::BTreeMap::new(),
            python_runtimes: std::collections::BTreeMap::new(),
            python_builds: Vec::new(),
            registered_pids: std::collections::BTreeSet::new(),
            registered_py_pids: std::collections::BTreeSet::new(),
        }
    }

    pub(crate) fn with_python_builds(
        mut self,
        builds: Vec<e_navigator_core::CpuProfilePythonBuild>,
    ) -> Self {
        self.python_builds = builds;
        self
    }

    #[cfg(test)]
    fn set_row_pool_for_test(&mut self, rows: u32) {
        self.row_pool = rows;
    }

    /// Scans the procfs view, loads unwind tables for new modules, and
    /// (re)registers per-process mappings. Removes processes that have
    /// exited since the previous pass.
    ///
    /// `hot_pids` are processes the sampler has actually observed
    /// on-CPU; they are registered first so the finite in-kernel row
    /// pool covers the workloads being profiled rather than being
    /// exhausted by idle system processes with large libraries. Exited
    /// pids are pruned from the tracker each pass.
    pub(crate) fn refresh(
        &mut self,
        sink: &mut impl UnwindMapSink,
        hot_pids: &HotPidTracker,
    ) -> UnwindRefreshStats {
        let mut stats = UnwindRefreshStats::default();
        let mut seen_pids = std::collections::BTreeSet::new();
        let mut seen_py_pids = std::collections::BTreeSet::new();

        // Preserve published row slots across refreshes and tail calls.
        // ponytail: fixed lifetime pool; add generation-switched pools only
        // if measured module churn exhausts these bounded immutable slots.

        let Ok(entries) = std::fs::read_dir(&self.procfs_root) else {
            return stats;
        };
        let alive: std::collections::BTreeSet<u32> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        hot_pids.retain_alive(&alive);
        let mut pids = hot_pids.ordered_snapshot();
        stats.tracked_processes = pids.len();
        if pids.len() > self.max_processes {
            stats.processes_skipped_limit = pids.len() - self.max_processes;
            pids.truncate(self.max_processes);
        }

        for pid in pids {
            let Some(generation) = sink.process_generation(pid) else {
                stats.process_identity_changes += 1;
                continue;
            };
            if let Some(mut mappings) = self.build_process_mappings(pid, sink, &mut stats)
                && mappings.count > 0
            {
                mappings.generation = generation;
                if sink.write_process(pid, &mappings) {
                    seen_pids.insert(pid);
                }
            }
            if let Some(mut info) = self.python_proc_info(pid, &mut stats) {
                info.generation = generation;
                if sink.write_python_process(pid, &info) {
                    seen_py_pids.insert(pid);
                }
            }
            if sink.process_generation(pid) != Some(generation) {
                sink.remove_process(pid);
                sink.remove_python_process(pid);
                seen_pids.remove(&pid);
                seen_py_pids.remove(&pid);
                stats.process_identity_changes += 1;
            }
        }
        stats.processes_registered = seen_pids.len();
        stats.python_registered = seen_py_pids.len();

        for stale in self.registered_pids.difference(&seen_pids) {
            sink.remove_process(*stale);
        }
        for stale in self.registered_py_pids.difference(&seen_py_pids) {
            sink.remove_python_process(*stale);
        }
        self.registered_pids = seen_pids;
        self.registered_py_pids = seen_py_pids;
        stats.cached_modules = self
            .parsed
            .values()
            .filter(|module| module.is_some())
            .count();
        stats.cached_rows = self.cached_rows;
        stats
    }

    /// Detects a supported CPython interpreter mapping and resolves the
    /// runtime address of `_PyRuntime` for the in-kernel frame walk.
    /// Other versions are counted, not silently skipped.
    fn python_proc_info(
        &mut self,
        pid: u32,
        stats: &mut UnwindRefreshStats,
    ) -> Option<PyProcInfoAbi> {
        let maps_path = self.procfs_root.join(pid.to_string()).join("maps");
        let Some(contents) = read_bounded_image(&maps_path, 256 * 1024)
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            stats.maps_rejected += 1;
            return None;
        };
        let module_map = ProcessModuleMap::parse_maps(&contents);
        // The process's pid namespace, so the in-kernel walker can match
        // CPython's namespace-local thread ids.
        let (pid_ns_dev, pid_ns_ino) = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(
                self.procfs_root
                    .join(pid.to_string())
                    .join("ns")
                    .join("pid"),
            )
            .map(|metadata| (metadata.dev(), metadata.ino()))
            .unwrap_or((0, 0))
        };
        for mapping in module_map.mappings() {
            let minor_hint = python_minor_version(&mapping.path);
            if minor_hint.is_some_and(|minor| !matches!(minor, 11 | 12)) {
                stats.python_unsupported_version += 1;
            }
            if self.python_builds.is_empty() {
                if minor_hint.is_some_and(|minor| matches!(minor, 11 | 12)) {
                    stats.python_unvalidated_builds += 1;
                }
                continue;
            }
            let Some(file_path) = target_module_path(&self.procfs_root, pid, &mapping.path) else {
                continue;
            };
            let Ok(metadata) = std::fs::metadata(&file_path) else {
                continue;
            };
            if metadata.len() > self.max_module_bytes {
                stats.modules_skipped_size += 1;
                continue;
            }
            let key = module_key(&metadata);
            if !self.python_runtimes.contains_key(&key)
                && self.python_runtimes.len() >= UNWIND_MAX_MODULES
            {
                stats.modules_skipped_module_budget += 1;
                return None;
            }
            let builds = &self.python_builds;
            let record = self.python_runtimes.entry(key).or_insert_with(|| {
                read_bounded_image(&file_path, self.max_module_bytes).and_then(|image| {
                    let descriptor = validated_python_image(&image, builds)?;
                    let runtime_vaddr = descriptor.runtime_vaddr;
                    let segments = parse_load_segments(&image);
                    if segments.is_empty() {
                        return None;
                    }
                    let mut fixed = [LoadSegment {
                        vaddr: 0,
                        file_offset: 0,
                        file_size: 0,
                    }; Self::MAX_SEGMENTS_PER_MODULE];
                    let count = segments.len().min(Self::MAX_SEGMENTS_PER_MODULE);
                    fixed[..count].copy_from_slice(&segments[..count]);
                    Some(PyRuntimeRecord {
                        minor: descriptor.minor,
                        runtime_vaddr,
                        segments: fixed,
                        segment_count: count,
                    })
                })
            });
            // The interpreter binary may not carry _PyRuntime (shared
            // libpython builds); keep scanning the remaining mappings.
            let Some(record) = *record else {
                if minor_hint.is_some() {
                    stats.python_unvalidated_builds += 1;
                }
                continue;
            };
            let Some(bias) = compute_load_bias(
                mapping.start,
                mapping.file_offset,
                &record.segments[..record.segment_count],
            ) else {
                continue;
            };
            if pid_ns_ino == 0 {
                stats.python_unvalidated_builds += 1;
                return None;
            }
            let runtime_addr = record.runtime_vaddr.checked_add(bias)?;
            return Some(match record.minor {
                11 => py311_proc_info(runtime_addr, pid_ns_dev, pid_ns_ino),
                12 => py312_proc_info(runtime_addr, pid_ns_dev, pid_ns_ino),
                _ => return None,
            });
        }
        None
    }

    fn build_process_mappings(
        &mut self,
        pid: u32,
        sink: &mut impl UnwindMapSink,
        stats: &mut UnwindRefreshStats,
    ) -> Option<UnwindProcMappings> {
        let maps_path = self.procfs_root.join(pid.to_string()).join("maps");
        let Some(contents) = read_bounded_image(&maps_path, 256 * 1024)
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            stats.maps_rejected += 1;
            return None;
        };
        let module_map = ProcessModuleMap::parse_maps(&contents);

        let mut result = UnwindProcMappings {
            generation: 0,
            count: 0,
            _pad: 0,
            entries: [UnwindMapping {
                start: 0,
                end: 0,
                bias: 0,
                module_id: 0,
                _pad: 0,
            }; UNWIND_MAX_MAPPINGS],
        };
        for mapping in module_map.mappings() {
            if (result.count as usize) >= UNWIND_MAX_MAPPINGS {
                stats.mappings_skipped_per_process_limit += 1;
                continue;
            }
            let Some(record) = self.module_record(pid, &mapping.path, sink, stats) else {
                continue;
            };
            let Some(bias) = compute_load_bias(
                mapping.start,
                mapping.file_offset,
                &record.segments[..record.segment_count],
            ) else {
                continue;
            };
            let index = result.count as usize;
            result.entries[index] = UnwindMapping {
                start: mapping.start,
                end: mapping.end,
                bias,
                module_id: record.module_id,
                _pad: 0,
            };
            result.count += 1;
        }
        Some(result)
    }

    /// Parses (once ever) the unwind table for a module file, then
    /// assigns it a row-pool position for this refresh. Reading is
    /// through the process's root so mount namespaces resolve; row
    /// positions are reassigned each pass, so a module claims pool space
    /// only if it fits behind the higher-priority processes already
    /// placed this refresh.
    fn module_record(
        &mut self,
        pid: u32,
        path: &str,
        sink: &mut impl UnwindMapSink,
        stats: &mut UnwindRefreshStats,
    ) -> Option<ModuleRecord> {
        let file_path = target_module_path(&self.procfs_root, pid, path)?;
        let metadata = std::fs::metadata(&file_path).ok()?;
        if metadata.len() > self.max_module_bytes {
            stats.modules_skipped_size += 1;
            return None;
        }
        let key = module_key(&metadata);

        if !self.parsed.contains_key(&key) {
            if self.parsed.len() >= UNWIND_MAX_MODULES {
                stats.modules_skipped_module_budget += 1;
                return None;
            }
            let cache_rows_remaining = (self.row_pool as usize).saturating_sub(self.cached_rows);
            let map_rows_remaining = (self.row_pool - self.row_cursor) as usize;
            let row_limit = cache_rows_remaining.min(map_rows_remaining);
            if row_limit == 0 {
                stats.modules_skipped_row_budget += 1;
                return None;
            }
            let parsed = self.parse_module(&file_path, row_limit, stats);
            if let Some(module) = parsed.as_ref() {
                self.cached_rows = self.cached_rows.saturating_add(module.rows.len());
            }
            self.parsed.insert(key, parsed);
        }
        // Scalars copied out so the immutable borrow of `parsed` ends
        // before the mutable row-pool bookkeeping below.
        let (module_id, row_len, segments, segment_count) = {
            let parsed = self.parsed.get(&key).and_then(Option::as_ref)?;
            (
                parsed.module_id,
                parsed.rows.len() as u32,
                parsed.segments,
                parsed.segment_count,
            )
        };

        // Already placed this refresh (another process maps the same
        // file): reuse its position.
        if self.assigned.contains_key(&key) {
            return Some(ModuleRecord {
                module_id,
                segments,
                segment_count,
            });
        }
        if self.row_cursor.saturating_add(row_len) > self.row_pool {
            stats.modules_skipped_row_budget += 1;
            return None;
        }
        let row_start = self.row_cursor;
        // Unpublished slots may have been overwritten after an earlier failed
        // module write. Rewrite them on every retry; published slots never move.
        let rows = &self.parsed.get(&key).and_then(Option::as_ref)?.rows;
        if !sink.write_rows(row_start, rows) {
            return None;
        }
        if !sink.write_module(module_id, UnwindModuleSpan { row_start, row_len }) {
            return None;
        }
        self.row_cursor += row_len;
        self.assigned.insert(key, row_start);
        stats.modules_loaded += 1;
        Some(ModuleRecord {
            module_id,
            segments,
            segment_count,
        })
    }

    /// Reads and parses a module's `.eh_frame` into row-ABI form,
    /// assigning it a stable module id. Files with no usable table are
    /// recorded as `None` so they are not re-read every pass.
    fn parse_module(
        &mut self,
        file_path: &std::path::Path,
        max_rows: usize,
        stats: &mut UnwindRefreshStats,
    ) -> Option<ParsedModule> {
        let image = read_bounded_image(file_path, self.max_module_bytes)?;
        let table = ElfUnwindTable::parse_bounded(&image, max_rows);
        if table.is_empty() {
            stats.modules_without_tables += 1;
            return None;
        }
        if table.truncated() {
            stats.tables_truncated += 1;
        }
        let segments = parse_load_segments(&image);
        if segments.is_empty() {
            stats.modules_without_tables += 1;
            return None;
        }
        let rows: Vec<UnwindRowAbi> = table.rows().iter().map(row_to_abi).collect();
        let module_id = self.next_module_id;
        self.next_module_id += 1;

        let mut fixed_segments = [LoadSegment {
            vaddr: 0,
            file_offset: 0,
            file_size: 0,
        }; Self::MAX_SEGMENTS_PER_MODULE];
        let segment_count = segments.len().min(Self::MAX_SEGMENTS_PER_MODULE);
        fixed_segments[..segment_count].copy_from_slice(&segments[..segment_count]);
        Some(ParsedModule {
            module_id,
            rows,
            segments: fixed_segments,
            segment_count,
        })
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn target_module_path(
    procfs_root: &std::path::Path,
    pid: u32,
    module: &str,
) -> Option<std::path::PathBuf> {
    use std::path::{Component, Path};
    let relative = Path::new(module).strip_prefix(Path::new("/")).ok()?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(
        procfs_root
            .join(pid.to_string())
            .join("root")
            .join(relative),
    )
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn read_bounded_image(path: &std::path::Path, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > limit {
        return None;
    }
    let mut image = Vec::new();
    file.take(limit.checked_add(1)?)
        .read_to_end(&mut image)
        .ok()?;
    (image.len() as u64 <= limit).then_some(image)
}

#[cfg(any(target_os = "linux", test))]
type ModuleIdentity = (u64, u64, u64, Option<std::time::SystemTime>);

#[cfg(any(target_os = "linux", test))]
fn module_key(metadata: &std::fs::Metadata) -> ModuleIdentity {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;
        (
            metadata.st_dev(),
            metadata.st_ino(),
            metadata.len(),
            metadata.modified().ok(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.modified().ok(),
        )
    }
}

/// Translates a runtime mapping into the load bias to subtract from
/// instruction pointers: the PT_LOAD segment containing the mapping's
/// file offset anchors the link-time address space.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn compute_load_bias(
    mapping_start: u64,
    mapping_file_offset: u64,
    segments: &[LoadSegment],
) -> Option<u64> {
    let segment = segments.iter().find(|segment| {
        mapping_file_offset >= segment.file_offset
            && mapping_file_offset < segment.file_offset.saturating_add(segment.file_size.max(1))
    })?;
    let link_addr = segment
        .vaddr
        .checked_add(mapping_file_offset.checked_sub(segment.file_offset)?)?;
    mapping_start.checked_sub(link_addr)
}

#[cfg(any(target_os = "linux", test))]
fn row_to_abi(row: &e_navigator_profiling::unwind::UnwindRow) -> UnwindRowAbi {
    let (cfa_kind, cfa_off) = match row.cfa {
        CfaRule::SpOffset(offset) => (UNWIND_CFA_SP, offset),
        CfaRule::FpOffset(offset) => (UNWIND_CFA_FP, offset),
        CfaRule::Unsupported => (UNWIND_CFA_UNSUPPORTED, 0),
        CfaRule::Invalid => (UNWIND_CFA_INVALID, 0),
    };
    let (ra_kind, ra_off) = match row.ra {
        RaRule::CfaOffset(offset) => (UNWIND_RA_CFA_OFFSET, offset),
        RaRule::LinkRegister => (UNWIND_RA_LINK_REGISTER, 0),
        RaRule::Undefined => (UNWIND_RA_UNDEFINED, 0),
        RaRule::Unsupported => (UNWIND_RA_UNSUPPORTED, 0),
    };
    let (fp_kind, fp_off) = match row.fp {
        FpRule::CfaOffset(offset) => (UNWIND_FP_CFA_OFFSET, offset),
        FpRule::Preserved | FpRule::Unsupported => (UNWIND_FP_PRESERVED, 0),
    };
    UnwindRowAbi {
        pc: row.pc,
        cfa_kind,
        ra_kind,
        fp_kind,
        _pad: 0,
        cfa_off,
        ra_off,
        fp_off,
    }
}

#[cfg(test)]
mod tests;

/// Extracts the CPython minor version from an interpreter or
/// libpython mapping path ("python3.12", "libpython3.12.so.1.0").
#[cfg(any(target_os = "linux", test))]
pub(crate) fn python_minor_version(path: &str) -> Option<u32> {
    let index = path.rfind("python3.")?;
    let digits: String = path[index + "python3.".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}
