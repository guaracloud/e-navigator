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
#[cfg(any(target_os = "linux", test))]
pub(crate) const UNWIND_MAX_MAPPINGS: usize = 24;
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
    pub count: u32,
    pub _pad: u32,
    pub entries: [UnwindMapping; UNWIND_MAX_MAPPINGS],
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
    unsafe impl aya::Pod for super::UnwindRowAbi {}
    unsafe impl aya::Pod for super::UnwindProcMappings {}
    unsafe impl aya::Pod for super::UnwindModuleSpan {}
    unsafe impl aya::Pod for super::PyProcInfoAbi {}
}

/// CPython walk parameters shipped to the eBPF program. Offsets are
/// version-specific; see [`py312_proc_info`] for their provenance.
#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PyProcInfoAbi {
    pub runtime_addr: u64,
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

/// Kernel-side CPython 3.12 struct offsets, measured with offsetof()
/// against CPython 3.12.13 headers (Py_BUILD_CORE, 64-bit, non-debug
/// build; python:3.12-bookworm). Non-standard builds that shift these
/// offsets fail the in-kernel walk with explicit py_stop accounting.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn py312_proc_info(runtime_addr: u64) -> PyProcInfoAbi {
    PyProcInfoAbi {
        runtime_addr,
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

/// Destination for unwind-table writes; the platform implementation
/// wraps the eBPF maps, tests collect writes in memory.
#[cfg(any(target_os = "linux", test))]
pub(crate) trait UnwindMapSink {
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
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct ModuleRecord {
    module_id: u32,
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
    row_cursor: u32,
    next_module_id: u32,
    /// (st_dev, st_ino) -> loaded module record; `None` records a module
    /// without a usable table so it is not re-parsed every pass.
    modules: std::collections::BTreeMap<(u64, u64), Option<ModuleRecord>>,
    /// (st_dev, st_ino) -> `_PyRuntime` link-time address and load
    /// segments of a CPython 3.12 module; `None` records absence.
    python_runtimes: std::collections::BTreeMap<(u64, u64), Option<PyRuntimeRecord>>,
    registered_pids: std::collections::BTreeSet<u32>,
    registered_py_pids: std::collections::BTreeSet<u32>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct PyRuntimeRecord {
    runtime_vaddr: u64,
    segments: [LoadSegment; 4],
    segment_count: usize,
}

#[cfg(any(target_os = "linux", test))]
impl UnwindTableManager {
    const MAX_SEGMENTS_PER_MODULE: usize = 4;

    pub(crate) fn new(procfs_root: std::path::PathBuf, max_processes: usize) -> Self {
        Self {
            procfs_root,
            max_processes,
            max_module_bytes: 512 * 1024 * 1024,
            row_cursor: 0,
            next_module_id: 0,
            modules: std::collections::BTreeMap::new(),
            python_runtimes: std::collections::BTreeMap::new(),
            registered_pids: std::collections::BTreeSet::new(),
            registered_py_pids: std::collections::BTreeSet::new(),
        }
    }

    /// Scans the procfs view, loads unwind tables for new modules, and
    /// (re)registers per-process mappings. Removes processes that have
    /// exited since the previous pass.
    pub(crate) fn refresh(&mut self, sink: &mut impl UnwindMapSink) -> UnwindRefreshStats {
        let mut stats = UnwindRefreshStats::default();
        let mut seen_pids = std::collections::BTreeSet::new();
        let mut seen_py_pids = std::collections::BTreeSet::new();

        let Ok(entries) = std::fs::read_dir(&self.procfs_root) else {
            return stats;
        };
        let mut pids: Vec<u32> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        pids.sort_unstable();
        if pids.len() > self.max_processes {
            stats.processes_skipped_limit = pids.len() - self.max_processes;
            pids.truncate(self.max_processes);
        }

        for pid in pids {
            if let Some(mappings) = self.build_process_mappings(pid, sink, &mut stats)
                && mappings.count > 0
                && sink.write_process(pid, &mappings)
            {
                seen_pids.insert(pid);
                stats.processes_registered += 1;
            }
            if let Some(info) = self.python_proc_info(pid, &mut stats)
                && sink.write_python_process(pid, &info)
            {
                seen_py_pids.insert(pid);
                stats.python_registered += 1;
            }
        }

        for stale in self.registered_pids.difference(&seen_pids) {
            sink.remove_process(*stale);
        }
        for stale in self.registered_py_pids.difference(&seen_py_pids) {
            sink.remove_python_process(*stale);
        }
        self.registered_pids = seen_pids;
        self.registered_py_pids = seen_py_pids;
        stats
    }

    /// Detects a CPython 3.12 interpreter mapping and resolves the
    /// runtime address of `_PyRuntime` for the in-kernel frame walk.
    /// Other CPython versions are counted, not silently skipped.
    fn python_proc_info(
        &mut self,
        pid: u32,
        stats: &mut UnwindRefreshStats,
    ) -> Option<PyProcInfoAbi> {
        let maps_path = self.procfs_root.join(pid.to_string()).join("maps");
        let contents = std::fs::read_to_string(&maps_path).ok()?;
        let module_map = ProcessModuleMap::parse_maps(&contents);
        for mapping in module_map.mappings() {
            let Some(minor) = python_minor_version(&mapping.path) else {
                continue;
            };
            if minor != 12 {
                stats.python_unsupported_version += 1;
                return None;
            }
            let file_path = self
                .procfs_root
                .join(pid.to_string())
                .join("root")
                .join(mapping.path.trim_start_matches('/'));
            let metadata = std::fs::metadata(&file_path).ok()?;
            if metadata.len() > self.max_module_bytes {
                return None;
            }
            let key = module_key(&metadata);
            let record = self.python_runtimes.entry(key).or_insert_with(|| {
                std::fs::read(&file_path).ok().and_then(|image| {
                    let runtime_vaddr = e_navigator_profiling::symbolize::find_elf_symbol_address(
                        &image,
                        "_PyRuntime",
                    )?;
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
                        runtime_vaddr,
                        segments: fixed,
                        segment_count: count,
                    })
                })
            });
            // The interpreter binary may not carry _PyRuntime (shared
            // libpython builds); keep scanning the remaining mappings.
            let Some(record) = *record else {
                continue;
            };
            let Some(bias) = compute_load_bias(
                mapping.start,
                mapping.file_offset,
                &record.segments[..record.segment_count],
            ) else {
                continue;
            };
            return Some(py312_proc_info(record.runtime_vaddr.wrapping_add(bias)));
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
        let contents = std::fs::read_to_string(&maps_path).ok()?;
        let module_map = ProcessModuleMap::parse_maps(&contents);

        let mut result = UnwindProcMappings {
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

    /// Loads (or reuses) the unwind table for a module file, reading it
    /// through the process's root so mount namespaces resolve.
    fn module_record(
        &mut self,
        pid: u32,
        path: &str,
        sink: &mut impl UnwindMapSink,
        stats: &mut UnwindRefreshStats,
    ) -> Option<ModuleRecord> {
        let file_path = self
            .procfs_root
            .join(pid.to_string())
            .join("root")
            .join(path.trim_start_matches('/'));
        let metadata = std::fs::metadata(&file_path).ok()?;
        if metadata.len() > self.max_module_bytes {
            return None;
        }
        let key = module_key(&metadata);
        if let Some(record) = self.modules.get(&key) {
            return *record;
        }

        let record = self.load_module(&file_path, sink, stats);
        self.modules.insert(key, record);
        record
    }

    fn load_module(
        &mut self,
        file_path: &std::path::Path,
        sink: &mut impl UnwindMapSink,
        stats: &mut UnwindRefreshStats,
    ) -> Option<ModuleRecord> {
        if self.modules.len() >= UNWIND_MAX_MODULES {
            stats.modules_skipped_module_budget += 1;
            return None;
        }
        let image = std::fs::read(file_path).ok()?;
        let table = ElfUnwindTable::parse(&image);
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
        let row_len = rows.len() as u32;
        if self.row_cursor.saturating_add(row_len) > UNWIND_ROW_POOL {
            stats.modules_skipped_row_budget += 1;
            return None;
        }
        let row_start = self.row_cursor;
        if !sink.write_rows(row_start, &rows) {
            return None;
        }
        let module_id = self.next_module_id;
        if !sink.write_module(module_id, UnwindModuleSpan { row_start, row_len }) {
            return None;
        }
        self.row_cursor += row_len;
        self.next_module_id += 1;
        stats.modules_loaded += 1;

        let mut fixed_segments = [LoadSegment {
            vaddr: 0,
            file_offset: 0,
            file_size: 0,
        }; Self::MAX_SEGMENTS_PER_MODULE];
        let segment_count = segments.len().min(Self::MAX_SEGMENTS_PER_MODULE);
        fixed_segments[..segment_count].copy_from_slice(&segments[..segment_count]);
        Some(ModuleRecord {
            module_id,
            segments: fixed_segments,
            segment_count,
        })
    }
}

#[cfg(any(target_os = "linux", test))]
fn module_key(metadata: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;
        (metadata.st_dev(), metadata.st_ino())
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
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
fn python_minor_version(path: &str) -> Option<u32> {
    let index = path.rfind("python3.")?;
    let digits: String = path[index + "python3.".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}
