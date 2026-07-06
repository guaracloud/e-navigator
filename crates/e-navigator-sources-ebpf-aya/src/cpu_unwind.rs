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
}

/// Destination for unwind-table writes; the platform implementation
/// wraps the eBPF maps, tests collect writes in memory.
#[cfg(any(target_os = "linux", test))]
pub(crate) trait UnwindMapSink {
    fn write_rows(&mut self, row_start: u32, rows: &[UnwindRowAbi]) -> bool;
    fn write_module(&mut self, module_id: u32, span: UnwindModuleSpan) -> bool;
    fn write_process(&mut self, pid: u32, mappings: &UnwindProcMappings) -> bool;
    fn remove_process(&mut self, pid: u32);
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
    registered_pids: std::collections::BTreeSet<u32>,
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
            registered_pids: std::collections::BTreeSet::new(),
        }
    }

    /// Scans the procfs view, loads unwind tables for new modules, and
    /// (re)registers per-process mappings. Removes processes that have
    /// exited since the previous pass.
    pub(crate) fn refresh(&mut self, sink: &mut impl UnwindMapSink) -> UnwindRefreshStats {
        let mut stats = UnwindRefreshStats::default();
        let mut seen_pids = std::collections::BTreeSet::new();

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
        }

        for stale in self.registered_pids.difference(&seen_pids) {
            sink.remove_process(*stale);
        }
        self.registered_pids = seen_pids;
        stats
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
