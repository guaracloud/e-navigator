#[cfg(any(target_os = "linux", test))]
use e_navigator_core::CpuProfileBackpressure;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_core::CpuProfileSourceConfig;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_profiling::model::{NormalizationLimits, RawProfileFrame, RawProfileSample};
#[cfg(any(target_os = "linux", test))]
use e_navigator_profiling::{
    jit::JitSymbolMap,
    symbolize::{ElfSymbolTable, ProcessModuleMap},
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingKind, SignalEnvelope,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_CPU_PROFILE_MAX_FRAMES: usize = 128;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PY_MAX_FRAMES: usize = 64;

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
    pub py_frame_count: u32,
    pub py_stop: u32,
    pub py_frames: [u64; RAW_PY_MAX_FRAMES],
}

/// Human-readable CPython walk stop reason; reasons other than
/// `complete` mean interpreter frames may be missing and are counted.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn py_stop_reason(py_stop: u32) -> Option<(&'static str, bool)> {
    match py_stop {
        0 => None,
        1 => Some(("complete", false)),
        2 => Some(("no_thread", true)),
        3 => Some(("read_fault", true)),
        4 => Some(("truncated", true)),
        _ => Some(("unknown", true)),
    }
}

/// A decoded CPU profile sample plus capture-side accounting that the
/// signal envelope alone does not expose to the reader loop.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct DecodedCpuProfileSample {
    pub signal: SignalEnvelope,
    /// Sampled process id in the symbolization pid namespace; used to
    /// prioritize unwind-table building for on-CPU processes.
    pub pid: u32,
    /// True when the kernel filled the configured frame budget and the
    /// stack may be deeper than what was captured.
    pub capture_truncated: bool,
    /// True when the sample's untranslated pid failed procfs identity
    /// verification and frames were left as raw addresses.
    pub pid_unverified: bool,
    /// True when a DWARF unwind stopped before the outermost frame for
    /// a reason other than the configured depth budget.
    pub dwarf_incomplete: bool,
    /// True when the CPython frame walk stopped before the root frame.
    pub py_incomplete: bool,
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

    /// Resolves a CPython code-object pointer to a function/file/line
    /// frame by reading the process's memory. Resolvers without that
    /// access return `None` and the frame keeps a raw pointer label.
    fn resolve_python_frame(&mut self, _pid: u32, _code_ptr: u64) -> Option<RawProfileFrame> {
        None
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
    /// Per-process JIT perf maps. Negative results are cached and retried on a
    /// short interval because runtimes commonly create the map after startup.
    jit_maps: std::collections::BTreeMap<u32, CachedJitSymbols>,
    /// Target-filesystem module identity -> parsed ELF symbol table, shared
    /// across every per-CPU reader thread: symbol tables of large modules
    /// dominate symbolizer memory and must not be duplicated per thread.
    symbols: std::sync::Arc<std::sync::Mutex<SharedSymbolTables>>,
    /// Cached thread comms for untranslated pids, keyed by (pid, tid);
    /// `None` records an unreadable thread. Bounded like the other caches;
    /// like them it can go stale on pid reuse, which at worst withholds or
    /// restores symbolization for later samples of a reused pid.
    thread_comms: std::collections::BTreeMap<(u32, u32), Option<String>>,
    /// Cached CPython code-object resolutions keyed by (pid, code ptr).
    /// Stale entries after code unloading or pid reuse only mislabel
    /// python frames of that reused id until eviction.
    python_frames: std::collections::BTreeMap<(u32, u64), Option<RawProfileFrame>>,
    /// Detected CPython minor version per pid. Unsupported and unreadable
    /// processes are negatively cached under the same pid bound.
    python_versions: std::collections::BTreeMap<u32, Option<u32>>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct CachedJitSymbols {
    last_checked: std::time::Instant,
    symbols: Option<JitSymbolMap>,
}

/// Stable-enough identity for a module image reached through a target
/// process's `/proc/<pid>/root`. Device/inode distinguish containers that
/// expose different files at the same absolute path; size and modification
/// time prevent stale reuse after a replacement.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    path: std::path::PathBuf,
    size: u64,
    modified: Option<std::time::SystemTime>,
}

/// Bounded target-module identity -> symbol-table cache shared by reader
/// threads.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
pub(crate) struct SharedSymbolTables {
    tables: std::collections::BTreeMap<ModuleFileIdentity, Option<std::sync::Arc<ElfSymbolTable>>>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct PythonObjectLayout {
    code_filename: u64,
    code_name: u64,
    code_qualname: u64,
    code_firstlineno: u64,
    unicode_data: u64,
    unicode_length: u64,
    unicode_state: u64,
}

#[cfg(any(target_os = "linux", test))]
impl PythonObjectLayout {
    fn for_minor(minor: u32) -> Option<Self> {
        use crate::cpu_unwind::{py311, py312};

        match minor {
            11 => Some(Self {
                code_filename: py311::CODE_FILENAME,
                code_name: py311::CODE_NAME,
                code_qualname: py311::CODE_QUALNAME,
                code_firstlineno: py311::CODE_FIRSTLINENO,
                unicode_data: py311::UNICODE_DATA,
                unicode_length: py311::UNICODE_LENGTH,
                unicode_state: py311::UNICODE_STATE,
            }),
            12 => Some(Self {
                code_filename: py312::CODE_FILENAME,
                code_name: py312::CODE_NAME,
                code_qualname: py312::CODE_QUALNAME,
                code_firstlineno: py312::CODE_FIRSTLINENO,
                unicode_data: py312::UNICODE_DATA,
                unicode_length: py312::UNICODE_LENGTH,
                unicode_state: py312::UNICODE_STATE,
            }),
            _ => None,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
impl ProcfsSymbolizer {
    const MAX_MODULE_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_JIT_MAP_BYTES: u64 = 16 * 1024 * 1024;
    const JIT_MAP_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

    #[cfg(test)]
    pub(crate) fn new(procfs_root: std::path::PathBuf, resolve_symbols: bool) -> Self {
        Self::with_shared_symbols(
            procfs_root,
            resolve_symbols,
            std::sync::Arc::new(std::sync::Mutex::new(SharedSymbolTables::default())),
        )
    }

    pub(crate) fn with_shared_symbols(
        procfs_root: std::path::PathBuf,
        resolve_symbols: bool,
        symbols: std::sync::Arc<std::sync::Mutex<SharedSymbolTables>>,
    ) -> Self {
        Self {
            procfs_root,
            resolve_symbols,
            max_cached_pids: 1024,
            max_cached_modules: 512,
            maps: std::collections::BTreeMap::new(),
            jit_maps: std::collections::BTreeMap::new(),
            symbols,
            thread_comms: std::collections::BTreeMap::new(),
            python_frames: std::collections::BTreeMap::new(),
            python_versions: std::collections::BTreeMap::new(),
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
        self.maps.entry(pid).or_default()
    }

    fn symbol_name(&mut self, pid: u32, module: &str, offset: u64) -> Option<String> {
        if !self.resolve_symbols {
            return None;
        }
        let module_path = self.module_image_path(pid, module)?;
        let metadata = std::fs::metadata(&module_path).ok()?;
        if metadata.len() > Self::MAX_MODULE_IMAGE_BYTES {
            return None;
        }
        let identity = Self::module_file_identity(&module_path, &metadata);
        let table = {
            let mut shared = match self.symbols.lock() {
                Ok(shared) => shared,
                Err(_) => return None,
            };
            if !shared.tables.contains_key(&identity) {
                if shared.tables.len() >= self.max_cached_modules
                    && let Some(oldest) = shared.tables.keys().next().cloned()
                {
                    shared.tables.remove(&oldest);
                }
                // Parsing under the lock trades brief reader stalls for
                // never parsing (and holding) a large table per thread.
                let table = self
                    .load_symbol_table(&module_path)
                    .map(std::sync::Arc::new);
                shared.tables.insert(identity.clone(), table);
            }
            shared.tables.get(&identity).and_then(Clone::clone)
        };
        table.and_then(|table| table.resolve(offset).map(ToString::to_string))
    }

    fn module_image_path(&self, pid: u32, module: &str) -> Option<std::path::PathBuf> {
        use std::path::{Component, Path};

        let relative = Path::new(module).strip_prefix(Path::new("/")).ok()?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }
        Some(
            self.procfs_root
                .join(pid.to_string())
                .join("root")
                .join(relative),
        )
    }

    fn module_file_identity(
        _module_path: &std::path::Path,
        metadata: &std::fs::Metadata,
    ) -> ModuleFileIdentity {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        ModuleFileIdentity {
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(not(unix))]
            path: _module_path.to_path_buf(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }

    fn jit_symbol(&mut self, pid: u32, ip: u64) -> Option<(String, u64)> {
        if !self.resolve_symbols {
            return None;
        }
        let refresh = self
            .jit_maps
            .get(&pid)
            .is_none_or(|cached| cached.last_checked.elapsed() >= Self::JIT_MAP_REFRESH_INTERVAL);
        if refresh {
            if !self.jit_maps.contains_key(&pid)
                && self.jit_maps.len() >= self.max_cached_pids
                && let Some(&oldest) = self.jit_maps.keys().next()
            {
                self.jit_maps.remove(&oldest);
            }
            self.jit_maps.insert(
                pid,
                CachedJitSymbols {
                    last_checked: std::time::Instant::now(),
                    symbols: self.load_jit_symbols(pid),
                },
            );
        }
        self.jit_maps
            .get(&pid)?
            .symbols
            .as_ref()?
            .resolve(ip)
            .map(|symbol| (symbol.name.to_string(), symbol.offset))
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

    /// Reads a bounded compact-ASCII CPython unicode object.
    fn read_python_string(
        mem: &std::fs::File,
        address: u64,
        layout: PythonObjectLayout,
    ) -> Option<String> {
        use std::os::unix::fs::FileExt;

        const MAX_PY_STRING_BYTES: u64 = 256;
        let mut word = [0u8; 8];
        mem.read_exact_at(&mut word, address.checked_add(layout.unicode_length)?)
            .ok()?;
        let length = u64::from_le_bytes(word).min(MAX_PY_STRING_BYTES);
        let mut state = [0u8; 4];
        mem.read_exact_at(&mut state, address.checked_add(layout.unicode_state)?)
            .ok()?;
        let state = u32::from_le_bytes(state);
        let kind = (state >> 2) & 0x7;
        let compact = state & (1 << 5) != 0;
        let ascii = state & (1 << 6) != 0;
        if !compact || !ascii || kind != 1 || length == 0 {
            return None;
        }
        let mut bytes = vec![0u8; length as usize];
        mem.read_exact_at(&mut bytes, address.checked_add(layout.unicode_data)?)
            .ok()?;
        let text = String::from_utf8(bytes).ok()?;
        text.chars().all(|c| !c.is_control()).then_some(text)
    }

    fn python_minor_version(&mut self, pid: u32) -> Option<u32> {
        if !self.python_versions.contains_key(&pid) {
            if self.python_versions.len() >= self.max_cached_pids
                && let Some(&oldest) = self.python_versions.keys().next()
            {
                self.python_versions.remove(&oldest);
            }
            let minor = self
                .process_map(pid)
                .mappings()
                .iter()
                .find_map(|mapping| crate::cpu_unwind::python_minor_version(&mapping.path));
            self.python_versions.insert(pid, minor);
        }
        self.python_versions.get(&pid).copied().flatten()
    }

    fn load_python_frame(&mut self, pid: u32, code_ptr: u64) -> Option<RawProfileFrame> {
        use std::os::unix::fs::FileExt;

        let layout = PythonObjectLayout::for_minor(self.python_minor_version(pid)?)?;
        let mem = std::fs::File::open(self.procfs_root.join(pid.to_string()).join("mem")).ok()?;
        let read_ptr = |offset: u64| -> Option<u64> {
            let mut word = [0u8; 8];
            mem.read_exact_at(&mut word, code_ptr.checked_add(offset)?)
                .ok()?;
            Some(u64::from_le_bytes(word))
        };
        let qualname_ptr = read_ptr(layout.code_qualname)?;
        let symbol = Self::read_python_string(&mem, qualname_ptr, layout).or_else(|| {
            let name_ptr = read_ptr(layout.code_name)?;
            Self::read_python_string(&mem, name_ptr, layout)
        })?;
        let file = read_ptr(layout.code_filename)
            .and_then(|filename_ptr| Self::read_python_string(&mem, filename_ptr, layout));
        let line = {
            let mut word = [0u8; 4];
            mem.read_exact_at(&mut word, code_ptr.checked_add(layout.code_firstlineno)?)
                .ok()
                .and_then(|()| u32::try_from(i32::from_le_bytes(word)).ok())
        };
        Some(RawProfileFrame {
            symbol: Some(symbol),
            module: Some("<python>".to_string()),
            file,
            line,
            module_offset: None,
        })
    }

    fn load_symbol_table(&self, module: &std::path::Path) -> Option<ElfSymbolTable> {
        let metadata = std::fs::metadata(module).ok()?;
        if metadata.len() > Self::MAX_MODULE_IMAGE_BYTES {
            return None;
        }
        let image = std::fs::read(module).ok()?;
        let table = ElfSymbolTable::parse(&image);
        (!table.is_empty()).then_some(table)
    }

    fn load_jit_symbols(&self, pid: u32) -> Option<JitSymbolMap> {
        let process_root = self.procfs_root.join(pid.to_string());
        let namespace_pid = self.target_namespace_pid(pid).unwrap_or(pid);
        for map_pid in [Some(namespace_pid), (namespace_pid != pid).then_some(pid)]
            .into_iter()
            .flatten()
        {
            let path = process_root
                .join("root")
                .join("tmp")
                .join(format!("perf-{map_pid}.map"));
            let Some(contents) = Self::read_bounded_utf8(&path, Self::MAX_JIT_MAP_BYTES) else {
                continue;
            };
            let symbols = JitSymbolMap::parse(&contents);
            if !symbols.is_empty() {
                return Some(symbols);
            }
        }
        None
    }

    fn target_namespace_pid(&self, pid: u32) -> Option<u32> {
        const MAX_STATUS_BYTES: u64 = 64 * 1024;

        let status = Self::read_bounded_utf8(
            &self.procfs_root.join(pid.to_string()).join("status"),
            MAX_STATUS_BYTES,
        )?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))?
            .split_whitespace()
            .next_back()?
            .parse()
            .ok()
    }

    fn read_bounded_utf8(path: &std::path::Path, max_bytes: u64) -> Option<String> {
        use std::io::Read;

        let file = std::fs::File::open(path).ok()?;
        if file.metadata().ok()?.len() > max_bytes {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > max_bytes {
            return None;
        }
        String::from_utf8(bytes).ok()
    }
}

#[cfg(any(target_os = "linux", test))]
impl FrameResolver for ProcfsSymbolizer {
    fn resolve(&mut self, pid: u32, ip: u64) -> RawProfileFrame {
        if let Some((symbol, offset)) = self.jit_symbol(pid, ip) {
            return RawProfileFrame {
                symbol: Some(symbol),
                module: Some("<jit>".to_string()),
                file: None,
                line: None,
                module_offset: Some(offset),
            };
        }
        let Some(location) = self.process_map(pid).resolve(ip) else {
            return RawAddressResolver.resolve(pid, ip);
        };
        let symbol = self
            .symbol_name(pid, &location.module, location.module_offset)
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

    fn resolve_python_frame(&mut self, pid: u32, code_ptr: u64) -> Option<RawProfileFrame> {
        let key = (pid, code_ptr);
        if !self.python_frames.contains_key(&key) {
            if self.python_frames.len() >= 4096
                && let Some(&oldest) = self.python_frames.keys().next()
            {
                self.python_frames.remove(&oldest);
            }
            let frame = self.load_python_frame(pid, code_ptr);
            self.python_frames.insert(key, frame);
        }
        self.python_frames.get(&key)?.clone()
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
    // Interpreter frames resolve leaf-first ahead of the native stack;
    // unverified pids keep raw pointers rather than reading an
    // unrelated process's memory.
    let py_slots = (raw.py_frame_count as usize).min(RAW_PY_MAX_FRAMES);
    let py_incomplete = py_stop_reason(raw.py_stop).is_some_and(|(_, incomplete)| incomplete);
    let mut py_count = 0usize;
    let stack_frames = if py_slots > 0 {
        let mut merged = Vec::with_capacity(py_slots + stack_frames.len());
        for &code_ptr in raw.py_frames.iter().take(py_slots) {
            // Zero slots are interpreter shim frames skipped in-kernel.
            if code_ptr == 0 {
                continue;
            }
            py_count += 1;
            let resolved = if pid_unverified {
                None
            } else {
                resolver.resolve_python_frame(raw.pid, code_ptr)
            };
            merged.push(resolved.unwrap_or_else(|| RawProfileFrame {
                symbol: Some(format!("py:{code_ptr:#x}")),
                module: Some("<python>".to_string()),
                file: None,
                line: None,
                module_offset: None,
            }));
        }
        merged.extend(stack_frames);
        merged
    } else {
        stack_frames
    };
    let timestamp_unix_nanos = if raw.timestamp_unix_nanos == 0 {
        observed_unix_nanos
    } else {
        raw.timestamp_unix_nanos
    };
    let jit_frame_count = stack_frames
        .iter()
        .filter(|frame| frame.module.as_deref() == Some("<jit>"))
        .count();
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
            if py_count > 0 {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.py_frames".to_string(),
                    value: py_count.to_string(),
                });
            }
            if jit_frame_count > 0 {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.jit_frames".to_string(),
                    value: jit_frame_count.to_string(),
                });
            }
            if let Some((reason, _)) = py_stop_reason(raw.py_stop) {
                attributes.push(ProfilingAttribute {
                    key: "profiling.stack.py_stop".to_string(),
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
            pid: raw.pid,
            capture_truncated,
            pid_unverified,
            dwarf_incomplete: unwind_stop_reason(raw.flags)
                .is_some_and(|(_, incomplete)| incomplete),
            py_incomplete,
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
    py_incomplete_samples: std::sync::atomic::AtomicU64,
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

    pub(crate) fn record_py_incomplete_sample(&self) {
        self.py_incomplete_samples
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Atomically reads and resets all counters, returning
    /// (lost_perf_events, backpressure_dropped, truncated_stacks,
    /// pid_unverified_samples, dwarf_incomplete_samples,
    /// py_incomplete_samples) since the last drain.
    pub(crate) fn drain(&self) -> (u64, u64, u64, u64, u64, u64) {
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
            self.py_incomplete_samples
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

/// Builds a bounded profiling warning reporting CPython frame walks
/// that stopped before the root frame; interpreter frames may be
/// missing from those samples.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn py_incomplete_warning(
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
            warning_type: "py_unwind_incomplete".to_string(),
            message: "cpython frame walks stopped before the root frame; interpreter \
                      frames may be missing"
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
                key: "profiling.stack.py_incomplete_samples".to_string(),
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
        PyProcInfoAbi, UnwindMapSink, UnwindModuleSpan, UnwindProcMappings, UnwindRowAbi,
        UnwindTableManager,
    };
    use crate::reader_shutdown::ReaderShutdown;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, MapData, ProgramArray as AyaProgramArray,
            perf::PerfEvent as PerfBufferEvent,
        },
        programs::perf_event::{
            PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
        },
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, CpuProfileBackpressure, CpuProfileSourceConfig, EbpfConfig,
        ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, warn};

    #[derive(Debug, Clone)]
    pub struct AyaCpuProfileSource {
        host: Option<String>,
        procfs_root: std::path::PathBuf,
        config: CpuProfileSourceConfig,
        ebpf: EbpfConfig,
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
                ebpf: EbpfConfig::default(),
            }
        }

        pub fn with_ebpf_config(mut self, ebpf: EbpfConfig) -> Self {
            self.ebpf = ebpf;
            self
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
            let (mut ebpf, transport) = crate::event_transport::load_ebpf(
                &self.ebpf,
                crate::ebpf_maps::SourceMapProfile::CpuProfile,
                "source.aya_cpu_profile",
            )?;
            let telemetry = std::sync::Arc::new(SourceTelemetry::new_with_transport(
                "source.aya_cpu_profile",
                transport.kind.as_str(),
            ));
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

            // This source's reader handles carry a different exit type, so the
            // applier runs detached; it terminates on shutdown via is_stopped.
            let _capture_filter_applier = crate::capture_filter::attach_capture_filter(
                &mut ebpf,
                "source.aya_cpu_profile",
                {
                    let shutdown = shutdown.clone();
                    move || shutdown.is_stopped()
                },
            )?;

            let profile_events = crate::event_transport::take_event_map(
                &mut ebpf,
                "CPU_PROFILE_EVENTS",
                transport,
                "source.aya_cpu_profile",
            )?;
            if let Some(handle) = crate::event_transport::spawn_transport_loss_reader(
                &mut ebpf,
                crate::ebpf_maps::SourceMapProfile::CpuProfile,
                transport,
                "source.aya_cpu_profile",
                shutdown.clone(),
                telemetry.clone(),
            )? {
                reader_handles.push(tokio::spawn(async move {
                    if let Err(err) = handle.await {
                        warn!(error = %err, "ring-buffer loss reader failed");
                    }
                    ReaderExit::Stopped
                }));
            }

            let perf_pages = cpu_profile_perf_pages(
                self.config.sample_frequency_hz,
                core::mem::size_of::<super::RawCpuProfileEvent>(),
            );
            let shared_symbols =
                std::sync::Arc::new(std::sync::Mutex::new(super::SharedSymbolTables::default()));
            // Tracks pids the sampler observes on-CPU so the unwind
            // manager prioritizes their tables over idle system
            // processes; sized generously above any realistic on-CPU
            // working set on one node.
            let hot_pids = std::sync::Arc::new(crate::cpu_unwind::HotPidTracker::new(4096));
            match profile_events {
                crate::event_transport::EventMap::Perf(mut perf_array) => {
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
                        let telemetry = telemetry.clone();
                        let mut resolver = super::ProcfsSymbolizer::with_shared_symbols(
                            self.procfs_root.clone(),
                            config.resolve_symbol_names,
                            shared_symbols.clone(),
                        );
                        let symbolize = config.symbolize;
                        let reader_hot_pids = hot_pids.clone();

                        reader_handles.push(tokio::task::spawn_blocking(move || {
                            while !reader_shutdown.is_stopped() {
                                if crate::perf_reader::wait_for_events(
                                    &buffer,
                                    "source.aya_cpu_profile",
                                    cpu_id,
                                ) != Some(true)
                                {
                                    continue;
                                }
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
                                            let bytes =
                                                crate::perf_sample::perf_sample_bytes(head, tail);
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
                                                telemetry.record_invalid_sample();
                                                return;
                                            };
                                            telemetry.record_decoded_sample();
                                            reader_hot_pids.record(decoded.pid);
                                            record_profile_degradation(&decoded, &drop_counters);
                                            accepted += 1;
                                            if send_with_backpressure(
                                                &cpu_tx,
                                                decoded.signal,
                                                backpressure,
                                            ) {
                                                telemetry.record_sent_signal();
                                            } else if matches!(
                                                backpressure,
                                                CpuProfileBackpressure::StopSource
                                            ) {
                                                telemetry.record_send_failure();
                                                reader_shutdown.stop();
                                                exit = ReaderExit::BackpressureStop;
                                            } else {
                                                telemetry.record_send_failure();
                                                drop_counters.record_backpressure_drop();
                                                warn!(
                                                    "dropped cpu profile sample due to backpressure"
                                                );
                                            }
                                        }
                                        PerfBufferEvent::Lost { count } => {
                                            telemetry.record_lost_perf_events(count);
                                            drop_counters.record_lost_perf_events(count);
                                            warn!(count, "lost cpu profile perf events");
                                        }
                                    }
                                    telemetry.maybe_log_summary();
                                });

                                if matches!(exit, ReaderExit::BackpressureStop) {
                                    return ReaderExit::BackpressureStop;
                                }
                            }
                            ReaderExit::Stopped
                        }));
                    }
                }
                crate::event_transport::EventMap::Ring(mut ring) => {
                    let cpu_tx = tx.clone();
                    let host = self.host.clone();
                    let config = self.config.clone();
                    let backpressure = config.backpressure;
                    let reader_shutdown = shutdown.clone();
                    let drop_counters = drop_counters.clone();
                    let telemetry = telemetry.clone();
                    let mut resolver = super::ProcfsSymbolizer::with_shared_symbols(
                        self.procfs_root.clone(),
                        config.resolve_symbol_names,
                        shared_symbols.clone(),
                    );
                    let symbolize = config.symbolize;
                    let reader_hot_pids = hot_pids.clone();
                    reader_handles.push(tokio::task::spawn_blocking(move || {
                        while !reader_shutdown.is_stopped() {
                            if crate::perf_reader::wait_for_ring_events(
                                &ring,
                                "source.aya_cpu_profile",
                            ) != Some(true)
                            {
                                continue;
                            }
                            let mut accepted = 0_usize;
                            while accepted < config.max_samples_per_batch {
                                let Some(item) = ring.next() else {
                                    break;
                                };
                                let decoded = if symbolize {
                                    raw_cpu_profile_to_signal(
                                        &item,
                                        host.clone(),
                                        &config,
                                        &mut resolver,
                                    )
                                } else {
                                    raw_cpu_profile_to_signal(
                                        &item,
                                        host.clone(),
                                        &config,
                                        &mut super::RawAddressResolver,
                                    )
                                };
                                let Some(decoded) = decoded else {
                                    telemetry.record_invalid_sample();
                                    continue;
                                };
                                telemetry.record_decoded_sample();
                                reader_hot_pids.record(decoded.pid);
                                record_profile_degradation(&decoded, &drop_counters);
                                accepted += 1;
                                if send_with_backpressure(&cpu_tx, decoded.signal, backpressure) {
                                    telemetry.record_sent_signal();
                                } else if matches!(backpressure, CpuProfileBackpressure::StopSource)
                                {
                                    telemetry.record_send_failure();
                                    reader_shutdown.stop();
                                    return ReaderExit::BackpressureStop;
                                } else {
                                    telemetry.record_send_failure();
                                    drop_counters.record_backpressure_drop();
                                    warn!("dropped cpu profile sample due to backpressure");
                                }
                                telemetry.maybe_log_summary();
                            }
                        }
                        ReaderExit::Stopped
                    }));
                }
            }

            if self.config.dwarf_unwind {
                let refresher_shutdown = shutdown.clone();
                let mut sink = EbpfUnwindSink::take_from(&mut ebpf)?;
                let mut manager = UnwindTableManager::new(
                    self.procfs_root.clone(),
                    self.config.max_unwind_processes,
                );
                let refresher_hot_pids = hot_pids.clone();
                reader_handles.push(tokio::task::spawn_blocking(move || {
                    // Populate immediately, then re-scan on the same
                    // cadence as the TLS library rescan.
                    loop {
                        let stats = manager.refresh(&mut sink, &refresher_hot_pids);
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
                        let (lost, dropped, truncated, foreign, dwarf_incomplete, py_incomplete) =
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
                        if py_incomplete > 0 {
                            let warning = super::py_incomplete_warning(
                                emitter_host.clone(),
                                py_incomplete,
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
            telemetry.mark_initialized();
            debug!("aya cpu profile source attached");
            let reader_results = join_reader_handles(reader_handles);
            tokio::pin!(reader_results);
            tokio::select! {
                result = &mut reader_results => result,
                signal = crate::shutdown::signal() => {
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

    fn record_profile_degradation(
        decoded: &super::DecodedCpuProfileSample,
        counters: &super::CpuProfileDropCounters,
    ) {
        if decoded.capture_truncated {
            counters.record_truncated_stack();
        }
        if decoded.pid_unverified {
            counters.record_pid_unverified_sample();
        }
        if decoded.dwarf_incomplete {
            counters.record_dwarf_incomplete_sample();
        }
        if decoded.py_incomplete {
            counters.record_py_incomplete_sample();
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
        for (index, name) in [(1u32, "cpu_profile_py_find"), (2u32, "cpu_profile_py_walk")] {
            let py_program: &mut PerfEvent = ebpf
                .program_mut(name)
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_cpu_profile".to_string(),
                    message: format!("missing {name} program"),
                })?
                .try_into()
                .map_err(module_error)?;
            py_program.load().map_err(module_error)?;
            let py_fd = py_program
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
            programs.set(index, &py_fd, 0).map_err(module_error)?;
        }
        Ok(())
    }

    /// eBPF-map-backed sink for the unwind table manager.
    struct EbpfUnwindSink {
        rows: AyaArray<aya::maps::MapData, UnwindRowAbi>,
        modules: AyaHashMap<aya::maps::MapData, u32, UnwindModuleSpan>,
        processes: AyaHashMap<aya::maps::MapData, u32, UnwindProcMappings>,
        python: AyaHashMap<aya::maps::MapData, u32, PyProcInfoAbi>,
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
                python: AyaHashMap::try_from(take(ebpf, "PY_PROC_INFO")?).map_err(module_error)?,
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

        fn write_python_process(&mut self, pid: u32, info: &PyProcInfoAbi) -> bool {
            self.python.insert(pid, info, 0).is_ok()
        }

        fn remove_python_process(&mut self, pid: u32) {
            let _ = self.python.remove(&pid);
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
        CoreError, CoreResult, CpuProfileSourceConfig, EbpfConfig, ModuleKind, ModuleMetadata,
        Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Clone)]
    pub struct AyaCpuProfileSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
        _config: CpuProfileSourceConfig,
        _ebpf: EbpfConfig,
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
                _ebpf: EbpfConfig::default(),
            }
        }

        pub fn with_ebpf_config(mut self, ebpf: EbpfConfig) -> Self {
            self._ebpf = ebpf;
            self
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
    fn procfs_symbolizer_scopes_module_images_to_target_root() {
        let dir =
            std::env::temp_dir().join(format!("e-nav-module-root-test-{}", std::process::id()));
        let symbolizer = ProcfsSymbolizer::new(dir.clone(), true);

        assert_eq!(
            symbolizer.module_image_path(779, "/usr/bin/app"),
            Some(dir.join("779/root/usr/bin/app"))
        );
        assert_eq!(symbolizer.module_image_path(779, "usr/bin/app"), None);
        assert_eq!(symbolizer.module_image_path(779, "/usr/../host/app"), None);
    }

    #[test]
    fn procfs_symbolizer_resolves_bounded_target_namespace_perf_maps() {
        let dir = std::env::temp_dir().join(format!("e-nav-jitsymtest-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let pid_dir = dir.join("778");
        std::fs::create_dir_all(pid_dir.join("root/tmp")).expect("create target tmp");
        std::fs::write(pid_dir.join("maps"), "").expect("write empty maps");
        std::fs::write(pid_dir.join("status"), "Name:\tnode\nNSpid:\t778\t1\n")
            .expect("write namespace status");
        std::fs::write(
            pid_dir.join("root/tmp/perf-1.map"),
            "7f0100001000 30 LazyCompile:*busy /app/server.js:12\n\
             7f0100002000 40 java::com.example.Worker::run\n",
        )
        .expect("write perf map");

        let mut symbolizer = ProcfsSymbolizer::new(dir.clone(), true);
        let node = symbolizer.resolve(778, 0x7f0100001010);
        assert_eq!(
            node.symbol.as_deref(),
            Some("LazyCompile:*busy /app/server.js:12")
        );
        assert_eq!(node.module.as_deref(), Some("<jit>"));
        assert_eq!(node.module_offset, Some(0x10));
        let java = symbolizer.resolve(778, 0x7f010000203f);
        assert_eq!(
            java.symbol.as_deref(),
            Some("java::com.example.Worker::run")
        );
        assert_eq!(java.module.as_deref(), Some("<jit>"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn jit_frames_are_counted_in_profile_attributes() {
        struct JitResolver;
        impl FrameResolver for JitResolver {
            fn resolve(&mut self, _pid: u32, ip: u64) -> RawProfileFrame {
                RawProfileFrame {
                    symbol: Some(format!("generated_{ip:x}")),
                    module: Some("<jit>".to_string()),
                    file: None,
                    line: None,
                    module_offset: Some(0),
                }
            }
        }

        let raw = RawCpuProfileEvent {
            pid: 778,
            tid: 778,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("node"),
            frame_count: 2,
            flags: 0,
            instruction_pointers: padded_pointers(&[0x1000, 0x2000]),
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
        };
        let signal = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut JitResolver,
        )
        .expect("JIT sample decodes")
        .signal;
        let SignalPayload::ProfileSampleObservation(sample) = signal.payload else {
            panic!("expected profile sample");
        };
        assert!(sample.attributes.iter().any(|attribute| {
            attribute.key == "profiling.stack.jit_frames" && attribute.value == "2"
        }));
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
        counters.record_py_incomplete_sample();
        assert_eq!(counters.drain(), (5, 1, 2, 1, 1, 1));
        // Draining resets all counters.
        assert_eq!(counters.drain(), (0, 0, 0, 0, 0, 0));
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
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
    fn python_frames_merge_leaf_first_with_attributes() {
        struct PyResolver;
        impl FrameResolver for PyResolver {
            fn resolve(&mut self, _pid: u32, ip: u64) -> RawProfileFrame {
                RawAddressResolver.resolve(0, ip)
            }

            fn resolve_python_frame(
                &mut self,
                _pid: u32,
                code_ptr: u64,
            ) -> Option<RawProfileFrame> {
                (code_ptr == 0x5000).then(|| RawProfileFrame {
                    symbol: Some("my_module.busy".to_string()),
                    module: Some("<python>".to_string()),
                    file: Some("/app/busy.py".to_string()),
                    line: Some(17),
                    module_offset: None,
                })
            }
        }

        let mut raw = RawCpuProfileEvent {
            pid: 42,
            tid: 43,
            uid: 1000,
            cgroup_id: 0,
            sample_count: 1,
            timestamp_unix_nanos: 1_000,
            command: fixed_command("python3"),
            frame_count: 1,
            flags: 0,
            instruction_pointers: padded_pointers(&[0xabc]),
            py_frame_count: 0,
            py_stop: 0,
            py_frames: [0; RAW_PY_MAX_FRAMES],
        };
        raw.py_frame_count = 2;
        raw.py_stop = 1; // complete
        raw.py_frames[0] = 0x5000;
        raw.py_frames[1] = 0x6000; // unresolvable -> raw pointer label

        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut PyResolver,
        )
        .expect("python sample decodes");
        assert!(!decoded.py_incomplete);
        let SignalPayload::ProfileSampleObservation(sample) = decoded.signal.payload else {
            panic!("expected profile sample");
        };
        // Python frames lead, leaf first; the native frame follows.
        assert_eq!(sample.stack_frames.len(), 3);
        assert_eq!(
            sample.stack_frames[0].symbol.as_deref(),
            Some("my_module.busy")
        );
        assert_eq!(sample.stack_frames[0].file.as_deref(), Some("/app/busy.py"));
        assert_eq!(sample.stack_frames[0].line, Some(17));
        assert_eq!(sample.stack_frames[1].symbol.as_deref(), Some("py:0x6000"));
        assert_eq!(
            sample.stack_frames[2].symbol.as_deref(),
            Some("ip:0000000000000abc")
        );
        assert!(sample.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.py_frames"
            && attribute.value == "2"));
        assert!(
            sample
                .attributes
                .iter()
                .any(|attribute| attribute.key == "profiling.stack.py_stop"
                    && attribute.value == "complete")
        );

        // A read-faulted walk is flagged incomplete.
        raw.py_stop = 3;
        let decoded = raw_cpu_profile_to_signal_with_clock(
            raw_as_bytes(&raw),
            None,
            &source_config(),
            10_000,
            &mut PyResolver,
        )
        .expect("incomplete python sample decodes");
        assert!(decoded.py_incomplete);
    }

    fn assert_python_code_object_resolution(minor: u32, layout: PythonObjectLayout) {
        use std::io::{Seek, SeekFrom, Write};

        let dir = std::env::temp_dir().join(format!("e-nav-pymem-{}-{minor}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let pid_dir = dir.join("888");
        std::fs::create_dir_all(&pid_dir).expect("pid dir");
        std::fs::write(
            pid_dir.join("maps"),
            format!("10000000-10100000 r-xp 00000000 fd:00 100 /usr/local/bin/python3.{minor}\n"),
        )
        .expect("maps file");
        let mut mem = std::fs::File::create(pid_dir.join("mem")).expect("mem file");

        let code_ptr: u64 = 0x1000;
        let qualname_ptr: u64 = 0x2000;
        let filename_ptr: u64 = 0x3000;
        let write_at = |mem: &mut std::fs::File, offset: u64, bytes: &[u8]| {
            mem.seek(SeekFrom::Start(offset)).expect("seek");
            mem.write_all(bytes).expect("write");
        };
        write_at(
            &mut mem,
            code_ptr + layout.code_qualname,
            &qualname_ptr.to_le_bytes(),
        );
        write_at(
            &mut mem,
            code_ptr + layout.code_filename,
            &filename_ptr.to_le_bytes(),
        );
        write_at(
            &mut mem,
            code_ptr + layout.code_firstlineno,
            &41i32.to_le_bytes(),
        );
        // Compact ASCII unicode objects: kind=1 (bits 2..5), compact
        // (bit 5), ascii (bit 6).
        let state: u32 = (1 << 2) | (1 << 5) | (1 << 6);
        for (ptr, text) in [
            (qualname_ptr, "pkg.mod.busy"),
            (filename_ptr, "/app/mod.py"),
        ] {
            write_at(
                &mut mem,
                ptr + layout.unicode_length,
                &(text.len() as u64).to_le_bytes(),
            );
            write_at(&mut mem, ptr + layout.unicode_state, &state.to_le_bytes());
            write_at(&mut mem, ptr + layout.unicode_data, text.as_bytes());
        }
        // Sensitive-looking adjacent memory that must never be exported.
        write_at(&mut mem, code_ptr + 0x200, b"password=hunter2");
        drop(mem);

        let mut symbolizer = ProcfsSymbolizer::new(dir.clone(), true);
        let frame = symbolizer
            .resolve_python_frame(888, code_ptr)
            .expect("python frame resolves");
        assert_eq!(frame.symbol.as_deref(), Some("pkg.mod.busy"));
        assert_eq!(frame.file.as_deref(), Some("/app/mod.py"));
        assert_eq!(frame.line, Some(41));
        assert_eq!(frame.module.as_deref(), Some("<python>"));
        let serialized = format!("{frame:?}");
        assert!(!serialized.contains("hunter2"));

        // Unreadable pointers resolve to None (cached), not garbage.
        assert!(symbolizer.resolve_python_frame(888, 0x9_0000).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn procfs_symbolizer_resolves_python311_code_objects() {
        assert_python_code_object_resolution(
            11,
            PythonObjectLayout::for_minor(11).expect("3.11 layout"),
        );
    }

    #[test]
    fn procfs_symbolizer_resolves_python312_code_objects() {
        assert_python_code_object_resolution(
            12,
            PythonObjectLayout::for_minor(12).expect("3.12 layout"),
        );
    }

    #[test]
    fn py_incomplete_warning_reports_count() {
        let signal = py_incomplete_warning(Some("node-a".to_string()), 4, 12_000);
        let SignalPayload::ProfilingWarningObservation(warning) = signal.payload else {
            panic!("expected profiling warning");
        };
        assert_eq!(warning.warning_type, "py_unwind_incomplete");
        assert!(warning.attributes.iter().any(|attribute| attribute.key
            == "profiling.stack.py_incomplete_samples"
            && attribute.value == "4"));
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
        assert_eq!(core::mem::size_of::<RawCpuProfileEvent>(), 1608);
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
