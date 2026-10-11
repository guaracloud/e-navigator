use super::*;
use e_navigator_profiling::unwind::{LoadSegment, UnwindRow};

#[derive(Default)]
struct MemorySink {
    rows: std::collections::BTreeMap<u32, Vec<UnwindRowAbi>>,
    modules: std::collections::BTreeMap<u32, UnwindModuleSpan>,
    processes: std::collections::BTreeMap<u32, (u32, Vec<UnwindMapping>)>,
    removed: Vec<u32>,
    python: std::collections::BTreeMap<u32, PyProcInfoAbi>,
    python_removed: Vec<u32>,
    reject_modules: bool,
    generation: u64,
    change_generation_on_write: bool,
}

impl UnwindMapSink for MemorySink {
    fn process_generation(&mut self, _pid: u32) -> Option<u64> {
        Some(self.generation)
    }
    fn write_rows(&mut self, row_start: u32, rows: &[UnwindRowAbi]) -> bool {
        self.rows.insert(row_start, rows.to_vec());
        true
    }

    fn write_module(&mut self, module_id: u32, span: UnwindModuleSpan) -> bool {
        if self.reject_modules {
            return false;
        }
        self.modules.insert(module_id, span);
        true
    }

    fn write_process(&mut self, pid: u32, mappings: &UnwindProcMappings) -> bool {
        if self.change_generation_on_write {
            self.generation += 1;
        }
        let entries = mappings.entries[..mappings.count as usize].to_vec();
        self.processes.insert(pid, (mappings.count, entries));
        true
    }

    fn remove_process(&mut self, pid: u32) {
        self.removed.push(pid);
        self.processes.remove(&pid);
    }

    fn write_python_process(&mut self, pid: u32, info: &PyProcInfoAbi) -> bool {
        self.python.insert(pid, *info);
        true
    }

    fn remove_python_process(&mut self, pid: u32) {
        self.python_removed.push(pid);
        self.python.remove(&pid);
    }
}

#[test]
fn refresh_discards_registrations_if_process_changes_during_publish() {
    let root = fake_procfs("generation", 710, 0x1000_0000);
    let mut manager = UnwindTableManager::new(root.clone(), 16).with_python_builds(Vec::new());
    let mut sink = MemorySink {
        change_generation_on_write: true,
        ..MemorySink::default()
    };
    let stats = manager.refresh(&mut sink, &tracked_pids(&[710]));
    assert_eq!(stats.processes_registered, 0);
    assert!(sink.processes.is_empty());
    assert_eq!(stats.process_identity_changes, 1);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn in_flight_mapping_changes_and_missing_generations_fail_closed() {
    assert_eq!(
        ProfileGenerationAbi {
            generation: 77,
            pending_mappings: 0
        }
        .usable(),
        Some(77)
    );
    for state in [
        ProfileGenerationAbi::default(),
        ProfileGenerationAbi {
            generation: 77,
            pending_mappings: 1,
        },
        ProfileGenerationAbi {
            generation: 77,
            pending_mappings: u64::MAX,
        },
    ] {
        assert_eq!(state.usable(), None);
    }
}

const EH_VADDR: u64 = 0x10_000;
const FUNC: u64 = 0x40_000;

/// Minimal ELF64 with a single-FDE `.eh_frame` (x86-64 prologue rules)
/// and one PT_LOAD segment starting at vaddr 0 / file offset 0.
fn synthetic_module() -> Vec<u8> {
    fn entry(content: &[u8]) -> Vec<u8> {
        let mut bytes = (content.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(content);
        bytes
    }
    let mut eh = {
        let mut content = 0u32.to_le_bytes().to_vec();
        content.push(1);
        content.extend_from_slice(b"zR\0");
        content.push(0x01);
        content.push(0x78);
        content.push(16);
        content.push(0x01);
        content.push(0x1b);
        content.extend_from_slice(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
        entry(&content)
    };
    {
        let content_start = eh.len() + 4;
        let pc_field_vaddr = EH_VADDR + content_start as u64 + 4;
        let pc_delta = (FUNC as i64 - pc_field_vaddr as i64) as i32;
        let mut content = (content_start as u32).to_le_bytes().to_vec();
        content.extend_from_slice(&pc_delta.to_le_bytes());
        content.extend_from_slice(&0x40i32.to_le_bytes());
        content.push(0x00);
        content.extend_from_slice(&[0x41, 0x0e, 0x10, 0x86, 0x02]);
        eh.extend_from_slice(&entry(&content));
    }

    let mut image = vec![0u8; 64];
    image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    image[4] = 2;
    image[5] = 1;
    image[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64

    let phoff = image.len() as u64;
    let mut phdr = vec![0u8; 56];
    phdr[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    phdr[8..16].copy_from_slice(&0u64.to_le_bytes()); // file offset
    phdr[16..24].copy_from_slice(&0u64.to_le_bytes()); // vaddr
    phdr[32..40].copy_from_slice(&0x100_000u64.to_le_bytes()); // filesz
    image.extend_from_slice(&phdr);

    let eh_offset = image.len() as u64;
    image.extend_from_slice(&eh);
    let shstrtab = b"\0.eh_frame\0.shstrtab\0";
    let shstrtab_offset = image.len() as u64;
    image.extend_from_slice(shstrtab);
    let shoff = image.len() as u64;
    let mut sections = vec![0u8; 64];
    let mut eh_section = vec![0u8; 64];
    eh_section[0..4].copy_from_slice(&1u32.to_le_bytes());
    eh_section[4..8].copy_from_slice(&1u32.to_le_bytes());
    eh_section[16..24].copy_from_slice(&EH_VADDR.to_le_bytes());
    eh_section[24..32].copy_from_slice(&eh_offset.to_le_bytes());
    eh_section[32..40].copy_from_slice(&(eh.len() as u64).to_le_bytes());
    sections.extend_from_slice(&eh_section);
    let mut str_section = vec![0u8; 64];
    str_section[0..4].copy_from_slice(&11u32.to_le_bytes());
    str_section[4..8].copy_from_slice(&3u32.to_le_bytes());
    str_section[24..32].copy_from_slice(&shstrtab_offset.to_le_bytes());
    str_section[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
    sections.extend_from_slice(&str_section);
    image.extend_from_slice(&sections);
    image[32..40].copy_from_slice(&phoff.to_le_bytes());
    image[40..48].copy_from_slice(&shoff.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes());
    image[60..62].copy_from_slice(&3u16.to_le_bytes());
    image[62..64].copy_from_slice(&2u16.to_le_bytes());
    image
}

/// Fake procfs: `<root>/<pid>/maps` + `<root>/<pid>/root/usr/bin/app`.
fn fake_procfs(tag: &str, pid: u32, mapping_start: u64) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("e-nav-unwindtest-{}-{tag}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let pid_dir = root.join(pid.to_string());
    let bin_dir = pid_dir.join("root").join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake procfs");
    std::fs::write(bin_dir.join("app"), synthetic_module()).expect("write module");
    std::fs::write(
        pid_dir.join("maps"),
        format!(
            "{mapping_start:x}-{:x} r-xp 00000000 fd:00 100 /usr/bin/app\n",
            mapping_start + 0x100_000
        ),
    )
    .expect("write maps");
    root
}

fn tracked_pids(pids: &[u32]) -> HotPidTracker {
    let tracker = HotPidTracker::new(64);
    for pid in pids {
        tracker.record(*pid);
    }
    tracker
}

#[test]
fn refresh_registers_process_with_rows_and_bias() {
    let root = fake_procfs("bias", 4242, 0x5555_0000_0000);
    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink::default();

    let stats = manager.refresh(&mut sink, &tracked_pids(&[4242]));
    assert_eq!(stats.processes_registered, 1);
    assert_eq!(stats.modules_loaded, 1);
    assert_eq!(stats.modules_without_tables, 0);

    let (count, entries) = sink.processes.get(&4242).expect("registered process");
    assert_eq!(*count, 1);
    // vaddr 0 maps at 0x5555_0000_0000 -> bias is the mapping start.
    assert_eq!(entries[0].bias, 0x5555_0000_0000);
    assert_eq!(entries[0].start, 0x5555_0000_0000);

    let span = sink
        .modules
        .get(&entries[0].module_id)
        .expect("module span");
    let rows = sink.rows.get(&span.row_start).expect("rows written");
    assert_eq!(rows.len() as u32, span.row_len);
    // First row: FUNC entry with CFA=rsp+8, RA at CFA-8.
    assert_eq!(rows[0].pc, FUNC);
    assert_eq!(rows[0].cfa_kind, UNWIND_CFA_SP);
    assert_eq!(rows[0].cfa_off, 8);
    assert_eq!(rows[0].ra_kind, UNWIND_RA_CFA_OFFSET);
    assert_eq!(rows[0].ra_off, -8);
    // Last row terminates the FDE range.
    assert_eq!(
        rows.last().expect("terminator").cfa_kind,
        UNWIND_CFA_INVALID
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn module_tables_are_shared_across_processes() {
    let root = fake_procfs("shared", 100, 0x1000_0000);
    // Second process, same procfs root, same module file content but a
    // distinct inode (copied file) -> parsed separately; same-file
    // sharing is keyed on (dev, ino).
    let pid_dir = root.join("101");
    let bin_dir = pid_dir.join("root").join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir).expect("second pid dir");
    std::fs::hard_link(
        root.join("100")
            .join("root")
            .join("usr")
            .join("bin")
            .join("app"),
        bin_dir.join("app"),
    )
    .expect("hard link module");
    std::fs::write(
        pid_dir.join("maps"),
        "20000000-20100000 r-xp 00000000 fd:00 100 /usr/bin/app\n",
    )
    .expect("write maps");

    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink::default();
    let stats = manager.refresh(&mut sink, &tracked_pids(&[100, 101]));

    assert_eq!(stats.processes_registered, 2);
    // Hard-linked file: same inode, parsed and written once.
    assert_eq!(stats.modules_loaded, 1);
    assert_eq!(sink.modules.len(), 1);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn exited_processes_are_removed_on_next_refresh() {
    let root = fake_procfs("exit", 300, 0x1000_0000);
    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink::default();
    let tracker = tracked_pids(&[300]);
    let stats = manager.refresh(&mut sink, &tracker);
    assert_eq!(stats.processes_registered, 1);

    std::fs::remove_dir_all(root.join("300")).expect("simulate exit");
    let stats = manager.refresh(&mut sink, &tracker);
    assert_eq!(stats.processes_registered, 0);
    assert_eq!(sink.removed, vec![300]);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn process_limit_is_bounded_and_counted() {
    let root = fake_procfs("limit", 400, 0x1000_0000);
    let pid_dir = root.join("401");
    std::fs::create_dir_all(pid_dir.join("root")).expect("dir");
    std::fs::write(pid_dir.join("maps"), "").expect("empty maps");

    let mut manager = UnwindTableManager::new(root.clone(), 1);
    let mut sink = MemorySink::default();
    let stats = manager.refresh(&mut sink, &tracked_pids(&[400, 401]));
    assert_eq!(stats.processes_skipped_limit, 1);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn hot_tracker_is_bounded_recent_and_prunes_dead_pids() {
    let tracker = HotPidTracker::new(2);
    assert_eq!(tracker.membership_revision(), 0);
    tracker.record(0); // ignored
    tracker.record(10);
    tracker.record(20);
    assert_eq!(tracker.membership_revision(), 2);
    // Refresh pid 10, then admit pid 30 by evicting least-recent pid 20.
    tracker.record(10);
    tracker.record(30);
    assert_eq!(tracker.snapshot(), [10, 30].into_iter().collect());
    assert_eq!(tracker.membership_revision(), 3);
    // Pruning drops pids no longer alive.
    tracker.retain_alive(&[30].into_iter().collect());
    assert_eq!(tracker.snapshot(), [30].into_iter().collect());
    assert_eq!(tracker.membership_revision(), 4);
}

#[test]
fn only_sampled_pids_receive_unwind_tables() {
    // Two processes, each with its own module; only the high pid has been
    // sampled. The cold process must not consume userspace or kernel rows.
    let root = fake_procfs("hot", 100, 0x1000_0000);
    let pid_dir = root.join("900");
    let bin_dir = pid_dir.join("root").join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir).expect("hot pid dir");
    // Distinct module file (distinct inode) so it consumes its own rows.
    std::fs::write(bin_dir.join("app"), synthetic_module()).expect("write module");
    std::fs::write(
        pid_dir.join("maps"),
        "20000000-20100000 r-xp 00000000 fd:00 100 /usr/bin/app\n",
    )
    .expect("write maps");

    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let hot = HotPidTracker::new(64);
    hot.record(900); // the high pid is the sampled one
    let mut sink = MemorySink::default();
    let stats = manager.refresh(&mut sink, &hot);

    // The sampled high pid registered; the cold low pid was never parsed.
    assert!(sink.processes.contains_key(&900));
    assert!(!sink.processes.contains_key(&100));
    assert_eq!(stats.processes_registered, 1);
    assert_eq!(stats.tracked_processes, 1);
    assert_eq!(stats.cached_modules, 1);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn cached_rows_never_exceed_the_kernel_row_pool() {
    let root = fake_procfs("row-cache", 500, 0x1000_0000);
    let pid_dir = root.join("501");
    let bin_dir = pid_dir.join("root").join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir).expect("second pid dir");
    std::fs::write(bin_dir.join("app"), synthetic_module()).expect("write second module");
    std::fs::write(
        pid_dir.join("maps"),
        "20000000-20100000 r-xp 00000000 fd:00 101 /usr/bin/app\n",
    )
    .expect("write second maps");

    let module_rows = ElfUnwindTable::parse(&synthetic_module()).len() as u32;
    let mut manager = UnwindTableManager::new(root.clone(), 16);
    manager.set_row_pool_for_test(module_rows);
    let mut sink = MemorySink::default();

    let stats = manager.refresh(&mut sink, &tracked_pids(&[500, 501]));

    assert!(stats.cached_rows <= module_rows as usize);
    assert!(manager.cached_rows <= module_rows as usize);
    assert_eq!(stats.cached_modules, 1);
    assert!(stats.modules_skipped_row_budget >= 1);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn refresh_keeps_published_rows_immutable_when_hot_order_changes() {
    let root = fake_procfs("immutable", 600, 0x1000_0000);
    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink::default();
    let tracker = tracked_pids(&[600]);
    manager.refresh(&mut sink, &tracker);
    let first_module = sink.processes[&600].1[0].module_id;
    let first_span = sink.modules[&first_module];
    let pid_dir = root.join("601");
    std::fs::create_dir_all(pid_dir.join("root/usr/bin")).expect("second process");
    std::fs::write(pid_dir.join("root/usr/bin/app"), synthetic_module()).expect("new module");
    std::fs::write(
        pid_dir.join("maps"),
        "20000000-20100000 r-xp 00000000 fd:00 101 /usr/bin/app\n",
    )
    .expect("maps");
    tracker.record(601);
    manager.refresh(&mut sink, &tracker);
    assert_eq!(
        sink.modules[&first_module], first_span,
        "a kernel walker may still be reading the published rows"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn load_bias_uses_the_segment_containing_the_file_offset() {
    let segments = [
        LoadSegment {
            vaddr: 0,
            file_offset: 0,
            file_size: 0x1000,
        },
        LoadSegment {
            vaddr: 0x2000,
            file_offset: 0x1000,
            file_size: 0x1000,
        },
    ];
    // Mapping of the second segment: file offset 0x1000 is link vaddr
    // 0x2000, mapped at 0x7f00_0000_1000.
    assert_eq!(
        compute_load_bias(0x7f00_0000_1000, 0x1000, &segments),
        Some(0x7f00_0000_1000 - 0x2000)
    );
    // Offset outside every segment has no bias.
    assert_eq!(compute_load_bias(0x7f00_0000_0000, 0x9000, &segments), None);
}

#[test]
fn row_conversion_covers_every_rule_kind() {
    use e_navigator_profiling::unwind::{CfaRule, FpRule, RaRule};

    let row = UnwindRow {
        pc: 0x10,
        cfa: CfaRule::FpOffset(16),
        ra: RaRule::LinkRegister,
        fp: FpRule::CfaOffset(-32),
    };
    let abi = row_to_abi(&row);
    assert_eq!(abi.cfa_kind, UNWIND_CFA_FP);
    assert_eq!(abi.cfa_off, 16);
    assert_eq!(abi.ra_kind, UNWIND_RA_LINK_REGISTER);
    assert_eq!(abi.fp_kind, UNWIND_FP_CFA_OFFSET);
    assert_eq!(abi.fp_off, -32);

    let row = UnwindRow {
        pc: 0x20,
        cfa: CfaRule::Invalid,
        ra: RaRule::Unsupported,
        fp: FpRule::Preserved,
    };
    let abi = row_to_abi(&row);
    assert_eq!(abi.cfa_kind, UNWIND_CFA_INVALID);
    assert_eq!(abi.ra_kind, UNWIND_RA_UNSUPPORTED);
    assert_eq!(abi.fp_kind, UNWIND_FP_PRESERVED);
}

#[test]
fn python_minor_version_parses_interpreter_paths() {
    assert_eq!(python_minor_version("/usr/local/bin/python3.12"), Some(12));
    assert_eq!(
        python_minor_version("/usr/lib/aarch64-linux-gnu/libpython3.11.so.1.0"),
        Some(11)
    );
    assert_eq!(python_minor_version("/usr/bin/app"), None);
    assert_eq!(python_minor_version("/opt/python3."), None);
}

#[test]
fn py311_offsets_match_measured_values() {
    // Ground truth measured with offsetof() against CPython 3.11.13.
    let info = py311_proc_info(0x1000, 0x42, 0xabc);
    assert_eq!(info.runtime_addr, 0x1000);
    assert_eq!(info.pid_ns_dev, 0x42);
    assert_eq!(info.pid_ns_ino, 0xabc);
    assert_eq!(info.interpreters_head, 40);
    assert_eq!(info.threads_head, 16);
    assert_eq!(info.tstate_native_thread_id, 160);
    assert_eq!(info.tstate_cframe, 56);
    assert_eq!(info.cframe_current_frame, 8);
    assert_eq!(info.iframe_code, 32);
    assert_eq!(info.iframe_previous, 48);
    assert_eq!(info.iframe_owner, 69);
}

#[test]
fn py312_offsets_match_measured_values() {
    // Ground truth measured with offsetof() against CPython 3.12.13.
    let info = py312_proc_info(0x1000, 0x42, 0xabc);
    assert_eq!(info.runtime_addr, 0x1000);
    assert_eq!(info.pid_ns_dev, 0x42);
    assert_eq!(info.pid_ns_ino, 0xabc);
    assert_eq!(info.interpreters_head, 40);
    assert_eq!(info.threads_head, 72);
    assert_eq!(info.tstate_native_thread_id, 144);
    assert_eq!(info.tstate_cframe, 56);
    assert_eq!(info.iframe_owner, 70);
}

#[test]
fn unsupported_python_versions_are_counted_not_registered() {
    let root = fake_procfs("py310", 700, 0x1000_0000);
    // Pretend the process maps an unsupported python3.10 interpreter.
    std::fs::write(
        root.join("700").join("maps"),
        "10000000-10100000 r-xp 00000000 fd:00 100 /usr/local/bin/python3.10\n",
    )
    .expect("write maps");

    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink::default();
    let stats = manager.refresh(&mut sink, &tracked_pids(&[700]));
    assert_eq!(stats.python_registered, 0);
    assert_eq!(stats.python_unsupported_version, 1);
    assert!(sink.python.is_empty());

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn python_descriptor_requires_attested_build_version_architecture_and_release_layout() {
    let build = e_navigator_core::CpuProfilePythonBuild {
        build_id: "0123456789abcdef".to_string(),
        version: "3.11.13".to_string(),
        architecture: "x86_64".to_string(),
    };
    let image = python_image(0x030b0df0, 62, false);
    let descriptor =
        validated_python_image(&image, std::slice::from_ref(&build)).expect("attested release");
    assert_eq!(descriptor.minor, 11);
    assert_eq!(descriptor.runtime_vaddr, 0x8000);
    assert!(validated_python_image(&image, &[]).is_none());
    for bad_image in [
        python_image(0x030b0cf0, 62, false),
        python_image(0x030b0df0, 183, false),
        python_image(0x030b0df0, 62, true),
        vec![0; 64],
    ] {
        assert!(validated_python_image(&bad_image, std::slice::from_ref(&build)).is_none());
    }
    let mut wrong_build = build.clone();
    wrong_build.build_id = "ffffffffffffffff".to_string();
    assert!(validated_python_image(&image, &[wrong_build]).is_none());
    let arm = e_navigator_core::CpuProfilePythonBuild {
        version: "3.12.13".to_string(),
        architecture: "aarch64".to_string(),
        ..build
    };
    assert_eq!(
        validated_python_image(&python_image(0x030c0df0, 183, false), &[arm])
            .expect("arm release")
            .minor,
        12
    );
}

pub(super) fn python_image(version: u32, machine: u16, debug: bool) -> Vec<u8> {
    // Real ELF64 section/symbol/note encoding, including a build ID and data
    // symbol. The release/debug and version controls are independent of paths.
    let names = b"\0.data\0.strtab\0.symtab\0.note.gnu.build-id\0.shstrtab\0";
    let strings = b"\0_PyRuntime\0Py_Version\0_Py_RefTotal\0";
    let mut image = vec![0u8; 120];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    image[16..18].copy_from_slice(&3u16.to_le_bytes());
    image[18..20].copy_from_slice(&machine.to_le_bytes());
    image[20..24].copy_from_slice(&1u32.to_le_bytes());
    image[32..40].copy_from_slice(&64u64.to_le_bytes());
    image[54..56].copy_from_slice(&56u16.to_le_bytes());
    image[56..58].copy_from_slice(&1u16.to_le_bytes());
    image[64..68].copy_from_slice(&1u32.to_le_bytes());
    image[68..72].copy_from_slice(&5u32.to_le_bytes());
    image[96..104].copy_from_slice(&65536u64.to_le_bytes());
    image[104..112].copy_from_slice(&65536u64.to_le_bytes());
    let mut sections = vec![0u8; 64];
    let mut section = |name: u32, kind: u32, addr: u64, data: &[u8], link: u32, entry: u64| {
        let offset = image.len() as u64;
        image.extend_from_slice(data);
        let mut header = [0u8; 64];
        header[..4].copy_from_slice(&name.to_le_bytes());
        header[4..8].copy_from_slice(&kind.to_le_bytes());
        header[16..24].copy_from_slice(&addr.to_le_bytes());
        header[24..32].copy_from_slice(&offset.to_le_bytes());
        header[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
        header[40..44].copy_from_slice(&link.to_le_bytes());
        header[56..64].copy_from_slice(&entry.to_le_bytes());
        sections.extend_from_slice(&header);
    };
    let mut data = vec![0u8; 16];
    data[..4].copy_from_slice(&version.to_le_bytes());
    section(1, 1, 0x8000, &data, 0, 0);
    section(7, 3, 0, strings, 0, 0);
    let mut symbols = vec![0u8; 24];
    for (name, address) in [(1u32, 0x8000u64), (12, 0x8000), (23, 0x8008)]
        .into_iter()
        .take(if debug { 3 } else { 2 })
    {
        let mut symbol = [0u8; 24];
        symbol[..4].copy_from_slice(&name.to_le_bytes());
        symbol[4] = 0x11;
        symbol[6..8].copy_from_slice(&1u16.to_le_bytes());
        symbol[8..16].copy_from_slice(&address.to_le_bytes());
        symbol[16..24].copy_from_slice(&8u64.to_le_bytes());
        symbols.extend_from_slice(&symbol);
    }
    section(15, 2, 0, &symbols, 2, 24);
    let mut note = [0u8; 24];
    note[..4].copy_from_slice(&4u32.to_le_bytes());
    note[4..8].copy_from_slice(&8u32.to_le_bytes());
    note[8..12].copy_from_slice(&3u32.to_le_bytes());
    note[12..16].copy_from_slice(b"GNU\0");
    note[16..].copy_from_slice(&[1, 35, 69, 103, 137, 171, 205, 239]);
    section(23, 7, 0, &note, 0, 0);
    section(42, 3, 0, names, 0, 0);
    let shoff = image.len() as u64;
    image.extend_from_slice(&sections);
    image[40..48].copy_from_slice(&shoff.to_le_bytes());
    image[52..54].copy_from_slice(&64u16.to_le_bytes());
    image[58..60].copy_from_slice(&64u16.to_le_bytes());
    image[60..62].copy_from_slice(&6u16.to_le_bytes());
    image[62..64].copy_from_slice(&5u16.to_le_bytes());
    image
}

#[test]
fn validated_python_registration_skips_unreadable_earlier_modules() {
    let root = fake_procfs("python-discovery", 711, 0x1000_0000);
    let process = root.join("711");
    std::fs::create_dir_all(process.join("root/usr/lib")).expect("module directory");
    std::fs::create_dir_all(process.join("ns")).expect("namespace directory");
    std::fs::write(process.join("ns/pid"), b"fixture").expect("namespace identity");
    std::fs::write(
        process.join("root/usr/lib/interpreter"),
        python_image(0x030b0df0, 62, false),
    )
    .expect("ELF");
    std::fs::write(process.join("maps"), "10000000-10010000 r-xp 00000000 00:00 1 /missing/deleted\n20000000-20010000 r-xp 00000000 00:00 2 /usr/lib/interpreter\n").expect("maps");
    let build = e_navigator_core::CpuProfilePythonBuild {
        build_id: "0123456789abcdef".into(),
        version: "3.11.13".into(),
        architecture: "x86_64".into(),
    };
    let mut manager = UnwindTableManager::new(root.clone(), 16).with_python_builds(vec![build]);
    let mut stats = UnwindRefreshStats::default();
    let info = manager
        .python_proc_info(711, &mut stats)
        .expect("validated interpreter after missing module");
    assert_eq!(info.runtime_addr, 0x2000_8000);
    std::fs::write(process.join("maps"), vec![b' '; 256 * 1024 + 1]).expect("oversize maps");
    assert!(manager.python_proc_info(711, &mut stats).is_none());
    assert!(
        manager
            .build_process_mappings(711, &mut MemorySink::default(), &mut stats)
            .is_none()
    );
    assert_eq!(stats.maps_rejected, 2);
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn failed_publication_rewrites_slots_overwritten_by_another_failed_module() {
    let root = fake_procfs("publication-retry", 712, 0x1000_0000);
    let second = root.join("712/root/usr/bin/second");
    let mut image = synthetic_module();
    let offset = image
        .windows(5)
        .position(|bytes| bytes == [0x0c, 0x07, 0x08, 0x90, 0x01])
        .expect("CFA rule");
    image[offset + 2] = 24;
    std::fs::write(&second, image).expect("second module");
    let mut manager = UnwindTableManager::new(root.clone(), 16);
    let mut sink = MemorySink {
        reject_modules: true,
        ..MemorySink::default()
    };
    let mut stats = UnwindRefreshStats::default();
    assert!(
        manager
            .module_record(712, "/usr/bin/app", &mut sink, &mut stats)
            .is_none()
    );
    assert!(
        manager
            .module_record(712, "/usr/bin/second", &mut sink, &mut stats)
            .is_none()
    );
    assert_eq!(sink.rows[&0][0].cfa_off, 24);
    sink.reject_modules = false;
    let record = manager
        .module_record(712, "/usr/bin/app", &mut sink, &mut stats)
        .expect("retry published");
    let span = sink.modules[&record.module_id];
    assert_eq!(span.row_start, 0);
    assert_eq!(sink.rows[&span.row_start][0].cfa_off, 8);
    std::fs::remove_dir_all(root).expect("cleanup");
}
