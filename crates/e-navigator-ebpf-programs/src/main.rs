#![no_std]
#![no_main]
#![allow(clippy::needless_borrows_for_generic_args)]

mod capture_policy;
mod dns_peer;

use aya_ebpf::{
    EbpfContext, Global,
    bindings::{BPF_F_USER_STACK, bpf_pidns_info},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_stack,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
        generated::{
            bpf_get_current_cgroup_id, bpf_get_current_task_btf, bpf_get_ns_current_pid_tgid,
            bpf_probe_read_kernel, bpf_probe_read_user as bpf_probe_read_user_raw,
            bpf_task_pt_regs,
        },
    },
    macros::{map, perf_event, tracepoint, uprobe, uretprobe},
    maps::{
        Array, HashMap, LruHashMap, PerCpuArray, PerfEventArray, PerfEventByteArray, ProgramArray,
    },
    programs::{PerfEventContext, ProbeContext, RetProbeContext, TracePointContext},
};
use capture_policy::{CAPTURE_FILTER_DISABLED, capture_allowed, listener_metadata_allowed};
use dns_peer::is_dns_ipv4_peer;

/// Source-stage diagnostics are intentionally opt-in. The userspace loader
/// overrides this read-only global before loading an object when diagnostic
/// sampling is enabled. Keeping the default fast path at zero avoids doing
/// several counter-map writes for every captured syscall in production.
#[unsafe(no_mangle)]
static SOURCE_DIAGNOSTICS_ENABLED: Global<u8> = Global::new(0);

const EXECUTABLE_LEN: usize = 256;
const MAX_ARGS: usize = 8;
const ARG_LEN: usize = 64;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const DNS_PACKET_BYTES: usize = 512;
const HTTP_MAX_IOVECS: usize = 3;
const HTTP_IOVEC_CHUNK_BYTES: usize = 96;
const HTTP_REQUEST_BYTES: usize = 1024;
const HTTP_DIAG_CONNECT_ENTER: u32 = 0;
const HTTP_DIAG_CONNECT_ACTIVE: u32 = 1;
const HTTP_DIAG_WRITE_ENTER: u32 = 2;
const HTTP_DIAG_WRITEV_ENTER: u32 = 3;
const HTTP_DIAG_SENDTO_ENTER: u32 = 4;
const HTTP_DIAG_SENDMSG_ENTER: u32 = 5;
const HTTP_DIAG_NULL_OR_EMPTY: u32 = 6;
const HTTP_DIAG_ACTIVE_CONNECTION_MISS: u32 = 7;
const HTTP_DIAG_NON_TCP_CONNECTION: u32 = 8;
const HTTP_DIAG_COPY_SUCCESS: u32 = 9;
const HTTP_DIAG_COPY_EMPTY: u32 = 10;
const HTTP_DIAG_OUTPUT_ATTEMPT: u32 = 11;
const HTTP_DIAG_FALLBACK_CANDIDATE: u32 = 12;
const HTTP_DIAG_FALLBACK_NON_HTTP_START: u32 = 13;
const HTTP_DIAG_FALLBACK_OUTPUT_ATTEMPT: u32 = 14;
const HTTP_DIAG_ACCEPT_ACTIVE: u32 = 15;
const HTTP_DIAG_INBOUND_READ_ENTER: u32 = 16;
const HTTP_DIAG_INBOUND_OUTPUT_ATTEMPT: u32 = 17;
const HTTP_DIAG_SERVER_WRITE_SUPPRESSED: u32 = 18;
const HTTP_DIAGNOSTIC_COUNTERS_LEN: u32 = 19;
const CONNECTION_ROLE_CLIENT: u32 = 0;
const CONNECTION_ROLE_SERVER: u32 = 1;
const PROTOCOL_DATA_BYTES: usize = 256;
const PROTOCOL_IOVEC_DATA_MAX: u32 = (PROTOCOL_DATA_BYTES - 1) as u32;
const PROTOCOL_MAX_IOVECS: u32 = 40;
const PROTOCOL_IOVEC_CHUNK: u32 = 8;
const PROTOCOL_DIAG_WRITE_ENTER: u32 = 0;
const PROTOCOL_DIAG_READ_ENTER: u32 = 1;
const PROTOCOL_DIAG_READ_EXIT: u32 = 2;
const PROTOCOL_DIAG_CONNECTION_MISS: u32 = 3;
const PROTOCOL_DIAG_PORT_FILTERED: u32 = 4;
const PROTOCOL_DIAG_NON_TCP_CONNECTION: u32 = 5;
const PROTOCOL_DIAG_NULL_OR_EMPTY: u32 = 6;
const PROTOCOL_DIAG_COPY_EMPTY: u32 = 7;
const PROTOCOL_DIAG_OUTPUT_ATTEMPT: u32 = 8;
const PROTOCOL_DIAG_WRITEV_ENTER: u32 = 9;
const PROTOCOL_DIAG_SENDMSG_ENTER: u32 = 10;
const PROTOCOL_DIAGNOSTIC_COUNTERS_LEN: u32 = 11;
const PROTOCOL_MAX_CAPTURE_SEGMENTS: usize = 16;
const PROTOCOL_MIN_CAPTURE_BYTES: u32 = PROTOCOL_DATA_BYTES as u32;
const PROTOCOL_MAX_CAPTURE_BYTES: u32 =
    (PROTOCOL_DATA_BYTES * PROTOCOL_MAX_CAPTURE_SEGMENTS) as u32;
const NETWORK_EVENT_OPEN: u32 = 1;
const NETWORK_EVENT_CLOSE: u32 = 2;
const NETWORK_EVENT_FAILURE: u32 = 3;
const TCP_STAT_KIND_RETRANSMIT: u32 = 1;
const TCP_STAT_KIND_RESET: u32 = 2;
const TCP_STAT_KIND_STATE: u32 = 3;
const TCP_RESET_DIRECTION_SEND: u32 = 1;
const TCP_RESET_DIRECTION_RECEIVE: u32 = 2;
const AF_INET_U16: u16 = 2;
const NETWORK_IO_READ: u32 = 1;
const NETWORK_IO_WRITE: u32 = 2;
const NEG_EINPROGRESS: i64 = -115;
const EXEC_EVENT_SOURCE_SYSCALL_ENTER: u32 = 1;
const EXEC_EVENT_SOURCE_SCHED_EXEC: u32 = 2;
const CPU_PROFILE_MAX_FRAMES: usize = 128;
const CPU_PROFILE_MIN_FRAMES: u32 = 1;
const CPU_PROFILE_FLAG_TRUNCATED: u32 = 1;
const CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED: u32 = 2;
const CPU_PROFILE_FLAG_DWARF: u32 = 4;
// DWARF unwind stop reason, stored in flags bits 8..16.
const UNWIND_STOP_SHIFT: u32 = 8;
const UNWIND_STOP_COMPLETE: u32 = 1;
const UNWIND_STOP_NO_MAPPING: u32 = 2;
const UNWIND_STOP_NO_RULE: u32 = 3;
const UNWIND_STOP_READ_FAULT: u32 = 4;
const UNWIND_STOP_BAD_FRAME: u32 = 5;
const UNWIND_STOP_DEPTH: u32 = 6;
const UNWIND_STOP_TAIL_LIMIT: u32 = 7;

// Power of two so an index mask (`& UNWIND_MAPPING_INDEX_MASK`) proves
// the array access in-bounds to the older kernel verifiers (6.6) that
// cannot track the loop-counter/count interaction otherwise.
const UNWIND_MAX_MAPPINGS: usize = 32;
const UNWIND_MAPPING_INDEX_MASK: usize = UNWIND_MAX_MAPPINGS - 1;
const UNWIND_ROW_POOL: u32 = 262_144;
const UNWIND_ROW_SEARCH_STEPS: u32 = 20;
const UNWIND_FRAMES_PER_ROUND: u32 = 16;
const UNWIND_MAX_ROUNDS: u32 = 8;

// Row rule kinds shared with the userspace loader.
const UNWIND_CFA_SP: u8 = 1;
const UNWIND_CFA_FP: u8 = 2;
const UNWIND_RA_CFA_OFFSET: u8 = 0;
const UNWIND_RA_LINK_REGISTER: u8 = 1;
const UNWIND_RA_UNDEFINED: u8 = 2;
const UNWIND_FP_CFA_OFFSET: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindRowAbi {
    pub pc: u64,
    pub cfa_kind: u8,
    pub ra_kind: u8,
    pub fp_kind: u8,
    pub _pad: u8,
    pub cfa_off: i32,
    pub ra_off: i32,
    pub fp_off: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindMapping {
    pub start: u64,
    pub end: u64,
    pub bias: u64,
    pub module_id: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindProcMappings {
    pub count: u32,
    pub _pad: u32,
    pub entries: [UnwindMapping; UNWIND_MAX_MAPPINGS],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindModuleSpan {
    pub row_start: u32,
    pub row_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnwindState {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub depth: u32,
    pub rounds: u32,
    pub frame_limit: u32,
    pub _pad: u32,
    pub py_tstate: u64,
    pub py_frame: u64,
    pub py_rounds: u32,
    pub _pad2: u32,
}

const PY_MAX_FRAMES: usize = 64;
const PY_FRAMES_PER_ROUND: u32 = 16;
const PY_MAX_ROUNDS: u32 = 4;
const PY_MAX_THREAD_VISITS: u32 = 64;
const PY_MAX_INTERPRETERS: u32 = 4;
const PY_STOP_COMPLETE: u32 = 1;
const PY_STOP_NO_THREAD: u32 = 2;
const PY_STOP_READ_FAULT: u32 = 3;
const PY_STOP_TRUNCATED: u32 = 4;

/// Per-process CPython walk parameters: the biased `_PyRuntime` address
/// plus version-specific struct offsets supplied by userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PyProcInfo {
    pub runtime_addr: u64,
    /// Device and inode of the process's pid namespace. CPython stores
    /// each thread's `native_thread_id` as the tid in the process's own
    /// namespace, so the thread match must translate the sampled tid
    /// into that namespace rather than compare host-namespace tids.
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
const TLS_DIAG_IO_ENTER: u32 = 0;
const TLS_DIAG_IO_EXIT: u32 = 1;
const TLS_DIAG_FD_UNRESOLVED: u32 = 2;
const TLS_DIAG_CONNECTION_MISS: u32 = 3;
const TLS_DIAG_PORT_FILTERED: u32 = 4;
const TLS_DIAG_NON_TCP_CONNECTION: u32 = 5;
const TLS_DIAG_NULL_OR_EMPTY: u32 = 6;
const TLS_DIAG_COPY_EMPTY: u32 = 7;
const TLS_DIAG_OUTPUT_ATTEMPT: u32 = 8;
const TLS_DIAG_SET_FD: u32 = 9;
const TLS_DIAGNOSTIC_COUNTERS_LEN: u32 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub argument_count: u32,
    pub event_source: u32,
    pub event_monotonic_nanos: u64,
    pub cgroup_id: u64,
    pub command: [u8; 16],
    pub executable: [u8; EXECUTABLE_LEN],
    pub arguments: [[u8; ARG_LEN]; MAX_ARGS],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExitEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub command: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawNetworkEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub errno: i32,
    pub family: u32,
    pub protocol: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub duration_nanos: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub command: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawTcpStatEvent {
    pub kind: u32,
    pub pid: u32,
    pub cgroup_id: u64,
    pub family: u32,
    pub old_state: i32,
    pub new_state: i32,
    pub reset_direction: u32,
    pub remote_port: u16,
    pub local_port: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub command: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawCpuProfileEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub sample_count: u64,
    pub timestamp_unix_nanos: u64,
    pub command: [u8; 16],
    pub frame_count: u32,
    pub flags: u32,
    pub instruction_pointers: [u64; CPU_PROFILE_MAX_FRAMES],
    pub py_frame_count: u32,
    pub py_stop: u32,
    /// CPython code-object pointers, leaf first; userspace resolves
    /// them to function/file/line through the process's memory.
    pub py_frames: [u64; PY_MAX_FRAMES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawDnsEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub protocol: u32,
    pub server_port_be: u16,
    pub server_addr_v4: u32,
    pub timestamp_unix_nanos: u64,
    pub latency_nanos: u64,
    pub packet_len: u32,
    pub command: [u8; 16],
    pub packet: [u8; DNS_PACKET_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawHttpRequestEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub family: u32,
    pub role: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub request_len: u32,
    /// Full syscall payload length before the bounded capture prefix. A value
    /// larger than `request_len` is an explicit reassembly gap.
    pub request_total_len: u32,
    pub request_iovec_lens: [u16; HTTP_MAX_IOVECS],
    pub command: [u8; 16],
    pub request: [u8; HTTP_REQUEST_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawProtocolDataEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub direction: u32,
    pub role: u32,
    pub family: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub payload_len: u32,
    pub payload_total_len: u32,
    pub payload_offset: u32,
    pub payload_captured_len: u32,
    pub command: [u8; 16],
    pub payload: [u8; PROTOCOL_DATA_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingProtocolRead {
    pub fd: i32,
    pub reserved: u32,
    pub buffer_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingProtocolIovecRead {
    pub fd: i32,
    pub reserved: u32,
    pub iov_ptr: u64,
    pub iov_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProtocolIovecState {
    pub iov_ptr: u64,
    pub iov_len: u64,
    pub total_len: u64,
    pub capture_limit: u32,
    pub captured_total: u32,
    pub slot: u32,
    pub capture_contiguous: u32,
    /// Exact successful syscall length for receive-side vectors; zero means
    /// an entry-side write whose complete vector length must be computed.
    pub total_bound: u64,
}

/// Keys the userspace TLS object pointer (`SSL*` or GnuTLS session) to the
/// process so the same pointer value in two processes never collides.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsHandleKey {
    pub tgid: u32,
    pub reserved: u32,
    pub handle: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsHandleFds {
    pub read_fd: i32,
    pub write_fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingTlsSetFd {
    pub handle: u64,
    pub fd: i32,
    /// Zero updates both directions; otherwise one of `NETWORK_IO_READ` or
    /// `NETWORK_IO_WRITE`.
    pub direction: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingTlsIo {
    pub handle: u64,
    pub buffer_ptr: u64,
    /// For the OpenSSL `_ex` variants, the userspace `size_t*` out-parameter
    /// receiving the processed byte count; zero for the classic variants and
    /// GnuTLS, where the byte count is the return value.
    pub count_ptr: u64,
    pub direction: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingConnect {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub family: u32,
    pub role: u32,
    pub protocol: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub started_at_nanos: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub command: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingNetworkIo {
    pub tgid: u32,
    pub fd: i32,
    pub direction: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingDnsRecv {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub buffer_ptr: u64,
    pub server_addr_ptr: u64,
    pub server_port_be: u16,
    pub server_addr_v4: u32,
    pub started_at_nanos: u64,
    pub command: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingHttpRead {
    pub fd: i32,
    pub reserved: u32,
    pub buffer_ptr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionKey {
    pub tgid: u32,
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingBind {
    pub fd: i32,
    pub family: u32,
    pub local_port_be: u16,
    pub reserved: u16,
    pub local_addr_v4: u32,
    pub local_addr_v6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenerKey {
    pub cgroup_id: u64,
    pub fd: i32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenerEndpoint {
    pub family: u32,
    pub local_port_be: u16,
    pub reserved: u16,
    pub local_addr_v4: u32,
    pub local_addr_v6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingAccept {
    pub listen_fd: i32,
    pub reserved: u32,
    pub sockaddr_ptr: u64,
}

#[map]
static EXEC_EVENTS: PerfEventArray<RawExecEvent> = PerfEventArray::new(0);

#[map]
static EXIT_EVENTS: PerfEventArray<RawExitEvent> = PerfEventArray::new(0);

#[map]
static NETWORK_EVENTS: PerfEventArray<RawNetworkEvent> = PerfEventArray::new(0);

#[map]
static TCP_STAT_EVENTS: PerfEventArray<RawTcpStatEvent> = PerfEventArray::new(0);

#[map]
static TCP_STAT_EVENT_SCRATCH: PerCpuArray<RawTcpStatEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CPU_PROFILE_EVENTS: PerfEventArray<RawCpuProfileEvent> = PerfEventArray::new(0);

#[map]
static DNS_EVENTS: PerfEventArray<RawDnsEvent> = PerfEventArray::new(0);

#[map]
static HTTP_REQUEST_EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
static HTTP_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(HTTP_DIAGNOSTIC_COUNTERS_LEN, 0);

#[map]
static PROTOCOL_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);

#[map]
static PROTOCOL_DATA_EVENT_SCRATCH: PerCpuArray<RawProtocolDataEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static PROTOCOL_IOVEC_STATE: PerCpuArray<ProtocolIovecState> = PerCpuArray::with_max_entries(1, 0);

/// Tail-call target 0 computes stable totals in verifier-small chunks;
/// target 1 emits the captured segments.
#[map]
static PROTOCOL_IOVEC_PROGS: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[map]
static PROTOCOL_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(PROTOCOL_DIAGNOSTIC_COUNTERS_LEN, 0);

// Ordinary BPF hash maps preallocate every bucket by default. Each E-Navigator
// source loads the shared eBPF object independently, so preallocation charges
// the full configured capacity for every retained source map even when only a
// handful of entries are live. `BPF_F_NO_PREALLOC` preserves the exact maximum
// entry bound and lookup/update semantics while charging storage as entries
// are inserted. LRU maps intentionally keep their required preallocated form.
const HASH_MAP_NO_PREALLOC: u32 = 1;

#[map]
static PROTOCOL_CAPTURE_PORTS: HashMap<u16, u32> =
    HashMap::with_max_entries(64, HASH_MAP_NO_PREALLOC);

#[map]
static PROTOCOL_CAPTURE_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

/// Whether the protocol source may emit accepted server sockets whose bound
/// port could not be recovered in-kernel. Userspace resolves those sockets
/// through bounded procfs lookup before selecting a configured parser.
#[map]
static PROTOCOL_CAPTURE_INBOUND: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static PENDING_PROTOCOL_READS: HashMap<u64, PendingProtocolRead> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_PROTOCOL_IOVEC_READS: HashMap<u64, PendingProtocolIovecRead> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static EXEC_EVENT_SCRATCH: PerCpuArray<RawExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EXIT_EVENT_SCRATCH: PerCpuArray<RawExitEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETWORK_EVENT_SCRATCH: PerCpuArray<RawNetworkEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CPU_PROFILE_EVENT_SCRATCH: PerCpuArray<RawCpuProfileEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static CPU_PROFILE_FRAME_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

/// dev (index 0) and inode (index 1) of the pid namespace backing the
/// procfs view userspace symbolizes from; zero inode disables translation.
#[map]
static CPU_PROFILE_PIDNS: Array<u64> = Array::with_max_entries(2, 0);

/// Flat pool of DWARF unwind rows shared by every module table.
#[map]
static UNWIND_ROWS: Array<UnwindRowAbi> = Array::with_max_entries(UNWIND_ROW_POOL, 0);

/// module id -> span of that module's rows inside UNWIND_ROWS.
#[map]
static UNWIND_MODULES: HashMap<u32, UnwindModuleSpan> =
    HashMap::with_max_entries(512, HASH_MAP_NO_PREALLOC);

/// pid (in the symbolization namespace) -> executable mappings with
/// precomputed load bias and module ids.
#[map]
static UNWIND_PROC_MAPPINGS: HashMap<u32, UnwindProcMappings> =
    HashMap::with_max_entries(1024, HASH_MAP_NO_PREALLOC);

/// Tail-call targets: index 0 = cpu_profile_unwind (chunked DWARF),
/// index 1 = cpu_profile_py_find (CPython thread-state search),
/// index 2 = cpu_profile_py_walk (CPython frame walk).
#[map]
static CPU_PROFILE_PROGS: ProgramArray = ProgramArray::with_max_entries(3, 0);

/// pid (in the symbolization namespace) -> CPython walk parameters.
#[map]
static PY_PROC_INFO: HashMap<u32, PyProcInfo> =
    HashMap::with_max_entries(1024, HASH_MAP_NO_PREALLOC);

#[map]
static CPU_PROFILE_UNWIND_STATE: PerCpuArray<UnwindState> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DNS_EVENT_SCRATCH: PerCpuArray<RawDnsEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static HTTP_REQUEST_EVENT_SCRATCH: PerCpuArray<RawHttpRequestEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static ARGV_CAPTURE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static PENDING_CONNECTS: HashMap<u64, PendingConnect> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static ACTIVE_CONNECTIONS: HashMap<ConnectionKey, PendingConnect> =
    HashMap::with_max_entries(16384, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_NETWORK_IO: HashMap<u64, PendingNetworkIo> =
    HashMap::with_max_entries(8192, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_DNS_RECVS: HashMap<u64, PendingDnsRecv> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_BINDS: HashMap<u64, PendingBind> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

/// Precise listener lookup for servers that bind and accept in one process.
#[map]
static PROCESS_LISTENER_ENDPOINTS: LruHashMap<ConnectionKey, ListenerEndpoint> =
    LruHashMap::with_max_entries(4096, 0);

/// Bounded prefork fallback: a child in the same cgroup commonly inherits the
/// parent's listening fd. The process-scoped map is always preferred so an
/// unrelated same-cgroup fd cannot override an ordinary server lookup.
#[map]
static LISTENER_ENDPOINTS: LruHashMap<ListenerKey, ListenerEndpoint> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
static PENDING_ACCEPTS: HashMap<u64, PendingAccept> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_HTTP_READS: HashMap<u64, PendingHttpRead> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

#[map]
static TLS_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);

#[map]
static TLS_DATA_EVENT_SCRATCH: PerCpuArray<RawProtocolDataEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static TLS_CAPTURE_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static TLS_CAPTURE_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(64, HASH_MAP_NO_PREALLOC);

#[map]
static TLS_HANDLE_FDS: HashMap<TlsHandleKey, TlsHandleFds> =
    HashMap::with_max_entries(16384, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_TLS_SET_FD: HashMap<u64, PendingTlsSetFd> =
    HashMap::with_max_entries(8192, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_TLS_IO: HashMap<u64, PendingTlsIo> =
    HashMap::with_max_entries(8192, HASH_MAP_NO_PREALLOC);

#[map]
static TLS_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(TLS_DIAGNOSTIC_COUNTERS_LEN, 0);

// Capture-filter control word held in CAPTURE_FILTER_CONTROL[0]. Userspace
// keeps this in lock-step with the `[capture_filter]` config; the kernel never
// sees a namespace or label, only cgroup ids and this posture byte.
// `0` disables the filter; `1` enables it with unknown cgroups captured; any
// other enabled value (userspace writes `2`) enables it with unknown cgroups
// dropped.

/// Single-slot control word: disabled, or enabled with the posture applied to
/// cgroups that are absent from `CGROUP_CAPTURE_FILTER`.
#[map]
static CAPTURE_FILTER_CONTROL: Array<u32> = Array::with_max_entries(1, 0);

/// Per-cgroup capture verdict populated by userspace: `1` capture, `0` drop.
/// Capacity mirrors `e_navigator_core::capture_filter::CAPTURE_FILTER_MAP_CAPACITY`.
#[map]
static CGROUP_CAPTURE_FILTER: HashMap<u64, u8> =
    HashMap::with_max_entries(8192, HASH_MAP_NO_PREALLOC);

/// Count of handler invocations suppressed by the capture filter, summed
/// across CPUs by userspace for the filter diagnostic (drop-with-accounting).
#[map]
static CAPTURE_FILTER_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_execve(ctx: TracePointContext) -> u32 {
    match try_tracepoint_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_execveat(ctx: TracePointContext) -> u32 {
    match try_tracepoint_execveat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_process_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_process_exec(ctx: TracePointContext) -> u32 {
    match try_tracepoint_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_connect_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_connect_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_connect_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_connect_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_close_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_close_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_dns_connect_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_dns_connect_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_dns_connect_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_dns_connect_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_dns_close_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_dns_close_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_connect_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_connect_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_connect_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_connect_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_close_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_close_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_write_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_write_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_writev_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_writev_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_sendto_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_sendto_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_sendmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_sendmsg_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_socket_bind_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_socket_bind_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_socket_bind_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_socket_bind_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_accept_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_accept_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_accept4_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_accept_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_accept_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_accept_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_accept4_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_accept_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_read_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_read_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_read_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_recvfrom_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_read_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_http_recvfrom_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_http_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_connect_enter(ctx: TracePointContext) -> u32 {
    match track_connect_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_connect_exit(ctx: TracePointContext) -> u32 {
    match track_connected_tcp_exit(&ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_close_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_close_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_write_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_write_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_sendto_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_write_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_writev_enter(ctx: TracePointContext) -> u32 {
    record_protocol_diagnostic(PROTOCOL_DIAG_WRITEV_ENTER);
    match try_tracepoint_protocol_writev_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_sendmsg_enter(ctx: TracePointContext) -> u32 {
    record_protocol_diagnostic(PROTOCOL_DIAG_SENDMSG_ENTER);
    match try_tracepoint_protocol_sendmsg_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_readv_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_read_enter(&ctx, false) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_readv_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_recvmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_read_enter(&ctx, true) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_recvmsg_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_iovec_emit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_emit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_iovec_compute(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_iovec_compute(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_read_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_read_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_read_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_recvfrom_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_read_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_protocol_recvfrom_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_protocol_read_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_read_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_read_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_read_exit(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_read_exit(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_write_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_write_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_write_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendto_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_sendto_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendto_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sendto_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvfrom_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_recvfrom_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvfrom_exit(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_recvfrom_exit(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendmsg_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_sendmsg_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendmsg_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sendmsg_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmsg_enter(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_recvmsg_enter(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmsg_exit(ctx: TracePointContext) -> u32 {
    let ret = match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    };
    match try_tracepoint_dns_recvmsg_exit(&ctx) {
        Ok(_) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_tcp_set_state(ctx: TracePointContext) -> u32 {
    match try_tracepoint_tcp_set_state(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_tcp_retransmit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_tcp_retransmit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_tcp_send_reset(ctx: TracePointContext) -> u32 {
    match try_tracepoint_tcp_reset(&ctx, TCP_RESET_DIRECTION_SEND) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_tcp_receive_reset(ctx: TracePointContext) -> u32 {
    match try_tracepoint_tcp_reset(&ctx, TCP_RESET_DIRECTION_RECEIVE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[perf_event]
pub fn sample_cpu_profile(ctx: PerfEventContext) -> u32 {
    match try_sample_cpu_profile(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

// OpenSSL: int SSL_write(SSL *ssl, const void *buf, int num).
#[uprobe]
pub fn uprobe_ssl_write_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_WRITE, true)
}

#[uretprobe]
pub fn uretprobe_ssl_write_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// OpenSSL: int SSL_read(SSL *ssl, void *buf, int num).
#[uprobe]
pub fn uprobe_ssl_read_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_READ, true)
}

#[uretprobe]
pub fn uretprobe_ssl_read_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_READ)
}

// OpenSSL 3: int SSL_write_ex(SSL *ssl, const void *buf, size_t num,
// size_t *written). The processed length is returned via `written`, not the
// int return value (1 on success).
#[uprobe]
pub fn uprobe_ssl_write_ex_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter_ex(&ctx, NETWORK_IO_WRITE)
}

#[uretprobe]
pub fn uretprobe_ssl_write_ex_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// OpenSSL 3: int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes).
#[uprobe]
pub fn uprobe_ssl_read_ex_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter_ex(&ctx, NETWORK_IO_READ)
}

#[uretprobe]
pub fn uretprobe_ssl_read_ex_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_READ)
}

// OpenSSL: int SSL_set_fd(SSL *ssl, int fd). The mapping is committed only
// after the function reports success.
#[uprobe]
pub fn uprobe_ssl_set_fd_enter(ctx: ProbeContext) -> u32 {
    tls_stash_handle_fd(&ctx, 0)
}

#[uretprobe]
pub fn uretprobe_ssl_set_fd_exit(ctx: RetProbeContext) -> u32 {
    tls_commit_handle_fd(&ctx)
}

// OpenSSL: int SSL_set_rfd(SSL *ssl, int fd).
#[uprobe]
pub fn uprobe_ssl_set_rfd_enter(ctx: ProbeContext) -> u32 {
    tls_stash_handle_fd(&ctx, NETWORK_IO_READ)
}

#[uretprobe]
pub fn uretprobe_ssl_set_rfd_exit(ctx: RetProbeContext) -> u32 {
    tls_commit_handle_fd(&ctx)
}

// OpenSSL: int SSL_set_wfd(SSL *ssl, int fd).
#[uprobe]
pub fn uprobe_ssl_set_wfd_enter(ctx: ProbeContext) -> u32 {
    tls_stash_handle_fd(&ctx, NETWORK_IO_WRITE)
}

#[uretprobe]
pub fn uretprobe_ssl_set_wfd_exit(ctx: RetProbeContext) -> u32 {
    tls_commit_handle_fd(&ctx)
}

// OpenSSL: void SSL_free(SSL *ssl).
#[uprobe]
pub fn uprobe_ssl_free(ctx: ProbeContext) -> u32 {
    tls_remove_handle(&ctx)
}

// GnuTLS: ssize_t gnutls_record_send(gnutls_session_t s, const void *d, size_t n).
#[uprobe]
pub fn uprobe_gnutls_record_send_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_WRITE, false)
}

#[uretprobe]
pub fn uretprobe_gnutls_record_send_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// GnuTLS: ssize_t gnutls_record_recv(gnutls_session_t s, void *d, size_t n).
#[uprobe]
pub fn uprobe_gnutls_record_recv_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_READ, false)
}

#[uretprobe]
pub fn uretprobe_gnutls_record_recv_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_READ)
}

// GnuTLS: void gnutls_transport_set_int2(gnutls_session_t s, int recv, int send).
// gnutls_transport_set_int(s, fd) expands to this with recv == send == fd,
// so this covers the standard socket-descriptor setup without confusing a
// custom transport pointer for an fd.
#[uprobe]
pub fn uprobe_gnutls_transport_set_int2(ctx: ProbeContext) -> u32 {
    tls_set_handle_fds(&ctx, 1, 2)
}

// GnuTLS: void gnutls_deinit(gnutls_session_t session).
#[uprobe]
pub fn uprobe_gnutls_deinit(ctx: ProbeContext) -> u32 {
    tls_remove_handle(&ctx)
}

fn try_tracepoint_execve(ctx: TracePointContext) -> Result<u32, i64> {
    try_tracepoint_exec_common(ctx, 16, 24)
}

fn try_tracepoint_execveat(ctx: TracePointContext) -> Result<u32, i64> {
    try_tracepoint_exec_common(ctx, 24, 32)
}

fn try_tracepoint_exec_common(
    ctx: TracePointContext,
    filename_offset: usize,
    argv_offset: usize,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = unsafe {
        let ptr = EXEC_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };

    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.argument_count = 0;
    event.event_source = EXEC_EVENT_SOURCE_SYSCALL_ENTER;
    event.event_monotonic_nanos = unsafe { bpf_ktime_get_ns() };
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.executable = [0; EXECUTABLE_LEN];
    event.arguments = [[0; ARG_LEN]; MAX_ARGS];
    let _ = read_exec_filename(&ctx, &mut event.executable, filename_offset);
    let _ = read_exec_arguments(&ctx, event, argv_offset);

    EXEC_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_process_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = unsafe {
        let ptr = EXEC_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };

    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.argument_count = 0;
    event.event_source = EXEC_EVENT_SOURCE_SCHED_EXEC;
    event.event_monotonic_nanos = unsafe { bpf_ktime_get_ns() };
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.executable = [0; EXECUTABLE_LEN];
    event.arguments = [[0; ARG_LEN]; MAX_ARGS];

    EXEC_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_process_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = unsafe {
        let ptr = EXIT_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };

    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;

    EXIT_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

fn tcp_stat_event_scratch() -> Result<&'static mut RawTcpStatEvent, i64> {
    let ptr = TCP_STAT_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.kind = 0;
    event.pid = 0;
    event.cgroup_id = 0;
    event.family = 0;
    event.old_state = 0;
    event.new_state = 0;
    event.reset_direction = 0;
    event.remote_port = 0;
    event.local_port = 0;
    event.remote_addr_v4 = 0;
    event.local_addr_v4 = 0;
    event.remote_addr_v6 = [0; 16];
    event.local_addr_v6 = [0; 16];
    event.timestamp_unix_nanos = 0;
    event.command = [0; 16];
    Ok(event)
}

fn tcp_stat_common(event: &mut RawTcpStatEvent) -> Result<bool, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(false);
    }
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    Ok(true)
}

// sock:inet_sock_set_state field offsets (stable): oldstate@16, newstate@20,
// sport@24 (host order), dport@26 (host order), family@28, protocol@30,
// saddr@32, daddr@36, saddr_v6@40, daddr_v6@56.
fn try_tracepoint_tcp_set_state(ctx: &TracePointContext) -> Result<u32, i64> {
    let protocol = unsafe { ctx.read_at::<u16>(30) }.map_err(|err| err as i64)?;
    if u32::from(protocol) != IPPROTO_TCP {
        return Ok(0);
    }
    let family = unsafe { ctx.read_at::<u16>(28) }.map_err(|err| err as i64)?;
    let event = tcp_stat_event_scratch()?;
    if !tcp_stat_common(event)? {
        return Ok(0);
    }
    event.kind = TCP_STAT_KIND_STATE;
    event.family = family as u32;
    event.old_state = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    event.new_state = unsafe { ctx.read_at::<i32>(20) }.map_err(|err| err as i64)?;
    event.local_port = unsafe { ctx.read_at::<u16>(24) }.map_err(|err| err as i64)?;
    event.remote_port = unsafe { ctx.read_at::<u16>(26) }.map_err(|err| err as i64)?;
    read_tcp_tuple_addrs(ctx, family, 32, 36, 40, 56, event)?;
    TCP_STAT_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

// tcp:tcp_retransmit_skb: sport@28 (host order), dport@30 (host order),
// family@32, saddr@34, daddr@38, saddr_v6@42, daddr_v6@58.
fn try_tracepoint_tcp_retransmit(ctx: &TracePointContext) -> Result<u32, i64> {
    let family = unsafe { ctx.read_at::<u16>(32) }.map_err(|err| err as i64)?;
    let event = tcp_stat_event_scratch()?;
    if !tcp_stat_common(event)? {
        return Ok(0);
    }
    event.kind = TCP_STAT_KIND_RETRANSMIT;
    event.family = family as u32;
    event.local_port = unsafe { ctx.read_at::<u16>(28) }.map_err(|err| err as i64)?;
    event.remote_port = unsafe { ctx.read_at::<u16>(30) }.map_err(|err| err as i64)?;
    read_tcp_tuple_addrs(ctx, family, 34, 38, 42, 58, event)?;
    TCP_STAT_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

// tcp:tcp_send_reset / tcp_receive_reset: src sockaddr@32, dest sockaddr@60
// (sockaddr_in/in6). Within each: family@+0, port@+2 (network order),
// v4 addr@+4, v6 addr@+8.
fn try_tracepoint_tcp_reset(ctx: &TracePointContext, direction: u32) -> Result<u32, i64> {
    let family = unsafe { ctx.read_at::<u16>(32) }.map_err(|err| err as i64)?;
    if family != AF_INET_U16 && family as u32 != AF_INET6 {
        return Ok(0);
    }
    let event = tcp_stat_event_scratch()?;
    if !tcp_stat_common(event)? {
        return Ok(0);
    }
    event.kind = TCP_STAT_KIND_RESET;
    event.family = family as u32;
    event.reset_direction = direction;
    // src is local, dest is remote.
    event.local_port = u16::from_be(unsafe { ctx.read_at::<u16>(34) }.map_err(|err| err as i64)?);
    event.remote_port = u16::from_be(unsafe { ctx.read_at::<u16>(62) }.map_err(|err| err as i64)?);
    if family == AF_INET_U16 {
        event.local_addr_v4 = unsafe { ctx.read_at::<u32>(36) }.map_err(|err| err as i64)?;
        event.remote_addr_v4 = unsafe { ctx.read_at::<u32>(64) }.map_err(|err| err as i64)?;
    } else {
        event.local_addr_v6 = unsafe { ctx.read_at::<[u8; 16]>(40) }.map_err(|err| err as i64)?;
        event.remote_addr_v6 = unsafe { ctx.read_at::<[u8; 16]>(68) }.map_err(|err| err as i64)?;
    }
    TCP_STAT_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

fn read_tcp_tuple_addrs(
    ctx: &TracePointContext,
    family: u16,
    local_v4_offset: usize,
    remote_v4_offset: usize,
    local_v6_offset: usize,
    remote_v6_offset: usize,
    event: &mut RawTcpStatEvent,
) -> Result<(), i64> {
    if family == AF_INET_U16 {
        event.local_addr_v4 =
            unsafe { ctx.read_at::<u32>(local_v4_offset) }.map_err(|err| err as i64)?;
        event.remote_addr_v4 =
            unsafe { ctx.read_at::<u32>(remote_v4_offset) }.map_err(|err| err as i64)?;
    } else if family as u32 == AF_INET6 {
        event.local_addr_v6 =
            unsafe { ctx.read_at::<[u8; 16]>(local_v6_offset) }.map_err(|err| err as i64)?;
        event.remote_addr_v6 =
            unsafe { ctx.read_at::<[u8; 16]>(remote_v6_offset) }.map_err(|err| err as i64)?;
    }
    Ok(())
}

fn try_sample_cpu_profile(ctx: PerfEventContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = unsafe {
        let ptr = CPU_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };

    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.sample_count = 1;
    event.timestamp_unix_nanos = 0;
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.frame_count = 0;
    event.flags = 0;
    // Translate the pid into the namespace of the procfs view userspace
    // symbolizes from. The helper only succeeds when that namespace is the
    // task's active pid namespace; otherwise the event keeps the
    // root-namespace pid and is flagged so userspace verifies the pid
    // against procfs before attributing frames to it.
    let pidns_dev = CPU_PROFILE_PIDNS.get(0).copied().unwrap_or(0);
    let pidns_ino = CPU_PROFILE_PIDNS.get(1).copied().unwrap_or(0);
    if pidns_ino != 0 {
        let mut pidns = bpf_pidns_info { pid: 0, tgid: 0 };
        let rc = unsafe {
            bpf_get_ns_current_pid_tgid(
                pidns_dev,
                pidns_ino,
                &mut pidns,
                core::mem::size_of::<bpf_pidns_info>() as u32,
            )
        };
        if rc == 0 {
            event.pid = pidns.tgid;
            event.tid = pidns.pid;
        } else {
            event.flags |= CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED;
        }
    }
    event.instruction_pointers = [0; CPU_PROFILE_MAX_FRAMES];
    event.py_frame_count = 0;
    event.py_stop = 0;
    event.py_frames = [0; PY_MAX_FRAMES];
    let frame_limit = cpu_profile_frame_limit();

    // DWARF path: only for pids userspace registered unwind tables
    // for. Untranslated pids (processes in child pid namespaces, e.g.
    // pods under a host-procfs agent) still match here when their
    // root-namespace pid is the one userspace registered; userspace
    // additionally identity-verifies those pids before symbolizing.
    // On any setup failure control falls through to the frame-pointer
    // path.
    if unsafe { UNWIND_PROC_MAPPINGS.get(&event.pid) }.is_some() {
        start_dwarf_unwind(&ctx, event, frame_limit);
        event.flags &= !CPU_PROFILE_FLAG_DWARF;
    }

    let stack_bytes = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            event.instruction_pointers.as_mut_ptr().cast(),
            frame_limit * core::mem::size_of::<u64>() as u32,
            u64::from(BPF_F_USER_STACK),
        )
    };
    if stack_bytes > 0 {
        let captured = ((stack_bytes as usize) / core::mem::size_of::<u64>())
            .min(CPU_PROFILE_MAX_FRAMES) as u32;
        event.frame_count = captured;
        // A full buffer means the stack may continue past the configured
        // depth; flag it so userspace can account the truncation.
        if captured >= frame_limit {
            event.flags |= CPU_PROFILE_FLAG_TRUNCATED;
        }
    }

    emit_cpu_profile_event(&ctx, event);
    Ok(0)
}

/// Emits the staged sample, first diverting through the CPython frame
/// walker for registered interpreter processes. Returning from the tail
/// call means it failed; the event is emitted without python frames.
#[inline(always)]
fn emit_cpu_profile_event(ctx: &PerfEventContext, event: &mut RawCpuProfileEvent) {
    if unsafe { PY_PROC_INFO.get(&event.pid) }.is_some() {
        unsafe {
            CPU_PROFILE_PROGS.tail_call(ctx, 1);
        }
    }
    CPU_PROFILE_EVENTS.output(ctx, &*event, 0);
}

#[perf_event]
pub fn cpu_profile_py_find(ctx: PerfEventContext) -> u32 {
    match try_cpu_profile_py_find(ctx) {
        Ok(code) => code,
        Err(code) => code as u32,
    }
}

/// Locates the sampled thread's CPython thread state by walking
/// `_PyRuntime` -> interpreters -> thread lists (flattened to one
/// bounded loop) and matching on the native thread id, then tail-calls
/// the frame walker. Every failure emits the event with an explicit
/// `py_stop` - never a dropped sample.
fn try_cpu_profile_py_find(ctx: PerfEventContext) -> Result<u32, i64> {
    let event = unsafe {
        let ptr = CPU_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let state = unsafe {
        let ptr = CPU_PROFILE_UNWIND_STATE.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let Some(info) = (unsafe { PY_PROC_INFO.get(&event.pid) }) else {
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    };

    // CPython records each thread's id in the process's own pid
    // namespace; translate the sampled thread into that namespace so
    // the match works for containerized interpreters. Falls back to the
    // (already namespace-translated) event tid if the helper is
    // unavailable.
    let match_tid = if info.pid_ns_ino != 0 {
        let mut nsinfo = bpf_pidns_info { pid: 0, tgid: 0 };
        let rc = unsafe {
            bpf_get_ns_current_pid_tgid(
                info.pid_ns_dev,
                info.pid_ns_ino,
                &mut nsinfo,
                core::mem::size_of::<bpf_pidns_info>() as u32,
            )
        };
        if rc == 0 {
            u64::from(nsinfo.pid)
        } else {
            u64::from(event.tid)
        }
    } else {
        u64::from(event.tid)
    };

    let mut stop = PY_STOP_NO_THREAD;
    let mut found: u64 = 0;
    'search: {
        let Some(mut interpreter) = read_user_u64(
            info.runtime_addr
                .wrapping_add(u64::from(info.interpreters_head)),
        ) else {
            stop = PY_STOP_READ_FAULT;
            break 'search;
        };
        let mut candidate: u64 = 0;
        let mut interpreters_left = PY_MAX_INTERPRETERS;
        for _ in 0..PY_MAX_THREAD_VISITS {
            if candidate == 0 {
                if interpreter == 0 || interpreters_left == 0 {
                    break;
                }
                interpreters_left -= 1;
                let Some(head) =
                    read_user_u64(interpreter.wrapping_add(u64::from(info.threads_head)))
                else {
                    stop = PY_STOP_READ_FAULT;
                    break 'search;
                };
                // PyInterpreterState.next is the first field.
                let Some(next_interpreter) = read_user_u64(interpreter) else {
                    stop = PY_STOP_READ_FAULT;
                    break 'search;
                };
                interpreter = next_interpreter;
                candidate = head;
                if candidate == 0 {
                    continue;
                }
            }
            let Some(native_id) =
                read_user_u64(candidate.wrapping_add(u64::from(info.tstate_native_thread_id)))
            else {
                stop = PY_STOP_READ_FAULT;
                break 'search;
            };
            if native_id == match_tid {
                found = candidate;
                break;
            }
            let Some(next) = read_user_u64(candidate.wrapping_add(u64::from(info.tstate_next)))
            else {
                stop = PY_STOP_READ_FAULT;
                break 'search;
            };
            candidate = next;
        }
    }

    if found == 0 {
        event.py_stop = stop;
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    }
    state.py_tstate = found;

    // Resolve the innermost interpreter frame up front so the walker
    // rounds only chain frame-to-frame.
    let Some(info) = (unsafe { PY_PROC_INFO.get(&event.pid) }) else {
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    };
    let Some(cframe) = read_user_u64(found.wrapping_add(u64::from(info.tstate_cframe))) else {
        event.py_stop = PY_STOP_READ_FAULT;
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    };
    let frame = if cframe == 0 {
        0
    } else {
        match read_user_u64(cframe.wrapping_add(u64::from(info.cframe_current_frame))) {
            Some(frame) => frame,
            None => {
                event.py_stop = PY_STOP_READ_FAULT;
                CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
                return Ok(0);
            }
        }
    };
    if frame == 0 {
        event.py_stop = PY_STOP_COMPLETE;
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    }
    state.py_frame = frame;
    state.py_rounds = 0;
    unsafe {
        CPU_PROFILE_PROGS.tail_call(&ctx, 2);
    }
    // Tail call failed; emit without python frames, accounted.
    event.py_stop = PY_STOP_READ_FAULT;
    CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

#[perf_event]
pub fn cpu_profile_py_walk(ctx: PerfEventContext) -> u32 {
    match try_cpu_profile_py_walk(ctx) {
        Ok(code) => code,
        Err(code) => code as u32,
    }
}

/// Walks the located thread state's `_PyInterpreterFrame` chain,
/// recording code-object pointers leaf first for userspace resolution.
/// Chunked: PY_FRAMES_PER_ROUND frames per round, self tail calls up
/// to PY_MAX_ROUNDS; shim frames are recorded as zero pointers and
/// dropped in userspace so each round's loop stays verifier-friendly.
fn try_cpu_profile_py_walk(ctx: PerfEventContext) -> Result<u32, i64> {
    let event = unsafe {
        let ptr = CPU_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let state = unsafe {
        let ptr = CPU_PROFILE_UNWIND_STATE.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let Some(info) = (unsafe { PY_PROC_INFO.get(&event.pid) }) else {
        CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    };
    let info = *info;

    let mut frame = state.py_frame;
    let mut stop = 0u32;
    for _ in 0..PY_FRAMES_PER_ROUND {
        if frame == 0 {
            stop = PY_STOP_COMPLETE;
            break;
        }
        if event.py_frame_count >= PY_MAX_FRAMES as u32 {
            stop = PY_STOP_TRUNCATED;
            break;
        }
        let Some(code) = read_user_u64(frame.wrapping_add(u64::from(info.iframe_code))) else {
            stop = PY_STOP_READ_FAULT;
            break;
        };
        // Shim frames threaded by the C stack (owner == 3) are stored
        // as zero and skipped during userspace resolution.
        let Some(owner) = read_user_u8(frame.wrapping_add(u64::from(info.iframe_owner))) else {
            stop = PY_STOP_READ_FAULT;
            break;
        };
        let index = (event.py_frame_count as usize).min(PY_MAX_FRAMES - 1);
        event.py_frames[index] = if owner == 3 { 0 } else { code };
        event.py_frame_count += 1;
        let Some(previous) = read_user_u64(frame.wrapping_add(u64::from(info.iframe_previous)))
        else {
            stop = PY_STOP_READ_FAULT;
            break;
        };
        frame = previous;
    }

    if stop == 0 {
        if frame == 0 {
            stop = PY_STOP_COMPLETE;
        } else {
            state.py_frame = frame;
            state.py_rounds += 1;
            if state.py_rounds < PY_MAX_ROUNDS {
                unsafe {
                    CPU_PROFILE_PROGS.tail_call(&ctx, 2);
                }
            }
            stop = PY_STOP_TRUNCATED;
        }
    }
    event.py_stop = stop;
    CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

/// Loads the sampled thread's user registers and tail-calls into the
/// chunked DWARF unwinder. Returns only when the tail call fails.
#[inline(always)]
fn start_dwarf_unwind(ctx: &PerfEventContext, event: &mut RawCpuProfileEvent, frame_limit: u32) {
    let Some(state_ptr) = CPU_PROFILE_UNWIND_STATE.get_ptr_mut(0) else {
        return;
    };
    let state = unsafe { &mut *state_ptr };
    let task = unsafe { bpf_get_current_task_btf() };
    if task.is_null() {
        return;
    }
    let regs = unsafe { bpf_task_pt_regs(task) };
    if regs == 0 {
        return;
    }
    let regs = regs as usize;
    // Offsets into the saved user register frame.
    #[cfg(bpf_target_arch = "aarch64")]
    let (pc_off, sp_off, fp_off, lr_off) = (256usize, 248usize, 232usize, 240usize);
    #[cfg(bpf_target_arch = "x86_64")]
    let (pc_off, sp_off, fp_off, lr_off) = (128usize, 152usize, 32usize, 128usize);
    #[cfg(not(any(bpf_target_arch = "aarch64", bpf_target_arch = "x86_64")))]
    {
        let _ = (ctx, event, frame_limit, regs);
        return;
    }

    let Some(pc) = read_kernel_u64(regs + pc_off) else {
        return;
    };
    let Some(sp) = read_kernel_u64(regs + sp_off) else {
        return;
    };
    let Some(fp) = read_kernel_u64(regs + fp_off) else {
        return;
    };
    let Some(lr) = read_kernel_u64(regs + lr_off) else {
        return;
    };
    if pc == 0 || sp == 0 {
        return;
    }
    state.pc = pc;
    state.sp = sp;
    state.fp = fp;
    state.lr = lr;
    state.depth = 0;
    state.rounds = 0;
    state.frame_limit = frame_limit.min(CPU_PROFILE_MAX_FRAMES as u32);
    event.flags |= CPU_PROFILE_FLAG_DWARF;
    unsafe {
        CPU_PROFILE_PROGS.tail_call(ctx, 0);
    }
}

#[inline(always)]
fn read_kernel_u64(address: usize) -> Option<u64> {
    let mut value: u64 = 0;
    let rc = unsafe {
        bpf_probe_read_kernel(
            core::ptr::from_mut(&mut value).cast(),
            core::mem::size_of::<u64>() as u32,
            address as *const core::ffi::c_void,
        )
    };
    (rc == 0).then_some(value)
}

#[perf_event]
pub fn cpu_profile_unwind(ctx: PerfEventContext) -> u32 {
    match try_cpu_profile_unwind(ctx) {
        Ok(code) => code,
        Err(code) => code as u32,
    }
}

/// One chunk of DWARF unwinding: up to UNWIND_FRAMES_PER_ROUND frames,
/// then a self tail call for the next chunk. Every exit path emits the
/// event with an explicit stop reason - degradation is accounted, never
/// silent.
fn try_cpu_profile_unwind(ctx: PerfEventContext) -> Result<u32, i64> {
    let event = unsafe {
        let ptr = CPU_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let state = unsafe {
        let ptr = CPU_PROFILE_UNWIND_STATE.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let Some(mappings) = (unsafe { UNWIND_PROC_MAPPINGS.get(&event.pid) }) else {
        return finish_unwind(&ctx, event, state, UNWIND_STOP_NO_MAPPING);
    };

    let mut stop = 0u32;
    for _ in 0..UNWIND_FRAMES_PER_ROUND {
        if state.depth >= state.frame_limit {
            stop = UNWIND_STOP_DEPTH;
            break;
        }
        // Record the current frame.
        let index = (state.depth as usize).min(CPU_PROFILE_MAX_FRAMES - 1);
        event.instruction_pointers[index] = state.pc;
        state.depth += 1;

        // For frames past the sampled leaf the recorded address is a
        // return address: look up the call site inside the caller.
        let lookup_pc = if state.depth == 1 {
            state.pc
        } else {
            state.pc.wrapping_sub(1)
        };

        let Some(mapping) = find_unwind_mapping(mappings, lookup_pc) else {
            stop = UNWIND_STOP_NO_MAPPING;
            break;
        };
        let pc_vaddr = lookup_pc.wrapping_sub(mapping.bias);
        let Some(row) = find_unwind_row(mapping.module_id, pc_vaddr) else {
            stop = UNWIND_STOP_NO_RULE;
            break;
        };

        // Canonical frame address.
        let base = match row.cfa_kind {
            UNWIND_CFA_SP => state.sp,
            UNWIND_CFA_FP => state.fp,
            _ => {
                stop = UNWIND_STOP_NO_RULE;
                break;
            }
        };
        let cfa = base.wrapping_add(row.cfa_off as i64 as u64);
        // The CFA must sit at or above the current stack pointer and
        // within a sane single-frame distance of it.
        if cfa < state.sp || cfa.wrapping_sub(state.sp) > (1 << 20) {
            stop = UNWIND_STOP_BAD_FRAME;
            break;
        }

        // Caller return address.
        let next_pc = match row.ra_kind {
            UNWIND_RA_CFA_OFFSET => {
                let address = cfa.wrapping_add(row.ra_off as i64 as u64);
                match read_user_u64(address) {
                    Some(value) => value,
                    None => {
                        stop = UNWIND_STOP_READ_FAULT;
                        break;
                    }
                }
            }
            UNWIND_RA_LINK_REGISTER if state.depth == 1 => state.lr,
            UNWIND_RA_UNDEFINED => {
                stop = UNWIND_STOP_COMPLETE;
                break;
            }
            _ => {
                stop = UNWIND_STOP_NO_RULE;
                break;
            }
        };
        if next_pc == 0 {
            stop = UNWIND_STOP_COMPLETE;
            break;
        }

        // Caller frame pointer, when this range saved it.
        if row.fp_kind == UNWIND_FP_CFA_OFFSET {
            let address = cfa.wrapping_add(row.fp_off as i64 as u64);
            match read_user_u64(address) {
                Some(value) => state.fp = value,
                None => {
                    stop = UNWIND_STOP_READ_FAULT;
                    break;
                }
            }
        }

        state.pc = next_pc;
        state.sp = cfa;
    }

    if stop != 0 {
        return finish_unwind(&ctx, event, state, stop);
    }
    if state.depth >= state.frame_limit {
        return finish_unwind(&ctx, event, state, UNWIND_STOP_DEPTH);
    }
    state.rounds += 1;
    if state.rounds >= UNWIND_MAX_ROUNDS {
        return finish_unwind(&ctx, event, state, UNWIND_STOP_TAIL_LIMIT);
    }
    unsafe {
        CPU_PROFILE_PROGS.tail_call(&ctx, 0);
    }
    // The tail call failed; account it instead of dropping the sample.
    finish_unwind(&ctx, event, state, UNWIND_STOP_TAIL_LIMIT)
}

#[inline(always)]
fn finish_unwind(
    ctx: &PerfEventContext,
    event: &mut RawCpuProfileEvent,
    state: &mut UnwindState,
    stop: u32,
) -> Result<u32, i64> {
    event.frame_count = state.depth.min(CPU_PROFILE_MAX_FRAMES as u32);
    event.flags |= stop << UNWIND_STOP_SHIFT;
    if stop == UNWIND_STOP_DEPTH {
        event.flags |= CPU_PROFILE_FLAG_TRUNCATED;
    }
    emit_cpu_profile_event(ctx, event);
    Ok(0)
}

#[inline(always)]
fn find_unwind_mapping(mappings: &UnwindProcMappings, pc: u64) -> Option<UnwindMapping> {
    let count = (mappings.count as usize).min(UNWIND_MAX_MAPPINGS);
    for index in 0..UNWIND_MAX_MAPPINGS {
        if index >= count {
            break;
        }
        // Bounds-checked slice access: the older kernel verifier (6.6)
        // rejects the running-pointer form LLVM produces from direct
        // indexing, so re-derive each entry from the base with an
        // explicit `get` the verifier can follow.
        let Some(entry) = mappings.entries.get(index & UNWIND_MAPPING_INDEX_MASK) else {
            break;
        };
        if pc >= entry.start && pc < entry.end {
            return Some(*entry);
        }
    }
    None
}

#[inline(always)]
fn find_unwind_row(module_id: u32, pc_vaddr: u64) -> Option<UnwindRowAbi> {
    let span = unsafe { UNWIND_MODULES.get(&module_id) }?;
    let row_len = span.row_len;
    if row_len == 0 || span.row_start >= UNWIND_ROW_POOL {
        return None;
    }
    let mut low = span.row_start;
    let mut high = span.row_start.saturating_add(row_len).min(UNWIND_ROW_POOL);
    // First row must already be at or below the target pc.
    let first = UNWIND_ROWS.get(low)?;
    if first.pc > pc_vaddr {
        return None;
    }
    for _ in 0..UNWIND_ROW_SEARCH_STEPS {
        if low + 1 >= high {
            break;
        }
        let mid = low + (high - low) / 2;
        let Some(row) = UNWIND_ROWS.get(mid) else {
            break;
        };
        if row.pc <= pc_vaddr {
            low = mid;
        } else {
            high = mid;
        }
    }
    let row = UNWIND_ROWS.get(low)?;
    // Kind 0 for the CFA marks an Invalid gap terminator row.
    (row.cfa_kind == UNWIND_CFA_SP || row.cfa_kind == UNWIND_CFA_FP).then_some(*row)
}

#[inline(always)]
fn read_user_u64(address: u64) -> Option<u64> {
    unsafe { bpf_probe_read_user::<u64>(address as *const u64).ok() }
}

#[inline(always)]
fn read_user_u8(address: u64) -> Option<u8> {
    unsafe { bpf_probe_read_user::<u8>(address as *const u8).ok() }
}

#[inline(always)]
fn cpu_profile_frame_limit() -> u32 {
    let configured = CPU_PROFILE_FRAME_LIMIT
        .get(0)
        .copied()
        .unwrap_or(CPU_PROFILE_MAX_FRAMES as u32);
    configured.clamp(CPU_PROFILE_MIN_FRAMES, CPU_PROFILE_MAX_FRAMES as u32)
}

#[inline(always)]
fn record_tls_diagnostic(stage: u32) {
    if SOURCE_DIAGNOSTICS_ENABLED.load() == 0 {
        return;
    }
    if let Some(counter) = TLS_DIAGNOSTIC_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

#[inline(always)]
fn tls_capture_limit() -> u32 {
    let configured = TLS_CAPTURE_LIMIT
        .get(0)
        .copied()
        .unwrap_or(PROTOCOL_MIN_CAPTURE_BYTES);
    configured.clamp(PROTOCOL_MIN_CAPTURE_BYTES, PROTOCOL_MAX_CAPTURE_BYTES)
}

#[inline(always)]
fn tls_handle_key(handle: u64) -> TlsHandleKey {
    let pid_tgid = bpf_get_current_pid_tgid();
    TlsHandleKey {
        tgid: (pid_tgid >> 32) as u32,
        reserved: 0,
        handle,
    }
}

/// Stashes an OpenSSL `SSL_set_*fd` call until its return probe confirms the
/// operation succeeded. A direction of zero updates both read and write fds.
#[inline(always)]
fn tls_stash_handle_fd(ctx: &ProbeContext, direction: u32) -> u32 {
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    let fd_value: i64 = match ctx.arg(1) {
        Some(value) => value,
        None => return 0,
    };
    if handle == 0 || fd_value < 0 {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingTlsSetFd {
        handle,
        fd: fd_value as i32,
        direction,
    };
    let _ = PENDING_TLS_SET_FD.insert(&pid_tgid, &pending, 0);
    0
}

fn tls_commit_handle_fd(ctx: &RetProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_TLS_SET_FD.get(&pid_tgid) } {
        Some(value) => *value,
        None => return 0,
    };
    PENDING_TLS_SET_FD.remove(&pid_tgid).ok();
    let retval: i64 = ctx.ret();
    if retval != 1 {
        return 0;
    }
    tls_update_handle_fds(pending.handle, pending.fd, pending.fd, pending.direction);
    0
}

/// Records the two explicit descriptors passed through GnuTLS's standard
/// socket transport API. Custom-pointer transports intentionally do not
/// populate this map.
#[inline(always)]
fn tls_set_handle_fds(ctx: &ProbeContext, read_arg_index: usize, write_arg_index: usize) -> u32 {
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    let read_fd: i64 = match ctx.arg(read_arg_index) {
        Some(value) => value,
        None => return 0,
    };
    let write_fd: i64 = match ctx.arg(write_arg_index) {
        Some(value) => value,
        None => return 0,
    };
    if handle == 0 || read_fd < 0 || write_fd < 0 {
        return 0;
    }
    tls_update_handle_fds(handle, read_fd as i32, write_fd as i32, 0);
    0
}

#[inline(always)]
fn tls_update_handle_fds(handle: u64, read_fd: i32, write_fd: i32, direction: u32) {
    let key = tls_handle_key(handle);
    let mut fds = unsafe { TLS_HANDLE_FDS.get(&key) }
        .copied()
        .unwrap_or(TlsHandleFds {
            read_fd: -1,
            write_fd: -1,
        });
    if direction == 0 || direction == NETWORK_IO_READ {
        fds.read_fd = read_fd;
    }
    if direction == 0 || direction == NETWORK_IO_WRITE {
        fds.write_fd = write_fd;
    }
    if TLS_HANDLE_FDS.insert(&key, &fds, 0).is_ok() {
        record_tls_diagnostic(TLS_DIAG_SET_FD);
    }
}

#[inline(always)]
fn tls_remove_handle(ctx: &ProbeContext) -> u32 {
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    if handle != 0 {
        TLS_HANDLE_FDS.remove(&tls_handle_key(handle)).ok();
    }
    0
}

fn tls_io_enter(ctx: &ProbeContext, direction: u32, return_is_i32: bool) -> u32 {
    record_tls_diagnostic(TLS_DIAG_IO_ENTER);
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    let buffer: u64 = match ctx.arg(1) {
        Some(value) => value,
        None => return 0,
    };
    if handle == 0 || buffer == 0 {
        record_tls_diagnostic(TLS_DIAG_NULL_OR_EMPTY);
        return 0;
    }
    stash_tls_io(handle, buffer, 0, direction, return_is_i32);
    0
}

/// Entry handler for the OpenSSL `_ex` variants, whose fourth argument is the
/// `size_t*` receiving the processed byte count.
fn tls_io_enter_ex(ctx: &ProbeContext, direction: u32) -> u32 {
    record_tls_diagnostic(TLS_DIAG_IO_ENTER);
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    let buffer: u64 = match ctx.arg(1) {
        Some(value) => value,
        None => return 0,
    };
    let count_ptr: u64 = ctx.arg(3).unwrap_or(0);
    if handle == 0 || buffer == 0 {
        record_tls_diagnostic(TLS_DIAG_NULL_OR_EMPTY);
        return 0;
    }
    stash_tls_io(handle, buffer, count_ptr, direction, false);
    0
}

#[inline(always)]
fn stash_tls_io(handle: u64, buffer: u64, count_ptr: u64, direction: u32, return_is_i32: bool) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingTlsIo {
        handle,
        buffer_ptr: buffer,
        count_ptr,
        direction,
        reserved: u32::from(return_is_i32),
    };
    let _ = PENDING_TLS_IO.insert(&pid_tgid, &pending, 0);
}

fn tls_io_exit(ctx: &RetProbeContext, direction: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_TLS_IO.get(&pid_tgid) } {
        Some(value) => *value,
        None => return 0,
    };
    PENDING_TLS_IO.remove(&pid_tgid).ok();
    if pending.direction != direction {
        return 0;
    }
    record_tls_diagnostic(TLS_DIAG_IO_EXIT);

    let retval: i64 = ctx.ret();
    // Classic variants return the byte count; `_ex` variants return 1 on
    // success and report the count through the stashed `size_t*`.
    let length = if pending.count_ptr != 0 {
        if retval != 1 {
            return 0;
        }
        match unsafe { bpf_probe_read_user::<u64>(pending.count_ptr as *const u64) } {
            Ok(value) => value,
            Err(_) => return 0,
        }
    } else if pending.reserved == 1 {
        // OpenSSL's classic APIs return a C `int`. On x86_64, a negative
        // value written to EAX is observed through RAX as zero-extended
        // `0x00000000ffffffff`; sign-extend from 32 bits before deciding
        // whether the call produced plaintext.
        let retval = retval as i32;
        if retval <= 0 {
            return 0;
        }
        retval as u64
    } else {
        // GnuTLS returns `ssize_t`, so preserve the native signed width.
        if retval <= 0 {
            return 0;
        }
        retval as u64
    };
    if length == 0 {
        return 0;
    }
    match emit_tls_data(
        ctx,
        pending.handle,
        direction,
        pending.buffer_ptr as *const u8,
        length,
    ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn tls_connection_for_handle(handle: u64, direction: u32) -> Option<PendingConnect> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let handle_key = TlsHandleKey {
        tgid,
        reserved: 0,
        handle,
    };
    let fds = match unsafe { TLS_HANDLE_FDS.get(&handle_key) } {
        Some(value) => *value,
        None => {
            record_tls_diagnostic(TLS_DIAG_FD_UNRESOLVED);
            return None;
        }
    };
    let fd = if direction == NETWORK_IO_READ {
        fds.read_fd
    } else {
        fds.write_fd
    };
    if fd < 0 {
        record_tls_diagnostic(TLS_DIAG_FD_UNRESOLVED);
        return None;
    }
    let key = ConnectionKey { tgid, fd };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => {
            record_tls_diagnostic(TLS_DIAG_CONNECTION_MISS);
            return None;
        }
    };
    if connection.protocol != IPPROTO_TCP {
        record_tls_diagnostic(TLS_DIAG_NON_TCP_CONNECTION);
        return None;
    }
    let capture_port = if connection.role == CONNECTION_ROLE_SERVER {
        u16::from_be(connection.local_port_be)
    } else {
        u16::from_be(connection.remote_port_be)
    };
    if unsafe { TLS_CAPTURE_PORTS.get(&capture_port) }.is_none() {
        record_tls_diagnostic(TLS_DIAG_PORT_FILTERED);
        return None;
    }
    Some(connection)
}

#[inline(always)]
fn emit_tls_data(
    ctx: &RetProbeContext,
    handle: u64,
    direction: u32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    let connection = match tls_connection_for_handle(handle, direction) {
        Some(value) => value,
        None => return Ok(0),
    };

    let event = tls_data_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = connection.fd;
    event.direction = direction;
    event.role = connection.role;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.payload_total_len = if len > u32::MAX as u64 {
        u32::MAX
    } else {
        len as u32
    };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;

    let limit = tls_capture_limit();
    let captured_total = if len > limit as u64 {
        limit
    } else {
        len as u32
    };
    event.payload_captured_len = captured_total;

    let mut emitted = false;
    let mut segment = 0;
    while segment < PROTOCOL_MAX_CAPTURE_SEGMENTS {
        let offset = (segment * PROTOCOL_DATA_BYTES) as u32;
        if offset >= captured_total {
            break;
        }
        let remaining = (captured_total - offset) as usize;
        let chunk_len = if remaining > PROTOCOL_DATA_BYTES {
            PROTOCOL_DATA_BYTES
        } else {
            remaining
        };
        let copied = unsafe {
            bpf_probe_read_user_buf(buffer.add(offset as usize), &mut event.payload[..chunk_len])
        };
        if copied.is_err() {
            break;
        }
        event.payload_offset = offset;
        event.payload_len = chunk_len as u32;
        record_tls_diagnostic(TLS_DIAG_OUTPUT_ATTEMPT);
        TLS_DATA_EVENTS.output(ctx, &*event, 0);
        emitted = true;
        segment += 1;
    }
    if !emitted {
        record_tls_diagnostic(TLS_DIAG_COPY_EMPTY);
    }
    Ok(0)
}

fn tls_data_event_scratch() -> Result<&'static mut RawProtocolDataEvent, i64> {
    let ptr = TLS_DATA_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.pid = 0;
    event.uid = 0;
    event.cgroup_id = 0;
    event.fd = -1;
    event.direction = 0;
    event.role = CONNECTION_ROLE_CLIENT;
    event.family = 0;
    event.remote_port_be = 0;
    event.local_port_be = 0;
    event.remote_addr_v4 = 0;
    event.local_addr_v4 = 0;
    event.remote_addr_v6 = [0; 16];
    event.local_addr_v6 = [0; 16];
    event.timestamp_unix_nanos = 0;
    event.payload_len = 0;
    event.payload_total_len = 0;
    event.payload_offset = 0;
    event.payload_captured_len = 0;
    event.command = [0; 16];
    event.payload = [0; PROTOCOL_DATA_BYTES];
    Ok(event)
}

fn try_tracepoint_connect_enter(ctx: TracePointContext) -> Result<u32, i64> {
    track_connect_enter(&ctx)
}

fn track_connect_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    // Filter at connection establishment: a denied workload's connection is
    // never tracked, so every downstream protocol/tls/http/dns read and write
    // for it early-exits on the ACTIVE_CONNECTIONS miss. This is the overhead
    // lever, not just scope control.
    let cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let family =
        unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }.map_err(|err| err as i64)?;

    let mut pending = PendingConnect {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id,
        fd,
        family: family as u32,
        role: CONNECTION_ROLE_CLIENT,
        protocol: IPPROTO_TCP,
        remote_port_be: 0,
        local_port_be: 0,
        remote_addr_v4: 0,
        local_addr_v4: 0,
        remote_addr_v6: [0; 16],
        local_addr_v6: [0; 16],
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        bytes_sent: 0,
        bytes_received: 0,
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };

    if family as u32 == AF_INET {
        read_sockaddr_in(sockaddr, &mut pending)?;
    } else if family as u32 == AF_INET6 {
        read_sockaddr_in6(sockaddr, &mut pending)?;
    } else {
        return Ok(0);
    }

    PENDING_CONNECTS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_connect_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_CONNECTS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_CONNECTS.remove(&pid_tgid).ok();

    let event = network_event_scratch()?;
    copy_pending_to_event(&pending, event);
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };

    if retval < 0 && retval != NEG_EINPROGRESS {
        event.event_type = NETWORK_EVENT_FAILURE;
        event.errno = (-retval) as i32;
        NETWORK_EVENTS.output(&ctx, &*event, 0);
        return Ok(0);
    }

    event.event_type = NETWORK_EVENT_OPEN;
    NETWORK_EVENTS.output(&ctx, &*event, 0);

    let key = ConnectionKey {
        tgid: pending.pid,
        fd: pending.fd,
    };
    ACTIVE_CONNECTIONS
        .insert(&key, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_dns_connect_enter(ctx: TracePointContext) -> Result<u32, i64> {
    track_connect_enter(&ctx)
}

fn try_tracepoint_dns_connect_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_CONNECTS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_CONNECTS.remove(&pid_tgid).ok();

    if retval < 0 && retval != NEG_EINPROGRESS {
        return Ok(0);
    }

    let key = ConnectionKey {
        tgid: pending.pid,
        fd: pending.fd,
    };
    ACTIVE_CONNECTIONS
        .insert(&key, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_close_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let pending = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    ACTIVE_CONNECTIONS.remove(&key).ok();

    let now = unsafe { bpf_ktime_get_ns() };
    let event = network_event_scratch()?;
    copy_pending_to_event(&pending, event);
    event.event_type = NETWORK_EVENT_CLOSE;
    event.timestamp_unix_nanos = now;
    event.duration_nanos = now - pending.started_at_nanos;
    NETWORK_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_dns_close_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    ACTIVE_CONNECTIONS.remove(&key).ok();
    Ok(0)
}

fn try_tracepoint_http_connect_enter(ctx: TracePointContext) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_CONNECT_ENTER);
    track_connect_enter(&ctx)
}

fn try_tracepoint_http_connect_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let activated = track_connected_tcp_exit(&ctx)?;
    if activated {
        record_http_diagnostic(HTTP_DIAG_CONNECT_ACTIVE);
    }
    Ok(0)
}

fn try_tracepoint_http_close_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    ACTIVE_CONNECTIONS.remove(&key).ok();
    Ok(0)
}

fn try_tracepoint_http_write_enter(ctx: TracePointContext) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_WRITE_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    emit_http_request_event(&ctx, fd, buffer, len)
}

fn try_tracepoint_http_writev_enter(ctx: TracePointContext) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_WRITEV_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let iov = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let iov_len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    emit_http_request_iovecs_event(&ctx, fd, iov, iov_len)
}

fn try_tracepoint_http_sendto_enter(ctx: TracePointContext) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_SENDTO_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    emit_http_request_event(&ctx, fd, buffer, len)
}

fn try_tracepoint_http_sendmsg_enter(ctx: TracePointContext) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_SENDMSG_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        record_http_diagnostic(HTTP_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let (iov, iov_len) = read_msghdr_iovecs(message)?;
    emit_http_request_iovecs_event(&ctx, fd, iov, iov_len)
}

fn try_tracepoint_network_io_enter(ctx: &TracePointContext, direction: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    if unsafe { ACTIVE_CONNECTIONS.get(&key) }.is_none() {
        return Ok(0);
    }

    let pending = PendingNetworkIo {
        tgid: key.tgid,
        fd,
        direction,
    };
    PENDING_NETWORK_IO
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_network_io_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_NETWORK_IO.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_NETWORK_IO.remove(&pid_tgid).ok();
    if retval <= 0 {
        return Ok(0);
    }

    let key = ConnectionKey {
        tgid: pending.tgid,
        fd: pending.fd,
    };
    let mut connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    if pending.direction == NETWORK_IO_WRITE {
        connection.bytes_sent = connection.bytes_sent.saturating_add(retval as u64);
    } else if pending.direction == NETWORK_IO_READ {
        connection.bytes_received = connection.bytes_received.saturating_add(retval as u64);
    }
    ACTIVE_CONNECTIONS
        .insert(&key, &connection, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn track_connected_tcp_exit(ctx: &TracePointContext) -> Result<bool, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_CONNECTS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(false),
    };
    PENDING_CONNECTS.remove(&pid_tgid).ok();

    if retval < 0 && retval != NEG_EINPROGRESS {
        return Ok(false);
    }
    if pending.protocol != IPPROTO_TCP {
        return Ok(false);
    }

    let key = ConnectionKey {
        tgid: pending.pid,
        fd: pending.fd,
    };
    ACTIVE_CONNECTIONS
        .insert(&key, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(true)
}

fn emit_http_request_event(
    ctx: &TracePointContext,
    fd: i32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    if buffer.is_null() || len == 0 {
        record_http_diagnostic(HTTP_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => {
            record_http_diagnostic(HTTP_DIAG_ACTIVE_CONNECTION_MISS);
            return emit_http_request_event_without_connection(ctx, fd, buffer, len);
        }
    };
    if connection.protocol != IPPROTO_TCP {
        record_http_diagnostic(HTTP_DIAG_NON_TCP_CONNECTION);
        return Ok(0);
    }
    // Accepted server sockets write HTTP responses. Feeding those bytes into
    // the request decoder produced two false invalid samples for many Python
    // responses (header and body writes) for every real inbound request.
    if connection.role != CONNECTION_ROLE_CLIENT {
        record_http_diagnostic(HTTP_DIAG_SERVER_WRITE_SUPPRESSED);
        return Ok(0);
    }

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = fd;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_http_request(buffer, len, event)?;
    if event.request_len == 0 {
        record_http_diagnostic(HTTP_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_COPY_SUCCESS);
    record_http_diagnostic(HTTP_DIAG_OUTPUT_ATTEMPT);
    output_http_request_event(ctx, event);
    Ok(0)
}

fn emit_http_request_event_without_connection(
    ctx: &TracePointContext,
    fd: i32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_FALLBACK_CANDIDATE);
    if !http_buffer_starts_like_request(buffer)? {
        record_http_diagnostic(HTTP_DIAG_FALLBACK_NON_HTTP_START);
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = http_request_event_scratch()?;
    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = fd;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_http_request(buffer, len, event)?;
    if event.request_len == 0 {
        record_http_diagnostic(HTTP_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_COPY_SUCCESS);
    record_http_diagnostic(HTTP_DIAG_FALLBACK_OUTPUT_ATTEMPT);
    record_http_diagnostic(HTTP_DIAG_OUTPUT_ATTEMPT);
    output_http_request_event(ctx, event);
    Ok(0)
}

#[inline(never)]
fn emit_http_request_iovecs_event(
    ctx: &TracePointContext,
    fd: i32,
    iov: *const u8,
    iov_len: u64,
) -> Result<u32, i64> {
    if iov.is_null() || iov_len == 0 {
        record_http_diagnostic(HTTP_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => {
            record_http_diagnostic(HTTP_DIAG_ACTIVE_CONNECTION_MISS);
            return emit_http_request_iovecs_event_without_connection(ctx, fd, iov, iov_len);
        }
    };
    if connection.protocol != IPPROTO_TCP {
        record_http_diagnostic(HTTP_DIAG_NON_TCP_CONNECTION);
        return Ok(0);
    }
    if connection.role != CONNECTION_ROLE_CLIENT {
        record_http_diagnostic(HTTP_DIAG_SERVER_WRITE_SUPPRESSED);
        return Ok(0);
    }

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = fd;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_http_request_iovecs(iov, iov_len, event)?;
    if event.request_len == 0 {
        record_http_diagnostic(HTTP_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_COPY_SUCCESS);
    record_http_diagnostic(HTTP_DIAG_OUTPUT_ATTEMPT);
    output_http_request_event(ctx, event);
    Ok(0)
}

#[inline(never)]
fn emit_http_request_iovecs_event_without_connection(
    ctx: &TracePointContext,
    fd: i32,
    iov: *const u8,
    iov_len: u64,
) -> Result<u32, i64> {
    record_http_diagnostic(HTTP_DIAG_FALLBACK_CANDIDATE);
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = http_request_event_scratch()?;
    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = fd;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_http_request_iovecs(iov, iov_len, event)?;
    if event.request_len == 0 {
        record_http_diagnostic(HTTP_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    if !http_request_event_starts_like_request(event) {
        record_http_diagnostic(HTTP_DIAG_FALLBACK_NON_HTTP_START);
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_COPY_SUCCESS);
    record_http_diagnostic(HTTP_DIAG_FALLBACK_OUTPUT_ATTEMPT);
    record_http_diagnostic(HTTP_DIAG_OUTPUT_ATTEMPT);
    output_http_request_event(ctx, event);
    Ok(0)
}

fn try_tracepoint_socket_bind_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    // Listener metadata is bounded and never emitted by itself. Track binds
    // before workload admission so a pod that binds before the Kubernetes
    // controller publishes its cgroup can still be filtered by the configured
    // port when it later accepts traffic. The accept and payload paths retain
    // the default-deny cgroup gate.
    let cgroup_id = current_cgroup_id();
    if !cgroup_listener_metadata_allowed(cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if sockaddr.is_null() {
        return Ok(0);
    }
    let family = unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }
        .map_err(|err| err as i64)? as u32;
    let mut pending = PendingBind {
        fd,
        family,
        local_port_be: 0,
        reserved: 0,
        local_addr_v4: 0,
        local_addr_v6: [0; 16],
    };
    if family == AF_INET {
        pending.local_port_be =
            unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
                .map_err(|err| err as i64)?;
        pending.local_addr_v4 =
            unsafe { bpf_probe_read_user::<u32>(sockaddr.add(4).cast::<u32>()) }
                .map_err(|err| err as i64)?;
    } else if family == AF_INET6 {
        pending.local_port_be =
            unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
                .map_err(|err| err as i64)?;
        pending.local_addr_v6 =
            unsafe { bpf_probe_read_user::<[u8; 16]>(sockaddr.add(8).cast::<[u8; 16]>()) }
                .map_err(|err| err as i64)?;
    } else {
        return Ok(0);
    }
    PENDING_BINDS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_socket_bind_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_BINDS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_BINDS.remove(&pid_tgid).ok();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval != 0 || pending.local_port_be == 0 {
        return Ok(0);
    }
    let key = ListenerKey {
        cgroup_id: current_cgroup_id(),
        fd: pending.fd,
        reserved: 0,
    };
    let process_key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd: pending.fd,
    };
    let endpoint = ListenerEndpoint {
        family: pending.family,
        local_port_be: pending.local_port_be,
        reserved: 0,
        local_addr_v4: pending.local_addr_v4,
        local_addr_v6: pending.local_addr_v6,
    };
    PROCESS_LISTENER_ENDPOINTS
        .insert(&process_key, &endpoint, 0)
        .map_err(|err| err as i64)?;
    LISTENER_ENDPOINTS
        .insert(&key, &endpoint, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_http_accept_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let listen_fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let pending = PendingAccept {
        listen_fd,
        reserved: 0,
        sockaddr_ptr: sockaddr as u64,
    };
    PENDING_ACCEPTS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_http_accept_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let accept = match unsafe { PENDING_ACCEPTS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_ACCEPTS.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval < 0 {
        return Ok(0);
    }

    // Filter server-accepted connections at establishment (overhead lever,
    // mirrors track_connect_enter for the client side).
    let cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }

    let uid_gid = bpf_get_current_uid_gid();
    let mut pending = PendingConnect {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id,
        fd: retval as i32,
        family: 0,
        role: CONNECTION_ROLE_SERVER,
        protocol: IPPROTO_TCP,
        remote_port_be: 0,
        local_port_be: 0,
        remote_addr_v4: 0,
        local_addr_v4: 0,
        remote_addr_v6: [0; 16],
        local_addr_v6: [0; 16],
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        bytes_sent: 0,
        bytes_received: 0,
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };

    let listener_key = ListenerKey {
        cgroup_id,
        fd: accept.listen_fd,
        reserved: 0,
    };
    let process_listener_key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd: accept.listen_fd,
    };
    let endpoint = unsafe { PROCESS_LISTENER_ENDPOINTS.get(&process_listener_key) }
        .or_else(|| unsafe { LISTENER_ENDPOINTS.get(&listener_key) });
    if let Some(endpoint) = endpoint {
        pending.family = endpoint.family;
        pending.local_port_be = endpoint.local_port_be;
        pending.local_addr_v4 = endpoint.local_addr_v4;
        pending.local_addr_v6 = endpoint.local_addr_v6;
    }

    if accept.sockaddr_ptr != 0 {
        let sockaddr = accept.sockaddr_ptr as *const u8;
        let family = unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }
            .map_err(|err| err as i64)?;
        pending.family = family as u32;
        if family as u32 == AF_INET {
            read_sockaddr_in(sockaddr, &mut pending)?;
        } else if family as u32 == AF_INET6 {
            read_sockaddr_in6(sockaddr, &mut pending)?;
        }
    }

    let key = ConnectionKey {
        tgid: pending.pid,
        fd: pending.fd,
    };
    ACTIVE_CONNECTIONS
        .insert(&key, &pending, 0)
        .map_err(|err| err as i64)?;
    record_http_diagnostic(HTTP_DIAG_ACCEPT_ACTIVE);
    Ok(0)
}

fn try_tracepoint_http_read_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if buffer.is_null() {
        return Ok(0);
    }

    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    if connection.role != CONNECTION_ROLE_SERVER {
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_INBOUND_READ_ENTER);

    let pending = PendingHttpRead {
        fd,
        reserved: 0,
        buffer_ptr: buffer as u64,
    };
    PENDING_HTTP_READS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_http_read_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_HTTP_READS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_HTTP_READS.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval <= 0 {
        return Ok(0);
    }

    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd: pending.fd,
    };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    if connection.role != CONNECTION_ROLE_SERVER {
        return Ok(0);
    }

    let buffer = pending.buffer_ptr as *const u8;

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = pending.fd;
    event.family = connection.family;
    event.role = CONNECTION_ROLE_SERVER;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_http_request(buffer, retval as u64, event)?;
    if event.request_len == 0 {
        record_http_diagnostic(HTTP_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    record_http_diagnostic(HTTP_DIAG_COPY_SUCCESS);
    record_http_diagnostic(HTTP_DIAG_INBOUND_OUTPUT_ATTEMPT);
    record_http_diagnostic(HTTP_DIAG_OUTPUT_ATTEMPT);
    output_http_request_event(ctx, event);
    Ok(0)
}

fn try_tracepoint_protocol_close_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    ACTIVE_CONNECTIONS.remove(&key).ok();
    Ok(0)
}

fn try_tracepoint_protocol_write_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    record_protocol_diagnostic(PROTOCOL_DIAG_WRITE_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    if buffer.is_null() || len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let connection = match protocol_capture_connection(fd) {
        Some(value) => value,
        None => return Ok(0),
    };
    emit_protocol_data_event(ctx, &connection, fd, NETWORK_IO_WRITE, buffer, len)
}

fn try_tracepoint_protocol_writev_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let iov = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let iov_len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    emit_protocol_iovec_event(ctx, fd, iov, iov_len, NETWORK_IO_WRITE, 0)
}

fn try_tracepoint_protocol_sendmsg_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }
    let (iov, iov_len) = read_msghdr_iovecs(message)?;
    emit_protocol_iovec_event(ctx, fd, iov, iov_len, NETWORK_IO_WRITE, 0)
}

#[inline(always)]
fn emit_protocol_iovec_event(
    ctx: &TracePointContext,
    fd: i32,
    iov: *const u8,
    iov_len: u64,
    direction: u32,
    total_bound: u64,
) -> Result<u32, i64> {
    if iov.is_null() || iov_len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let connection = match protocol_capture_connection(fd) {
        Some(value) => value,
        None => return Ok(0),
    };

    let cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    let event = protocol_data_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = cgroup_id;
    event.fd = fd;
    event.direction = direction;
    event.role = connection.role;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;

    let state_ptr = PROTOCOL_IOVEC_STATE.get_ptr_mut(0).ok_or(1_i64)?;
    let state = unsafe { &mut *state_ptr };
    state.iov_ptr = iov as u64;
    state.iov_len = iov_len;
    state.total_len = 0;
    state.capture_limit = protocol_capture_limit();
    state.captured_total = 0;
    state.slot = 0;
    state.capture_contiguous = 1;
    state.total_bound = total_bound;
    unsafe {
        PROTOCOL_IOVEC_PROGS.tail_call(ctx, 0);
    }
    record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
    Ok(0)
}

#[inline(always)]
fn try_tracepoint_protocol_iovec_compute(ctx: &TracePointContext) -> Result<u32, i64> {
    let state_ptr = PROTOCOL_IOVEC_STATE.get_ptr_mut(0).ok_or(1_i64)?;
    let state = unsafe { &mut *state_ptr };
    let iov = state.iov_ptr as *const u8;
    let mut processed = 0_u32;
    while processed < PROTOCOL_IOVEC_CHUNK {
        if state.slot >= PROTOCOL_MAX_IOVECS
            || u64::from(state.slot) >= state.iov_len
            || (state.total_bound != 0 && state.total_len >= state.total_bound)
        {
            break;
        }
        let raw_slot_len = read_protocol_iovec_len(iov, state.slot)?;
        let slot_len = if state.total_bound != 0 {
            raw_slot_len.min(state.total_bound.saturating_sub(state.total_len))
        } else {
            raw_slot_len
        };
        state.total_len = state.total_len.saturating_add(slot_len);
        if state.capture_contiguous != 0 {
            let remaining = state.capture_limit.saturating_sub(state.captured_total);
            let bounded = if slot_len > u64::from(remaining) {
                remaining
            } else {
                slot_len as u32
            };
            let captured = if bounded > PROTOCOL_IOVEC_DATA_MAX {
                PROTOCOL_IOVEC_DATA_MAX
            } else {
                bounded
            };
            state.captured_total = state.captured_total.saturating_add(captured);
            state.capture_contiguous = u32::from(u64::from(captured) == slot_len);
        }
        state.slot = state.slot.saturating_add(1);
        processed += 1;
    }

    if state.slot < PROTOCOL_MAX_IOVECS
        && u64::from(state.slot) < state.iov_len
        && (state.total_bound == 0 || state.total_len < state.total_bound)
    {
        unsafe {
            PROTOCOL_IOVEC_PROGS.tail_call(ctx, 0);
        }
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
        return Ok(0);
    }

    let event_ptr = PROTOCOL_DATA_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *event_ptr };
    event.payload_total_len = if state.total_bound != 0 {
        state.total_bound.min(u32::MAX as u64) as u32
    } else if state.iov_len > u64::from(PROTOCOL_MAX_IOVECS) || state.total_len > u32::MAX as u64 {
        u32::MAX
    } else {
        state.total_len as u32
    };
    event.payload_captured_len = state.captured_total;
    if state.captured_total == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    unsafe {
        PROTOCOL_IOVEC_PROGS.tail_call(ctx, 1);
    }
    record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
    Ok(0)
}

#[inline(always)]
fn try_tracepoint_protocol_iovec_emit(ctx: &TracePointContext) -> Result<u32, i64> {
    let state_ptr = PROTOCOL_IOVEC_STATE.get_ptr(0).ok_or(1_i64)?;
    let state = unsafe { &*state_ptr };
    let event_ptr = PROTOCOL_DATA_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *event_ptr };
    let iov = state.iov_ptr as *const u8;
    let iov_len = state.iov_len;
    let captured_total = event.payload_captured_len;

    // Emit one segment per complete iovec prefix. All segments share the
    // syscall timestamp and totals, so userspace can join only adjacent
    // offsets and turn any missing event or bounded tail into a gap.
    let mut emitted = false;
    let mut offset = 0_u32;
    let mut slot = 0_u32;
    while slot < PROTOCOL_MAX_IOVECS {
        if u64::from(slot) >= iov_len || offset >= captured_total {
            break;
        }
        let (buffer, slot_len) = read_protocol_iovec(iov, slot)?;
        let remaining = captured_total.saturating_sub(offset);
        let bounded = if slot_len > u64::from(remaining) {
            remaining
        } else {
            slot_len as u32
        };
        let captured = if bounded > PROTOCOL_IOVEC_DATA_MAX {
            PROTOCOL_IOVEC_DATA_MAX
        } else {
            bounded
        };
        if captured == 0 {
            if slot_len == 0 {
                slot += 1;
                continue;
            }
            break;
        }
        if buffer.is_null() {
            record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
            return Ok(0);
        }
        event.payload_offset = offset;
        event.payload_len = captured;
        let copy_len = unsafe { core::ptr::addr_of!(event.payload_len).read_volatile() };
        if copy_len > PROTOCOL_IOVEC_DATA_MAX {
            return Ok(0);
        }
        let copied = unsafe {
            bpf_probe_read_user_raw(event.payload.as_mut_ptr().cast(), copy_len, buffer.cast())
        };
        if copied != 0 {
            return Ok(0);
        }
        record_protocol_diagnostic(PROTOCOL_DIAG_OUTPUT_ATTEMPT);
        PROTOCOL_DATA_EVENTS.output(ctx, &*event, 0);
        emitted = true;
        offset = offset.saturating_add(captured);
        if u64::from(captured) != slot_len {
            break;
        }
        slot += 1;
    }
    if !emitted {
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
    }
    Ok(0)
}

#[inline(always)]
fn read_protocol_iovec_len(iov: *const u8, slot: u32) -> Result<u64, i64> {
    let offset = slot as usize * 16 + 8;
    unsafe { bpf_probe_read_user::<u64>(iov.add(offset).cast::<u64>()) }.map_err(|err| err as i64)
}

#[inline(always)]
fn read_protocol_iovec(iov: *const u8, slot: u32) -> Result<(*const u8, u64), i64> {
    let offset = slot as usize * 16;
    let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov.add(offset).cast::<*const u8>()) }
        .map_err(|err| err as i64)?;
    let len = unsafe { bpf_probe_read_user::<u64>(iov.add(offset + 8).cast::<u64>()) }
        .map_err(|err| err as i64)?;
    Ok((buffer, len))
}

#[inline(always)]
fn try_tracepoint_protocol_iovec_read_enter(
    ctx: &TracePointContext,
    recvmsg: bool,
) -> Result<u32, i64> {
    record_protocol_diagnostic(PROTOCOL_DIAG_READ_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let pointer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let (iov, iov_len) = if recvmsg {
        if pointer.is_null() {
            record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
            return Ok(0);
        }
        read_msghdr_iovecs(pointer)?
    } else {
        let iov_len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
        (pointer, iov_len)
    };
    if iov.is_null() || iov_len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }
    if protocol_capture_connection(fd).is_none() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingProtocolIovecRead {
        fd,
        reserved: 0,
        iov_ptr: iov as u64,
        iov_len,
    };
    PENDING_PROTOCOL_IOVEC_READS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

#[inline(always)]
fn try_tracepoint_protocol_iovec_read_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_PROTOCOL_IOVEC_READS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_PROTOCOL_IOVEC_READS.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval <= 0 {
        return Ok(0);
    }
    let connection = match protocol_capture_connection(pending.fd) {
        Some(value) => value,
        None => return Ok(0),
    };
    record_protocol_diagnostic(PROTOCOL_DIAG_READ_EXIT);

    // A single receive buffer is contiguous even when its iovec capacity is
    // much larger than the returned bytes. Reuse the scalar segment emitter
    // so the configured capture limit, rather than one event, bounds it.
    if pending.iov_len == 1 {
        let (buffer, capacity) = read_protocol_iovec(pending.iov_ptr as *const u8, 0)?;
        let len = (retval as u64).min(capacity);
        return emit_protocol_data_event(
            ctx,
            &connection,
            pending.fd,
            NETWORK_IO_READ,
            buffer,
            len,
        );
    }

    emit_protocol_iovec_event(
        ctx,
        pending.fd,
        pending.iov_ptr as *const u8,
        pending.iov_len,
        NETWORK_IO_READ,
        retval as u64,
    )
}

fn try_tracepoint_protocol_read_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    record_protocol_diagnostic(PROTOCOL_DIAG_READ_ENTER);
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if buffer.is_null() {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    if protocol_capture_connection(fd).is_none() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingProtocolRead {
        fd,
        reserved: 0,
        buffer_ptr: buffer as u64,
    };
    PENDING_PROTOCOL_READS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_protocol_read_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_PROTOCOL_READS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_PROTOCOL_READS.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval <= 0 {
        return Ok(0);
    }

    let connection = match protocol_capture_connection(pending.fd) {
        Some(value) => value,
        None => return Ok(0),
    };
    record_protocol_diagnostic(PROTOCOL_DIAG_READ_EXIT);
    emit_protocol_data_event(
        ctx,
        &connection,
        pending.fd,
        NETWORK_IO_READ,
        pending.buffer_ptr as *const u8,
        retval as u64,
    )
}

#[inline(always)]
fn protocol_capture_connection(fd: i32) -> Option<PendingConnect> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => {
            record_protocol_diagnostic(PROTOCOL_DIAG_CONNECTION_MISS);
            return None;
        }
    };
    if connection.protocol != IPPROTO_TCP {
        record_protocol_diagnostic(PROTOCOL_DIAG_NON_TCP_CONNECTION);
        return None;
    }
    let capture_port = if connection.role == CONNECTION_ROLE_SERVER {
        u16::from_be(connection.local_port_be)
    } else {
        u16::from_be(connection.remote_port_be)
    };
    let unresolved_inbound = connection.role == CONNECTION_ROLE_SERVER && capture_port == 0;
    let inbound_enabled = PROTOCOL_CAPTURE_INBOUND.get(0).copied().unwrap_or(0) == 1;
    if (unresolved_inbound && !inbound_enabled)
        || (!unresolved_inbound && unsafe { PROTOCOL_CAPTURE_PORTS.get(&capture_port) }.is_none())
    {
        record_protocol_diagnostic(PROTOCOL_DIAG_PORT_FILTERED);
        return None;
    }
    Some(connection)
}

#[inline(always)]
fn emit_protocol_data_event(
    ctx: &TracePointContext,
    connection: &PendingConnect,
    fd: i32,
    direction: u32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    let event = protocol_data_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.fd = fd;
    event.direction = direction;
    event.role = connection.role;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.payload_total_len = if len > u32::MAX as u64 {
        u32::MAX
    } else {
        len as u32
    };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    if buffer.is_null() || len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    output_protocol_payload_segments(ctx, event, buffer, len);
    Ok(0)
}

#[inline(always)]
fn protocol_capture_limit() -> u32 {
    let configured = PROTOCOL_CAPTURE_LIMIT
        .get(0)
        .copied()
        .unwrap_or(PROTOCOL_MIN_CAPTURE_BYTES);
    configured.clamp(PROTOCOL_MIN_CAPTURE_BYTES, PROTOCOL_MAX_CAPTURE_BYTES)
}

/// Emits the leading `min(len, capture limit)` bytes of `buffer` as one or
/// more contiguous segment events sharing the metadata already staged in
/// `event`. A failed user read stops the loop early; the missing tail stays
/// accounted because every emitted segment carries `payload_captured_len`
/// and `payload_total_len`, which userspace turns into an explicit gap.
fn output_protocol_payload_segments(
    ctx: &TracePointContext,
    event: &mut RawProtocolDataEvent,
    buffer: *const u8,
    len: u64,
) {
    let limit = protocol_capture_limit();
    let captured_total = if len > limit as u64 {
        limit
    } else {
        len as u32
    };
    event.payload_captured_len = captured_total;

    let mut emitted = false;
    let mut segment = 0;
    while segment < PROTOCOL_MAX_CAPTURE_SEGMENTS {
        let offset = (segment * PROTOCOL_DATA_BYTES) as u32;
        if offset >= captured_total {
            break;
        }
        let remaining = (captured_total - offset) as usize;
        let chunk_len = if remaining > PROTOCOL_DATA_BYTES {
            PROTOCOL_DATA_BYTES
        } else {
            remaining
        };
        let copied = unsafe {
            bpf_probe_read_user_buf(buffer.add(offset as usize), &mut event.payload[..chunk_len])
        };
        if copied.is_err() {
            break;
        }
        event.payload_offset = offset;
        event.payload_len = chunk_len as u32;
        record_protocol_diagnostic(PROTOCOL_DIAG_OUTPUT_ATTEMPT);
        PROTOCOL_DATA_EVENTS.output(ctx, &*event, 0);
        emitted = true;
        segment += 1;
    }
    if !emitted {
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
    }
}

fn protocol_data_event_scratch() -> Result<&'static mut RawProtocolDataEvent, i64> {
    let ptr = PROTOCOL_DATA_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.pid = 0;
    event.uid = 0;
    event.cgroup_id = 0;
    event.fd = -1;
    event.direction = 0;
    event.role = CONNECTION_ROLE_CLIENT;
    event.family = 0;
    event.remote_port_be = 0;
    event.local_port_be = 0;
    event.remote_addr_v4 = 0;
    event.local_addr_v4 = 0;
    event.remote_addr_v6 = [0; 16];
    event.local_addr_v6 = [0; 16];
    event.timestamp_unix_nanos = 0;
    event.payload_len = 0;
    event.payload_total_len = 0;
    event.payload_offset = 0;
    event.payload_captured_len = 0;
    event.command = [0; 16];
    event.payload = [0; PROTOCOL_DATA_BYTES];
    Ok(event)
}

#[inline(always)]
fn record_protocol_diagnostic(stage: u32) {
    if SOURCE_DIAGNOSTICS_ENABLED.load() == 0 {
        return;
    }
    if let Some(counter) = PROTOCOL_DIAGNOSTIC_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

fn try_tracepoint_dns_sendto_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(48) }.map_err(|err| err as i64)?;
    if sockaddr.is_null() {
        return emit_dns_connected_send_event(ctx, fd, buffer, len);
    }
    emit_dns_send_event(ctx, buffer, len, sockaddr)
}

fn try_tracepoint_sendto_exit(ctx: TracePointContext) -> Result<u32, i64> {
    try_tracepoint_network_io_exit(&ctx)
}

fn try_tracepoint_dns_sendmsg_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        return Ok(0);
    }

    let sockaddr = read_msghdr_name(message)?;
    let (buffer, len) = read_msghdr_first_iov(message)?;
    if sockaddr.is_null() {
        return emit_dns_connected_send_event(ctx, fd, buffer, len);
    }
    emit_dns_send_event(ctx, buffer, len, sockaddr)
}

fn try_tracepoint_sendmsg_exit(ctx: TracePointContext) -> Result<u32, i64> {
    try_tracepoint_network_io_exit(&ctx)
}

fn try_tracepoint_dns_write_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    emit_dns_connected_send_event(ctx, fd, buffer, len)
}

fn emit_dns_send_event(
    ctx: &TracePointContext,
    buffer: *const u8,
    len: u64,
    sockaddr: *const u8,
) -> Result<u32, i64> {
    if buffer.is_null() || sockaddr.is_null() || len == 0 {
        return Ok(0);
    }

    let family =
        unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }.map_err(|err| err as i64)?;
    let server_port_be = unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
        .map_err(|err| err as i64)?;
    if !is_dns_ipv4_peer(family, server_port_be) {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = dns_event_scratch()?;
    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.protocol = IPPROTO_UDP;
    event.server_port_be = server_port_be;
    event.server_addr_v4 = unsafe { bpf_probe_read_user::<u32>(sockaddr.add(4).cast::<u32>()) }
        .map_err(|err| err as i64)?;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_dns_packet(buffer, len, event)?;
    DNS_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

fn emit_dns_connected_send_event(
    ctx: &TracePointContext,
    fd: i32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    if buffer.is_null() || len == 0 {
        return Ok(0);
    }

    let peer = match connected_dns_peer(fd) {
        Some(value) => value,
        None => return Ok(0),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = dns_event_scratch()?;
    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.protocol = IPPROTO_UDP;
    event.server_port_be = peer.remote_port_be;
    event.server_addr_v4 = peer.remote_addr_v4;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    copy_dns_packet(buffer, len, event)?;
    DNS_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_dns_read_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if buffer.is_null() {
        return Ok(0);
    }

    let peer = match connected_dns_peer(fd) {
        Some(value) => value,
        None => return Ok(0),
    };

    let pending = PendingDnsRecv {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
        fd,
        buffer_ptr: buffer as u64,
        server_addr_ptr: 0,
        server_port_be: peer.remote_port_be,
        server_addr_v4: peer.remote_addr_v4,
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };
    PENDING_DNS_RECVS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn connected_dns_peer(fd: i32) -> Option<PendingConnect> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let key = ConnectionKey {
        tgid: (pid_tgid >> 32) as u32,
        fd,
    };
    let peer = unsafe { ACTIVE_CONNECTIONS.get(&key) }.copied()?;
    if peer.family != AF_INET {
        return None;
    }
    if u16::from_be(peer.remote_port_be) != 53 {
        return None;
    }
    Some(peer)
}

fn connected_dns_recv_peer(fd: i32) -> Option<PendingConnect> {
    connected_dns_peer(fd)
}

fn try_tracepoint_dns_recvfrom_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(48) }.map_err(|err| err as i64)?;
    if buffer.is_null() {
        return Ok(0);
    }

    let mut server_addr_ptr = sockaddr as u64;
    let mut server_port_be = 0;
    let mut server_addr_v4 = 0;
    if sockaddr.is_null() {
        let peer = match connected_dns_recv_peer(fd) {
            Some(value) => value,
            None => return Ok(0),
        };
        server_addr_ptr = 0;
        server_port_be = peer.remote_port_be;
        server_addr_v4 = peer.remote_addr_v4;
    }

    let pending = PendingDnsRecv {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
        fd,
        buffer_ptr: buffer as u64,
        server_addr_ptr,
        server_port_be,
        server_addr_v4,
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };
    PENDING_DNS_RECVS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_dns_recvfrom_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_DNS_RECVS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_DNS_RECVS.remove(&pid_tgid).ok();
    if retval <= 0 {
        return Ok(0);
    }

    let event = dns_event_scratch()?;
    event.pid = pending.pid;
    event.uid = pending.uid;
    event.cgroup_id = pending.cgroup_id;
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(0);
    }
    event.protocol = IPPROTO_UDP;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.latency_nanos = event.timestamp_unix_nanos - pending.started_at_nanos;
    event.command = pending.command;

    if pending.server_addr_ptr != 0 {
        let sockaddr = pending.server_addr_ptr as *const u8;
        let family = unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }
            .map_err(|err| err as i64)?;
        let server_port_be = unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
            .map_err(|err| err as i64)?;
        if !is_dns_ipv4_peer(family, server_port_be) {
            return Ok(0);
        }
        event.server_port_be = server_port_be;
        event.server_addr_v4 = unsafe { bpf_probe_read_user::<u32>(sockaddr.add(4).cast::<u32>()) }
            .map_err(|err| err as i64)?;
    } else if is_dns_ipv4_peer(AF_INET as u16, pending.server_port_be) {
        event.server_port_be = pending.server_port_be;
        event.server_addr_v4 = pending.server_addr_v4;
    } else {
        return Ok(0);
    }

    copy_dns_packet(pending.buffer_ptr as *const u8, retval as u64, event)?;
    DNS_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_dns_read_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    try_tracepoint_dns_recvfrom_exit(ctx)
}

fn try_tracepoint_dns_recvmsg_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        return Ok(0);
    }

    let (buffer, _) = read_msghdr_first_iov(message)?;
    if buffer.is_null() {
        return Ok(0);
    }
    let sockaddr = read_msghdr_name(message)?;
    let mut server_addr_ptr = sockaddr as u64;
    let mut server_port_be = 0;
    let mut server_addr_v4 = 0;
    if sockaddr.is_null() {
        let peer = match connected_dns_recv_peer(fd) {
            Some(value) => value,
            None => return Ok(0),
        };
        server_addr_ptr = 0;
        server_port_be = peer.remote_port_be;
        server_addr_v4 = peer.remote_addr_v4;
    }

    let pending = PendingDnsRecv {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
        fd,
        buffer_ptr: buffer as u64,
        server_addr_ptr,
        server_port_be,
        server_addr_v4,
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };
    PENDING_DNS_RECVS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_dns_recvmsg_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    try_tracepoint_dns_recvfrom_exit(ctx)
}

fn read_msghdr_name(message: *const u8) -> Result<*const u8, i64> {
    unsafe { bpf_probe_read_user::<*const u8>(message.cast::<*const u8>()) }
        .map_err(|err| err as i64)
}

fn read_msghdr_iovecs(message: *const u8) -> Result<(*const u8, u64), i64> {
    let iov = unsafe { bpf_probe_read_user::<*const u8>(message.add(16).cast::<*const u8>()) }
        .map_err(|err| err as i64)?;
    let iov_len = unsafe { bpf_probe_read_user::<u64>(message.add(24).cast::<u64>()) }
        .map_err(|err| err as i64)?;
    Ok((iov, iov_len))
}

fn read_msghdr_first_iov(message: *const u8) -> Result<(*const u8, u64), i64> {
    let (iov, _) = read_msghdr_iovecs(message)?;
    if iov.is_null() {
        return Ok((core::ptr::null(), 0));
    }
    read_first_iov(iov)
}

fn read_first_iov(iov: *const u8) -> Result<(*const u8, u64), i64> {
    let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov.cast::<*const u8>()) }
        .map_err(|err| err as i64)?;
    let len = unsafe { bpf_probe_read_user::<u64>(iov.add(8).cast::<u64>()) }
        .map_err(|err| err as i64)?;
    Ok((buffer, len))
}

fn read_exec_arguments(
    ctx: &TracePointContext,
    event: &mut RawExecEvent,
    argv_offset: usize,
) -> Result<(), i64> {
    let enabled = ARGV_CAPTURE_ENABLED.get(0).copied().unwrap_or(0);
    if enabled == 0 {
        return Ok(());
    }

    let argv = unsafe { ctx.read_at::<*const *const u8>(argv_offset) }.map_err(|err| err as i64)?;
    let mut index = 0;
    while index < MAX_ARGS {
        let arg_ptr_ptr = unsafe { argv.add(index) };
        let arg_ptr =
            unsafe { bpf_probe_read_user::<*const u8>(arg_ptr_ptr) }.map_err(|err| err as i64)?;
        if arg_ptr.is_null() {
            break;
        }

        let _ = unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut event.arguments[index]) }
            .map_err(|err| err as i64)?;
        event.argument_count += 1;
        index += 1;
    }

    Ok(())
}

fn read_exec_filename(
    ctx: &TracePointContext,
    executable: &mut [u8; EXECUTABLE_LEN],
    filename_offset: usize,
) -> Result<(), i64> {
    let filename_ptr =
        unsafe { ctx.read_at::<*const u8>(filename_offset) }.map_err(|err| err as i64)?;
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, executable) }
        .map_err(|err| err as i64)?;
    Ok(())
}

fn network_event_scratch() -> Result<&'static mut RawNetworkEvent, i64> {
    let ptr = NETWORK_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.event_type = 0;
    event.pid = 0;
    event.uid = 0;
    event.cgroup_id = 0;
    event.fd = -1;
    event.errno = 0;
    event.family = 0;
    event.protocol = 0;
    event.remote_port_be = 0;
    event.local_port_be = 0;
    event.remote_addr_v4 = 0;
    event.local_addr_v4 = 0;
    event.remote_addr_v6 = [0; 16];
    event.local_addr_v6 = [0; 16];
    event.timestamp_unix_nanos = 0;
    event.duration_nanos = 0;
    event.bytes_sent = 0;
    event.bytes_received = 0;
    event.command = [0; 16];
    Ok(event)
}

fn dns_event_scratch() -> Result<&'static mut RawDnsEvent, i64> {
    let ptr = DNS_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.pid = 0;
    event.uid = 0;
    event.cgroup_id = 0;
    event.protocol = 0;
    event.server_port_be = 0;
    event.server_addr_v4 = 0;
    event.timestamp_unix_nanos = 0;
    event.latency_nanos = 0;
    event.packet_len = 0;
    event.command = [0; 16];
    event.packet = [0; DNS_PACKET_BYTES];
    Ok(event)
}

#[inline(always)]
fn http_request_capture_span(event: &RawHttpRequestEvent) -> usize {
    let request_len = if event.request_len as usize > HTTP_REQUEST_BYTES {
        HTTP_REQUEST_BYTES
    } else {
        event.request_len as usize
    };
    if event.request_iovec_lens[2] > 0 {
        (HTTP_IOVEC_CHUNK_BYTES * 2 + event.request_iovec_lens[2] as usize).min(HTTP_REQUEST_BYTES)
    } else if event.request_iovec_lens[1] > 0 {
        (HTTP_IOVEC_CHUNK_BYTES + event.request_iovec_lens[1] as usize).min(HTTP_REQUEST_BYTES)
    } else {
        request_len
    }
}

#[inline(always)]
fn output_http_request_event(ctx: &TracePointContext, event: &RawHttpRequestEvent) {
    let prefix_len = core::mem::offset_of!(RawHttpRequestEvent, request);
    let output_len = prefix_len + http_request_capture_span(event);
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(event).cast::<u8>(),
            output_len.min(core::mem::size_of::<RawHttpRequestEvent>()),
        )
    };
    HTTP_REQUEST_EVENTS.output(ctx, bytes, 0);
}

fn http_request_event_scratch() -> Result<&'static mut RawHttpRequestEvent, i64> {
    let ptr = HTTP_REQUEST_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *ptr };
    event.pid = 0;
    event.uid = 0;
    event.cgroup_id = 0;
    event.fd = -1;
    event.family = 0;
    event.role = CONNECTION_ROLE_CLIENT;
    event.remote_port_be = 0;
    event.local_port_be = 0;
    event.remote_addr_v4 = 0;
    event.local_addr_v4 = 0;
    event.remote_addr_v6 = [0; 16];
    event.local_addr_v6 = [0; 16];
    event.timestamp_unix_nanos = 0;
    event.request_len = 0;
    event.request_total_len = 0;
    event.request_iovec_lens = [0; HTTP_MAX_IOVECS];
    event.command = [0; 16];
    Ok(event)
}

#[inline(always)]
fn record_http_diagnostic(stage: u32) {
    if SOURCE_DIAGNOSTICS_ENABLED.load() == 0 {
        return;
    }
    if let Some(counter) = HTTP_DIAGNOSTIC_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

fn http_buffer_starts_like_request(buffer: *const u8) -> Result<bool, i64> {
    let first = unsafe { bpf_probe_read_user::<u8>(buffer) }.map_err(|err| err as i64)?;
    if !http_method_start_likely(first) {
        return Ok(false);
    }
    if first != b'H' {
        return Ok(true);
    }

    let second = unsafe { bpf_probe_read_user::<u8>(buffer.add(1)) }.map_err(|err| err as i64)?;
    let third = unsafe { bpf_probe_read_user::<u8>(buffer.add(2)) }.map_err(|err| err as i64)?;
    let fourth = unsafe { bpf_probe_read_user::<u8>(buffer.add(3)) }.map_err(|err| err as i64)?;
    let fifth = unsafe { bpf_probe_read_user::<u8>(buffer.add(4)) }.map_err(|err| err as i64)?;
    Ok(!(second == b'T' && third == b'T' && fourth == b'P' && fifth == b'/'))
}

fn http_request_event_starts_like_request(event: &RawHttpRequestEvent) -> bool {
    if event.request_len == 0 {
        return false;
    }
    if !http_method_start_likely(event.request[0]) {
        return false;
    }
    event.request_len < 5 || &event.request[..5] != b"HTTP/"
}

#[inline(always)]
fn http_method_start_likely(first: u8) -> bool {
    first == b'C'
        || first == b'D'
        || first == b'G'
        || first == b'H'
        || first == b'O'
        || first == b'P'
        || first == b'T'
}

fn copy_dns_packet(buffer: *const u8, len: u64, event: &mut RawDnsEvent) -> Result<(), i64> {
    let capped_len = if len > DNS_PACKET_BYTES as u64 {
        DNS_PACKET_BYTES
    } else {
        len as usize
    };
    let mut index = 0;
    while index < DNS_PACKET_BYTES {
        if index >= capped_len {
            break;
        }
        event.packet[index] =
            unsafe { bpf_probe_read_user::<u8>(buffer.add(index)) }.map_err(|err| err as i64)?;
        index += 1;
    }
    event.packet_len = capped_len as u32;
    Ok(())
}

fn copy_http_request(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<(), i64> {
    let copied = copy_http_request_chunk(buffer, len, event, 0, HTTP_REQUEST_BYTES)?;
    event.request_len = copied as u32;
    event.request_total_len = if len > u32::MAX as u64 {
        u32::MAX
    } else {
        len as u32
    };
    Ok(())
}

fn copy_http_request_chunk(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
    output_index: usize,
    max_chunk_len: usize,
) -> Result<usize, i64> {
    if output_index >= HTTP_REQUEST_BYTES {
        return Ok(0);
    }

    let remaining = HTTP_REQUEST_BYTES - output_index;
    let capped_len = if len > remaining as u64 {
        remaining
    } else {
        len as usize
    };
    let capped_len = if capped_len > max_chunk_len {
        max_chunk_len
    } else {
        capped_len
    };
    if capped_len == 0 {
        return Ok(0);
    }

    unsafe {
        bpf_probe_read_user_buf(
            buffer,
            &mut event.request[output_index..output_index + capped_len],
        )
    }
    .map_err(|err| err as i64)?;
    Ok(capped_len)
}

#[inline(never)]
fn copy_http_request_iovecs(
    iov: *const u8,
    iov_len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<(), i64> {
    let mut output_index = 0;
    let mut total_len = 0_u64;

    if iov_len > 0 {
        let iov_entry = iov;
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        total_len = total_len.saturating_add(len);
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot0(buffer, len, event)?;
            event.request_iovec_lens[0] = copied as u16;
            output_index += copied;
        }
    }

    if iov_len > 1 && output_index < HTTP_REQUEST_BYTES {
        let iov_entry = unsafe { iov.add(16) };
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        total_len = total_len.saturating_add(len);
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot1(buffer, len, event)?;
            event.request_iovec_lens[1] = copied as u16;
            output_index += copied;
        }
    }

    if iov_len > 2 && output_index < HTTP_REQUEST_BYTES {
        let iov_entry = unsafe { iov.add(32) };
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        total_len = total_len.saturating_add(len);
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot2(buffer, len, event)?;
            event.request_iovec_lens[2] = copied as u16;
            output_index += copied;
        }
    }

    event.request_len = output_index as u32;
    // More than three iovecs means an uncaptured tail even if the first three
    // happen to fill the capture buffer. Mark it as a gap rather than
    // allowing userspace to splice non-adjacent bytes.
    if iov_len > HTTP_MAX_IOVECS as u64 {
        total_len = total_len.max(output_index as u64 + 1);
    }
    event.request_total_len = if total_len > u32::MAX as u64 {
        u32::MAX
    } else {
        total_len as u32
    };
    Ok(())
}

#[inline(always)]
fn copy_http_request_iovec_slot0(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let request = event.request.as_mut_ptr();
    copy_http_request_iovec_bytes(buffer, len, request)
}

#[inline(always)]
fn copy_http_request_iovec_slot1(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let request = unsafe { event.request.as_mut_ptr().add(HTTP_IOVEC_CHUNK_BYTES) };
    copy_http_request_iovec_bytes(buffer, len, request)
}

#[inline(always)]
fn copy_http_request_iovec_slot2(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let request = unsafe { event.request.as_mut_ptr().add(HTTP_IOVEC_CHUNK_BYTES * 2) };
    copy_http_request_iovec_bytes(buffer, len, request)
}

#[inline(always)]
fn copy_http_request_iovec_bytes(
    buffer: *const u8,
    len: u64,
    request: *mut u8,
) -> Result<usize, i64> {
    let capped_len = if len > HTTP_IOVEC_CHUNK_BYTES as u64 {
        HTTP_IOVEC_CHUNK_BYTES
    } else {
        len as usize
    };
    if capped_len == 0 {
        return Ok(0);
    }

    // Copy complete 16-byte blocks with a single helper invocation. The
    // remaining loop is bounded to at most 15 bytes, which keeps Linux 6.6's
    // verifier below its one-million processed-instruction ceiling without
    // reading beyond the userspace iovec.
    let mut index = 0_usize;
    if capped_len >= 16 {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.cast::<[u8; 16]>() = bytes };
        index = 16;
    }
    if capped_len >= 32 {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.add(16).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.add(16).cast::<[u8; 16]>() = bytes };
        index = 32;
    }
    if capped_len >= 48 {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.add(32).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.add(32).cast::<[u8; 16]>() = bytes };
        index = 48;
    }
    if capped_len >= 64 {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.add(48).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.add(48).cast::<[u8; 16]>() = bytes };
        index = 64;
    }
    if capped_len >= 80 {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.add(64).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.add(64).cast::<[u8; 16]>() = bytes };
        index = 80;
    }
    if capped_len >= HTTP_IOVEC_CHUNK_BYTES {
        let bytes = unsafe { bpf_probe_read_user::<[u8; 16]>(buffer.add(80).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
        unsafe { *request.add(80).cast::<[u8; 16]>() = bytes };
        index = HTTP_IOVEC_CHUNK_BYTES;
    }

    while index < HTTP_IOVEC_CHUNK_BYTES {
        if index >= capped_len {
            break;
        }
        let byte =
            unsafe { bpf_probe_read_user::<u8>(buffer.add(index)) }.map_err(|err| err as i64)?;
        unsafe {
            *request.add(index) = byte;
        }
        index += 1;
    }
    Ok(capped_len)
}

fn copy_pending_to_event(pending: &PendingConnect, event: &mut RawNetworkEvent) {
    event.pid = pending.pid;
    event.uid = pending.uid;
    event.cgroup_id = pending.cgroup_id;
    event.fd = pending.fd;
    event.family = pending.family;
    event.protocol = pending.protocol;
    event.remote_port_be = pending.remote_port_be;
    event.local_port_be = pending.local_port_be;
    event.remote_addr_v4 = pending.remote_addr_v4;
    event.local_addr_v4 = pending.local_addr_v4;
    event.remote_addr_v6 = pending.remote_addr_v6;
    event.local_addr_v6 = pending.local_addr_v6;
    event.bytes_sent = pending.bytes_sent;
    event.bytes_received = pending.bytes_received;
    event.command = pending.command;
}

fn current_cgroup_id() -> u64 {
    unsafe { bpf_get_current_cgroup_id() }
}

/// Whether the workload owning `cgroup_id` should be probed.
///
/// One `Array` load on the disabled fast path (the common case: filter off →
/// every workload captured, historical behaviour). When the filter is active,
/// one additional `HashMap` lookup: an explicit per-cgroup verdict wins, and
/// cgroups absent from the map fall to the configured unknown-cgroup posture
/// (bootstrap window, host/non-pod processes, missing Kubernetes API).
#[inline(always)]
fn cgroup_capture_allowed(cgroup_id: u64) -> bool {
    let control = CAPTURE_FILTER_CONTROL
        .get(0)
        .copied()
        .unwrap_or(CAPTURE_FILTER_DISABLED);
    let explicit_verdict = unsafe { CGROUP_CAPTURE_FILTER.get(&cgroup_id) }.copied();
    capture_allowed(control, explicit_verdict)
}

/// Whether bounded listener metadata should be retained for `cgroup_id`.
///
/// An unknown cgroup may belong to a pod that bound its listener before the
/// Kubernetes controller published the workload verdict. Retaining only this
/// endpoint metadata closes that admission race; known denied cgroups still
/// skip the map, and accept/payload emission continues to use the stricter
/// `cgroup_capture_allowed` decision.
#[inline(always)]
fn cgroup_listener_metadata_allowed(cgroup_id: u64) -> bool {
    let control = CAPTURE_FILTER_CONTROL
        .get(0)
        .copied()
        .unwrap_or(CAPTURE_FILTER_DISABLED);
    let explicit_verdict = unsafe { CGROUP_CAPTURE_FILTER.get(&cgroup_id) }.copied();
    listener_metadata_allowed(control, explicit_verdict)
}

/// Account one handler invocation suppressed by the capture filter.
#[inline(always)]
fn record_capture_filter_drop() {
    if let Some(counter) = CAPTURE_FILTER_DROPPED.get_ptr_mut(0) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

fn read_sockaddr_in(sockaddr: *const u8, pending: &mut PendingConnect) -> Result<(), i64> {
    pending.remote_port_be = unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
        .map_err(|err| err as i64)?;
    pending.remote_addr_v4 = unsafe { bpf_probe_read_user::<u32>(sockaddr.add(4).cast::<u32>()) }
        .map_err(|err| err as i64)?;
    Ok(())
}

fn read_sockaddr_in6(sockaddr: *const u8, pending: &mut PendingConnect) -> Result<(), i64> {
    pending.remote_port_be = unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
        .map_err(|err| err as i64)?;
    pending.remote_addr_v6 =
        unsafe { bpf_probe_read_user::<[u8; 16]>(sockaddr.add(8).cast::<[u8; 16]>()) }
            .map_err(|err| err as i64)?;
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
