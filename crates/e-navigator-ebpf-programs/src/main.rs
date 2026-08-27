#![no_std]
#![no_main]
#![allow(clippy::needless_borrows_for_generic_args)]
//! Kernel-side eBPF programs and fixed event layouts for E-Navigator sources.

#[cfg(all(feature = "perf-buffer", feature = "ring-buffer"))]
compile_error!("exactly one event transport feature must be enabled");
#[cfg(not(any(feature = "perf-buffer", feature = "ring-buffer")))]
compile_error!("one event transport feature must be enabled");

mod capture_policy;
mod dns_peer;
mod http_propagation;
mod network_mmsg;

#[cfg(feature = "ring-buffer")]
use aya_ebpf::maps::RingBuf;
#[cfg(feature = "perf-buffer")]
use aya_ebpf::maps::{PerfEventArray, PerfEventByteArray};
use aya_ebpf::{
    EbpfContext, Global,
    bindings::{
        BPF_F_USER_STACK, BPF_NOEXIST, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, bpf_pidns_info,
        sk_action::{SK_DROP, SK_PASS},
    },
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_stack,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
        generated::{
            bpf_get_current_cgroup_id, bpf_get_current_task_btf, bpf_get_ns_current_pid_tgid,
            bpf_get_socket_cookie, bpf_loop, bpf_msg_pull_data, bpf_probe_read_kernel,
            bpf_probe_read_user as bpf_probe_read_user_raw, bpf_task_pt_regs,
        },
    },
    macros::{fexit, map, perf_event, sk_msg, sock_ops, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, ProgramArray, Queue, SockHash},
    programs::{
        FExitContext, PerfEventContext, ProbeContext, RetProbeContext, SkMsgContext,
        SockOpsContext, TracePointContext,
    },
};
use capture_policy::{CAPTURE_FILTER_DISABLED, capture_allowed, listener_metadata_allowed};
use dns_peer::is_dns_ipv4_peer;
use e_navigator_context_propagation::{
    MAX_TRACESTATE_BYTES, TraceContext, format_traceparent_header,
};
use http_propagation::plan_bpf_http1_propagation_loop;
use network_mmsg::{completed_messages, message_length_offset};

/// Source-stage diagnostics are intentionally opt-in. The userspace loader
/// overrides this read-only global before loading an object when diagnostic
/// sampling is enabled. Keeping the default fast path at zero avoids doing
/// several counter-map writes for every captured syscall in production.
#[unsafe(no_mangle)]
static SOURCE_DIAGNOSTICS_ENABLED: Global<u8> = Global::new(0);

/// Cleartext HTTP/1 propagation is opt-in because attaching SK_MSG changes
/// application traffic and has a deliberately narrower support contract than
/// passive capture.
#[unsafe(no_mangle)]
static HTTP_CONTEXT_PROPAGATION_ENABLED: Global<u8> = Global::new(0);

#[unsafe(no_mangle)]
static HTTP_CONTEXT_PROPAGATION_TTL_NANOS: Global<u64> = Global::new(30_000_000_000);

const EXECUTABLE_LEN: usize = 256;
const MAX_ARGS: usize = 8;
const ARG_LEN: usize = 64;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const DNS_PACKET_BYTES: usize = 512;
const HTTP_MAX_IOVECS: usize = 3;
/// Maximum writev/sendmsg vector length whose complete byte count is summed
/// before SK_MSG mutation. Payload capture remains bounded to the contiguous
/// prefix held in the first three verifier-safe slots.
const HTTP_MAX_LENGTH_IOVECS: u64 = 40;
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
const HTTP_DIAG_NON_HTTP_CONNECTION_SKIP: u32 = 19;
const HTTP_DIAGNOSTIC_COUNTERS_LEN: u32 = 20;
const HTTP_PROPAGATION_DIAGNOSTIC_COUNTERS_LEN: u32 = 16;
const HTTP_PROPAGATION_DIAG_SOCKET_TRACKED: u32 = 0;
const HTTP_PROPAGATION_DIAG_SOCKET_TRACK_FAILED: u32 = 1;
const HTTP_PROPAGATION_DIAG_PLANNED: u32 = 2;
const HTTP_PROPAGATION_DIAG_INJECTED: u32 = 3;
const HTTP_PROPAGATION_DIAG_BYPASSED: u32 = 4;
const HTTP_PROPAGATION_DIAG_CONTEXT_POOL_EMPTY: u32 = 5;
const HTTP_PROPAGATION_DIAG_PENDING_CONTENDED: u32 = 6;
const HTTP_PROPAGATION_DIAG_PUSH_FAILED: u32 = 7;
const HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED: u32 = 8;
const HTTP_PROPAGATION_DIAG_THREAD_CONTEXT_FAILED: u32 = 9;
const HTTP_PROPAGATION_DIAG_PLANNING_INELIGIBLE: u32 = 10;
const HTTP_PROPAGATION_DIAG_PLANNER_REJECTED: u32 = 11;
const HTTP_PROPAGATION_DIAG_MUTATION_MISMATCH: u32 = 12;
const HTTP_PROPAGATION_DIAG_INBOUND_ACTIVATED: u32 = 13;
const HTTP_PROPAGATION_DIAG_INBOUND_REJECTED: u32 = 14;
const HTTP_PROPAGATION_DIAG_UNSUPPORTED_IOVEC: u32 = 15;
const HTTP_PROPAGATION_CAPTURE_UNSUPPORTED_IOVEC: u8 = 1;
const HTTP_PROPAGATION_GENERATED: u32 = 1;
const HTTP_PARSE_METHOD: u8 = 0;
const HTTP_PARSE_TARGET: u8 = 1;
const HTTP_PARSE_VERSION: u8 = 2;
const HTTP_PARSE_REQUEST_LF: u8 = 3;
const HTTP_PARSE_HEADER_NAME: u8 = 4;
const HTTP_PARSE_HEADER_VALUE: u8 = 5;
const HTTP_PARSE_HEADER_LF: u8 = 6;
const HTTP_FIELD_OTHER: u8 = 0;
const HTTP_FIELD_CONTENT_LENGTH: u8 = 1;
const HTTP_FIELD_TRANSFER_ENCODING: u8 = 2;
const HTTP_HEADER_PLAN_CHUNKED: u32 = 1 << 31;
const HTTP_CHUNK_SIZE: u8 = 0;
const HTTP_CHUNK_EXTENSION: u8 = 1;
const HTTP_CHUNK_SIZE_LF: u8 = 2;
const HTTP_CHUNK_DATA: u8 = 3;
const HTTP_CHUNK_DATA_CR: u8 = 4;
const HTTP_CHUNK_DATA_LF: u8 = 5;
const HTTP_CHUNK_TRAILER_NAME: u8 = 6;
const HTTP_CHUNK_TRAILER_VALUE: u8 = 7;
const HTTP_CHUNK_TRAILER_LF: u8 = 8;
const HTTP_FNV_OFFSET: u64 = 0xcbf29ce484222325;
const HTTP_FNV_PRIME: u64 = 0x100000001b3;
const HTTP_TRACEPARENT_HASH: u64 = 0xa22e83ed935e6e5e;
const HTTP_TRACESTATE_HASH: u64 = 0x958c9556effaa193;
const HTTP_UPGRADE_HASH: u64 = 0x7f7d77d7c2a03db7;
const HTTP_PLAN_PENDING: u8 = 0;
const HTTP_PLAN_VALID: u8 = 1;
const HTTP_PLAN_INVALID: u8 = 2;
const TRACESTATE_PARSE_START: u8 = 0;
const TRACESTATE_PARSE_KEY: u8 = 1;
const TRACESTATE_PARSE_VALUE: u8 = 2;
const TRACESTATE_HEADER_PREFIX: [u8; 12] = *b"tracestate: ";
const HEADER_LINE_END: [u8; 2] = *b"\r\n";

/// First captured payload not yet inspected for an HTTP/1 request start.
const HTTP_CONN_UNKNOWN: u32 = 0;
/// First captured payload started like an HTTP/1 request; keep capturing.
const HTTP_CONN_HTTP: u32 = 1;
/// First captured payload did not start like an HTTP/1 request; skip the
/// connection's remaining payload capture entirely.
const HTTP_CONN_NOT_HTTP: u32 = 2;
const CONNECTION_ROLE_CLIENT: u32 = 0;
const CONNECTION_ROLE_SERVER: u32 = 1;
const PROTOCOL_DATA_BYTES: usize = 256;
const PROTOCOL_IOVEC_DATA_MAX: u32 = (PROTOCOL_DATA_BYTES - 1) as u32;
const PROTOCOL_MAX_IOVECS: u32 = 40;
const PROTOCOL_IOVEC_CHUNK: u32 = 8;
/// Iovec slots the emit tail program consumes per tail-call round. Each slot
/// costs two user probe reads, a bounded payload copy, and an event output,
/// so unchunked emission of all `PROTOCOL_MAX_IOVECS` slots exceeds the
/// one-million-instruction verifier budget on arm64 kernels.
const PROTOCOL_IOVEC_EMIT_CHUNK: u32 = 8;
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
#[cfg(bpf_target_arch = "aarch64")]
const NETWORK_RECVMMSG_SYSCALL: i32 = 243;
#[cfg(bpf_target_arch = "aarch64")]
const NETWORK_SENDMMSG_SYSCALL: i32 = 269;
#[cfg(bpf_target_arch = "x86_64")]
const NETWORK_RECVMMSG_SYSCALL: i32 = 299;
#[cfg(bpf_target_arch = "x86_64")]
const NETWORK_SENDMMSG_SYSCALL: i32 = 307;
const NETWORK_MMSG_DIAGNOSTIC_COUNTERS_LEN: u32 = 2;
const NETWORK_MMSG_DIAG_ACCOUNTED: u32 = 0;
const NETWORK_MMSG_DIAG_UNSUPPORTED: u32 = 1;
const NEG_EINPROGRESS: i64 = -115;
const EXEC_EVENT_SOURCE_SYSCALL_ENTER: u32 = 1;
const EXEC_EVENT_SOURCE_SCHED_EXEC: u32 = 2;
const CPU_PROFILE_MAX_FRAMES: usize = 128;
const CPU_PROFILE_MIN_FRAMES: u32 = 1;
const KERNEL_PROFILE_MAX_FRAMES: usize = 64;
const KERNEL_PROFILE_MIN_FRAMES: u32 = 1;
const KERNEL_PROFILE_FLAG_TRUNCATED: u32 = 1;
const KERNEL_PROFILE_FLAG_CAPTURE_FAILED: u32 = 2;
const CPU_PROFILE_FLAG_TRUNCATED: u32 = 1;
const CPU_PROFILE_FLAG_PID_NS_UNTRANSLATED: u32 = 2;
const CPU_PROFILE_FLAG_DWARF: u32 = 4;
const PROFILE_KIND_CPU: u32 = 1;
const PROFILE_KIND_LOCK: u32 = 3;
const PROFILE_MODE_ON_CPU: u32 = 1;
const PROFILE_MODE_OFF_CPU: u32 = 2;
const PROFILE_MODE_FUTEX_WAIT: u32 = 3;
const PROFILE_CONFIG_OFF_CPU_ENABLED: u32 = 0;
const PROFILE_CONFIG_LOCK_ENABLED: u32 = 1;
const PROFILE_CONFIG_OFF_CPU_MIN_NANOS: u32 = 2;
const PROFILE_CONFIG_LOCK_MIN_NANOS: u32 = 3;
const PROFILE_CONFIG_OFF_CPU_RATE_PER_CPU: u32 = 4;
const PROFILE_CONFIG_LOCK_RATE_PER_CPU: u32 = 5;
const PROFILE_CONFIG_FUTEX_SYSCALL: u32 = 6;
const PROFILE_CONFIG_KERNEL_STACK_ENABLED: u32 = 7;
const PROFILE_CONFIG_LEN: u32 = 8;
const PROFILE_RATE_OFF_CPU: u32 = 0;
const PROFILE_RATE_LOCK: u32 = 1;
const PROFILE_PREPARE_FILTERED: u32 = 0;
const PROFILE_PREPARE_STACK_FAILED: u32 = 1;
const PROFILE_PREPARE_CAPTURED: u32 = 2;
const PROFILE_RATE_LEN: u32 = 2;
const PROFILE_DIAG_OFF_CPU_ENTRIES: u32 = 0;
const PROFILE_DIAG_OFF_CPU_UPDATE_FAILURES: u32 = 1;
const PROFILE_DIAG_OFF_CPU_REPLACEMENTS: u32 = 2;
const PROFILE_DIAG_OFF_CPU_BELOW_MIN: u32 = 4;
const PROFILE_DIAG_OFF_CPU_RATE_LIMITED: u32 = 5;
const PROFILE_DIAG_OFF_CPU_STACK_FAILURES: u32 = 6;
const PROFILE_DIAG_OFF_CPU_OUTPUTS: u32 = 7;
const PROFILE_DIAG_LOCK_ENTRIES: u32 = 8;
const PROFILE_DIAG_LOCK_UPDATE_FAILURES: u32 = 9;
const PROFILE_DIAG_LOCK_REPLACEMENTS: u32 = 10;
const PROFILE_DIAG_LOCK_BELOW_MIN: u32 = 12;
const PROFILE_DIAG_LOCK_RATE_LIMITED: u32 = 13;
const PROFILE_DIAG_LOCK_STACK_FAILURES: u32 = 14;
const PROFILE_DIAG_LOCK_OUTPUTS: u32 = 15;
const PROFILE_DIAGNOSTIC_COUNTERS_LEN: u32 = 16;
const PROFILE_PENDING_MAX_ENTRIES: u32 = 4096;
const PROFILE_RATE_WINDOW_NANOS: u64 = 1_000_000_000;
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAIT_BITSET: u32 = 9;
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
const GO_TLS_COUNTER_ENTRY: u32 = 0;
const GO_TLS_COUNTER_EXIT: u32 = 1;
const GO_TLS_COUNTER_LAYOUT_MISS: u32 = 2;
const GO_TLS_COUNTER_PENDING_MISS: u32 = 3;
const GO_TLS_COUNTER_STATE_UPDATE_FAILURE: u32 = 4;
const GO_TLS_COUNTER_FD_RESOLVED: u32 = 5;
const GO_TLS_COUNTER_FD_UNRESOLVED: u32 = 6;
const GO_TLS_COUNTER_OUTPUT_ATTEMPT: u32 = 7;
const GO_TLS_COUNTER_STATE_REPLACED: u32 = 8;
const GO_TLS_COUNTERS_LEN: u32 = 9;
const GO_TLS_MAX_FD: i64 = 1_048_575;
const TRANSPORT_LOSS_EXEC: u32 = 0;
const TRANSPORT_LOSS_EXIT: u32 = 1;
const TRANSPORT_LOSS_NETWORK: u32 = 2;
const TRANSPORT_LOSS_TCP_STAT: u32 = 3;
const TRANSPORT_LOSS_CPU_PROFILE: u32 = 4;
const TRANSPORT_LOSS_DNS: u32 = 5;
const TRANSPORT_LOSS_HTTP: u32 = 6;
const TRANSPORT_LOSS_PROTOCOL: u32 = 7;
const TRANSPORT_LOSS_TLS: u32 = 8;
#[cfg(feature = "ring-buffer")]
const EVENT_TRANSPORT_LOSSES_LEN: u32 = 9;
#[cfg(feature = "ring-buffer")]
const DEFAULT_RING_BUFFER_BYTES: u32 = 256 * 1024;

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
    pub profile_kind: u32,
    pub profile_mode: u32,
    pub profile_status: i32,
    pub reserved: u32,
    /// Duration weight for event-driven profiles. Zero for periodic on-CPU
    /// samples, whose weight is derived from the configured sample period.
    pub weight_nanos: u64,
    pub instruction_pointers: [u64; CPU_PROFILE_MAX_FRAMES],
    pub kernel_frame_count: u32,
    pub kernel_flags: u32,
    pub kernel_instruction_pointers: [u64; KERNEL_PROFILE_MAX_FRAMES],
    pub py_frame_count: u32,
    pub py_stop: u32,
    /// CPython code-object pointers, leaf first; userspace resolves
    /// them to function/file/line through the process's memory.
    pub py_frames: [u64; PY_MAX_FRAMES],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProfileRateState {
    pub window_started_nanos: u64,
    pub emitted: u64,
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
pub struct RawHttpPropagationContext {
    pub state: u32,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: [u8; 8],
    pub trace_flags: u8,
    pub reserved: u8,
    pub insert_at: u16,
    pub started_at_nanos: u64,
    pub tracestate_len: u16,
    pub tracestate_reserved: [u8; 6],
    pub tracestate: [u8; MAX_TRACESTATE_BYTES],
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
    pub propagation: RawHttpPropagationContext,
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
    /// Monotonic connection-generation token. Unlike `(pid, fd)`, this
    /// changes when an fd is closed and reused for the same peer.
    pub connection_started_at_nanos: u64,
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
    /// Emit-stage cursor: next iovec slot the emit tail program consumes.
    pub emit_slot: u32,
    /// Emit-stage cursor: payload offset of the next emitted segment.
    pub emit_offset: u32,
    /// Nonzero once the emit stage has emitted at least one segment.
    pub emit_emitted: u32,
    /// Nonzero once the emit stage hit a terminal condition (bounded tail,
    /// partial capture, or vector end) and must not re-chain.
    pub emit_done: u32,
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

/// Version-gated private Go runtime layout populated by userspace for each
/// capture-ready process. Map absence disables Go ABI reads fail-closed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GoTlsProcessLayout {
    pub sysfd_offset: u32,
    pub reserved: u32,
}

/// Goroutine identity, rather than OS thread identity, keeps entry/return
/// correlation valid when the Go scheduler migrates work between threads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GoTlsIoKey {
    pub tgid: u32,
    pub direction: u32,
    pub goroutine: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingGoTlsIo {
    pub buffer_ptr: u64,
    pub requested_len: u64,
    pub fd: i32,
    pub direction: u32,
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
    /// HTTP source only: lazily assigned `HTTP_CONN_*` classification of the
    /// connection's first captured payload. Other sources leave it unknown.
    /// If a second source ever needs a per-connection capture verdict, this
    /// field should generalize into a source-neutral capture class rather
    /// than gaining a sibling; the port-scoped protocol source currently
    /// expresses its verdict through its port maps instead.
    pub http_state: u32,
    /// Keeps the map value free of uninitialized tail padding.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingNetworkIo {
    pub tgid: u32,
    pub fd: i32,
    pub direction: u32,
    /// A splice can move bytes between two tracked sockets. Ordinary I/O uses
    /// `-1` and direction zero for this slot.
    pub secondary_fd: i32,
    pub secondary_direction: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingNetworkMmsg {
    pub tgid: u32,
    pub fd: i32,
    pub direction: u32,
    pub vlen: u32,
    pub messages_ptr: u64,
}

#[repr(C)]
struct NetworkMmsgSumState {
    messages: *const u8,
    total: u64,
    completed: u32,
    failed: u32,
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

#[cfg(feature = "perf-buffer")]
#[map]
static EXEC_EVENTS: PerfEventArray<RawExecEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static EXIT_EVENTS: PerfEventArray<RawExitEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static NETWORK_EVENTS: PerfEventArray<RawNetworkEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static TCP_STAT_EVENTS: PerfEventArray<RawTcpStatEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static TCP_STAT_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[map]
static TCP_STAT_EVENT_SCRATCH: PerCpuArray<RawTcpStatEvent> = PerCpuArray::with_max_entries(1, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static CPU_PROFILE_EVENTS: PerfEventArray<RawCpuProfileEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static CPU_PROFILE_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static DNS_EVENTS: PerfEventArray<RawDnsEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static HTTP_REQUEST_EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static HTTP_REQUEST_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

#[map]
static HTTP_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(HTTP_DIAGNOSTIC_COUNTERS_LEN, 0);

#[cfg(feature = "perf-buffer")]
#[map]
static PROTOCOL_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static PROTOCOL_DATA_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

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

/// Opt-in capture of bounded payload prefixes on every TCP port. Userspace
/// still emits semantics only after strict, unique protocol classification.
#[map]
static PROTOCOL_CAPTURE_ALL: Array<u32> = Array::with_max_entries(1, 0);

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

// The event-driven profilers use distinct per-CPU scratch values so a perf
// interrupt cannot overwrite an in-flight tracepoint sample on the same CPU.
#[map]
static OFF_CPU_PROFILE_EVENT_SCRATCH: PerCpuArray<RawCpuProfileEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static LOCK_PROFILE_EVENT_SCRATCH: PerCpuArray<RawCpuProfileEvent> =
    PerCpuArray::with_max_entries(1, 0);

// Fixed-capacity, non-preallocated state. A full map rejects new entries and
// increments an explicit update-failure counter; it never evicts silently.
#[map]
static PENDING_OFF_CPU_PROFILES: HashMap<u64, RawCpuProfileEvent> =
    HashMap::with_max_entries(PROFILE_PENDING_MAX_ENTRIES, HASH_MAP_NO_PREALLOC);

#[map]
static PENDING_LOCK_PROFILES: HashMap<u64, RawCpuProfileEvent> =
    HashMap::with_max_entries(PROFILE_PENDING_MAX_ENTRIES, HASH_MAP_NO_PREALLOC);

/// Enable flags, minimum durations, rate caps, and the host futex syscall id.
#[map]
static PROFILE_CAPTURE_CONFIG: Array<u64> = Array::with_max_entries(PROFILE_CONFIG_LEN, 0);

#[map]
static PROFILE_RATE_STATE: PerCpuArray<ProfileRateState> =
    PerCpuArray::with_max_entries(PROFILE_RATE_LEN, 0);

#[map]
static PROFILE_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(PROFILE_DIAGNOSTIC_COUNTERS_LEN, 0);

#[map]
static CPU_PROFILE_FRAME_LIMIT: Array<u32> = Array::with_max_entries(2, 0);

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

/// CSPRNG-generated contexts supplied and continuously replenished by the
/// userspace loader. The kernel consumes each element at most once.
#[map]
static HTTP_PROPAGATION_CONTEXTS: Queue<TraceContext> = Queue::with_max_entries(4096, 0);

/// Active client TCP sockets selected by the opt-in plaintext port allowlist.
#[map]
static HTTP_PROPAGATION_SOCKETS: SockHash<u64> = SockHash::with_max_entries(8192, 0);

/// One in-flight eligible write per calling thread. `BPF_NOEXIST` preserves
/// the older request if the same thread somehow overlaps socket writes.
#[map]
static PENDING_HTTP_PROPAGATIONS: HashMap<u64, RawHttpRequestEvent> =
    HashMap::with_max_entries(4096, HASH_MAP_NO_PREALLOC);

/// Best-effort same-thread continuation for synchronous request handlers.
/// Async/thread-hop runtimes are an explicit nonclaim.
#[map]
static HTTP_THREAD_TRACE_CONTEXTS: LruHashMap<u64, RawHttpPropagationContext> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
static HTTP_PROPAGATION_PORTS: HashMap<u16, u8> =
    HashMap::with_max_entries(32, HASH_MAP_NO_PREALLOC);

#[map]
static HTTP_PROPAGATION_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(HTTP_PROPAGATION_DIAGNOSTIC_COUNTERS_LEN, 0);

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
static PENDING_NETWORK_MMSG: HashMap<u64, PendingNetworkMmsg> =
    HashMap::with_max_entries(8192, HASH_MAP_NO_PREALLOC);

#[map]
static NETWORK_MMSG_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(NETWORK_MMSG_DIAGNOSTIC_COUNTERS_LEN, 0);

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

#[cfg(feature = "perf-buffer")]
#[map]
static TLS_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);
#[cfg(feature = "ring-buffer")]
#[map]
static TLS_DATA_EVENTS: RingBuf = RingBuf::with_byte_size(DEFAULT_RING_BUFFER_BYTES, 0);

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
static GO_TLS_PROCESS_LAYOUTS: LruHashMap<u32, GoTlsProcessLayout> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
static PENDING_GO_TLS_IO: LruHashMap<GoTlsIoKey, PendingGoTlsIo> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
static GO_TLS_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(GO_TLS_COUNTERS_LEN, 0);

#[map]
static TLS_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(TLS_DIAGNOSTIC_COUNTERS_LEN, 0);

/// Per-source producer failures for the selected kernel-to-userspace event
/// transport. Perf-event losses are surfaced directly to userspace by Aya;
/// ring-buffer reservation failures are surfaced only to the eBPF producer,
/// so every failed output increments the corresponding per-CPU slot here.
#[cfg(feature = "ring-buffer")]
#[map]
static EVENT_TRANSPORT_LOSSES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(EVENT_TRANSPORT_LOSSES_LEN, 0);

#[cfg(feature = "ring-buffer")]
#[inline(always)]
fn record_transport_loss(index: u32) {
    if let Some(counter) = EVENT_TRANSPORT_LOSSES.get_ptr_mut(index) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

#[cfg(feature = "ring-buffer")]
#[inline(always)]
fn output_ring_event<T: ?Sized>(map: &RingBuf, event: &T) -> Result<(), i32> {
    map.output::<T>(event, 0)
}

#[cfg(feature = "perf-buffer")]
macro_rules! output_event {
    ($map:ident, $loss_index:expr, $ctx:expr, $event:expr) => {{
        let _ = $loss_index;
        $map.output($ctx, $event, 0);
    }};
}

#[cfg(feature = "ring-buffer")]
macro_rules! output_event {
    ($map:ident, $loss_index:expr, $ctx:expr, $event:expr) => {{
        let _ = $ctx;
        if output_ring_event(&$map, $event).is_err() {
            record_transport_loss($loss_index);
        }
    }};
}

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
pub fn tracepoint_http_write_exit(ctx: TracePointContext) -> u32 {
    flush_pending_http_propagation(&ctx)
}

#[tracepoint]
pub fn tracepoint_http_writev_exit(ctx: TracePointContext) -> u32 {
    flush_pending_http_propagation(&ctx)
}

#[tracepoint]
pub fn tracepoint_http_sendto_exit(ctx: TracePointContext) -> u32 {
    flush_pending_http_propagation(&ctx)
}

#[tracepoint]
pub fn tracepoint_http_sendmsg_exit(ctx: TracePointContext) -> u32 {
    flush_pending_http_propagation(&ctx)
}

#[sock_ops]
pub fn sockops_http_context_propagation(ctx: SockOpsContext) -> u32 {
    try_sockops_http_context_propagation(&ctx)
}

#[sk_msg]
pub fn sk_msg_http_context_propagation(ctx: SkMsgContext) -> u32 {
    try_sk_msg_http_context_propagation(&ctx)
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
pub fn tracepoint_readv_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_readv_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_writev_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_writev_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendfile_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendfile_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_splice_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_splice_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_splice_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_io_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

/// BTF-backed network byte accounting for `ksys_read`. The fourth fexit
/// context slot is the target function's return value after its three
/// arguments. Keeping this path independent of `bpf_get_func_ret` preserves
/// the Linux 5.5 fexit compatibility floor.
#[fexit]
pub fn fexit_ksys_read(ctx: FExitContext) -> u32 {
    match try_fexit_network_io(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

/// BTF-backed network byte accounting for `ksys_write`.
#[fexit]
pub fn fexit_ksys_write(ctx: FExitContext) -> u32 {
    match try_fexit_network_io(&ctx, NETWORK_IO_WRITE) {
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
pub fn tracepoint_sendmmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_mmsg_enter(&ctx, NETWORK_IO_WRITE) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendmmsg_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_mmsg_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_mmsg_enter(&ctx, NETWORK_IO_READ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmmsg_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_network_mmsg_exit(&ctx) {
        Ok(ret) => ret,
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

#[tracepoint]
pub fn tracepoint_profile_sched_switch(ctx: TracePointContext) -> u32 {
    match try_profile_sched_switch(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_profile_futex_enter(ctx: TracePointContext) -> u32 {
    match try_profile_futex_enter(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_profile_futex_exit(ctx: TracePointContext) -> u32 {
    match try_profile_futex_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_profile_process_exit(_ctx: TracePointContext) -> u32 {
    let key = bpf_get_current_pid_tgid();
    // Off-CPU state is keyed only by tid because sched_switch exposes
    // next_pid, while futex state can retain the collision-safe pid/tid key.
    let _ = PENDING_OFF_CPU_PROFILES.remove(&u64::from(key as u32));
    let _ = PENDING_LOCK_PROFILES.remove(&key);
    0
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

// Go ABIInternal entry/return sites for crypto/tls.(*Conn).Read. Return sites
// are ordinary uprobes attached to each decoded RET instruction because a Go
// goroutine can migrate between OS threads while the call is in flight.
#[uprobe]
pub fn uprobe_go_tls_read_enter(ctx: ProbeContext) -> u32 {
    go_tls_io_enter(&ctx, NETWORK_IO_READ)
}

#[uprobe]
pub fn uprobe_go_tls_read_exit(ctx: ProbeContext) -> u32 {
    go_tls_io_exit(&ctx, NETWORK_IO_READ)
}

#[uprobe]
pub fn uprobe_go_tls_write_enter(ctx: ProbeContext) -> u32 {
    go_tls_io_enter(&ctx, NETWORK_IO_WRITE)
}

#[uprobe]
pub fn uprobe_go_tls_write_exit(ctx: ProbeContext) -> u32 {
    go_tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// The nested netFD method exposes the concrete socket descriptor without
// guessing the dynamic concrete type stored in tls.Conn's net.Conn interface.
#[uprobe]
pub fn uprobe_go_netfd_read_enter(ctx: ProbeContext) -> u32 {
    go_tls_netfd_enter(&ctx, NETWORK_IO_READ)
}

#[uprobe]
pub fn uprobe_go_netfd_write_enter(ctx: ProbeContext) -> u32 {
    go_tls_netfd_enter(&ctx, NETWORK_IO_WRITE)
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

    output_event!(EXEC_EVENTS, TRANSPORT_LOSS_EXEC, &ctx, &*event);
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

    output_event!(EXEC_EVENTS, TRANSPORT_LOSS_EXEC, &ctx, &*event);
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

    output_event!(EXIT_EVENTS, TRANSPORT_LOSS_EXIT, &ctx, &*event);
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
    output_event!(TCP_STAT_EVENTS, TRANSPORT_LOSS_TCP_STAT, ctx, &*event);
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
    output_event!(TCP_STAT_EVENTS, TRANSPORT_LOSS_TCP_STAT, ctx, &*event);
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
    output_event!(TCP_STAT_EVENTS, TRANSPORT_LOSS_TCP_STAT, ctx, &*event);
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

fn try_profile_sched_switch(ctx: &TracePointContext) -> Result<u32, i64> {
    if profile_config(PROFILE_CONFIG_OFF_CPU_ENABLED) == 0 {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    // Validated by userspace against tracefs before this program is attached.
    let next_tid = unsafe { ctx.read_at::<u32>(56) }.map_err(|err| err as i64)?;
    if next_tid != 0 {
        finish_event_driven_profile(
            ctx,
            &PENDING_OFF_CPU_PROFILES,
            u64::from(next_tid),
            now,
            PROFILE_CONFIG_OFF_CPU_MIN_NANOS,
            PROFILE_CONFIG_OFF_CPU_RATE_PER_CPU,
            PROFILE_RATE_OFF_CPU,
            PROFILE_DIAG_OFF_CPU_BELOW_MIN,
            PROFILE_DIAG_OFF_CPU_RATE_LIMITED,
            PROFILE_DIAG_OFF_CPU_OUTPUTS,
        );
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    if tid == 0 {
        return Ok(0);
    }
    let event = unsafe {
        let ptr = OFF_CPU_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let prepare =
        prepare_event_driven_profile(ctx, event, PROFILE_KIND_CPU, PROFILE_MODE_OFF_CPU, now)?;
    if prepare == PROFILE_PREPARE_FILTERED {
        return Ok(0);
    }
    record_profile_counter(PROFILE_DIAG_OFF_CPU_ENTRIES);
    if prepare == PROFILE_PREPARE_STACK_FAILED {
        record_profile_counter(PROFILE_DIAG_OFF_CPU_STACK_FAILURES);
        return Ok(0);
    }
    let key = u64::from(tid);
    if unsafe { PENDING_OFF_CPU_PROFILES.get(&key) }.is_some() {
        record_profile_counter(PROFILE_DIAG_OFF_CPU_REPLACEMENTS);
    }
    if PENDING_OFF_CPU_PROFILES.insert(&key, &*event, 0).is_err() {
        record_profile_counter(PROFILE_DIAG_OFF_CPU_UPDATE_FAILURES);
    }
    Ok(0)
}

fn try_profile_futex_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    if profile_config(PROFILE_CONFIG_LOCK_ENABLED) == 0 {
        return Ok(0);
    }
    let syscall = unsafe { ctx.read_at::<i64>(8) }.map_err(|err| err as i64)? as u64;
    if syscall != profile_config(PROFILE_CONFIG_FUTEX_SYSCALL) {
        return Ok(0);
    }
    let operation = unsafe { ctx.read_at::<u64>(24) }.map_err(|err| err as i64)? as u32;
    let command = operation & FUTEX_CMD_MASK;
    if command != FUTEX_WAIT && command != FUTEX_WAIT_BITSET {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let event = unsafe {
        let ptr = LOCK_PROFILE_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };
    let prepare =
        prepare_event_driven_profile(ctx, event, PROFILE_KIND_LOCK, PROFILE_MODE_FUTEX_WAIT, now)?;
    if prepare == PROFILE_PREPARE_FILTERED {
        return Ok(0);
    }
    record_profile_counter(PROFILE_DIAG_LOCK_ENTRIES);
    if prepare == PROFILE_PREPARE_STACK_FAILED {
        record_profile_counter(PROFILE_DIAG_LOCK_STACK_FAILURES);
        return Ok(0);
    }
    event.profile_status = command as i32;
    let key = bpf_get_current_pid_tgid();
    if unsafe { PENDING_LOCK_PROFILES.get(&key) }.is_some() {
        record_profile_counter(PROFILE_DIAG_LOCK_REPLACEMENTS);
    }
    if PENDING_LOCK_PROFILES.insert(&key, &*event, 0).is_err() {
        record_profile_counter(PROFILE_DIAG_LOCK_UPDATE_FAILURES);
    }
    Ok(0)
}

fn try_profile_futex_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    if profile_config(PROFILE_CONFIG_LOCK_ENABLED) == 0 {
        return Ok(0);
    }
    let syscall = unsafe { ctx.read_at::<i64>(8) }.map_err(|err| err as i64)? as u64;
    if syscall != profile_config(PROFILE_CONFIG_FUTEX_SYSCALL) {
        return Ok(0);
    }
    let key = bpf_get_current_pid_tgid();
    if !cgroup_capture_allowed(current_cgroup_id()) {
        record_capture_filter_drop();
        // A verdict can change while the syscall is blocked. Never retain an
        // entry whose completion is now denied.
        let _ = PENDING_LOCK_PROFILES.remove(&key);
        return Ok(0);
    }
    let status = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)? as i32;
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(ptr) = PENDING_LOCK_PROFILES.get_ptr_mut(&key) {
        unsafe {
            (*ptr).profile_status = status;
        }
    }
    finish_event_driven_profile(
        ctx,
        &PENDING_LOCK_PROFILES,
        key,
        now,
        PROFILE_CONFIG_LOCK_MIN_NANOS,
        PROFILE_CONFIG_LOCK_RATE_PER_CPU,
        PROFILE_RATE_LOCK,
        PROFILE_DIAG_LOCK_BELOW_MIN,
        PROFILE_DIAG_LOCK_RATE_LIMITED,
        PROFILE_DIAG_LOCK_OUTPUTS,
    );
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn finish_event_driven_profile(
    ctx: &TracePointContext,
    pending: &HashMap<u64, RawCpuProfileEvent>,
    key: u64,
    now: u64,
    min_duration_config: u32,
    rate_config: u32,
    rate_index: u32,
    below_min_counter: u32,
    rate_limited_counter: u32,
    output_counter: u32,
) {
    // An absent state is not a scoped miss: sched_switch exposes no next-task
    // cgroup, and raw sys_exit exposes no futex operation. Counting either
    // would mislabel intentionally filtered/non-wait activity as data loss.
    // Insert failures and replacements remain explicit scoped counters.
    let Some(event_ptr) = pending.get_ptr_mut(&key) else {
        return;
    };
    let event = unsafe { &mut *event_ptr };
    let duration = now.saturating_sub(event.timestamp_unix_nanos);
    event.timestamp_unix_nanos = 0;
    event.weight_nanos = duration;
    if duration < profile_config(min_duration_config) {
        record_profile_counter(below_min_counter);
        let _ = pending.remove(&key);
        return;
    }
    if !profile_rate_allowed(rate_index, profile_config(rate_config), now) {
        record_profile_counter(rate_limited_counter);
        let _ = pending.remove(&key);
        return;
    }
    record_profile_counter(output_counter);
    output_event!(CPU_PROFILE_EVENTS, TRANSPORT_LOSS_CPU_PROFILE, ctx, &*event);
    let _ = pending.remove(&key);
}

#[inline(always)]
fn prepare_event_driven_profile(
    ctx: &TracePointContext,
    event: &mut RawCpuProfileEvent,
    profile_kind: u32,
    profile_mode: u32,
    started_nanos: u64,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = pid_tgid as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
    if !cgroup_capture_allowed(event.cgroup_id) {
        record_capture_filter_drop();
        return Ok(PROFILE_PREPARE_FILTERED);
    }
    event.sample_count = 1;
    event.timestamp_unix_nanos = started_nanos;
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.frame_count = 0;
    event.flags = 0;
    event.profile_kind = profile_kind;
    event.profile_mode = profile_mode;
    event.profile_status = 0;
    event.reserved = 0;
    event.weight_nanos = 0;
    translate_profile_pid(event);
    event.instruction_pointers = [0; CPU_PROFILE_MAX_FRAMES];
    event.kernel_frame_count = 0;
    event.kernel_flags = 0;
    event.kernel_instruction_pointers = [0; KERNEL_PROFILE_MAX_FRAMES];
    event.py_frame_count = 0;
    event.py_stop = 0;
    event.py_frames = [0; PY_MAX_FRAMES];
    let frame_limit = cpu_profile_frame_limit();
    let stack_bytes = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            event.instruction_pointers.as_mut_ptr().cast(),
            frame_limit * core::mem::size_of::<u64>() as u32,
            u64::from(BPF_F_USER_STACK),
        )
    };
    if stack_bytes <= 0 {
        return Ok(PROFILE_PREPARE_STACK_FAILED);
    }
    let captured =
        ((stack_bytes as usize) / core::mem::size_of::<u64>()).min(CPU_PROFILE_MAX_FRAMES) as u32;
    event.frame_count = captured;
    if captured >= frame_limit {
        event.flags |= CPU_PROFILE_FLAG_TRUNCATED;
    }
    if captured > 0 {
        capture_kernel_stack(ctx.as_ptr(), event);
        Ok(PROFILE_PREPARE_CAPTURED)
    } else {
        Ok(PROFILE_PREPARE_STACK_FAILED)
    }
}

#[inline(always)]
fn translate_profile_pid(event: &mut RawCpuProfileEvent) {
    let pidns_dev = CPU_PROFILE_PIDNS.get(0).copied().unwrap_or(0);
    let pidns_ino = CPU_PROFILE_PIDNS.get(1).copied().unwrap_or(0);
    if pidns_ino == 0 {
        return;
    }
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

#[inline(always)]
fn profile_config(index: u32) -> u64 {
    PROFILE_CAPTURE_CONFIG.get(index).copied().unwrap_or(0)
}

#[inline(always)]
fn profile_rate_allowed(index: u32, limit: u64, now: u64) -> bool {
    if limit == 0 {
        return false;
    }
    let Some(ptr) = PROFILE_RATE_STATE.get_ptr_mut(index) else {
        return false;
    };
    let state = unsafe { &mut *ptr };
    if now.saturating_sub(state.window_started_nanos) >= PROFILE_RATE_WINDOW_NANOS {
        state.window_started_nanos = now;
        state.emitted = 0;
    }
    if state.emitted >= limit {
        return false;
    }
    state.emitted = state.emitted.saturating_add(1);
    true
}

#[inline(always)]
fn record_profile_counter(index: u32) {
    if let Some(counter) = PROFILE_DIAGNOSTIC_COUNTERS.get_ptr_mut(index) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
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
    event.profile_kind = PROFILE_KIND_CPU;
    event.profile_mode = PROFILE_MODE_ON_CPU;
    event.profile_status = 0;
    event.reserved = 0;
    event.weight_nanos = 0;
    // Translate into the procfs namespace userspace symbolizes from. On
    // failure the root pid is retained and explicitly marked for identity
    // verification before symbolization.
    translate_profile_pid(event);
    event.instruction_pointers = [0; CPU_PROFILE_MAX_FRAMES];
    event.kernel_frame_count = 0;
    event.kernel_flags = 0;
    event.kernel_instruction_pointers = [0; KERNEL_PROFILE_MAX_FRAMES];
    event.py_frame_count = 0;
    event.py_stop = 0;
    event.py_frames = [0; PY_MAX_FRAMES];
    let frame_limit = cpu_profile_frame_limit();
    capture_kernel_stack(ctx.as_ptr(), event);

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
    output_event!(CPU_PROFILE_EVENTS, TRANSPORT_LOSS_CPU_PROFILE, ctx, &*event);
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
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
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
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
        return Ok(0);
    }
    state.py_tstate = found;

    // Resolve the innermost interpreter frame up front so the walker
    // rounds only chain frame-to-frame.
    let Some(info) = (unsafe { PY_PROC_INFO.get(&event.pid) }) else {
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
        return Ok(0);
    };
    let Some(cframe) = read_user_u64(found.wrapping_add(u64::from(info.tstate_cframe))) else {
        event.py_stop = PY_STOP_READ_FAULT;
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
        return Ok(0);
    };
    let frame = if cframe == 0 {
        0
    } else {
        match read_user_u64(cframe.wrapping_add(u64::from(info.cframe_current_frame))) {
            Some(frame) => frame,
            None => {
                event.py_stop = PY_STOP_READ_FAULT;
                output_event!(
                    CPU_PROFILE_EVENTS,
                    TRANSPORT_LOSS_CPU_PROFILE,
                    &ctx,
                    &*event
                );
                return Ok(0);
            }
        }
    };
    if frame == 0 {
        event.py_stop = PY_STOP_COMPLETE;
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
        return Ok(0);
    }
    state.py_frame = frame;
    state.py_rounds = 0;
    unsafe {
        CPU_PROFILE_PROGS.tail_call(&ctx, 2);
    }
    // Tail call failed; emit without python frames, accounted.
    event.py_stop = PY_STOP_READ_FAULT;
    output_event!(
        CPU_PROFILE_EVENTS,
        TRANSPORT_LOSS_CPU_PROFILE,
        &ctx,
        &*event
    );
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
        output_event!(
            CPU_PROFILE_EVENTS,
            TRANSPORT_LOSS_CPU_PROFILE,
            &ctx,
            &*event
        );
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
    output_event!(
        CPU_PROFILE_EVENTS,
        TRANSPORT_LOSS_CPU_PROFILE,
        &ctx,
        &*event
    );
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
fn kernel_profile_frame_limit() -> u32 {
    let configured = CPU_PROFILE_FRAME_LIMIT
        .get(1)
        .copied()
        .unwrap_or(KERNEL_PROFILE_MAX_FRAMES as u32);
    configured.clamp(KERNEL_PROFILE_MIN_FRAMES, KERNEL_PROFILE_MAX_FRAMES as u32)
}

#[inline(always)]
fn capture_kernel_stack(ctx: *mut core::ffi::c_void, event: &mut RawCpuProfileEvent) {
    if profile_config(PROFILE_CONFIG_KERNEL_STACK_ENABLED) == 0 {
        return;
    }
    let frame_limit = kernel_profile_frame_limit();
    let stack_bytes = unsafe {
        bpf_get_stack(
            ctx,
            event.kernel_instruction_pointers.as_mut_ptr().cast(),
            frame_limit * core::mem::size_of::<u64>() as u32,
            0,
        )
    };
    if stack_bytes <= 0 {
        event.kernel_flags |= KERNEL_PROFILE_FLAG_CAPTURE_FAILED;
        return;
    }
    let captured = ((stack_bytes as usize) / core::mem::size_of::<u64>())
        .min(KERNEL_PROFILE_MAX_FRAMES) as u32;
    event.kernel_frame_count = captured;
    if captured >= frame_limit {
        event.kernel_flags |= KERNEL_PROFILE_FLAG_TRUNCATED;
    }
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
fn record_go_tls_counter(stage: u32) {
    if let Some(counter) = GO_TLS_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_abi_registers(ctx: &ProbeContext) -> Option<(u64, u64, u64, u64)> {
    if ctx.regs.is_null() {
        return None;
    }
    // SAFETY: Aya passes the kernel-owned `pt_regs` context for this uprobe.
    // The x86_64 binding is a C-layout register frame; no userspace pointer is
    // dereferenced here. R14 is Go's fixed goroutine register and RAX/RBX/RCX
    // are the first three ABIInternal integer argument/result registers.
    let regs = unsafe { &*ctx.regs };
    Some((regs.r14, regs.rax, regs.rbx, regs.rcx))
}

#[cfg(not(bpf_target_arch = "x86_64"))]
#[inline(always)]
fn go_abi_registers(ctx: &ProbeContext) -> Option<(u64, u64, u64, u64)> {
    let _ = ctx;
    None
}

#[inline(always)]
fn go_tls_key(tgid: u32, direction: u32, goroutine: u64) -> GoTlsIoKey {
    GoTlsIoKey {
        tgid,
        direction,
        goroutine,
    }
}

fn go_tls_io_enter(ctx: &ProbeContext, direction: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if unsafe { GO_TLS_PROCESS_LAYOUTS.get(&tgid) }.is_none() {
        record_go_tls_counter(GO_TLS_COUNTER_LAYOUT_MISS);
        return 0;
    }
    let Some((goroutine, _receiver, buffer, requested_len)) = go_abi_registers(ctx) else {
        record_go_tls_counter(GO_TLS_COUNTER_LAYOUT_MISS);
        return 0;
    };
    if goroutine == 0 || buffer == 0 || requested_len == 0 {
        return 0;
    }
    record_go_tls_counter(GO_TLS_COUNTER_ENTRY);
    let key = go_tls_key(tgid, direction, goroutine);
    if unsafe { PENDING_GO_TLS_IO.get(&key) }.is_some() {
        record_go_tls_counter(GO_TLS_COUNTER_STATE_REPLACED);
    }
    let pending = PendingGoTlsIo {
        buffer_ptr: buffer,
        requested_len,
        fd: -1,
        direction,
    };
    if PENDING_GO_TLS_IO.insert(&key, &pending, 0).is_err() {
        record_go_tls_counter(GO_TLS_COUNTER_STATE_UPDATE_FAILURE);
    }
    0
}

fn go_tls_netfd_enter(ctx: &ProbeContext, direction: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let Some((goroutine, netfd, _buffer, _len)) = go_abi_registers(ctx) else {
        return 0;
    };
    if goroutine == 0 || netfd == 0 {
        return 0;
    }
    let key = go_tls_key(tgid, direction, goroutine);
    let mut pending = match unsafe { PENDING_GO_TLS_IO.get(&key) } {
        Some(value) => *value,
        None => return 0,
    };
    if pending.fd >= 0 {
        return 0;
    }
    let layout = match unsafe { GO_TLS_PROCESS_LAYOUTS.get(&tgid) } {
        Some(value) => *value,
        None => {
            record_go_tls_counter(GO_TLS_COUNTER_LAYOUT_MISS);
            return 0;
        }
    };
    let sysfd_address = netfd.wrapping_add(u64::from(layout.sysfd_offset));
    let fd = match unsafe { bpf_probe_read_user::<i64>(sysfd_address as *const i64) } {
        Ok(value) if (0..=GO_TLS_MAX_FD).contains(&value) => value as i32,
        _ => {
            record_go_tls_counter(GO_TLS_COUNTER_FD_UNRESOLVED);
            return 0;
        }
    };
    if tls_connection_for_fd(fd).is_none() {
        record_go_tls_counter(GO_TLS_COUNTER_FD_UNRESOLVED);
        return 0;
    }
    pending.fd = fd;
    if PENDING_GO_TLS_IO.insert(&key, &pending, 0).is_err() {
        record_go_tls_counter(GO_TLS_COUNTER_STATE_UPDATE_FAILURE);
        return 0;
    }
    record_go_tls_counter(GO_TLS_COUNTER_FD_RESOLVED);
    0
}

fn go_tls_io_exit(ctx: &ProbeContext, direction: u32) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let Some((goroutine, returned_len, _error_type, _error_data)) = go_abi_registers(ctx) else {
        return 0;
    };
    let key = go_tls_key(tgid, direction, goroutine);
    let pending = match unsafe { PENDING_GO_TLS_IO.get(&key) } {
        Some(value) => *value,
        None => {
            record_go_tls_counter(GO_TLS_COUNTER_PENDING_MISS);
            return 0;
        }
    };
    PENDING_GO_TLS_IO.remove(&key).ok();
    record_go_tls_counter(GO_TLS_COUNTER_EXIT);
    if pending.direction != direction
        || pending.fd < 0
        || returned_len == 0
        || returned_len as i64 <= 0
    {
        if pending.fd < 0 {
            record_go_tls_counter(GO_TLS_COUNTER_FD_UNRESOLVED);
        }
        return 0;
    }
    let length = returned_len.min(pending.requested_len);
    match emit_tls_data_for_fd(
        ctx,
        pending.fd,
        direction,
        pending.buffer_ptr as *const u8,
        length,
        true,
    ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
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
    tls_connection_for_fd(fd)
}

fn tls_connection_for_fd(fd: i32) -> Option<PendingConnect> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
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
fn emit_tls_data<C: EbpfContext>(
    ctx: &C,
    handle: u64,
    direction: u32,
    buffer: *const u8,
    len: u64,
) -> Result<u32, i64> {
    let connection = match tls_connection_for_handle(handle, direction) {
        Some(value) => value,
        None => return Ok(0),
    };
    emit_tls_data_for_connection(ctx, connection, direction, buffer, len, false)
}

#[inline(always)]
fn emit_tls_data_for_fd<C: EbpfContext>(
    ctx: &C,
    fd: i32,
    direction: u32,
    buffer: *const u8,
    len: u64,
    go_tls: bool,
) -> Result<u32, i64> {
    let connection = match tls_connection_for_fd(fd) {
        Some(value) => value,
        None => return Ok(0),
    };
    emit_tls_data_for_connection(ctx, connection, direction, buffer, len, go_tls)
}

#[inline(always)]
fn emit_tls_data_for_connection<C: EbpfContext>(
    ctx: &C,
    connection: PendingConnect,
    direction: u32,
    buffer: *const u8,
    len: u64,
    go_tls: bool,
) -> Result<u32, i64> {
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
    event.connection_started_at_nanos = connection.started_at_nanos;
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
        if go_tls {
            record_go_tls_counter(GO_TLS_COUNTER_OUTPUT_ATTEMPT);
        }
        output_event!(TLS_DATA_EVENTS, TRANSPORT_LOSS_TLS, ctx, &*event);
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
    event.connection_started_at_nanos = 0;
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
        http_state: HTTP_CONN_UNKNOWN,
        reserved: 0,
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
        output_event!(NETWORK_EVENTS, TRANSPORT_LOSS_NETWORK, &ctx, &*event);
        return Ok(0);
    }

    event.event_type = NETWORK_EVENT_OPEN;
    output_event!(NETWORK_EVENTS, TRANSPORT_LOSS_NETWORK, &ctx, &*event);

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
    output_event!(NETWORK_EVENTS, TRANSPORT_LOSS_NETWORK, &ctx, &*event);
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
    try_track_network_io(pid_tgid, fd, direction, -1, 0)
}

fn try_tracepoint_network_mmsg_enter(ctx: &TracePointContext, direction: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let messages = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let vlen = unsafe { ctx.read_at::<u32>(32) }.map_err(|err| err as i64)?;
    if messages.is_null() || vlen == 0 || !network_connection_tracked(tgid, fd) {
        return Ok(0);
    }
    if !native_mmsg_syscall(ctx, direction)? {
        record_network_mmsg_diagnostic(NETWORK_MMSG_DIAG_UNSUPPORTED);
        return Ok(0);
    }

    let pending = PendingNetworkMmsg {
        tgid,
        fd,
        direction,
        vlen,
        messages_ptr: messages as u64,
    };
    PENDING_NETWORK_MMSG
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

#[inline(always)]
fn native_mmsg_syscall(ctx: &TracePointContext, direction: u32) -> Result<bool, i64> {
    let syscall = unsafe { ctx.read_at::<i32>(8) }.map_err(|err| err as i64)?;
    #[cfg(any(bpf_target_arch = "aarch64", bpf_target_arch = "x86_64"))]
    {
        let expected = if direction == NETWORK_IO_WRITE {
            NETWORK_SENDMMSG_SYSCALL
        } else {
            NETWORK_RECVMMSG_SYSCALL
        };
        Ok(syscall == expected)
    }
    #[cfg(not(any(bpf_target_arch = "aarch64", bpf_target_arch = "x86_64")))]
    {
        let _ = (syscall, direction);
        Ok(false)
    }
}

fn try_tracepoint_network_mmsg_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match unsafe { PENDING_NETWORK_MMSG.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_NETWORK_MMSG.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval <= 0 {
        return Ok(0);
    }
    let Some(completed) = completed_messages(retval, pending.vlen) else {
        record_network_mmsg_diagnostic(NETWORK_MMSG_DIAG_UNSUPPORTED);
        return Ok(0);
    };
    let mut state = NetworkMmsgSumState {
        messages: pending.messages_ptr as *const u8,
        total: 0,
        completed,
        failed: 0,
    };
    let callback = bpf_network_mmsg_sum_step as *const () as *mut c_void;
    let context = (&mut state as *mut NetworkMmsgSumState).cast::<c_void>();
    // SAFETY: `state` remains live and exclusively borrowed for the synchronous
    // helper call. The callback receives this exact pointer, runs serially, and
    // never stores it beyond `bpf_loop`.
    let loops = unsafe { bpf_loop(completed, callback, context, 0) };
    if loops != i64::from(completed) || state.failed != 0 {
        record_network_mmsg_diagnostic(NETWORK_MMSG_DIAG_UNSUPPORTED);
        return Ok(0);
    }
    if state.total > 0 {
        add_network_io_bytes(pending.tgid, pending.fd, pending.direction, state.total)?;
    }
    record_network_mmsg_diagnostic(NETWORK_MMSG_DIAG_ACCOUNTED);
    Ok(0)
}

unsafe extern "C" fn bpf_network_mmsg_sum_step(index: u64, context: *mut c_void) -> i64 {
    // SAFETY: the only caller passes a live, exclusively borrowed
    // `NetworkMmsgSumState` for the full synchronous `bpf_loop` invocation.
    let state = unsafe { &mut *context.cast::<NetworkMmsgSumState>() };
    let Some(offset) = message_length_offset(index, state.completed) else {
        state.failed = 1;
        return 1;
    };
    // `wrapping_add` avoids asserting that an untrusted userspace allocation is
    // a Rust in-bounds object. The offset is bounded to one native LP64
    // `mmsghdr` slot; `bpf_probe_read_user` performs the checked copy and
    // returns an error for an unreadable address.
    let length_ptr = state.messages.wrapping_add(offset).cast::<u32>();
    // SAFETY: `length_ptr` is intentionally treated as an untrusted userspace
    // address and is dereferenced only by the kernel's checked probe helper.
    let length = match unsafe { bpf_probe_read_user::<u32>(length_ptr) } {
        Ok(length) => length,
        Err(_) => {
            state.failed = 1;
            return 1;
        }
    };
    state.total = state.total.saturating_add(u64::from(length));
    0
}

#[inline(always)]
fn record_network_mmsg_diagnostic(index: u32) {
    if let Some(counter) = NETWORK_MMSG_DIAGNOSTIC_COUNTERS.get_ptr_mut(index) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

fn try_tracepoint_network_splice_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let input_fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let output_fd = unsafe { ctx.read_at::<i32>(32) }.map_err(|err| err as i64)?;
    let input_tracked = network_connection_tracked(tgid, input_fd);
    let output_tracked = network_connection_tracked(tgid, output_fd);

    if input_tracked {
        let (secondary_fd, secondary_direction) = if output_tracked {
            (output_fd, NETWORK_IO_WRITE)
        } else {
            (-1, 0)
        };
        return try_track_network_io(
            pid_tgid,
            input_fd,
            NETWORK_IO_READ,
            secondary_fd,
            secondary_direction,
        );
    }
    if output_tracked {
        return try_track_network_io(pid_tgid, output_fd, NETWORK_IO_WRITE, -1, 0);
    }
    Ok(0)
}

fn try_track_network_io(
    pid_tgid: u64,
    fd: i32,
    direction: u32,
    secondary_fd: i32,
    secondary_direction: u32,
) -> Result<u32, i64> {
    let tgid = (pid_tgid >> 32) as u32;
    let key = ConnectionKey { tgid, fd };
    if unsafe { ACTIVE_CONNECTIONS.get(&key) }.is_none() {
        return Ok(0);
    }

    let pending = PendingNetworkIo {
        tgid,
        fd,
        direction,
        secondary_fd,
        secondary_direction,
    };
    PENDING_NETWORK_IO
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn network_connection_tracked(tgid: u32, fd: i32) -> bool {
    let key = ConnectionKey { tgid, fd };
    unsafe { ACTIVE_CONNECTIONS.get(&key) }.is_some()
}

fn try_tracepoint_network_io_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    let pending = match unsafe { PENDING_NETWORK_IO.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_NETWORK_IO.remove(&pid_tgid).ok();
    complete_network_io(pending, retval)
}

fn try_fexit_network_io(ctx: &FExitContext, direction: u32) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd = ctx.arg::<u32>(0) as i32;
    let retval = ctx.arg::<i64>(3);
    let pending = PendingNetworkIo {
        tgid: (pid_tgid >> 32) as u32,
        fd,
        direction,
        secondary_fd: -1,
        secondary_direction: 0,
    };
    complete_network_io(pending, retval)
}

fn complete_network_io(pending: PendingNetworkIo, retval: i64) -> Result<u32, i64> {
    if retval <= 0 {
        return Ok(0);
    }

    add_network_io_bytes(pending.tgid, pending.fd, pending.direction, retval as u64)?;
    if pending.secondary_direction != 0 {
        add_network_io_bytes(
            pending.tgid,
            pending.secondary_fd,
            pending.secondary_direction,
            retval as u64,
        )?;
    }
    Ok(0)
}

fn add_network_io_bytes(tgid: u32, fd: i32, direction: u32, bytes: u64) -> Result<(), i64> {
    let key = ConnectionKey { tgid, fd };
    let mut connection = match unsafe { ACTIVE_CONNECTIONS.get(&key) } {
        Some(value) => *value,
        None => return Ok(()),
    };
    if direction == NETWORK_IO_WRITE {
        connection.bytes_sent = connection.bytes_sent.saturating_add(bytes);
    } else if direction == NETWORK_IO_READ {
        connection.bytes_received = connection.bytes_received.saturating_add(bytes);
    }
    ACTIVE_CONNECTIONS
        .insert(&key, &connection, 0)
        .map_err(|err| err as i64)?;
    Ok(())
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

#[inline(always)]
fn http_context_propagation_enabled() -> bool {
    HTTP_CONTEXT_PROPAGATION_ENABLED.load() != 0
}

fn try_sockops_http_context_propagation(ctx: &SockOpsContext) -> u32 {
    if !http_context_propagation_enabled()
        || ctx.op() != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32
        || (ctx.family() != AF_INET && ctx.family() != AF_INET6)
    {
        return 0;
    }
    if !cgroup_capture_allowed(current_cgroup_id()) {
        record_capture_filter_drop();
        return 0;
    }
    // `bpf_sock_ops.remote_port` is a 32-bit network-order port. This is
    // equivalent to the kernel samples' `bpf_ntohl(remote_port)` conversion.
    let remote_port = u32::from_be(ctx.remote_port()) as u16;
    if unsafe { HTTP_PROPAGATION_PORTS.get(&remote_port) }.is_none() {
        return 0;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_SOCKET_TRACK_FAILED);
        return 0;
    }
    let mut key = cookie;
    let ops = unsafe { &mut *ctx.ops };
    if HTTP_PROPAGATION_SOCKETS.update(&mut key, ops, 0).is_ok() {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_SOCKET_TRACKED);
    } else {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_SOCKET_TRACK_FAILED);
    }
    0
}

fn try_sk_msg_http_context_propagation(ctx: &SkMsgContext) -> u32 {
    if !http_context_propagation_enabled() {
        return SK_PASS as u32;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = match PENDING_HTTP_PROPAGATIONS.get_ptr_mut(&pid_tgid) {
        Some(pending) => unsafe { &mut *pending },
        None => return SK_PASS as u32,
    };
    let size = ctx.size() as usize;
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pending_len = pending.request_len as usize;
    if size == 0
        || size != pending.request_total_len as usize
        || pending_len > HTTP_REQUEST_BYTES
        || data
            .checked_add(pending_len)
            .is_none_or(|end| end > data_end)
    {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_BYPASSED);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_MUTATION_MISMATCH);
        return SK_PASS as u32;
    }
    if !http_message_matches_capture(
        data as *const u8,
        data_end as *const u8,
        pending,
        pending_len,
    ) {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_BYPASSED);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_MUTATION_MISMATCH);
        return SK_PASS as u32;
    }
    let message_insert_at = pending.propagation.insert_at as usize;
    if message_insert_at > size {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_BYPASSED);
        return SK_PASS as u32;
    }
    let context = TraceContext {
        trace_id: pending.propagation.trace_id,
        span_id: pending.propagation.span_id,
        trace_flags: pending.propagation.trace_flags,
    };
    let header = format_traceparent_header(context);
    let tracestate_len = pending.propagation.tracestate_len as usize;
    if tracestate_len > MAX_TRACESTATE_BYTES {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_BYPASSED);
        return SK_PASS as u32;
    }
    let inserted_len = header.len()
        + if tracestate_len == 0 {
            0
        } else {
            TRACESTATE_HEADER_PREFIX.len() + tracestate_len + HEADER_LINE_END.len()
        };
    if ctx
        .push_data(message_insert_at as u32, inserted_len as u32, 0)
        .is_err()
    {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PUSH_FAILED);
        return SK_PASS as u32;
    }

    let inserted_end_offset = match message_insert_at.checked_add(inserted_len) {
        Some(end) => end,
        None => {
            finish_pending_http_propagation(ctx, pid_tgid, false);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
            return SK_DROP as u32;
        }
    };
    if unsafe {
        bpf_msg_pull_data(
            ctx.msg,
            message_insert_at as u32,
            inserted_end_offset as u32,
            0,
        )
    } != 0
    {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
        return SK_DROP as u32;
    }

    // `bpf_msg_push_data` invalidates direct packet pointers. Pull only the
    // inserted range into a linear span, then reload and prove every bound
    // before the first write. If the kernel cannot expose the pushed bytes,
    // dropping is the only safe way to avoid transmitting uninitialized data.
    // `bpf_msg_pull_data(start, end)` narrows the direct-access window so
    // `data` is the byte at `start`, not the beginning of the whole message.
    let data = ctx.data();
    let data_end = ctx.data_end();
    let header_start = data;
    let inserted_end = match header_start.checked_add(inserted_len) {
        Some(end) => end,
        None => {
            finish_pending_http_propagation(ctx, pid_tgid, false);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
            return SK_DROP as u32;
        }
    };
    let traceparent_end = match header_start.checked_add(header.len()) {
        Some(end) => end,
        None => {
            finish_pending_http_propagation(ctx, pid_tgid, false);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
            return SK_DROP as u32;
        }
    };
    if inserted_end > data_end || traceparent_end > data_end {
        finish_pending_http_propagation(ctx, pid_tgid, false);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
        return SK_DROP as u32;
    }
    let target = header_start as *mut [u8; 70];
    unsafe {
        *target = header;
    }
    if tracestate_len > 0 {
        let tracestate_header = traceparent_end as *mut u8;
        if unsafe { tracestate_header.add(TRACESTATE_HEADER_PREFIX.len()) } > data_end as *mut u8 {
            finish_pending_http_propagation(ctx, pid_tgid, false);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
            return SK_DROP as u32;
        }
        unsafe {
            *tracestate_header.cast::<[u8; 12]>() = TRACESTATE_HEADER_PREFIX;
        }
        let tracestate_target = unsafe { tracestate_header.add(TRACESTATE_HEADER_PREFIX.len()) };
        let tracestate_source = pending.propagation.tracestate.as_ptr();
        macro_rules! copy_tracestate_chunk {
            ($offset:expr) => {
                if tracestate_len >= $offset + 16 {
                    let chunk_target = unsafe { tracestate_target.add($offset) };
                    if unsafe { chunk_target.add(16) } > data_end as *mut u8 {
                        finish_pending_http_propagation(ctx, pid_tgid, false);
                        record_http_propagation_diagnostic(
                            HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED,
                        );
                        return SK_DROP as u32;
                    }
                    unsafe {
                        *chunk_target.cast::<[u8; 16]>() =
                            *tracestate_source.add($offset).cast::<[u8; 16]>();
                    }
                }
            };
        }
        copy_tracestate_chunk!(0);
        copy_tracestate_chunk!(16);
        copy_tracestate_chunk!(32);
        copy_tracestate_chunk!(48);
        copy_tracestate_chunk!(64);
        copy_tracestate_chunk!(80);
        copy_tracestate_chunk!(96);
        copy_tracestate_chunk!(112);
        copy_tracestate_chunk!(128);
        copy_tracestate_chunk!(144);
        copy_tracestate_chunk!(160);
        copy_tracestate_chunk!(176);
        copy_tracestate_chunk!(192);
        copy_tracestate_chunk!(208);
        copy_tracestate_chunk!(224);
        copy_tracestate_chunk!(240);
        copy_tracestate_chunk!(256);
        copy_tracestate_chunk!(272);
        copy_tracestate_chunk!(288);
        copy_tracestate_chunk!(304);
        copy_tracestate_chunk!(320);
        copy_tracestate_chunk!(336);
        copy_tracestate_chunk!(352);
        copy_tracestate_chunk!(368);
        copy_tracestate_chunk!(384);
        copy_tracestate_chunk!(400);
        copy_tracestate_chunk!(416);
        copy_tracestate_chunk!(432);
        copy_tracestate_chunk!(448);
        copy_tracestate_chunk!(464);
        copy_tracestate_chunk!(480);
        copy_tracestate_chunk!(496);

        let tail_len = tracestate_len & 15;
        let tail_start = tracestate_len - tail_len;
        macro_rules! copy_tracestate_tail_byte {
            ($offset:expr) => {
                if tail_len > $offset {
                    let tail_target = unsafe { tracestate_target.add(tail_start + $offset) };
                    if unsafe { tail_target.add(1) } > data_end as *mut u8 {
                        finish_pending_http_propagation(ctx, pid_tgid, false);
                        record_http_propagation_diagnostic(
                            HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED,
                        );
                        return SK_DROP as u32;
                    }
                    unsafe {
                        *tail_target = *tracestate_source.add(tail_start + $offset);
                    }
                }
            };
        }
        copy_tracestate_tail_byte!(0);
        copy_tracestate_tail_byte!(1);
        copy_tracestate_tail_byte!(2);
        copy_tracestate_tail_byte!(3);
        copy_tracestate_tail_byte!(4);
        copy_tracestate_tail_byte!(5);
        copy_tracestate_tail_byte!(6);
        copy_tracestate_tail_byte!(7);
        copy_tracestate_tail_byte!(8);
        copy_tracestate_tail_byte!(9);
        copy_tracestate_tail_byte!(10);
        copy_tracestate_tail_byte!(11);
        copy_tracestate_tail_byte!(12);
        copy_tracestate_tail_byte!(13);
        copy_tracestate_tail_byte!(14);
        let line_end = unsafe { tracestate_target.add(tracestate_len) };
        if unsafe { line_end.add(HEADER_LINE_END.len()) } > data_end as *mut u8 {
            finish_pending_http_propagation(ctx, pid_tgid, false);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_POST_PUSH_BOUNDS_FAILED);
            return SK_DROP as u32;
        }
        unsafe {
            *line_end.cast::<[u8; 2]>() = HEADER_LINE_END;
        }
    }
    finish_pending_http_propagation(ctx, pid_tgid, true);
    record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_INJECTED);
    SK_PASS as u32
}

#[inline(always)]
fn http_message_matches_capture(
    message: *const u8,
    message_end: *const u8,
    pending: &RawHttpRequestEvent,
    len: usize,
) -> bool {
    if len > HTTP_REQUEST_BYTES {
        return false;
    }
    let captured = pending.request.as_ptr();
    let mut index = 0_usize;
    while index < HTTP_REQUEST_BYTES {
        if index >= len {
            break;
        }
        let message_byte = unsafe { message.add(index) };
        if unsafe { message_byte.add(1) } > message_end {
            return false;
        }
        if unsafe { *message_byte != *captured.add(index) } {
            return false;
        }
        index += 1;
    }
    true
}

fn prepare_http_context_propagation(event: &mut RawHttpRequestEvent) -> bool {
    if !http_context_propagation_enabled() {
        return false;
    }
    if event.propagation.reserved == HTTP_PROPAGATION_CAPTURE_UNSUPPORTED_IOVEC {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PLANNING_INELIGIBLE);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_UNSUPPORTED_IOVEC);
        return false;
    }
    if event.request_len == 0
        || event.request_total_len < event.request_len
        || event.request_len as usize > HTTP_REQUEST_BYTES
    {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PLANNING_INELIGIBLE);
        return false;
    }
    let insert_at = match plan_bpf_http1_propagation_loop(event) {
        Some(insert_at) => insert_at,
        None => {
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_BYPASSED);
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PLANNER_REJECTED);
            return false;
        }
    };
    let seed = match HTTP_PROPAGATION_CONTEXTS.pop() {
        Ok(Some(seed)) => seed,
        _ => {
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_CONTEXT_POOL_EMPTY);
            return false;
        }
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let now = unsafe { bpf_ktime_get_ns() };
    let mut context = seed;
    let mut parent_span_id = [0_u8; 8];
    if let Some(current) = unsafe { HTTP_THREAD_TRACE_CONTEXTS.get(&pid_tgid) } {
        let ttl = HTTP_CONTEXT_PROPAGATION_TTL_NANOS.load();
        if now.saturating_sub(current.started_at_nanos) <= ttl {
            context.trace_id = current.trace_id;
            context.trace_flags = current.trace_flags;
            parent_span_id = current.span_id;
            copy_raw_tracestate(current, &mut event.propagation);
        } else {
            let _ = HTTP_THREAD_TRACE_CONTEXTS.remove(&pid_tgid);
        }
    }
    event.propagation.state = HTTP_PROPAGATION_GENERATED;
    event.propagation.trace_id = context.trace_id;
    event.propagation.span_id = context.span_id;
    event.propagation.parent_span_id = parent_span_id;
    event.propagation.trace_flags = context.trace_flags;
    event.propagation.insert_at = insert_at;
    if PENDING_HTTP_PROPAGATIONS
        .insert(&pid_tgid, &*event, BPF_NOEXIST as u64)
        .is_err()
    {
        clear_raw_http_propagation_context(&mut event.propagation);
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PENDING_CONTENDED);
        return false;
    }
    record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_PLANNED);
    true
}

#[repr(C)]
struct BpfHttpRequestLineState {
    request: *const u8,
    len: u32,
    component_len: u32,
    insert_at: u16,
    phase: u8,
    result: u8,
    method_connect: bool,
    method_pri: bool,
}

#[repr(C)]
struct BpfHttpIovecLengthState {
    iov: *const u8,
    iov_len: u64,
    total_len: u64,
    valid: bool,
}

#[repr(C)]
struct BpfInboundHeaderState {
    request: *const u8,
    len: u32,
    start: u32,
    component_len: u32,
    value_len: u16,
    value_significant_len: u16,
    value_start: u16,
    traceparent_at: u16,
    phase: u8,
    result: u8,
    ending_headers: bool,
    traceparent_name: bool,
    capture_traceparent: bool,
    value_started: bool,
    saw_traceparent: bool,
    traceparent_invalid: bool,
}

#[repr(C)]
struct BpfTraceparentValueState {
    request: *const u8,
    len: u32,
    start: u32,
    traceparent_high_nibble: u8,
    trace_flags: u8,
    result: u8,
    trace_id: [u8; 16],
    span_id: [u8; 8],
}

#[repr(C)]
struct BpfInboundTracestateState {
    request: *const u8,
    tracestate: *mut u8,
    header_hash: u64,
    len: u32,
    start: u32,
    component_len: u32,
    tracestate_len: u16,
    trailing_ows: u16,
    phase: u8,
    result: u8,
    ending_headers: bool,
    capture_tracestate: bool,
    value_started: bool,
    saw_tracestate: bool,
    invalid: bool,
}

#[repr(C)]
struct BpfTracestateValidationState {
    value: *const u8,
    key_hash: u64,
    seen_hash_bits_low: u64,
    seen_hash_bits_high: u64,
    len: u32,
    key_len: u16,
    value_len: u16,
    value_significant_len: u16,
    system_len: u8,
    member_count: u8,
    phase: u8,
    result: u8,
    first_key_byte_lowercase: bool,
    first_key_byte_digit: bool,
    saw_at: bool,
    value_has_non_space: bool,
}

#[inline(never)]
fn bpf_http1_request_line(event: &RawHttpRequestEvent) -> Option<u16> {
    let mut state = BpfHttpRequestLineState {
        request: event.request.as_ptr(),
        len: event.request_len,
        component_len: 0,
        insert_at: 0,
        phase: HTTP_PARSE_METHOD,
        result: HTTP_PLAN_PENDING,
        method_connect: true,
        method_pri: true,
    };
    let callback = bpf_http_request_line_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfHttpRequestLineState).cast::<c_void>();
    let loops = unsafe { bpf_loop(event.request_len, callback, context, 0) };
    if loops < 0 || state.result != HTTP_PLAN_VALID {
        return None;
    }
    Some(state.insert_at)
}

unsafe extern "C" fn bpf_http_request_line_step(index: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfHttpRequestLineState>() };
    if index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    let byte = unsafe { *state.request.add(index as usize) };
    let phase = state.phase & 3;
    if phase == HTTP_PARSE_METHOD {
        if byte == b' ' {
            if state.component_len == 0
                || (state.component_len == 7 && state.method_connect)
                || (state.component_len == 3 && state.method_pri)
            {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_PARSE_TARGET;
            state.component_len = 0;
        } else {
            if state.component_len >= 16 || !(byte.is_ascii_uppercase() || byte == b'-') {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.method_connect = state.method_connect
                && byte == bpf_http_method_byte(state.component_len, true).unwrap_or(0);
            state.method_pri = state.method_pri
                && byte == bpf_http_method_byte(state.component_len, false).unwrap_or(0);
            state.component_len += 1;
        }
    } else if phase == HTTP_PARSE_TARGET {
        if byte == b' ' {
            if state.component_len == 0 {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_PARSE_VERSION;
            state.component_len = 0;
        } else {
            if !(0x21..=0x7e).contains(&byte) {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.component_len = state.component_len.saturating_add(1);
        }
    } else if phase == HTTP_PARSE_VERSION {
        if byte == b'\r' {
            if state.component_len != 8 {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_PARSE_REQUEST_LF;
        } else {
            let matches = if state.component_len == 7 {
                byte == b'0' || byte == b'1'
            } else {
                byte == bpf_http_version_byte(state.component_len)
            };
            if !matches {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.component_len += 1;
        }
    } else if phase == HTTP_PARSE_REQUEST_LF {
        if byte != b'\n' || index + 1 > u64::from(u16::MAX) {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        state.insert_at = (index + 1) as u16;
        state.result = HTTP_PLAN_VALID;
        return 1;
    } else {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    0
}

#[inline(always)]
fn bpf_http_method_byte(index: u32, connect: bool) -> Option<u8> {
    if connect {
        match index {
            0 => Some(b'C'),
            1 => Some(b'O'),
            2 => Some(b'N'),
            3 => Some(b'N'),
            4 => Some(b'E'),
            5 => Some(b'C'),
            6 => Some(b'T'),
            _ => None,
        }
    } else {
        match index {
            0 => Some(b'P'),
            1 => Some(b'R'),
            2 => Some(b'I'),
            _ => None,
        }
    }
}

#[inline(always)]
fn bpf_http_version_byte(index: u32) -> u8 {
    match index {
        0 => b'H',
        1 | 2 => b'T',
        3 => b'P',
        4 => b'/',
        5 => b'1',
        6 => b'.',
        7 => b'0',
        _ => 0,
    }
}

#[inline(always)]
fn bpf_content_length_name_byte(index: u32) -> u8 {
    match index {
        0 => b'c',
        1 => b'o',
        2 => b'n',
        3 => b't',
        4 => b'e',
        5 => b'n',
        6 => b't',
        7 => b'-',
        8 => b'l',
        9 => b'e',
        10 => b'n',
        11 => b'g',
        12 => b't',
        13 => b'h',
        _ => 0,
    }
}

#[inline(always)]
fn bpf_transfer_encoding_value_byte(index: u32) -> u8 {
    match index {
        0 => b'c',
        1 => b'h',
        2 => b'u',
        3 => b'n',
        4 => b'k',
        5 => b'e',
        6 => b'd',
        _ => 0,
    }
}

#[inline(always)]
fn bpf_transfer_encoding_name_byte(index: u32) -> u8 {
    match index {
        0 => b't',
        1 => b'r',
        2 => b'a',
        3 => b'n',
        4 => b's',
        5 => b'f',
        6 => b'e',
        7 => b'r',
        8 => b'-',
        9 => b'e',
        10 => b'n',
        11 => b'c',
        12 => b'o',
        13 => b'd',
        14 => b'i',
        15 => b'n',
        16 => b'g',
        _ => 0,
    }
}

#[inline(always)]
fn bpf_http_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline(always)]
fn bpf_traceparent_name_byte(index: u32) -> Option<u8> {
    match index {
        0 => Some(b't'),
        1 => Some(b'r'),
        2 => Some(b'a'),
        3 => Some(b'c'),
        4 => Some(b'e'),
        5 => Some(b'p'),
        6 => Some(b'a'),
        7 => Some(b'r'),
        8 => Some(b'e'),
        9 => Some(b'n'),
        10 => Some(b't'),
        _ => None,
    }
}

#[inline(always)]
fn bpf_http_header_requires_bypass(len: u32, hash: u64) -> bool {
    (len == 11 && hash == HTTP_TRACEPARENT_HASH)
        || (len == 10 && hash == HTTP_TRACESTATE_HASH)
        || (len == 7 && hash == HTTP_UPGRADE_HASH)
}

#[inline(always)]
fn bpf_http_field_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[inline(always)]
fn bpf_http_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || byte >= 0x20 && byte != 0x7f
}

#[inline(never)]
fn extract_bpf_inbound_http_context(event: &mut RawHttpRequestEvent) -> Option<TraceContext> {
    let insert_at = bpf_http1_request_line(event)?;
    let start = u32::from(insert_at);
    if start >= event.request_len {
        return None;
    }
    event.propagation.tracestate_len = 0;
    let mut state = BpfInboundHeaderState {
        request: event.request.as_ptr(),
        len: event.request_len,
        start,
        component_len: 0,
        value_len: 0,
        value_significant_len: 0,
        value_start: 0,
        traceparent_at: 0,
        phase: HTTP_PARSE_HEADER_NAME,
        result: HTTP_PLAN_PENDING,
        ending_headers: false,
        traceparent_name: true,
        capture_traceparent: false,
        value_started: false,
        saw_traceparent: false,
        traceparent_invalid: false,
    };
    let callback = bpf_inbound_http_header_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfInboundHeaderState).cast::<c_void>();
    let remaining = event.request_len - start;
    let loops = unsafe { bpf_loop(remaining, callback, context, 0) };
    if loops < 0
        || state.result != HTTP_PLAN_VALID
        || !state.saw_traceparent
        || state.traceparent_invalid
    {
        return None;
    }
    let remote_parent = bpf_parse_traceparent_value(event, state.traceparent_at)?;
    let tracestate_len = bpf_copy_inbound_tracestate(event, insert_at);
    if tracestate_len > 0
        && bpf_validate_tracestate(event.propagation.tracestate.as_ptr(), tracestate_len)
    {
        event.propagation.tracestate_len = tracestate_len;
    }
    Some(remote_parent)
}

unsafe extern "C" fn bpf_inbound_http_header_step(relative: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfInboundHeaderState>() };
    let index = u64::from(state.start) + relative;
    if index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        return bpf_inbound_header_invalid(state);
    }
    let byte = unsafe { *state.request.add(index as usize) };
    let phase = state.phase & 7;
    if phase == HTTP_PARSE_HEADER_NAME {
        if byte == b'\r' {
            if state.component_len != 0 {
                return bpf_inbound_header_invalid(state);
            }
            state.ending_headers = true;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else if byte == b':' {
            if state.component_len == 0 {
                return bpf_inbound_header_invalid(state);
            }
            state.capture_traceparent = state.component_len == 11 && state.traceparent_name;
            if state.capture_traceparent && state.saw_traceparent {
                state.traceparent_invalid = true;
            }
            state.phase = HTTP_PARSE_HEADER_VALUE;
            state.value_started = false;
            state.value_len = 0;
            state.value_significant_len = 0;
        } else {
            if !bpf_http_field_name_byte(byte) {
                return bpf_inbound_header_invalid(state);
            }
            state.traceparent_name = state.traceparent_name
                && byte.to_ascii_lowercase()
                    == bpf_traceparent_name_byte(state.component_len).unwrap_or(0);
            state.component_len += 1;
        }
    } else if phase == HTTP_PARSE_HEADER_VALUE {
        if byte == b'\r' {
            if state.capture_traceparent {
                if !state.value_started || state.value_significant_len != 55 {
                    state.traceparent_invalid = true;
                }
                state.traceparent_at = state.value_start;
                state.saw_traceparent = true;
            }
            state.ending_headers = false;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else {
            if !bpf_http_field_value_byte(byte) {
                return bpf_inbound_header_invalid(state);
            }
            if state.capture_traceparent {
                let ows = byte == b' ' || byte == b'\t';
                if !state.value_started && ows {
                    return 0;
                }
                if !state.value_started {
                    state.value_started = true;
                    state.value_start = index as u16;
                }
                state.value_len = state.value_len.saturating_add(1);
                if !ows {
                    state.value_significant_len = state.value_len;
                }
            }
        }
    } else if phase == HTTP_PARSE_HEADER_LF {
        if byte != b'\n' {
            return bpf_inbound_header_invalid(state);
        }
        if state.ending_headers {
            state.result = HTTP_PLAN_VALID;
            return 1;
        }
        state.phase = HTTP_PARSE_HEADER_NAME;
        state.component_len = 0;
        state.traceparent_name = true;
        state.capture_traceparent = false;
    } else {
        return bpf_inbound_header_invalid(state);
    }
    0
}

#[inline(never)]
fn bpf_parse_traceparent_value(event: &RawHttpRequestEvent, start: u16) -> Option<TraceContext> {
    let mut state = BpfTraceparentValueState {
        request: event.request.as_ptr(),
        len: event.request_len,
        start: u32::from(start),
        traceparent_high_nibble: 0,
        trace_flags: 0,
        result: HTTP_PLAN_PENDING,
        trace_id: [0; 16],
        span_id: [0; 8],
    };
    let callback = bpf_traceparent_value_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfTraceparentValueState).cast::<c_void>();
    let loops = unsafe { bpf_loop(55, callback, context, 0) };
    if loops < 0
        || state.result != HTTP_PLAN_VALID
        || !bpf_nonzero_trace_id(&state.trace_id)
        || !bpf_nonzero_span_id(&state.span_id)
    {
        return None;
    }
    Some(TraceContext {
        trace_id: state.trace_id,
        span_id: state.span_id,
        trace_flags: state.trace_flags,
    })
}

unsafe extern "C" fn bpf_traceparent_value_step(position: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfTraceparentValueState>() };
    let index = u64::from(state.start) + position;
    if position >= 55 || index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    let byte = unsafe { *state.request.add(index as usize) };
    if position == 0 || position == 1 {
        if byte != b'0' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else if position == 2 || position == 35 || position == 52 {
        if byte != b'-' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else {
        let nibble = bpf_hex_nibble(byte);
        if nibble > 0x0f {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        } else if (3..35).contains(&position) {
            let digit = ((position - 3) & 31) as u8;
            if digit & 1 == 0 {
                state.traceparent_high_nibble = nibble;
            } else {
                let target = usize::from(digit >> 1);
                unsafe {
                    *state.trace_id.as_mut_ptr().add(target) =
                        state.traceparent_high_nibble << 4 | nibble;
                }
            }
        } else if (36..52).contains(&position) {
            let digit = ((position - 36) & 15) as u8;
            if digit & 1 == 0 {
                state.traceparent_high_nibble = nibble;
            } else {
                let target = usize::from(digit >> 1);
                unsafe {
                    *state.span_id.as_mut_ptr().add(target) =
                        state.traceparent_high_nibble << 4 | nibble;
                }
            }
        } else if position == 53 {
            state.traceparent_high_nibble = nibble;
        } else if position == 54 {
            state.trace_flags = state.traceparent_high_nibble << 4 | nibble;
        } else {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    }
    if position == 54 {
        state.result = HTTP_PLAN_VALID;
        return 1;
    }
    0
}

#[inline(never)]
fn bpf_copy_inbound_tracestate(event: &mut RawHttpRequestEvent, insert_at: u16) -> u16 {
    let start = u32::from(insert_at);
    let mut state = BpfInboundTracestateState {
        request: event.request.as_ptr(),
        tracestate: event.propagation.tracestate.as_mut_ptr(),
        header_hash: HTTP_FNV_OFFSET,
        len: event.request_len,
        start,
        component_len: 0,
        tracestate_len: 0,
        trailing_ows: 0,
        phase: HTTP_PARSE_HEADER_NAME,
        result: HTTP_PLAN_PENDING,
        ending_headers: false,
        capture_tracestate: false,
        value_started: false,
        saw_tracestate: false,
        invalid: false,
    };
    let callback = bpf_inbound_tracestate_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfInboundTracestateState).cast::<c_void>();
    let remaining = event.request_len - start;
    let loops = unsafe { bpf_loop(remaining, callback, context, 0) };
    if loops < 0 || state.result != HTTP_PLAN_VALID || !state.saw_tracestate || state.invalid {
        return 0;
    }
    state.tracestate_len
}

unsafe extern "C" fn bpf_inbound_tracestate_step(relative: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfInboundTracestateState>() };
    let index = u64::from(state.start) + relative;
    if index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        return bpf_inbound_tracestate_invalid(state);
    }
    let byte = unsafe { *state.request.add(index as usize) };
    let phase = state.phase & 7;
    if phase == HTTP_PARSE_HEADER_NAME {
        if byte == b'\r' {
            if state.component_len != 0 {
                return bpf_inbound_tracestate_invalid(state);
            }
            state.ending_headers = true;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else if byte == b':' {
            if state.component_len == 0 {
                return bpf_inbound_tracestate_invalid(state);
            }
            state.capture_tracestate =
                state.component_len == 10 && state.header_hash == HTTP_TRACESTATE_HASH;
            state.phase = HTTP_PARSE_HEADER_VALUE;
            state.value_started = false;
            state.trailing_ows = 0;
        } else {
            if !bpf_http_field_name_byte(byte) {
                return bpf_inbound_tracestate_invalid(state);
            }
            let lowercase = byte.to_ascii_lowercase();
            state.header_hash =
                (state.header_hash ^ u64::from(lowercase)).wrapping_mul(HTTP_FNV_PRIME);
            state.component_len += 1;
        }
    } else if phase == HTTP_PARSE_HEADER_VALUE {
        if byte == b'\r' {
            if state.capture_tracestate {
                if !state.value_started {
                    state.invalid = true;
                } else {
                    state.tracestate_len = state.tracestate_len.saturating_sub(state.trailing_ows);
                    state.saw_tracestate = true;
                }
            }
            state.ending_headers = false;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else {
            if !bpf_http_field_value_byte(byte) {
                return bpf_inbound_tracestate_invalid(state);
            }
            if state.capture_tracestate {
                bpf_capture_tracestate_byte(state, byte);
            }
        }
    } else if phase == HTTP_PARSE_HEADER_LF {
        if byte != b'\n' {
            return bpf_inbound_tracestate_invalid(state);
        }
        if state.ending_headers {
            state.result = HTTP_PLAN_VALID;
            return 1;
        }
        state.phase = HTTP_PARSE_HEADER_NAME;
        state.component_len = 0;
        state.header_hash = HTTP_FNV_OFFSET;
        state.capture_tracestate = false;
    } else {
        return bpf_inbound_tracestate_invalid(state);
    }
    0
}

#[inline(always)]
fn bpf_capture_tracestate_byte(state: &mut BpfInboundTracestateState, byte: u8) {
    let ows = byte == b' ' || byte == b'\t';
    if !state.value_started && ows {
        return;
    }
    if !state.value_started {
        if state.saw_tracestate {
            if state.tracestate_len as usize >= MAX_TRACESTATE_BYTES {
                state.invalid = true;
                return;
            }
            unsafe {
                *state.tracestate.add(state.tracestate_len as usize) = b',';
            }
            state.tracestate_len += 1;
        }
        state.value_started = true;
    }
    if state.tracestate_len as usize >= MAX_TRACESTATE_BYTES {
        state.invalid = true;
        return;
    }
    unsafe {
        *state.tracestate.add(state.tracestate_len as usize) = byte;
    }
    state.tracestate_len += 1;
    if ows {
        state.trailing_ows = state.trailing_ows.saturating_add(1);
    } else {
        state.trailing_ows = 0;
    }
}

#[inline(always)]
fn bpf_inbound_tracestate_invalid(state: &mut BpfInboundTracestateState) -> i64 {
    state.result = HTTP_PLAN_INVALID;
    1
}

#[inline(always)]
fn bpf_inbound_header_invalid(state: &mut BpfInboundHeaderState) -> i64 {
    state.result = HTTP_PLAN_INVALID;
    1
}

#[inline(always)]
fn bpf_hex_nibble(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else if (b'a'..=b'f').contains(&byte) {
        byte - b'a' + 10
    } else {
        0xff
    }
}

#[inline(always)]
fn bpf_nonzero_trace_id(id: &[u8; 16]) -> bool {
    id[0]
        | id[1]
        | id[2]
        | id[3]
        | id[4]
        | id[5]
        | id[6]
        | id[7]
        | id[8]
        | id[9]
        | id[10]
        | id[11]
        | id[12]
        | id[13]
        | id[14]
        | id[15]
        != 0
}

#[inline(always)]
fn bpf_nonzero_span_id(id: &[u8; 8]) -> bool {
    id[0] | id[1] | id[2] | id[3] | id[4] | id[5] | id[6] | id[7] != 0
}

#[inline(never)]
fn bpf_validate_tracestate(value: *const u8, len: u16) -> bool {
    if len == 0 || len as usize > MAX_TRACESTATE_BYTES {
        return false;
    }
    let mut state = BpfTracestateValidationState {
        value,
        key_hash: HTTP_FNV_OFFSET,
        seen_hash_bits_low: 0,
        seen_hash_bits_high: 0,
        len: u32::from(len),
        key_len: 0,
        value_len: 0,
        value_significant_len: 0,
        system_len: 0,
        member_count: 0,
        phase: TRACESTATE_PARSE_START,
        result: HTTP_PLAN_PENDING,
        first_key_byte_lowercase: false,
        first_key_byte_digit: false,
        saw_at: false,
        value_has_non_space: false,
    };
    let callback = bpf_tracestate_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfTracestateValidationState).cast::<c_void>();
    let loops = unsafe { bpf_loop(u32::from(len), callback, context, 0) };
    loops >= 0 && state.result == HTTP_PLAN_VALID
}

unsafe extern "C" fn bpf_tracestate_step(index: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfTracestateValidationState>() };
    if index >= u64::from(state.len) || index >= MAX_TRACESTATE_BYTES as u64 {
        return bpf_tracestate_invalid(state);
    }
    let byte = unsafe { *state.value.add(index as usize) };
    let mut phase = state.phase & 3;
    if phase == TRACESTATE_PARSE_START {
        if byte == b' ' || byte == b'\t' {
            if index + 1 == u64::from(state.len) {
                return bpf_tracestate_invalid(state);
            }
            return 0;
        }
        if byte == b',' {
            return bpf_tracestate_invalid(state);
        }
        state.key_hash = HTTP_FNV_OFFSET;
        state.key_len = 0;
        state.system_len = 0;
        state.first_key_byte_lowercase = false;
        state.first_key_byte_digit = false;
        state.saw_at = false;
        phase = TRACESTATE_PARSE_KEY;
    }
    if phase == TRACESTATE_PARSE_KEY {
        if byte == b'=' {
            if !bpf_finish_tracestate_key(state) {
                return bpf_tracestate_invalid(state);
            }
            state.value_len = 0;
            state.value_significant_len = 0;
            state.value_has_non_space = false;
            state.phase = TRACESTATE_PARSE_VALUE;
        } else {
            if !bpf_capture_tracestate_key_byte(state, byte) {
                return bpf_tracestate_invalid(state);
            }
            state.phase = TRACESTATE_PARSE_KEY;
        }
    } else if phase == TRACESTATE_PARSE_VALUE {
        if byte == b',' {
            if !bpf_finish_tracestate_value(state) || index + 1 == u64::from(state.len) {
                return bpf_tracestate_invalid(state);
            }
            state.phase = TRACESTATE_PARSE_START;
        } else {
            if !(0x20..=0x7e).contains(&byte) || byte == b'=' {
                return bpf_tracestate_invalid(state);
            }
            state.value_len = state.value_len.saturating_add(1);
            if byte != b' ' {
                state.value_significant_len = state.value_len;
                state.value_has_non_space = true;
            }
        }
    }
    if index + 1 == u64::from(state.len) {
        if state.phase != TRACESTATE_PARSE_VALUE || !bpf_finish_tracestate_value(state) {
            return bpf_tracestate_invalid(state);
        }
        state.result = HTTP_PLAN_VALID;
        return 1;
    }
    0
}

#[inline(always)]
fn bpf_capture_tracestate_key_byte(state: &mut BpfTracestateValidationState, byte: u8) -> bool {
    if byte == b'@' {
        if state.saw_at
            || state.key_len == 0
            || state.key_len > 241
            || !(state.first_key_byte_lowercase || state.first_key_byte_digit)
        {
            return false;
        }
        state.saw_at = true;
        state.system_len = 0;
    } else {
        if !bpf_tracestate_key_byte(byte) {
            return false;
        }
        if state.key_len == 0 {
            state.first_key_byte_lowercase = byte.is_ascii_lowercase();
            state.first_key_byte_digit = byte.is_ascii_digit();
        }
        if state.saw_at {
            if state.system_len == 0 && !byte.is_ascii_lowercase() {
                return false;
            }
            state.system_len = state.system_len.saturating_add(1);
            if state.system_len > 14 {
                return false;
            }
        }
    }
    state.key_len = state.key_len.saturating_add(1);
    if state.key_len > 256 {
        return false;
    }
    state.key_hash = (state.key_hash ^ u64::from(byte)).wrapping_mul(HTTP_FNV_PRIME);
    true
}

#[inline(always)]
fn bpf_finish_tracestate_key(state: &mut BpfTracestateValidationState) -> bool {
    if state.key_len == 0
        || (!state.saw_at && !state.first_key_byte_lowercase)
        || (state.saw_at && state.system_len == 0)
        || state.member_count >= 32
    {
        return false;
    }
    let low_bit = 1_u64 << (state.key_hash & 63);
    let high_bit = 1_u64 << ((state.key_hash >> 32) & 63);
    if state.seen_hash_bits_low & low_bit != 0 && state.seen_hash_bits_high & high_bit != 0 {
        return false;
    }
    state.seen_hash_bits_low |= low_bit;
    state.seen_hash_bits_high |= high_bit;
    state.member_count += 1;
    true
}

#[inline(always)]
fn bpf_finish_tracestate_value(state: &BpfTracestateValidationState) -> bool {
    state.value_has_non_space
        && state.value_significant_len > 0
        && state.value_significant_len <= 256
}

#[inline(always)]
fn bpf_tracestate_key_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'*' | b'/')
}

#[inline(always)]
fn bpf_tracestate_invalid(state: &mut BpfTracestateValidationState) -> i64 {
    state.result = HTTP_PLAN_INVALID;
    1
}

fn activate_inbound_http_context(event: &mut RawHttpRequestEvent) {
    if !http_context_propagation_enabled()
        || event.request_len == 0
        || event.request_len != event.request_total_len
        || event.request_len as usize > HTTP_REQUEST_BYTES
    {
        return;
    }
    let Some(remote_parent) = extract_bpf_inbound_http_context(event) else {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_INBOUND_REJECTED);
        return;
    };
    let seed = match HTTP_PROPAGATION_CONTEXTS.pop() {
        Ok(Some(seed)) => seed,
        _ => {
            record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_CONTEXT_POOL_EMPTY);
            return;
        }
    };
    let server_context = TraceContext {
        trace_id: remote_parent.trace_id,
        span_id: seed.span_id,
        trace_flags: remote_parent.trace_flags,
    };
    let now = unsafe { bpf_ktime_get_ns() };
    event.propagation.state = HTTP_PROPAGATION_GENERATED;
    event.propagation.trace_id = server_context.trace_id;
    event.propagation.span_id = server_context.span_id;
    event.propagation.parent_span_id = remote_parent.span_id;
    event.propagation.trace_flags = server_context.trace_flags;
    event.propagation.started_at_nanos = now;
    let pid_tgid = bpf_get_current_pid_tgid();
    if HTTP_THREAD_TRACE_CONTEXTS
        .insert(&pid_tgid, &event.propagation, 0)
        .is_err()
    {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_THREAD_CONTEXT_FAILED);
    } else {
        record_http_propagation_diagnostic(HTTP_PROPAGATION_DIAG_INBOUND_ACTIVATED);
    }
}

fn clear_current_http_thread_context() {
    if http_context_propagation_enabled() {
        let _ = HTTP_THREAD_TRACE_CONTEXTS.remove(&bpf_get_current_pid_tgid());
    }
}

fn finish_pending_http_propagation<C: EbpfContext>(ctx: &C, pid_tgid: u64, injected: bool) {
    if let Some(pending) = PENDING_HTTP_PROPAGATIONS.get_ptr_mut(&pid_tgid) {
        let pending = unsafe { &mut *pending };
        if !injected {
            clear_raw_http_propagation_context(&mut pending.propagation);
        }
        output_http_request_event(ctx, pending);
    }
    let _ = PENDING_HTTP_PROPAGATIONS.remove(&pid_tgid);
}

fn flush_pending_http_propagation(ctx: &TracePointContext) -> u32 {
    if http_context_propagation_enabled() {
        finish_pending_http_propagation(ctx, bpf_get_current_pid_tgid(), false);
    }
    0
}

#[inline(always)]
fn record_http_propagation_diagnostic(stage: u32) {
    if let Some(counter) = HTTP_PROPAGATION_DIAGNOSTIC_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
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
        clear_current_http_thread_context();
        record_http_diagnostic(HTTP_DIAG_SERVER_WRITE_SUPPRESSED);
        return Ok(0);
    }
    if !http_connection_payload_captures(&key, buffer)? {
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
    if prepare_http_context_propagation(event) {
        return Ok(0);
    }
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
        clear_current_http_thread_context();
        record_http_diagnostic(HTTP_DIAG_SERVER_WRITE_SUPPRESSED);
        return Ok(0);
    }
    // Classify from the first non-empty iovec slot; an empty or unreadable
    // first slot leaves the connection unclassified rather than misjudging it.
    let (first_buffer, first_len) = read_protocol_iovec(iov, 0)?;
    if first_len > 0
        && !first_buffer.is_null()
        && !http_connection_payload_captures(&key, first_buffer)?
    {
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
    if compact_http_request_iovecs_for_propagation(event) && prepare_http_context_propagation(event)
    {
        return Ok(0);
    }
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
        http_state: HTTP_CONN_UNKNOWN,
        reserved: 0,
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
    if !http_connection_payload_captures(&key, buffer)? {
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
    activate_inbound_http_context(event);
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
    state.emit_slot = 0;
    state.emit_offset = 0;
    state.emit_emitted = 0;
    state.emit_done = 0;
    unsafe {
        PROTOCOL_IOVEC_PROGS.tail_call(ctx, 1);
    }
    record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
    Ok(0)
}

#[inline(always)]
fn try_tracepoint_protocol_iovec_emit(ctx: &TracePointContext) -> Result<u32, i64> {
    let state_ptr = PROTOCOL_IOVEC_STATE.get_ptr_mut(0).ok_or(1_i64)?;
    let state = unsafe { &mut *state_ptr };
    let event_ptr = PROTOCOL_DATA_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    let event = unsafe { &mut *event_ptr };
    let iov = state.iov_ptr as *const u8;
    let iov_len = state.iov_len;
    let captured_total = event.payload_captured_len;

    // Emit one segment per complete iovec prefix. All segments share the
    // syscall timestamp and totals, so userspace can join only adjacent
    // offsets and turn any missing event or bounded tail into a gap.
    //
    // The loop runs at most `PROTOCOL_IOVEC_EMIT_CHUNK` slots per tail-call
    // round and re-chains through `PROTOCOL_IOVEC_PROGS` slot 1 with the
    // cursor kept in `PROTOCOL_IOVEC_STATE`; emitting every slot in one
    // program exceeds the verifier instruction budget on arm64 kernels.
    let mut processed = 0_u32;
    while processed < PROTOCOL_IOVEC_EMIT_CHUNK {
        processed += 1;
        let slot = state.emit_slot;
        let offset = state.emit_offset;
        if slot >= PROTOCOL_MAX_IOVECS || u64::from(slot) >= iov_len || offset >= captured_total {
            state.emit_done = 1;
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
                state.emit_slot = slot.saturating_add(1);
                continue;
            }
            state.emit_done = 1;
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
        output_event!(PROTOCOL_DATA_EVENTS, TRANSPORT_LOSS_PROTOCOL, ctx, &*event);
        state.emit_emitted = 1;
        state.emit_offset = offset.saturating_add(captured);
        if u64::from(captured) != slot_len {
            state.emit_done = 1;
            break;
        }
        state.emit_slot = slot.saturating_add(1);
    }
    if state.emit_done == 0
        && state.emit_slot < PROTOCOL_MAX_IOVECS
        && u64::from(state.emit_slot) < iov_len
        && state.emit_offset < captured_total
    {
        unsafe {
            PROTOCOL_IOVEC_PROGS.tail_call(ctx, 1);
        }
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    if state.emit_emitted == 0 {
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
    let capture_all = PROTOCOL_CAPTURE_ALL.get(0).copied().unwrap_or(0) == 1;
    if (unresolved_inbound && !inbound_enabled)
        || (!unresolved_inbound
            && !capture_all
            && unsafe { PROTOCOL_CAPTURE_PORTS.get(&capture_port) }.is_none())
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
    event.connection_started_at_nanos = connection.started_at_nanos;
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
        output_event!(PROTOCOL_DATA_EVENTS, TRANSPORT_LOSS_PROTOCOL, ctx, &*event);
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
    event.connection_started_at_nanos = 0;
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
    output_event!(DNS_EVENTS, TRANSPORT_LOSS_DNS, ctx, &*event);
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
    output_event!(DNS_EVENTS, TRANSPORT_LOSS_DNS, ctx, &*event);
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
    output_event!(DNS_EVENTS, TRANSPORT_LOSS_DNS, ctx, &*event);
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
fn output_http_request_event<C: EbpfContext>(ctx: &C, event: &RawHttpRequestEvent) {
    let prefix_len = core::mem::offset_of!(RawHttpRequestEvent, request);
    let output_len = prefix_len + http_request_capture_span(event);
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(event).cast::<u8>(),
            output_len.min(core::mem::size_of::<RawHttpRequestEvent>()),
        )
    };
    output_event!(HTTP_REQUEST_EVENTS, TRANSPORT_LOSS_HTTP, ctx, bytes);
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
    clear_raw_http_propagation_context(&mut event.propagation);
    event.command = [0; 16];
    Ok(event)
}

#[inline(always)]
fn clear_raw_http_propagation_context(context: &mut RawHttpPropagationContext) {
    context.state = 0;
    context.trace_id = [0; 16];
    context.span_id = [0; 8];
    context.parent_span_id = [0; 8];
    context.trace_flags = 0;
    context.reserved = 0;
    context.insert_at = 0;
    context.started_at_nanos = 0;
    context.tracestate_len = 0;
}

#[inline(always)]
fn copy_raw_tracestate(
    source: &RawHttpPropagationContext,
    destination: &mut RawHttpPropagationContext,
) {
    let len = source.tracestate_len as usize;
    if len > MAX_TRACESTATE_BYTES {
        destination.tracestate_len = 0;
        return;
    }
    let mut index = 0_usize;
    while index < MAX_TRACESTATE_BYTES {
        if index >= len {
            break;
        }
        destination.tracestate[index] = source.tracestate[index];
        index += 1;
    }
    destination.tracestate_len = source.tracestate_len;
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

/// Classifies a tracked connection's first captured payload. Runs once per
/// connection; the verdict is cached in `ACTIVE_CONNECTIONS` so non-HTTP
/// connections (databases, message brokers, RPC framing) stop paying the
/// payload copy, event output, and userspace decode on every syscall.
///
/// The HTTP/2 connection preface (`PRI * HTTP/2.0`) starts like an HTTP/1
/// method token but belongs to the port-scoped protocol source, so it
/// classifies as non-HTTP here.
fn http_classify_first_payload(buffer: *const u8) -> Result<bool, i64> {
    if !http_buffer_starts_like_request(buffer)? {
        return Ok(false);
    }
    let first = unsafe { bpf_probe_read_user::<u8>(buffer) }.map_err(|err| err as i64)?;
    if first != b'P' {
        return Ok(true);
    }
    let second = unsafe { bpf_probe_read_user::<u8>(buffer.add(1)) }.map_err(|err| err as i64)?;
    let third = unsafe { bpf_probe_read_user::<u8>(buffer.add(2)) }.map_err(|err| err as i64)?;
    let fourth = unsafe { bpf_probe_read_user::<u8>(buffer.add(3)) }.map_err(|err| err as i64)?;
    Ok(!(second == b'R' && third == b'I' && fourth == b' '))
}

/// Returns whether the HTTP source should capture this tracked connection's
/// payload, classifying the first captured payload and caching the verdict.
///
/// The verdict is written through the map value pointer instead of copying
/// the connection struct and re-inserting it: the in-place single-field
/// store keeps the caller's stack frame small enough for the kernel's
/// 512-byte combined call-stack limit and cannot lose concurrent updates
/// to the connection's byte counters.
#[inline(always)]
fn http_connection_payload_captures(key: &ConnectionKey, buffer: *const u8) -> Result<bool, i64> {
    let Some(connection) = ACTIVE_CONNECTIONS.get_ptr_mut(key) else {
        return Ok(true);
    };
    match unsafe { (*connection).http_state } {
        HTTP_CONN_HTTP => Ok(true),
        HTTP_CONN_NOT_HTTP => {
            record_http_diagnostic(HTTP_DIAG_NON_HTTP_CONNECTION_SKIP);
            Ok(false)
        }
        _ => {
            let is_http = http_classify_first_payload(buffer)?;
            unsafe {
                (*connection).http_state = if is_http {
                    HTTP_CONN_HTTP
                } else {
                    HTTP_CONN_NOT_HTTP
                };
            }
            if !is_http {
                record_http_diagnostic(HTTP_DIAG_NON_HTTP_CONNECTION_SKIP);
            }
            Ok(is_http)
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
    let mut capture_contiguous = true;
    let total_len = http_request_iovec_total_len(iov, iov_len);
    if total_len.is_none() {
        event.propagation.reserved = HTTP_PROPAGATION_CAPTURE_UNSUPPORTED_IOVEC;
    }

    if iov_len > 0 {
        let iov_entry = iov;
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot0(buffer, len, event)?;
            event.request_iovec_lens[0] = copied as u16;
            output_index += copied;
            capture_contiguous = copied as u64 == len;
        } else if len > 0 {
            capture_contiguous = false;
        }
    }

    if iov_len > 1 && capture_contiguous && output_index < HTTP_REQUEST_BYTES {
        let iov_entry = unsafe { iov.add(16) };
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot1(buffer, len, event)?;
            event.request_iovec_lens[1] = copied as u16;
            output_index += copied;
            capture_contiguous = copied as u64 == len;
        } else if len > 0 {
            capture_contiguous = false;
        }
    }

    if iov_len > 2 && capture_contiguous && output_index < HTTP_REQUEST_BYTES {
        let iov_entry = unsafe { iov.add(32) };
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot2(buffer, len, event)?;
            event.request_iovec_lens[2] = copied as u16;
            output_index += copied;
        }
    }

    event.request_len = output_index as u32;
    event.request_total_len = total_len.unwrap_or_else(|| (output_index as u32).saturating_add(1));
    Ok(())
}

#[inline(never)]
fn http_request_iovec_total_len(iov: *const u8, iov_len: u64) -> Option<u32> {
    if iov.is_null() || iov_len == 0 || iov_len > HTTP_MAX_LENGTH_IOVECS {
        return None;
    }
    let mut state = BpfHttpIovecLengthState {
        iov,
        iov_len,
        total_len: 0,
        valid: true,
    };
    let callback = bpf_http_iovec_length_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfHttpIovecLengthState).cast::<c_void>();
    let loops = unsafe { bpf_loop(iov_len as u32, callback, context, 0) };
    if loops < 0 || !state.valid || state.total_len > u64::from(u32::MAX) {
        return None;
    }
    Some(state.total_len as u32)
}

unsafe extern "C" fn bpf_http_iovec_length_step(index: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfHttpIovecLengthState>() };
    if index >= state.iov_len || index >= HTTP_MAX_LENGTH_IOVECS {
        state.valid = false;
        return 1;
    }
    let offset = index as usize * 16 + 8;
    let len = match unsafe { bpf_probe_read_user::<u64>(state.iov.add(offset).cast::<u64>()) } {
        Ok(len) => len,
        Err(_) => {
            state.valid = false;
            return 1;
        }
    };
    let Some(total_len) = state.total_len.checked_add(len) else {
        state.valid = false;
        return 1;
    };
    state.total_len = total_len;
    0
}

#[inline(never)]
fn compact_http_request_iovecs_for_propagation(event: &mut RawHttpRequestEvent) -> bool {
    let first_len = event.request_iovec_lens[0] as usize;
    let second_len = event.request_iovec_lens[1] as usize;
    let third_len = event.request_iovec_lens[2] as usize;
    if first_len > HTTP_IOVEC_CHUNK_BYTES
        || second_len > HTTP_IOVEC_CHUNK_BYTES
        || third_len > HTTP_IOVEC_CHUNK_BYTES
        || first_len + second_len + third_len != event.request_len as usize
    {
        return false;
    }

    let request = event.request.as_mut_ptr();
    let mut index = 0_usize;
    while index < HTTP_IOVEC_CHUNK_BYTES {
        if index >= second_len {
            break;
        }
        unsafe {
            *request.add(first_len + index) = *request.add(HTTP_IOVEC_CHUNK_BYTES + index);
        }
        index += 1;
    }

    index = 0;
    while index < HTTP_IOVEC_CHUNK_BYTES {
        if index >= third_len {
            break;
        }
        unsafe {
            *request.add(first_len + second_len + index) =
                *request.add(HTTP_IOVEC_CHUNK_BYTES * 2 + index);
        }
        index += 1;
    }
    event.request_iovec_lens = [0; HTTP_MAX_IOVECS];
    true
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
