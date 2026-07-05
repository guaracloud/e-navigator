#![no_std]
#![no_main]
#![allow(clippy::needless_borrows_for_generic_args)]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_USER_STACK,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_stack,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes, generated::bpf_get_current_cgroup_id,
    },
    macros::{map, perf_event, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::{PerfEventContext, ProbeContext, RetProbeContext, TracePointContext},
};

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
const HTTP_REQUEST_BYTES: usize = HTTP_IOVEC_CHUNK_BYTES * HTTP_MAX_IOVECS;
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
const HTTP_DIAGNOSTIC_COUNTERS_LEN: u32 = 18;
const CONNECTION_ROLE_CLIENT: u32 = 0;
const CONNECTION_ROLE_SERVER: u32 = 1;
const PROTOCOL_DATA_BYTES: usize = 256;
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
const PROTOCOL_TOTAL_LEN_IOVECS: usize = 8;
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
const CPU_PROFILE_MAX_FRAMES: usize = 32;
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
    pub instruction_pointers: [u64; CPU_PROFILE_MAX_FRAMES],
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
pub struct PendingTlsIo {
    pub handle: u64,
    pub buffer_ptr: u64,
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
static HTTP_REQUEST_EVENTS: PerfEventArray<RawHttpRequestEvent> = PerfEventArray::new(0);

#[map]
static HTTP_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(HTTP_DIAGNOSTIC_COUNTERS_LEN, 0);

#[map]
static PROTOCOL_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);

#[map]
static PROTOCOL_DATA_EVENT_SCRATCH: PerCpuArray<RawProtocolDataEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static PROTOCOL_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(PROTOCOL_DIAGNOSTIC_COUNTERS_LEN, 0);

#[map]
static PROTOCOL_CAPTURE_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(64, 0);

#[map]
static PROTOCOL_CAPTURE_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static PENDING_PROTOCOL_READS: HashMap<u64, PendingProtocolRead> =
    HashMap::with_max_entries(4096, 0);

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
static DNS_EVENT_SCRATCH: PerCpuArray<RawDnsEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static HTTP_REQUEST_EVENT_SCRATCH: PerCpuArray<RawHttpRequestEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static ARGV_CAPTURE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static PENDING_CONNECTS: HashMap<u64, PendingConnect> = HashMap::with_max_entries(4096, 0);

#[map]
static ACTIVE_CONNECTIONS: HashMap<ConnectionKey, PendingConnect> =
    HashMap::with_max_entries(16384, 0);

#[map]
static PENDING_NETWORK_IO: HashMap<u64, PendingNetworkIo> = HashMap::with_max_entries(8192, 0);

#[map]
static PENDING_DNS_RECVS: HashMap<u64, PendingDnsRecv> = HashMap::with_max_entries(4096, 0);

#[map]
static PENDING_ACCEPTS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
static PENDING_HTTP_READS: HashMap<u64, PendingHttpRead> = HashMap::with_max_entries(4096, 0);

#[map]
static TLS_DATA_EVENTS: PerfEventArray<RawProtocolDataEvent> = PerfEventArray::new(0);

#[map]
static TLS_DATA_EVENT_SCRATCH: PerCpuArray<RawProtocolDataEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static TLS_CAPTURE_LIMIT: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static TLS_CAPTURE_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(64, 0);

#[map]
static TLS_HANDLE_FDS: HashMap<TlsHandleKey, i32> = HashMap::with_max_entries(16384, 0);

#[map]
static PENDING_TLS_IO: HashMap<u64, PendingTlsIo> = HashMap::with_max_entries(8192, 0);

#[map]
static TLS_DIAGNOSTIC_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(TLS_DIAGNOSTIC_COUNTERS_LEN, 0);

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

// OpenSSL/BoringSSL: int SSL_write(SSL *ssl, const void *buf, int num).
#[uprobe]
pub fn uprobe_ssl_write_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_WRITE)
}

#[uretprobe]
pub fn uretprobe_ssl_write_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// OpenSSL/BoringSSL: int SSL_read(SSL *ssl, void *buf, int num).
#[uprobe]
pub fn uprobe_ssl_read_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_READ)
}

#[uretprobe]
pub fn uretprobe_ssl_read_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_READ)
}

// OpenSSL/BoringSSL: int SSL_set_fd(SSL *ssl, int fd).
#[uprobe]
pub fn uprobe_ssl_set_fd(ctx: ProbeContext) -> u32 {
    tls_set_handle_fd(&ctx, 1)
}

// GnuTLS: ssize_t gnutls_record_send(gnutls_session_t s, const void *d, size_t n).
#[uprobe]
pub fn uprobe_gnutls_record_send_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_WRITE)
}

#[uretprobe]
pub fn uretprobe_gnutls_record_send_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_WRITE)
}

// GnuTLS: ssize_t gnutls_record_recv(gnutls_session_t s, void *d, size_t n).
#[uprobe]
pub fn uprobe_gnutls_record_recv_enter(ctx: ProbeContext) -> u32 {
    tls_io_enter(&ctx, NETWORK_IO_READ)
}

#[uretprobe]
pub fn uretprobe_gnutls_record_recv_exit(ctx: RetProbeContext) -> u32 {
    tls_io_exit(&ctx, NETWORK_IO_READ)
}

// GnuTLS: void gnutls_transport_set_ptr(gnutls_session_t s, gnutls_transport_ptr_t p).
// gnutls_transport_set_int(s, fd) expands to set_ptr(s, (void*)(intptr_t)fd),
// so the fd travels in the pointer argument.
#[uprobe]
pub fn uprobe_gnutls_transport_set_ptr(ctx: ProbeContext) -> u32 {
    tls_set_handle_fd(&ctx, 1)
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

fn tcp_stat_common(event: &mut RawTcpStatEvent) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.cgroup_id = current_cgroup_id();
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    Ok(())
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
    tcp_stat_common(event)?;
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
    tcp_stat_common(event)?;
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
    tcp_stat_common(event)?;
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
    event.sample_count = 1;
    event.timestamp_unix_nanos = 0;
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.frame_count = 0;
    event.instruction_pointers = [0; CPU_PROFILE_MAX_FRAMES];
    let stack_bytes = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            event.instruction_pointers.as_mut_ptr().cast(),
            (CPU_PROFILE_MAX_FRAMES * core::mem::size_of::<u64>()) as u32,
            u64::from(BPF_F_USER_STACK),
        )
    };
    if stack_bytes > 0 {
        event.frame_count = ((stack_bytes as usize) / core::mem::size_of::<u64>())
            .min(CPU_PROFILE_MAX_FRAMES) as u32;
    }

    CPU_PROFILE_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

#[inline(always)]
fn record_tls_diagnostic(stage: u32) {
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

/// Records the fd behind a userspace TLS handle (`SSL*` or GnuTLS session).
/// `fd_arg_index` is the probe argument carrying the fd (or, for GnuTLS, the
/// pointer whose integer value is the fd).
#[inline(always)]
fn tls_set_handle_fd(ctx: &ProbeContext, fd_arg_index: usize) -> u32 {
    let handle: u64 = match ctx.arg(0) {
        Some(value) => value,
        None => return 0,
    };
    let fd_value: i64 = match ctx.arg(fd_arg_index) {
        Some(value) => value,
        None => return 0,
    };
    if handle == 0 || fd_value < 0 {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let key = TlsHandleKey {
        tgid: (pid_tgid >> 32) as u32,
        reserved: 0,
        handle,
    };
    if TLS_HANDLE_FDS.insert(&key, &(fd_value as i32), 0).is_ok() {
        record_tls_diagnostic(TLS_DIAG_SET_FD);
    }
    0
}

fn tls_io_enter(ctx: &ProbeContext, direction: u32) -> u32 {
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
    let pid_tgid = bpf_get_current_pid_tgid();
    let pending = PendingTlsIo {
        handle,
        buffer_ptr: buffer,
        direction,
        reserved: 0,
    };
    let _ = PENDING_TLS_IO.insert(&pid_tgid, &pending, 0);
    0
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
    if retval <= 0 {
        return 0;
    }
    match emit_tls_data(
        ctx,
        pending.handle,
        direction,
        pending.buffer_ptr as *const u8,
        retval as u64,
    ) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn tls_connection_for_handle(handle: u64) -> Option<PendingConnect> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let handle_key = TlsHandleKey {
        tgid,
        reserved: 0,
        handle,
    };
    let fd = match unsafe { TLS_HANDLE_FDS.get(&handle_key) } {
        Some(value) => *value,
        None => {
            record_tls_diagnostic(TLS_DIAG_FD_UNRESOLVED);
            return None;
        }
    };
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
    let remote_port = u16::from_be(connection.remote_port_be);
    if unsafe { TLS_CAPTURE_PORTS.get(&remote_port) }.is_none() {
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
    let connection = match tls_connection_for_handle(handle) {
        Some(value) => value,
        None => return Ok(0),
    };

    let event = tls_data_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    event.fd = connection.fd;
    event.direction = direction;
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
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let family =
        unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }.map_err(|err| err as i64)?;

    let mut pending = PendingConnect {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
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

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
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
    HTTP_REQUEST_EVENTS.output(ctx, &*event, 0);
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
    HTTP_REQUEST_EVENTS.output(ctx, &*event, 0);
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

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
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
    HTTP_REQUEST_EVENTS.output(ctx, &*event, 0);
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
    HTTP_REQUEST_EVENTS.output(ctx, &*event, 0);
    Ok(0)
}

fn try_tracepoint_http_accept_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sockaddr = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let sockaddr_ptr = sockaddr as u64;
    PENDING_ACCEPTS
        .insert(&pid_tgid, &sockaddr_ptr, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_http_accept_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sockaddr_ptr = match unsafe { PENDING_ACCEPTS.get(&pid_tgid) } {
        Some(value) => *value,
        None => return Ok(0),
    };
    PENDING_ACCEPTS.remove(&pid_tgid).ok();

    let retval = unsafe { ctx.read_at::<i64>(16) }.map_err(|err| err as i64)?;
    if retval < 0 {
        return Ok(0);
    }

    let uid_gid = bpf_get_current_uid_gid();
    let mut pending = PendingConnect {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
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

    if sockaddr_ptr != 0 {
        let sockaddr = sockaddr_ptr as *const u8;
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
    if !http_buffer_starts_like_request(buffer)? {
        return Ok(0);
    }

    let event = http_request_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
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
    HTTP_REQUEST_EVENTS.output(ctx, &*event, 0);
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
    emit_protocol_iovec_event(ctx, fd, iov, iov_len)
}

fn try_tracepoint_protocol_sendmsg_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }
    let (iov, iov_len) = read_msghdr_iovecs(message)?;
    emit_protocol_iovec_event(ctx, fd, iov, iov_len)
}

#[inline(always)]
fn emit_protocol_iovec_event(
    ctx: &TracePointContext,
    fd: i32,
    iov: *const u8,
    iov_len: u64,
) -> Result<u32, i64> {
    if iov.is_null() || iov_len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_NULL_OR_EMPTY);
        return Ok(0);
    }

    let connection = match protocol_capture_connection(fd) {
        Some(value) => value,
        None => return Ok(0),
    };

    let event = protocol_data_event_scratch()?;
    event.pid = connection.pid;
    event.uid = connection.uid;
    event.cgroup_id = current_cgroup_id();
    event.fd = fd;
    event.direction = NETWORK_IO_WRITE;
    event.family = connection.family;
    event.remote_port_be = connection.remote_port_be;
    event.local_port_be = connection.local_port_be;
    event.remote_addr_v4 = connection.remote_addr_v4;
    event.local_addr_v4 = connection.local_addr_v4;
    event.remote_addr_v6 = connection.remote_addr_v6;
    event.local_addr_v6 = connection.local_addr_v6;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;

    // Only the first iovec is copied; the remaining iovec bytes are
    // accounted as an uncaptured tail gap through payload_total_len so the
    // userspace stream decoder never splices non-adjacent bytes.
    let mut total_len: u64 = 0;
    let mut index: usize = 0;
    while index < PROTOCOL_TOTAL_LEN_IOVECS {
        if index as u64 >= iov_len {
            break;
        }
        let entry = unsafe { iov.add(index * 16) };
        let len = unsafe { bpf_probe_read_user::<u64>(entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
        total_len = total_len.saturating_add(len);
        index += 1;
    }
    let first_buffer = unsafe { bpf_probe_read_user::<*const u8>(iov.cast::<*const u8>()) }
        .map_err(|err| err as i64)?;
    let first_len = unsafe { bpf_probe_read_user::<u64>(iov.add(8).cast::<u64>()) }
        .map_err(|err| err as i64)?;
    event.payload_total_len = if total_len > u32::MAX as u64 {
        u32::MAX
    } else {
        total_len as u32
    };
    if first_buffer.is_null() || first_len == 0 {
        record_protocol_diagnostic(PROTOCOL_DIAG_COPY_EMPTY);
        return Ok(0);
    }
    output_protocol_payload_segments(ctx, event, first_buffer, first_len);
    Ok(0)
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
    let remote_port = u16::from_be(connection.remote_port_be);
    if unsafe { PROTOCOL_CAPTURE_PORTS.get(&remote_port) }.is_none() {
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
    event.fd = fd;
    event.direction = direction;
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
    if family as u32 != AF_INET {
        return Ok(0);
    }

    let server_port_be = unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
        .map_err(|err| err as i64)?;
    if u16::from_be(server_port_be) != 53 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = dns_event_scratch()?;
    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.cgroup_id = current_cgroup_id();
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
    event.protocol = IPPROTO_UDP;
    event.timestamp_unix_nanos = unsafe { bpf_ktime_get_ns() };
    event.latency_nanos = event.timestamp_unix_nanos - pending.started_at_nanos;
    event.command = pending.command;

    if pending.server_addr_ptr != 0 {
        let sockaddr = pending.server_addr_ptr as *const u8;
        let family = unsafe { bpf_probe_read_user::<u16>(sockaddr.cast::<u16>()) }
            .map_err(|err| err as i64)?;
        if family as u32 == AF_INET {
            event.server_port_be =
                unsafe { bpf_probe_read_user::<u16>(sockaddr.add(2).cast::<u16>()) }
                    .map_err(|err| err as i64)?;
            event.server_addr_v4 =
                unsafe { bpf_probe_read_user::<u32>(sockaddr.add(4).cast::<u32>()) }
                    .map_err(|err| err as i64)?;
            if event.server_port_be != 0 && u16::from_be(event.server_port_be) != 53 {
                return Ok(0);
            }
        }
    } else if pending.server_port_be != 0 {
        event.server_port_be = pending.server_port_be;
        event.server_addr_v4 = pending.server_addr_v4;
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
    event.request_iovec_lens = [0; HTTP_MAX_IOVECS];
    event.command = [0; 16];
    event.request = [0; HTTP_REQUEST_BYTES];
    Ok(event)
}

#[inline(always)]
fn record_http_diagnostic(stage: u32) {
    if let Some(counter) = HTTP_DIAGNOSTIC_COUNTERS.get_ptr_mut(stage) {
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

fn http_buffer_starts_like_request(buffer: *const u8) -> Result<bool, i64> {
    let first = unsafe { bpf_probe_read_user::<u8>(buffer) }.map_err(|err| err as i64)?;
    Ok(http_method_start_likely(first))
}

fn http_request_event_starts_like_request(event: &RawHttpRequestEvent) -> bool {
    if event.request_len == 0 {
        return false;
    }
    http_method_start_likely(event.request[0])
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
        }
    }

    if iov_len > 1 && output_index < HTTP_REQUEST_BYTES {
        let iov_entry = unsafe { iov.add(16) };
        let buffer = unsafe { bpf_probe_read_user::<*const u8>(iov_entry.cast::<*const u8>()) }
            .map_err(|err| err as i64)?;
        let len = unsafe { bpf_probe_read_user::<u64>(iov_entry.add(8).cast::<u64>()) }
            .map_err(|err| err as i64)?;
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
        if !buffer.is_null() && len > 0 {
            let copied = copy_http_request_iovec_slot2(buffer, len, event)?;
            event.request_iovec_lens[2] = copied as u16;
            output_index += copied;
        }
    }

    event.request_len = output_index as u32;
    Ok(())
}

#[inline(never)]
fn copy_http_request_iovec_slot0(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let capped_len = if len > HTTP_IOVEC_CHUNK_BYTES as u64 {
        HTTP_IOVEC_CHUNK_BYTES
    } else {
        len as usize
    };
    if capped_len == 0 {
        return Ok(0);
    }

    let request = event.request.as_mut_ptr();
    let mut index = 0;
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

#[inline(never)]
fn copy_http_request_iovec_slot1(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let capped_len = if len > HTTP_IOVEC_CHUNK_BYTES as u64 {
        HTTP_IOVEC_CHUNK_BYTES
    } else {
        len as usize
    };
    if capped_len == 0 {
        return Ok(0);
    }

    let request = unsafe { event.request.as_mut_ptr().add(HTTP_IOVEC_CHUNK_BYTES) };
    let mut index = 0;
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

#[inline(never)]
fn copy_http_request_iovec_slot2(
    buffer: *const u8,
    len: u64,
    event: &mut RawHttpRequestEvent,
) -> Result<usize, i64> {
    let capped_len = if len > HTTP_IOVEC_CHUNK_BYTES as u64 {
        HTTP_IOVEC_CHUNK_BYTES
    } else {
        len as usize
    };
    if capped_len == 0 {
        return Ok(0);
    }

    let request = unsafe { event.request.as_mut_ptr().add(HTTP_IOVEC_CHUNK_BYTES * 2) };
    let mut index = 0;
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
