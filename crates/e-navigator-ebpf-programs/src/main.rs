#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_USER_STACK,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_stack,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
        generated::bpf_get_current_cgroup_id,
    },
    macros::{map, perf_event, tracepoint},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::{PerfEventContext, TracePointContext},
};

const EXECUTABLE_LEN: usize = 256;
const MAX_ARGS: usize = 8;
const ARG_LEN: usize = 64;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const DNS_PACKET_BYTES: usize = 512;
const NETWORK_EVENT_OPEN: u32 = 1;
const NETWORK_EVENT_CLOSE: u32 = 2;
const NETWORK_EVENT_FAILURE: u32 = 3;
const NETWORK_IO_READ: u32 = 1;
const NETWORK_IO_WRITE: u32 = 2;
const NEG_EINPROGRESS: i64 = -115;
const EXEC_EVENT_SOURCE_SYSCALL_ENTER: u32 = 1;
const EXEC_EVENT_SOURCE_SCHED_EXEC: u32 = 2;
const CPU_PROFILE_MAX_FRAMES: usize = 4;

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
pub struct PendingConnect {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub family: u32,
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
static CPU_PROFILE_EVENTS: PerfEventArray<RawCpuProfileEvent> = PerfEventArray::new(0);

#[map]
static DNS_EVENTS: PerfEventArray<RawDnsEvent> = PerfEventArray::new(0);

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
    match try_tracepoint_sendto_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvfrom_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_recvfrom_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvfrom_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_recvfrom_exit(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_sendmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sendmsg_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmsg_enter(ctx: TracePointContext) -> u32 {
    match try_tracepoint_recvmsg_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn tracepoint_recvmsg_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_recvmsg_exit(ctx) {
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

fn try_tracepoint_sendto_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let len = unsafe { ctx.read_at::<u64>(32) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(48) }.map_err(|err| err as i64)?;
    if sockaddr.is_null() {
        return emit_dns_connected_send_event(&ctx, fd, buffer, len);
    }
    emit_dns_send_event(&ctx, buffer, len, sockaddr)
}

fn try_tracepoint_sendmsg_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let message = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    if message.is_null() {
        return Ok(0);
    }

    let sockaddr = read_msghdr_name(message)?;
    let (buffer, len) = read_msghdr_first_iov(message)?;
    if sockaddr.is_null() {
        return emit_dns_connected_send_event(&ctx, fd, buffer, len);
    }
    emit_dns_send_event(&ctx, buffer, len, sockaddr)
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

fn try_tracepoint_recvfrom_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let fd = unsafe { ctx.read_at::<i32>(16) }.map_err(|err| err as i64)?;
    let buffer = unsafe { ctx.read_at::<*const u8>(24) }.map_err(|err| err as i64)?;
    let sockaddr = unsafe { ctx.read_at::<*const u8>(48) }.map_err(|err| err as i64)?;
    if buffer.is_null() {
        return Ok(0);
    }

    let pending = PendingDnsRecv {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
        fd,
        buffer_ptr: buffer as u64,
        server_addr_ptr: sockaddr as u64,
        server_port_be: 0,
        server_addr_v4: 0,
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };
    PENDING_DNS_RECVS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_recvfrom_exit(ctx: &TracePointContext) -> Result<u32, i64> {
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
    try_tracepoint_recvfrom_exit(ctx)
}

fn try_tracepoint_recvmsg_enter(ctx: TracePointContext) -> Result<u32, i64> {
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

    let pending = PendingDnsRecv {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        cgroup_id: current_cgroup_id(),
        fd,
        buffer_ptr: buffer as u64,
        server_addr_ptr: read_msghdr_name(message)? as u64,
        server_port_be: 0,
        server_addr_v4: 0,
        started_at_nanos: unsafe { bpf_ktime_get_ns() },
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
    };
    PENDING_DNS_RECVS
        .insert(&pid_tgid, &pending, 0)
        .map_err(|err| err as i64)?;
    Ok(0)
}

fn try_tracepoint_recvmsg_exit(ctx: TracePointContext) -> Result<u32, i64> {
    try_tracepoint_recvfrom_exit(&ctx)
}

fn read_msghdr_name(message: *const u8) -> Result<*const u8, i64> {
    unsafe { bpf_probe_read_user::<*const u8>(message.cast::<*const u8>()) }
        .map_err(|err| err as i64)
}

fn read_msghdr_first_iov(message: *const u8) -> Result<(*const u8, u64), i64> {
    let iov = unsafe { bpf_probe_read_user::<*const u8>(message.add(16).cast::<*const u8>()) }
        .map_err(|err| err as i64)?;
    if iov.is_null() {
        return Ok((core::ptr::null(), 0));
    }
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
