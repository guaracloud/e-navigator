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
const NETWORK_EVENT_OPEN: u32 = 1;
const NETWORK_EVENT_CLOSE: u32 = 2;
const NETWORK_EVENT_FAILURE: u32 = 3;
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
static EXEC_EVENT_SCRATCH: PerCpuArray<RawExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EXIT_EVENT_SCRATCH: PerCpuArray<RawExitEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static NETWORK_EVENT_SCRATCH: PerCpuArray<RawNetworkEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CPU_PROFILE_EVENT_SCRATCH: PerCpuArray<RawCpuProfileEvent> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
static ARGV_CAPTURE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static PENDING_CONNECTS: HashMap<u64, PendingConnect> = HashMap::with_max_entries(4096, 0);

#[map]
static ACTIVE_CONNECTIONS: HashMap<ConnectionKey, PendingConnect> =
    HashMap::with_max_entries(16384, 0);

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
    event.event_monotonic_nanos = bpf_ktime_get_ns();
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
    event.event_monotonic_nanos = bpf_ktime_get_ns();
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

    if retval < 0 {
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
    event.command = [0; 16];
    Ok(event)
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
