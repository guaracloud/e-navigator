#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};

const EXECUTABLE_LEN: usize = 256;
const MAX_ARGS: usize = 8;
const ARG_LEN: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub argument_count: u32,
    pub command: [u8; 16],
    pub executable: [u8; EXECUTABLE_LEN],
    pub arguments: [[u8; ARG_LEN]; MAX_ARGS],
}

#[map]
static EXEC_EVENTS: PerfEventArray<RawExecEvent> = PerfEventArray::new(0);

#[map]
static EXEC_EVENT_SCRATCH: PerCpuArray<RawExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
static ARGV_CAPTURE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_execve(ctx: TracePointContext) -> u32 {
    match try_tracepoint_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = unsafe {
        let ptr = EXEC_EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
        &mut *ptr
    };

    event.pid = (pid_tgid >> 32) as u32;
    event.uid = uid_gid as u32;
    event.argument_count = 0;
    event.command = bpf_get_current_comm().map_err(|err| err as i64)?;
    event.executable = [0; EXECUTABLE_LEN];
    event.arguments = [[0; ARG_LEN]; MAX_ARGS];
    let _ = read_exec_filename(&ctx, &mut event.executable);
    let _ = read_exec_arguments(&ctx, event);

    EXEC_EVENTS.output(&ctx, &*event, 0);
    Ok(0)
}

fn read_exec_arguments(ctx: &TracePointContext, event: &mut RawExecEvent) -> Result<(), i64> {
    let enabled = unsafe { ARGV_CAPTURE_ENABLED.get(0).copied().unwrap_or(0) };
    if enabled == 0 {
        return Ok(());
    }

    let argv = unsafe { ctx.read_at::<*const *const u8>(24) }.map_err(|err| err as i64)?;
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
) -> Result<(), i64> {
    let filename_ptr = unsafe { ctx.read_at::<*const u8>(16) }.map_err(|err| err as i64)?;
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, executable) }
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
