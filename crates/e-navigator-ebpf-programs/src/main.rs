#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

const EXECUTABLE_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 16],
    pub executable: [u8; EXECUTABLE_LEN],
}

#[map]
static EXEC_EVENTS: PerfEventArray<RawExecEvent> = PerfEventArray::new(0);

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
    let event = RawExecEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        command: bpf_get_current_comm().map_err(|err| err as i64)?,
        executable: read_exec_filename(&ctx).unwrap_or([0; EXECUTABLE_LEN]),
    };

    EXEC_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

fn read_exec_filename(ctx: &TracePointContext) -> Result<[u8; EXECUTABLE_LEN], i64> {
    let filename_ptr = unsafe { ctx.read_at::<*const u8>(16) }.map_err(|err| err as i64)?;
    let mut executable = [0_u8; EXECUTABLE_LEN];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut executable) }
        .map_err(|err| err as i64)?;
    Ok(executable)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
