#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use soc_common::{
    KernelEventType, RawConnectEvent, RawExecEvent, RawOpenatEvent,
    ARGS_MAX_LEN, COMM_MAX_LEN, PATH_MAX_LEN,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB kernel ring buffer

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let mut event = RawExecEvent {
        event_type: KernelEventType::Execve as u32,
        pid,
        tgid,
        ppid: 0,
        uid,
        gid,
        timestamp_ns,
        comm: [0u8; COMM_MAX_LEN],
        filename: [0u8; PATH_MAX_LEN],
        args: [0u8; ARGS_MAX_LEN],
    };

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = if comm.len() < COMM_MAX_LEN { comm.len() } else { COMM_MAX_LEN };
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    }

    // Read filename argument from tracepoint context (syscall arg 0: filename)
    // On x86_64 sys_enter_execve format: offset 16 is filename ptr
    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(16) } {
        if !filename_ptr.is_null() {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
            };
        }
    }

    // Reserve space in RingBuf and write event
    if let Some(mut entry) = EVENTS.reserve::<RawExecEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_connect(_ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let mut event = RawConnectEvent {
        event_type: KernelEventType::Connect as u32,
        pid,
        uid,
        family: 2, // AF_INET default placeholder
        port: 0,
        dest_ip: [0u8; 16],
        comm: [0u8; COMM_MAX_LEN],
        timestamp_ns,
    };

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = if comm.len() < COMM_MAX_LEN { comm.len() } else { COMM_MAX_LEN };
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    }

    if let Some(mut entry) = EVENTS.reserve::<RawConnectEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let mut event = RawOpenatEvent {
        event_type: KernelEventType::Openat as u32,
        pid,
        uid,
        flags: 0,
        filename: [0u8; PATH_MAX_LEN],
        comm: [0u8; COMM_MAX_LEN],
        timestamp_ns,
    };

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = if comm.len() < COMM_MAX_LEN { comm.len() } else { COMM_MAX_LEN };
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    }

    // sys_enter_openat format: offset 24 is pathname ptr on x86_64
    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(24) } {
        if !filename_ptr.is_null() {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
            };
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<RawOpenatEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
