#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
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
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB fixed kernel ring buffer

// -----------------------------------------------------------------------------
// Tracepoint: sys_enter_execve
// Format for syscalls/sys_enter_execve on x86_64:
// offset 0:  common fields (tracepoint header)
// offset 16: const char * filename
// offset 24: const char *const * argv
// offset 32: const char *const * envp
// -----------------------------------------------------------------------------
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

    // Read filename (arg0 at offset 16)
    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(16) } {
        if !filename_ptr.is_null() {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
            };
        }
    }

    // Read initial argument from argv (arg1 at offset 24)
    if let Ok(argv_ptr) = unsafe { ctx.read_at::<*const *const u8>(24) } {
        if !argv_ptr.is_null() {
            // Read argv[0] or argv[1] pointer safely
            if let Ok(arg0_ptr) = unsafe { bpf_probe_read_user(argv_ptr) } {
                if !arg0_ptr.is_null() {
                    let _ = unsafe {
                        bpf_probe_read_user_str_bytes(arg0_ptr, &mut event.args)
                    };
                }
            }
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<RawExecEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

// -----------------------------------------------------------------------------
// Tracepoint: sys_enter_connect
// Format for syscalls/sys_enter_connect on x86_64:
// offset 16: int fd
// offset 24: struct sockaddr * uservaddr
// offset 32: int addrlen
// -----------------------------------------------------------------------------
#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let mut event = RawConnectEvent {
        event_type: KernelEventType::Connect as u32,
        pid,
        uid,
        family: 0,
        port: 0,
        dest_ip: [0u8; 16],
        comm: [0u8; COMM_MAX_LEN],
        timestamp_ns,
    };

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = if comm.len() < COMM_MAX_LEN { comm.len() } else { COMM_MAX_LEN };
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    }

    // Read sockaddr pointer (arg1 at offset 24)
    if let Ok(sockaddr_ptr) = unsafe { ctx.read_at::<*const SockAddrIn>(24) } {
        if !sockaddr_ptr.is_null() {
            if let Ok(sock) = unsafe { bpf_probe_read_user(sockaddr_ptr) } {
                event.family = sock.sin_family;
                // Convert network byte order to host byte order for port
                event.port = u16::from_be(sock.sin_port);
                let ip_bytes = sock.sin_addr.to_ne_bytes();
                event.dest_ip[0..4].copy_from_slice(&ip_bytes);
            }
        }
    }

    if let Some(mut entry) = EVENTS.reserve::<RawConnectEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

// -----------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// Format for syscalls/sys_enter_openat on x86_64:
// offset 16: int dfd
// offset 24: const char * filename
// offset 32: int flags
// offset 40: umode_t mode
// -----------------------------------------------------------------------------
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

    // Read filename (arg1 at offset 24)
    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(24) } {
        if !filename_ptr.is_null() {
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename)
            };
        }
    }

    // Read flags (arg2 at offset 32)
    if let Ok(flags) = unsafe { ctx.read_at::<u32>(32) } {
        event.flags = flags;
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
