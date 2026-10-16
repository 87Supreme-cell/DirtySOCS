use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use soc_common::{
    KernelEventType, RawConnectEvent, RawExecEvent, RawOpenatEvent,
    COMM_MAX_LEN, PATH_MAX_LEN,
};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{info, warn};

// Embed the compiled eBPF ELF bytecode directly into the binary
pub const EBPF_BYTECODE: &[u8] =
    include_bytes!("../../soc-ebpf/target/bpfel-unknown-none/release/soc-ebpf");

#[derive(Debug, Clone)]
pub enum KernelEvent {
    Exec(RawExecEvent),
    Connect(RawConnectEvent),
    Openat(RawOpenatEvent),
}

pub struct BpfEngine {
    event_tx: broadcast::Sender<KernelEvent>,
    is_simulated: bool,
}

impl BpfEngine {
    pub fn new() -> (Self, broadcast::Receiver<KernelEvent>) {
        let (tx, rx) = broadcast::channel(10_000);
        (
            Self {
                event_tx: tx,
                is_simulated: false,
            },
            rx,
        )
    }

    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_tx.subscribe()
    }

    pub fn is_simulated(&self) -> bool {
        self.is_simulated
    }

    /// Attempts to attach real Aya eBPF probes to the Linux kernel.
    /// If unprivileged and `simulate_if_unprivileged` is true, falls back to simulation mode.
    pub async fn start(&mut self, simulate_if_unprivileged: bool) -> anyhow::Result<()> {
        let is_root = unsafe { libc::geteuid() == 0 };

        if !is_root {
            if simulate_if_unprivileged {
                warn!("Running as non-root (UID != 0). Initializing unprivileged kernel simulation engine.");
                self.is_simulated = true;
                self.start_simulation();
                return Ok(());
            } else {
                return Err(anyhow::anyhow!(
                    "Attaching eBPF tracepoints requires root or CAP_BPF / CAP_SYS_ADMIN. Pass --simulate-kernel-if-unprivileged to test without root."
                ));
            }
        }

        info!("Root privileges verified. Loading eBPF bytecode ({} bytes)...", EBPF_BYTECODE.len());

        let mut bpf = match Ebpf::load(EBPF_BYTECODE) {
            Ok(bpf) => bpf,
            Err(e) => {
                if simulate_if_unprivileged {
                    warn!("Aya eBPF verifier/load error: {}. Falling back to simulation.", e);
                    self.is_simulated = true;
                    self.start_simulation();
                    return Ok(());
                } else {
                    return Err(e.into());
                }
            }
        };

        // Attach sys_enter_execve tracepoint
        if let Some(prog) = bpf.program_mut("sys_enter_execve") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_execve")?;
            info!("Attached tracepoint: syscalls/sys_enter_execve");
        }

        // Attach sys_enter_connect tracepoint
        if let Some(prog) = bpf.program_mut("sys_enter_connect") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_connect")?;
            info!("Attached tracepoint: syscalls/sys_enter_connect");
        }

        // Attach sys_enter_openat tracepoint
        if let Some(prog) = bpf.program_mut("sys_enter_openat") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("syscalls", "sys_enter_openat")?;
            info!("Attached tracepoint: syscalls/sys_enter_openat");
        }

        // Poll RingBuf
        let ring_buf_map = bpf.take_map("EVENTS").ok_or_else(|| {
            anyhow::anyhow!("Failed to find 'EVENTS' RingBuf map in compiled eBPF object")
        })?;

        let ring_buf = RingBuf::try_from(ring_buf_map)?;
        let tx = self.event_tx.clone();

        tokio::task::spawn_blocking(move || {
            info!("Kernel eBPF RingBuf consumer thread started.");
            let mut ring = ring_buf;
            loop {
                // Drain ring buffer items
                while let Some(item) = ring.next() {
                    let data = &*item;
                    if data.len() >= 4 {
                        let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                        if event_type == KernelEventType::Execve as u32
                            && data.len() >= std::mem::size_of::<RawExecEvent>()
                        {
                            let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawExecEvent) };
                            let _ = tx.send(KernelEvent::Exec(event));
                        } else if event_type == KernelEventType::Connect as u32
                            && data.len() >= std::mem::size_of::<RawConnectEvent>()
                        {
                            let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawConnectEvent) };
                            let _ = tx.send(KernelEvent::Connect(event));
                        } else if event_type == KernelEventType::Openat as u32
                            && data.len() >= std::mem::size_of::<RawOpenatEvent>()
                        {
                            let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawOpenatEvent) };
                            let _ = tx.send(KernelEvent::Openat(event));
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        Ok(())
    }

    /// Spawns a synthetic kernel telemetry loop for unprivileged evaluation and interview demonstrations
    fn start_simulation(&self) {
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            info!("Simulation telemetry loop active. Emitting synthetic syscall events...");
            let mut counter: u32 = 0;
            loop {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                counter += 1;

                // Alternate between benign activity and anomalous behavior
                let is_anomaly = counter % 6 == 0;

                let mut comm_bytes = [0u8; COMM_MAX_LEN];
                let mut path_bytes = [0u8; PATH_MAX_LEN];

                let (comm_str, path_str, pid) = if is_anomaly {
                    (".sys_update", "/tmp/.sys_update", 4821)
                } else {
                    let comms = ["gnome-shell", "bash", "sshd", "curl", "systemd-resolved"];
                    let paths = ["/usr/bin/gnome-shell", "/usr/bin/bash", "/usr/sbin/sshd", "/usr/bin/curl", "/lib/systemd/systemd-resolved"];
                    let idx = (counter as usize) % comms.len();
                    (comms[idx], paths[idx], 1000 + (counter % 50))
                };

                let c_bytes = comm_str.as_bytes();
                comm_bytes[..c_bytes.len().min(COMM_MAX_LEN)].copy_from_slice(&c_bytes[..c_bytes.len().min(COMM_MAX_LEN)]);

                let p_bytes = path_str.as_bytes();
                path_bytes[..p_bytes.len().min(PATH_MAX_LEN)].copy_from_slice(&p_bytes[..p_bytes.len().min(PATH_MAX_LEN)]);

                let exec_ev = RawExecEvent {
                    event_type: KernelEventType::Execve as u32,
                    pid,
                    tgid: pid,
                    ppid: 1042,
                    uid: if is_anomaly { 1000 } else { 1000 },
                    gid: 1000,
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                    comm: comm_bytes,
                    filename: path_bytes,
                    args: [0u8; soc_common::ARGS_MAX_LEN],
                };

                let _ = tx.send(KernelEvent::Exec(exec_ev));

                // If anomaly, also emit a sensitive openat event to /etc/shadow
                if is_anomaly {
                    let mut shadow_path = [0u8; PATH_MAX_LEN];
                    let s_str = "/etc/shadow".as_bytes();
                    shadow_path[..s_str.len()].copy_from_slice(s_str);

                    let openat_ev = RawOpenatEvent {
                        event_type: KernelEventType::Openat as u32,
                        pid: 4821,
                        uid: 1000,
                        flags: 0,
                        filename: shadow_path,
                        comm: comm_bytes,
                        timestamp_ns: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64,
                    };
                    let _ = tx.send(KernelEvent::Openat(openat_ev));
                }
            }
        });
    }
}
