mod bpf_loader;

use bpf_loader::{BpfEngine, KernelEvent};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "soc-daemon", about = "DirtySOCS Kernel-Observability & AI-Assisted SOC Analyst Daemon")]
pub struct CliArgs {
    #[arg(short, long, default_value = "/tmp/dirtysocs.sock")]
    pub socket_path: PathBuf,

    #[arg(long, default_value = "true")]
    pub simulate_kernel_if_unprivileged: bool,

    #[arg(long, default_value = "true")]
    pub mock_ai: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soc_daemon=debug,info".into()),
        )
        .init();

    let args = CliArgs::parse();
    info!("Initializing DirtySOCS Ring-3 Endpoint Daemon v0.1.0");
    info!("Target Unix Domain Socket: {:?}", args.socket_path);

    // Lifecycle clean teardown hook
    let sock_path_clone = args.socket_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal. Performing clean teardown...");
        if sock_path_clone.exists() {
            let _ = std::fs::remove_file(&sock_path_clone);
            info!("Unlinked Unix socket: {:?}", sock_path_clone);
        }
        std::process::exit(0);
    });

    // Initialize eBPF Observability Layer
    let (mut bpf_engine, mut event_rx) = BpfEngine::new();
    bpf_engine.start(args.simulate_kernel_if_unprivileged).await?;

    info!(
        "Kernel Observability Engine running (simulated={}). Listening for ring-0 events...",
        bpf_engine.is_simulated()
    );

    // Sample event logger task
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match event {
                KernelEvent::Exec(e) => {
                    info!(
                        "[eBPF execve] PID: {}, Path: '{}', Comm: '{}'",
                        e.pid,
                        e.filename_str(),
                        e.comm_str()
                    );
                }
                KernelEvent::Connect(c) => {
                    info!(
                        "[eBPF connect] PID: {}, Comm: '{}', Port: {}",
                        c.pid,
                        c.comm_str(),
                        c.port
                    );
                }
                KernelEvent::Openat(o) => {
                    info!(
                        "[eBPF openat] PID: {}, File: '{}'",
                        o.pid,
                        o.filename_str()
                    );
                }
            }
        }
    });

    // In future phases, D-Bus, journald, pipeline, and IPC servers run here
    info!("DirtySOCS Phase 2 Verification: Press Ctrl+C to terminate cleanly.");
    
    // Keep main alive for demonstration or signal
    tokio::signal::ctrl_c().await?;
    info!("Exiting DirtySOCS.");
    Ok(())
}
