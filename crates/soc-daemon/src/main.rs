use clap::Parser;
use soc_daemon::bpf_loader::BpfEngine;
use soc_daemon::export::DossierExporter;
use soc_daemon::heuristics::HeuristicsGate;
use soc_daemon::ipc_server::{IpcServer, MitigationCardEntry};
use soc_daemon::pipeline::{PiiScrubber, SlidingWindowAggregator};
use soc_daemon::proc_metrics::ProcMetricsCollector;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "soc-daemon",
    about = "DirtySOCS Kernel-Observability & AI-Assisted SOC Analyst Daemon"
)]
pub struct CliArgs {
    #[arg(short, long, default_value = "/tmp/dirtysocs.sock")]
    pub socket_path: PathBuf,

    #[arg(long, default_value = "true")]
    pub simulate_kernel_if_unprivileged: bool,

    #[arg(long, default_value = "true")]
    pub mock_ai: bool,

    #[arg(long, default_value = "output/dossiers")]
    pub dossier_output_dir: PathBuf,
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
    info!("=======================================================");
    info!("  DirtySOCS: Hybrid Kernel-Observability & AI SOC Daemon");
    info!("  License: MIT | Compliance: CIS RHEL 9 & NIST SP 800-53");
    info!("=======================================================");
    info!("Target Unix Domain Socket: {:?}", args.socket_path);
    info!("Dossier Export Directory: {:?}", args.dossier_output_dir);

    // Lifecycle clean teardown hook
    let sock_path_clone = args.socket_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal. Performing clean teardown...");
        if sock_path_clone.exists() {
            let _ = std::fs::remove_file(&sock_path_clone);
            info!("Unlinked Unix socket: {:?}", sock_path_clone);
        }
        std::process::exit(0);
    });

    // 1. Initialize Pipeline & Knowledge Corpus
    let _scrubber = Arc::new(PiiScrubber::new());
    let aggregator = Arc::new(SlidingWindowAggregator::new(Duration::from_secs(60)));
    let heuristics = Arc::new(HeuristicsGate::new(aggregator.clone()));
    let exporter = Arc::new(DossierExporter::new());
    let active_advisories = Arc::new(Mutex::new(Vec::<MitigationCardEntry>::new()));

    // 2. Start Framed IPC Server over Unix Domain Socket
    let ipc_server = IpcServer::new(
        args.socket_path.clone(),
        aggregator.clone(),
        active_advisories.clone(),
    );
    ipc_server.run().await?;

    // 3. Initialize eBPF Observability Layer
    let (mut bpf_engine, mut event_rx) = BpfEngine::new();
    bpf_engine.start(args.simulate_kernel_if_unprivileged).await?;

    info!(
        "Kernel Observability Engine running (simulated={}). Listening for ring-0 events...",
        bpf_engine.is_simulated()
    );

    // 4. Telemetry Processing & Anomaly Gate Worker
    let dossier_dir = args.dossier_output_dir.clone();
    let exporter_clone = exporter.clone();
    let aggregator_clone = aggregator.clone();
    let heuristics_clone = heuristics.clone();
    let advisories_clone = active_advisories.clone();

    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            if let Some(trigger) = heuristics_clone.evaluate_kernel_event(&event) {
                warn!("=========================================================");
                warn!("🚨 ANOMALY TRIGGERED: {}", trigger.advisory.incident_id);
                warn!("Standard: {} (Control {})", trigger.rule.standard, trigger.rule.control_id);
                warn!("MITRE Technique: {}", trigger.advisory.mitre_technique);
                warn!("Plain English: {}", trigger.rule.plain_english_description);
                warn!("=========================================================");

                // Store in active advisories
                {
                    let mut adv = advisories_clone.lock().unwrap();
                    let target_pid = trigger.event.pid.unwrap_or(0);
                    adv.push(MitigationCardEntry {
                        advisory: trigger.advisory.clone(),
                        target_pid,
                    });
                }

                // Export Air-Gapped Investigation Dossier automatically
                let snapshot = aggregator_clone.snapshot();
                if let Ok((json_file, md_file)) = exporter_clone.generate_dossier(
                    &trigger.advisory,
                    trigger.rule,
                    snapshot,
                    &dossier_dir,
                ) {
                    info!("Forensic investigation files generated:");
                    info!("  -> JSON: {}", json_file);
                    info!("  -> Markdown: {}", md_file);
                }
            }
        }
    });

    // 5. Background Host Metrics Logger
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let metrics = ProcMetricsCollector::collect();
            info!(
                "[Proc Telemetry] CPU: {:.1}% | RSS: {} MB | Open FDs: {} | Active Procs: {}",
                metrics.cpu_usage_percent,
                metrics.memory_rss_bytes / (1024 * 1024),
                metrics.fd_open_count,
                metrics.active_processes_count
            );
        }
    });

    info!("DirtySOCS Core Service Active: Socket bound, IPC online, monitoring kernel.");
    tokio::signal::ctrl_c().await?;
    info!("Clean shutdown complete.");
    Ok(())
}
