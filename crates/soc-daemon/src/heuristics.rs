use crate::bpf_loader::KernelEvent;
use crate::corpus::{ComplianceCorpus, ComplianceRule};
use crate::pipeline::SlidingWindowAggregator;
use soc_common::{MitigationAdvisory, TelemetryEvent};
use std::sync::Arc;
use tracing::warn;

pub struct HeuristicsGate {
    aggregator: Arc<SlidingWindowAggregator>,
}

#[derive(Debug, Clone)]
pub struct AnomalyTrigger {
    pub rule: &'static ComplianceRule,
    #[allow(dead_code)]
    pub event: TelemetryEvent,
    pub advisory: MitigationAdvisory,
}

impl HeuristicsGate {
    pub fn new(aggregator: Arc<SlidingWindowAggregator>) -> Self {
        Self { aggregator }
    }

    /// Evaluates incoming kernel telemetry against the deterministic baseline gate.
    /// Returns Some(AnomalyTrigger) if an anomaly crosses the threshold.
    pub fn evaluate_kernel_event(&self, event: &KernelEvent) -> Option<AnomalyTrigger> {
        match event {
            KernelEvent::Exec(raw_exec) => {
                let path = raw_exec.filename_str();
                let comm = raw_exec.comm_str();
                let pid = raw_exec.pid;

                let te = TelemetryEvent {
                    subsystem: "ebpf".to_string(),
                    event_type: "sys_enter_execve".to_string(),
                    process: Some(comm.clone()),
                    pid: Some(pid),
                    ppid: Some(raw_exec.ppid),
                    target_interface: None,
                    target_path: Some(path.clone()),
                    target_network: None,
                    unit: None,
                    exit_code: None,
                    count: 1,
                    details: Some(format!("Executed: {} via comm: {}", path, comm)),
                };

                // Deduplicate in 60s sliding window
                self.aggregator.record(te.clone());

                // Deterministic Gate: Flag executions originating from /tmp, /dev/shm, or /var/tmp
                if let Some(rule) = ComplianceCorpus::find_rule_for_exec(&path) {
                    warn!(
                        "Deterministic Gate Alert: Execution from temporary path: '{}' (PID: {})",
                        path, pid
                    );

                    let advisory = MitigationAdvisory {
                        incident_id: format!("INC-{}", 80000 + (pid % 10000)),
                        severity: rule.default_severity.to_string(),
                        mitre_technique: rule.default_mitre_technique.to_string(),
                        root_cause_analysis: format!(
                            "Process '{}' (PID {}) executed binary from temporary storage ('{}') violating system confinement baselines.",
                            comm, pid, path
                        ),
                        risk_summary: rule.plain_english_description.to_string(),
                        recommended_actions: vec![
                            format!("Terminate suspicious process PID {}", pid),
                            "Verify filesystem mount flags (/tmp noexec)".to_string(),
                            "Inspect parent shell session and audit logs".to_string(),
                        ],
                        created_at: Some(chrono::Utc::now().to_rfc3339()),
                        status: Some("PENDING_REVIEW".to_string()),
                    };

                    return Some(AnomalyTrigger {
                        rule,
                        event: te,
                        advisory,
                    });
                }
                None
            }

            KernelEvent::Openat(raw_openat) => {
                let path = raw_openat.filename_str();
                let pid = raw_openat.pid;

                let te = TelemetryEvent {
                    subsystem: "ebpf".to_string(),
                    event_type: "sys_enter_openat".to_string(),
                    process: Some(raw_openat.comm_str()),
                    pid: Some(pid),
                    ppid: None,
                    target_interface: None,
                    target_path: Some(path.clone()),
                    target_network: None,
                    unit: None,
                    exit_code: None,
                    count: 1,
                    details: Some(format!("Openat target: {}", path)),
                };

                self.aggregator.record(te.clone());

                if let Some(rule) = ComplianceCorpus::find_rule_for_openat(&path) {
                    warn!(
                        "Deterministic Gate Alert: Restricted file open: '{}' (PID: {})",
                        path, pid
                    );

                    let advisory = MitigationAdvisory {
                        incident_id: format!("INC-{}", 90000 + (pid % 10000)),
                        severity: rule.default_severity.to_string(),
                        mitre_technique: rule.default_mitre_technique.to_string(),
                        root_cause_analysis: format!(
                            "Unauthorized openat attempt targeting sensitive file '{}' by PID {}.",
                            path, pid
                        ),
                        risk_summary: rule.plain_english_description.to_string(),
                        recommended_actions: vec![
                            format!("Verify permissions for PID {}", pid),
                            "Check AppArmor / SELinux mediation profiles".to_string(),
                        ],
                        created_at: Some(chrono::Utc::now().to_rfc3339()),
                        status: Some("PENDING_REVIEW".to_string()),
                    };

                    return Some(AnomalyTrigger {
                        rule,
                        event: te,
                        advisory,
                    });
                }
                None
            }

            KernelEvent::Connect(raw_conn) => {
                let te = TelemetryEvent {
                    subsystem: "ebpf".to_string(),
                    event_type: "sys_enter_connect".to_string(),
                    process: Some(raw_conn.comm_str()),
                    pid: Some(raw_conn.pid),
                    ppid: None,
                    target_interface: None,
                    target_path: None,
                    target_network: Some(format!("Port: {}", raw_conn.port)),
                    unit: None,
                    exit_code: None,
                    count: 1,
                    details: Some(format!("Outbound connect port: {}", raw_conn.port)),
                };
                self.aggregator.record(te);
                None
            }
        }
    }
}
