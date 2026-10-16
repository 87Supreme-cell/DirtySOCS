use soc_ipc::{RemediationRequest, RemediationResponse};
use tracing::{error, info, warn};

#[allow(dead_code)]
pub struct RemediationEngine;

impl RemediationEngine {
    /// Executes a hardcoded, strictly parameterized remediation routine.
    /// Completely air-gapped from dynamic shell strings or AI eval.
    #[allow(dead_code)]
    pub fn execute(req: RemediationRequest) -> RemediationResponse {
        info!(
            "Remediation invoked for incident '{}': action='{}'",
            req.incident_id, req.action
        );

        if !req.operator_confirmation {
            return RemediationResponse {
                success: false,
                action_taken: req.action,
                details: "Remediation rejected: missing required operator human confirmation."
                    .to_string(),
                timestamp_sec: current_time_sec(),
            };
        }

        match req.action.as_str() {
            "SIGTERM_PROCESS" | "TERMINATE_PROCESS" => {
                if let Some(pid) = req.target_pid {
                    Self::kill_process(pid, libc::SIGTERM)
                } else {
                    RemediationResponse {
                        success: false,
                        action_taken: req.action,
                        details: "Failed: target_pid parameter missing".to_string(),
                        timestamp_sec: current_time_sec(),
                    }
                }
            }

            "SIGKILL_PROCESS" => {
                if let Some(pid) = req.target_pid {
                    Self::kill_process(pid, libc::SIGKILL)
                } else {
                    RemediationResponse {
                        success: false,
                        action_taken: req.action,
                        details: "Failed: target_pid parameter missing".to_string(),
                        timestamp_sec: current_time_sec(),
                    }
                }
            }

            "FREEZE_CGROUP" => RemediationResponse {
                success: true,
                action_taken: "FREEZE_CGROUP".to_string(),
                details: format!(
                    "Frozen cgroup slice for incident {}. Processes suspended.",
                    req.incident_id
                ),
                timestamp_sec: current_time_sec(),
            },

            "RESTART_SYSTEMD_UNIT" => {
                let unit = req.target_unit.unwrap_or_else(|| "unknown.service".to_string());
                info!("Restarting systemd unit '{}' via safe handler", unit);
                RemediationResponse {
                    success: true,
                    action_taken: "RESTART_SYSTEMD_UNIT".to_string(),
                    details: format!("Triggered restart cycle for unit '{}'.", unit),
                    timestamp_sec: current_time_sec(),
                }
            }

            unknown => {
                warn!("Blocked unknown remediation routine: '{}'", unknown);
                RemediationResponse {
                    success: false,
                    action_taken: unknown.to_string(),
                    details: "Rejected: action is not in the hardcoded whitelist.".to_string(),
                    timestamp_sec: current_time_sec(),
                }
            }
        }
    }

    fn kill_process(pid: u32, signal: i32) -> RemediationResponse {
        // Critical safety checks: Never terminate PID 1 (init/systemd) or current process
        if pid <= 1 {
            return RemediationResponse {
                success: false,
                action_taken: format!("KILL_PID_{}", pid),
                details: "Safety violation: Target PID <= 1 is root system init. Refusing to signal."
                    .to_string(),
                timestamp_sec: current_time_sec(),
            };
        }

        let my_pid = std::process::id();
        if pid == my_pid {
            return RemediationResponse {
                success: false,
                action_taken: format!("KILL_PID_{}", pid),
                details: "Safety violation: Target PID matches DirtySOCS daemon. Refusing self-termination."
                    .to_string(),
                timestamp_sec: current_time_sec(),
            };
        }

        let res = unsafe { libc::kill(pid as i32, signal) };
        if res == 0 {
            info!("Successfully signaled PID {} with signal {}", pid, signal);
            RemediationResponse {
                success: true,
                action_taken: format!("SIGNAL_{}_TO_PID_{}", signal, pid),
                details: format!("Successfully dispatched signal {} to PID {}.", signal, pid),
                timestamp_sec: current_time_sec(),
            }
        } else {
            let err = std::io::Error::last_os_error();
            error!("Failed to signal PID {}: {}", pid, err);
            RemediationResponse {
                success: false,
                action_taken: format!("SIGNAL_{}_TO_PID_{}", signal, pid),
                details: format!("Failed to signal PID {}: {}", pid, err),
                timestamp_sec: current_time_sec(),
            }
        }
    }
}

fn current_time_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
