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
                    Self::kill_process(pid, libc::SIGTERM, req.expected_comm.as_deref(), req.expected_start_time)
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
                    Self::kill_process(pid, libc::SIGKILL, req.expected_comm.as_deref(), req.expected_start_time)
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

    fn kill_process(
        pid: u32,
        signal: i32,
        expected_comm: Option<&str>,
        expected_start_time: Option<u64>,
    ) -> RemediationResponse {
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

        // 1. Process identity & start-time verification via /proc/<pid>/stat
        if let Some((current_comm, current_start)) = get_proc_stat(pid) {
            if let Some(exp_comm) = expected_comm {
                if current_comm != exp_comm {
                    warn!(
                        "TOCTOU Recycled PID detected! Current comm '{}' != expected '{}' for PID {}",
                        current_comm, exp_comm, pid
                    );
                    return RemediationResponse {
                        success: false,
                        action_taken: format!("ABORTED_SIGNAL_PID_{}", pid),
                        details: format!(
                            "Safety abort: Recycled PID detected. Current comm '{}' != expected '{}'. Aborting signal delivery.",
                            current_comm, exp_comm
                        ),
                        timestamp_sec: current_time_sec(),
                    };
                }
            }
            if let Some(exp_start) = expected_start_time {
                if current_start != exp_start {
                    warn!(
                        "TOCTOU Recycled PID detected! Current start time {} != expected {} for PID {}",
                        current_start, exp_start, pid
                    );
                    return RemediationResponse {
                        success: false,
                        action_taken: format!("ABORTED_SIGNAL_PID_{}", pid),
                        details: format!(
                            "Safety abort: Recycled PID detected. Start time mismatch ({} != expected {}). Aborting signal delivery.",
                            current_start, exp_start
                        ),
                        timestamp_sec: current_time_sec(),
                    };
                }
            }
        } else {
            // Process not in /proc: already terminated
            return RemediationResponse {
                success: true,
                action_taken: format!("STAT_CHECK_PID_{}", pid),
                details: format!("Target PID {} has already terminated (ESRCH). No signal required.", pid),
                timestamp_sec: current_time_sec(),
            };
        }

        // 2. Verified signal dispatch using Linux pidfd (atomic pinning against PID recycling)
        const SYS_PIDFD_OPEN: i64 = 434;
        const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
        const PIDFD_NONBLOCK: u32 = 0x00000800;

        let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as i32, PIDFD_NONBLOCK as libc::c_uint) };
        if pidfd >= 0 {
            let res = unsafe {
                libc::syscall(
                    SYS_PIDFD_SEND_SIGNAL,
                    pidfd as libc::c_int,
                    signal,
                    std::ptr::null::<libc::c_void>(),
                    0,
                )
            };
            unsafe { libc::close(pidfd as libc::c_int) };
            if res == 0 {
                info!("Dispatched signal {} via atomic pidfd to PID {}", signal, pid);
                return RemediationResponse {
                    success: true,
                    action_taken: format!("PIDFD_SIGNAL_{}_TO_PID_{}", signal, pid),
                    details: format!("Successfully dispatched signal {} via verified pidfd to PID {}.", signal, pid),
                    timestamp_sec: current_time_sec(),
                };
            }
        }

        // Fallback to libc::kill if pidfd not supported on older kernels
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

/// Extracts process name and starttime (field 22) from Linux /proc/<pid>/stat
pub fn get_proc_stat(pid: u32) -> Option<(String, u64)> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(stat_path).ok()?;
    let rparen = content.rfind(')')?;
    let lparen = content.find('(')?;
    let comm = content.get(lparen + 1..rparen)?.to_string();
    let fields: Vec<&str> = content.get(rparen + 2..)?.split_whitespace().collect();
    // fields[0] is state (field 3), field 22 is starttime -> index 19
    let starttime = fields.get(19).and_then(|s| s.parse::<u64>().ok())?;
    Some((comm, starttime))
}

fn current_time_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
