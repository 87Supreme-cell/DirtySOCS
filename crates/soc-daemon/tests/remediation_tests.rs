use soc_daemon::remediation::RemediationEngine;
use soc_ipc::RemediationRequest;

#[test]
fn test_remediation_blocks_pid_1() {
    let req = RemediationRequest {
        action: "SIGTERM_PROCESS".to_string(),
        incident_id: "INC-TEST".to_string(),
        target_pid: Some(1), // Target is root init
        target_unit: None,
        expected_comm: None,
        expected_start_time: None,
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    assert!(!resp.success, "Must reject targeting PID 1");
    assert!(resp.details.contains("PID <= 1 is root system init"));
}

#[test]
fn test_remediation_blocks_unauthorized_execution() {
    let req = RemediationRequest {
        action: "SIGTERM_PROCESS".to_string(),
        incident_id: "INC-TEST".to_string(),
        target_pid: Some(4821),
        target_unit: None,
        expected_comm: None,
        expected_start_time: None,
        operator_confirmation: false, // Operator did NOT confirm
    };

    let resp = RemediationEngine::execute(req);
    assert!(!resp.success, "Must reject without explicit human confirmation");
    assert!(resp.details.contains("missing required operator human confirmation"));
}

#[test]
fn test_remediation_blocks_self_termination() {
    let my_pid = std::process::id();
    let req = RemediationRequest {
        action: "SIGTERM_PROCESS".to_string(),
        incident_id: "INC-TEST".to_string(),
        target_pid: Some(my_pid),
        target_unit: None,
        expected_comm: None,
        expected_start_time: None,
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    assert!(!resp.success, "Must reject targeting daemon's own PID");
    assert!(resp.details.contains("Refusing self-termination"));
}

#[test]
fn test_remediation_detects_recycled_pid_comm_mismatch() {
    // Spawn an innocent process
    let mut child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .expect("Failed to spawn child");
    let child_pid = child.id();

    // Attacker claims this was .sys_update malware, but PID now runs sleep
    let req = RemediationRequest {
        action: "SIGKILL_PROCESS".to_string(),
        incident_id: "INC-RECYCLE-TEST".to_string(),
        target_pid: Some(child_pid),
        target_unit: None,
        expected_comm: Some(".sys_update".to_string()), // Mismatch!
        expected_start_time: None,
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    let _ = child.kill();
    let _ = child.wait();

    assert!(!resp.success, "Must abort signal delivery when comm does not match expected");
    assert!(resp.details.contains("Recycled PID detected"));
}

#[test]
fn test_remediation_detects_recycled_pid_starttime_mismatch() {
    let mut child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .expect("Failed to spawn child");
    let child_pid = child.id();

    // Mismatched fictitious starttime
    let req = RemediationRequest {
        action: "SIGKILL_PROCESS".to_string(),
        incident_id: "INC-RECYCLE-TEST".to_string(),
        target_pid: Some(child_pid),
        target_unit: None,
        expected_comm: None,
        expected_start_time: Some(12345), // Mismatch!
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    let _ = child.kill();
    let _ = child.wait();

    assert!(!resp.success, "Must abort signal delivery when starttime does not match expected");
    assert!(resp.details.contains("Start time mismatch"));
}

#[test]
fn test_remediation_handles_already_terminated_process() {
    let mut child = std::process::Command::new("sleep")
        .arg("0.01")
        .spawn()
        .expect("Failed to spawn child");
    let child_pid = child.id();
    let _ = child.wait(); // Child is guaranteed dead

    let req = RemediationRequest {
        action: "SIGTERM_PROCESS".to_string(),
        incident_id: "INC-DEAD-TEST".to_string(),
        target_pid: Some(child_pid),
        target_unit: None,
        expected_comm: None,
        expected_start_time: None,
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    assert!(resp.success);
    assert!(resp.details.contains("already terminated"));
}
