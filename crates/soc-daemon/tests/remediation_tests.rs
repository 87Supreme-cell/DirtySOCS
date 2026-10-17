use soc_daemon::remediation::RemediationEngine;
use soc_ipc::RemediationRequest;

#[test]
fn test_remediation_blocks_pid_1() {
    let req = RemediationRequest {
        action: "SIGTERM_PROCESS".to_string(),
        incident_id: "INC-TEST".to_string(),
        target_pid: Some(1), // Target is root init
        target_unit: None,
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
        operator_confirmation: true,
    };

    let resp = RemediationEngine::execute(req);
    assert!(!resp.success, "Must reject targeting daemon's own PID");
    assert!(resp.details.contains("Refusing self-termination"));
}
