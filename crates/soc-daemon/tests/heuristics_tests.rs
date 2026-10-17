use soc_common::{
    KernelEventType, RawExecEvent, RawOpenatEvent, ARGS_MAX_LEN, COMM_MAX_LEN, PATH_MAX_LEN,
};
use soc_daemon::bpf_loader::KernelEvent;
use soc_daemon::heuristics::HeuristicsGate;
use soc_daemon::pipeline::SlidingWindowAggregator;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_heuristics_gate_flags_tmp_execution() {
    let aggregator = Arc::new(SlidingWindowAggregator::new(Duration::from_secs(60)));
    let gate = HeuristicsGate::new(aggregator);

    let mut path_bytes = [0u8; PATH_MAX_LEN];
    let p_str = "/tmp/.sys_update".as_bytes();
    path_bytes[..p_str.len()].copy_from_slice(p_str);

    let raw_exec = RawExecEvent {
        event_type: KernelEventType::Execve as u32,
        pid: 4821,
        tgid: 4821,
        ppid: 1042,
        uid: 1000,
        gid: 1000,
        timestamp_ns: 12345678,
        comm: [0u8; COMM_MAX_LEN],
        filename: path_bytes,
        args: [0u8; ARGS_MAX_LEN],
    };

    let trigger = gate.evaluate_kernel_event(&KernelEvent::Exec(raw_exec));
    assert!(trigger.is_some(), "Execution from /tmp must trigger gate");

    let t = trigger.unwrap();
    assert_eq!(t.rule.standard, "CIS RHEL 9");
    assert_eq!(t.rule.control_id, "1.1.2");
    assert_eq!(t.advisory.severity, "CRITICAL");
    assert!(t.advisory.mitre_technique.contains("T1204"));
}

#[test]
fn test_heuristics_gate_flags_credential_file_open() {
    let aggregator = Arc::new(SlidingWindowAggregator::new(Duration::from_secs(60)));
    let gate = HeuristicsGate::new(aggregator);

    let mut path_bytes = [0u8; PATH_MAX_LEN];
    let p_str = "/etc/shadow".as_bytes();
    path_bytes[..p_str.len()].copy_from_slice(p_str);

    let raw_openat = RawOpenatEvent {
        event_type: KernelEventType::Openat as u32,
        pid: 4821,
        uid: 1000,
        flags: 0,
        filename: path_bytes,
        comm: [0u8; COMM_MAX_LEN],
        timestamp_ns: 12345678,
    };

    let trigger = gate.evaluate_kernel_event(&KernelEvent::Openat(raw_openat));
    assert!(trigger.is_some(), "Opening /etc/shadow must trigger gate");

    let t = trigger.unwrap();
    assert_eq!(t.rule.standard, "CIS RHEL 9");
    assert_eq!(t.rule.control_id, "4.1.4");
    assert!(t.advisory.mitre_technique.contains("T1003.008"));
}
