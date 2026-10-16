#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub const PATH_MAX_LEN: usize = 128;
pub const COMM_MAX_LEN: usize = 32;
pub const ARGS_MAX_LEN: usize = 96;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum KernelEventType {
    Execve = 1,
    Connect = 2,
    Openat = 3,
}

/// Raw kernel event emitted via eBPF ring buffer for process executions (sys_enter_execve)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawExecEvent {
    pub event_type: u32,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_MAX_LEN],
    pub filename: [u8; PATH_MAX_LEN],
    pub args: [u8; ARGS_MAX_LEN],
}

impl RawExecEvent {
    #[cfg(feature = "std")]
    pub fn comm_str(&self) -> String {
        bytes_to_str(&self.comm)
    }

    #[cfg(feature = "std")]
    pub fn filename_str(&self) -> String {
        bytes_to_str(&self.filename)
    }

    #[cfg(feature = "std")]
    pub fn args_str(&self) -> String {
        bytes_to_str(&self.args)
    }
}

/// Raw kernel event emitted for socket connections (sys_enter_connect / sys_enter_bind)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawConnectEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub family: u16,
    pub port: u16,
    pub dest_ip: [u8; 16], // IPv4-mapped or IPv6
    pub comm: [u8; COMM_MAX_LEN],
    pub timestamp_ns: u64,
}

impl RawConnectEvent {
    #[cfg(feature = "std")]
    pub fn comm_str(&self) -> String {
        bytes_to_str(&self.comm)
    }
}

/// Raw kernel event emitted for file opens (sys_enter_openat)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawOpenatEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub filename: [u8; PATH_MAX_LEN],
    pub comm: [u8; COMM_MAX_LEN],
    pub timestamp_ns: u64,
}

impl RawOpenatEvent {
    #[cfg(feature = "std")]
    pub fn filename_str(&self) -> String {
        bytes_to_str(&self.filename)
    }

    #[cfg(feature = "std")]
    pub fn comm_str(&self) -> String {
        bytes_to_str(&self.comm)
    }
}

#[cfg(feature = "std")]
fn bytes_to_str(bytes: &[u8]) -> String {
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul_pos]).to_string()
}

// -----------------------------------------------------------------------------
// Normalized Telemetry Models & AI Contracts (Standard Library)
// -----------------------------------------------------------------------------

#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchRequest {
    pub timestamp: String,
    pub host_id: String,
    pub anomaly_window_sec: u32,
    pub telemetry_batch: Vec<TelemetryEvent>,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub subsystem: String, // "ebpf", "dbus", "systemd"
    #[serde(rename = "type")]
    pub event_type: String, // "exec_anomaly", "apparmor_denial", "service_failure"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationAdvisory {
    pub incident_id: String,
    pub severity: String, // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub mitre_technique: String,
    pub root_cause_analysis: String,
    pub risk_summary: String,
    pub recommended_actions: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub status: Option<String>, // "PENDING_REVIEW", "APPROVED", "DISMISSED", "EXECUTED"
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSystemMetrics {
    pub cpu_usage_percent: f32,
    pub memory_rss_bytes: u64,
    pub total_memory_bytes: u64,
    pub fd_open_count: u32,
    pub active_processes_count: u32,
    pub uptime_seconds: u64,
    pub timestamp_sec: u64,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    pub is_anomalous: bool,
    pub anomaly_reason: Option<String>,
}
