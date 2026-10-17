use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::codec::LengthDelimitedCodec;

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/dirtysocs.sock";
pub const SECURE_SOCKET_DIR: &str = "/run/dirtysocs";
pub const SECURE_SOCKET_PATH: &str = "/run/dirtysocs/dirtysocs.sock";

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success<T: Serialize>(id: u64, result: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(serde_json::to_value(result).unwrap_or(serde_json::Value::Null)),
            error: None,
        }
    }

    pub fn error(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Strictly typed parameters for remediation invocation.
/// Barred from arbitrary shell or dynamic script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRequest {
    pub action: String, // "SIGTERM_PROCESS", "SIGKILL_PROCESS", "FREEZE_CGROUP", "RESTART_SYSTEMD_UNIT"
    pub incident_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_start_time: Option<u64>,
    pub operator_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResponse {
    pub success: bool,
    pub action_taken: String,
    pub details: String,
    pub timestamp_sec: u64,
}

/// Helper function to configure length-delimited framed codec
/// Standard 4-byte big-endian frame prefix up to 16MB maximum payload.
pub fn create_framed_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .max_frame_length(16 * 1024 * 1024)
        .new_codec()
}
