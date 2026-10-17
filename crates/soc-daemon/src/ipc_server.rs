use crate::pipeline::SlidingWindowAggregator;
use crate::proc_metrics::ProcMetricsCollector;
use crate::remediation::RemediationEngine;
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use soc_common::MitigationAdvisory;
use soc_ipc::{
    create_framed_codec, JsonRpcRequest, JsonRpcResponse, RemediationRequest,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

pub struct IpcServer {
    socket_path: PathBuf,
    aggregator: Arc<SlidingWindowAggregator>,
    active_advisories: Arc<Mutex<Vec<MitigationCardEntry>>>,
}

pub struct MitigationCardEntry {
    pub advisory: MitigationAdvisory,
    #[allow(dead_code)]
    pub target_pid: u32,
}

impl IpcServer {
    pub fn new(
        socket_path: PathBuf,
        aggregator: Arc<SlidingWindowAggregator>,
        active_advisories: Arc<Mutex<Vec<MitigationCardEntry>>>,
    ) -> Self {
        Self {
            socket_path,
            aggregator,
            active_advisories,
        }
    }

    /// Starts the Unix Domain Socket framed RPC server
    pub async fn run(&self) -> anyhow::Result<()> {
        // Unlink old socket file if it exists
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Bound Unix Domain Socket at: {:?}", self.socket_path);

        // Enforce strict POSIX 0660 permissions (Owner & Authorized Group read/write only)
        if let Ok(metadata) = fs::metadata(&self.socket_path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o660);
            let _ = fs::set_permissions(&self.socket_path, permissions);
            info!("Enforced socket permissions 0660 on {:?}", self.socket_path);
        }

        let aggregator = self.aggregator.clone();
        let advisories = self.active_advisories.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let agg = aggregator.clone();
                        let adv = advisories.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(stream, agg, adv).await {
                                warn!("IPC client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("IPC accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(
        stream: UnixStream,
        aggregator: Arc<SlidingWindowAggregator>,
        advisories: Arc<Mutex<Vec<MitigationCardEntry>>>,
    ) -> anyhow::Result<()> {
        // Enforce peer authorization via SO_PEERCRED
        if let Ok(cred) = stream.peer_cred() {
            let caller_uid = cred.uid();
            let daemon_uid = unsafe { libc::geteuid() };
            // Permit root (UID 0) or the UID matching the daemon's runtime identity
            if caller_uid != 0 && caller_uid != daemon_uid {
                warn!("Blocked unauthorized IPC connection from UID: {}", caller_uid);
                anyhow::bail!("Access denied: unauthorized peer UID {}", caller_uid);
            }
            info!("Authorized IPC client connection from UID: {}", caller_uid);
        }

        let codec = create_framed_codec();
        let mut framed = Framed::new(stream, codec);

        while let Some(frame) = framed.next().await {
            let bytes: BytesMut = frame?;
            let req: JsonRpcRequest = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = JsonRpcResponse::error(0, -32700, format!("Parse error: {}", e));
                    let resp_bytes = Bytes::from(serde_json::to_vec(&err_resp)?);
                    framed.send(resp_bytes).await?;
                    continue;
                }
            };

            let resp = match req.method.as_str() {
                "get_metrics" => {
                    let metrics = ProcMetricsCollector::collect();
                    JsonRpcResponse::success(req.id, metrics)
                }

                "get_logs" => {
                    let logs = aggregator.snapshot();
                    JsonRpcResponse::success(req.id, logs)
                }

                "get_advisories" => {
                    let adv_list: Vec<MitigationAdvisory> = advisories
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|entry| entry.advisory.clone())
                        .collect();
                    JsonRpcResponse::success(req.id, adv_list)
                }

                "execute_remediation" => {
                    match serde_json::from_value::<RemediationRequest>(req.params) {
                        Ok(rem_req) => {
                            let result = RemediationEngine::execute(rem_req);
                            JsonRpcResponse::success(req.id, result)
                        }
                        Err(e) => JsonRpcResponse::error(
                            req.id,
                            -32602,
                            format!("Invalid remediation parameters: {}", e),
                        ),
                    }
                }

                unknown => JsonRpcResponse::error(
                    req.id,
                    -32601,
                    format!("Method not found: '{}'", unknown),
                ),
            };

            let resp_bytes = Bytes::from(serde_json::to_vec(&resp)?);
            framed.send(resp_bytes).await?;
        }

        Ok(())
    }
}
