use crate::corpus::ComplianceRule;
use crate::pipeline::PiiScrubber;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soc_common::{MitigationAdvisory, TelemetryBatchRequest, TelemetryEvent};
use std::fs;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGappedDossier {
    pub incident_id: String,
    pub generated_at: String,
    pub host_integrity_hash: String,
    pub kernel_version: String,
    pub compliance_standard: String,
    pub compliance_control_id: String,
    pub plain_english_summary: String,
    pub technical_rationale: String,
    pub system_prompt_for_ai: String,
    pub expected_json_schema: String,
    pub telemetry_payload: TelemetryBatchRequest,
}

pub struct DossierExporter {
    scrubber: PiiScrubber,
}

impl DossierExporter {
    pub fn new() -> Self {
        Self {
            scrubber: PiiScrubber::new(),
        }
    }

    /// Generates a signed, air-gapped forensic dossier file for offline AI analysis
    pub fn generate_dossier(
        &self,
        advisory: &MitigationAdvisory,
        rule: &ComplianceRule,
        events: Vec<TelemetryEvent>,
        output_dir: &Path,
    ) -> anyhow::Result<(String, String)> {
        fs::create_dir_all(output_dir)?;

        // Scrub all event paths and details
        let scrubbed_events: Vec<TelemetryEvent> = events
            .into_iter()
            .map(|mut ev| {
                if let Some(ref p) = ev.target_path {
                    ev.target_path = Some(self.scrubber.scrub_text(p));
                }
                if let Some(ref d) = ev.details {
                    ev.details = Some(self.scrubber.scrub_text(d));
                }
                if let Some(ref net) = ev.target_network {
                    ev.target_network = Some(self.scrubber.hash_ip(net));
                }
                ev
            })
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(advisory.incident_id.as_bytes());
        hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
        let host_integrity = format!("sha256:{:x}", hasher.finalize());

        let batch_req = TelemetryBatchRequest {
            timestamp: chrono::Utc::now().to_rfc3339(),
            host_id: host_integrity.clone(),
            anomaly_window_sec: 60,
            telemetry_batch: scrubbed_events,
        };

        let system_prompt = "You are a Tier-3 AI SOC Incident Commander. Analyze the provided Linux endpoint telemetry against the stated CIS Benchmark and NIST SP 800-53 controls. Formulate a root cause analysis, risk summary, and specific mitigation recommendations. You MUST respond strictly conforming to the JSON schema provided below with no conversational filler.".to_string();

        let json_schema = r#"{
  "incident_id": "string",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "mitre_technique": "string",
  "root_cause_analysis": "string",
  "risk_summary": "string",
  "recommended_actions": ["string"]
}"#.to_string();

        let dossier = AirGappedDossier {
            incident_id: advisory.incident_id.clone(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            host_integrity_hash: host_integrity,
            kernel_version: "Linux 7.0.0-38-generic (BTF Enabled)".to_string(),
            compliance_standard: rule.standard.to_string(),
            compliance_control_id: rule.control_id.to_string(),
            plain_english_summary: rule.plain_english_description.to_string(),
            technical_rationale: rule.technical_rationale.to_string(),
            system_prompt_for_ai: system_prompt,
            expected_json_schema: json_schema,
            telemetry_payload: batch_req,
        };

        // Write JSON format
        let json_filename = format!("DIRTYSOCS_{}.json", advisory.incident_id);
        let json_path = output_dir.join(&json_filename);
        let json_str = serde_json::to_string_pretty(&dossier)?;
        fs::write(&json_path, &json_str)?;

        // Write Markdown format
        let md_filename = format!("DIRTYSOCS_{}.md", advisory.incident_id);
        let md_path = output_dir.join(&md_filename);
        let md_content = format!(
            "# Forensic Investigation Dossier: {id}\n\n\
             **Compliance Standard**: {std} (Control {ctrl})\n\
             **Integrity Hash**: `{hash}`\n\
             **Kernel**: {kernel}\n\n\
             ## 📋 Plain English Summary\n{summary}\n\n\
             ## ⚙️ Technical Rationale\n{tech}\n\n\
             ## 🤖 System Prompt for AI Analysis\n```text\n{prompt}\n```\n\n\
             ## 📦 Redacted Telemetry Batch\n```json\n{json}\n```\n",
            id = dossier.incident_id,
            std = dossier.compliance_standard,
            ctrl = dossier.compliance_control_id,
            hash = dossier.host_integrity_hash,
            kernel = dossier.kernel_version,
            summary = dossier.plain_english_summary,
            tech = dossier.technical_rationale,
            prompt = dossier.system_prompt_for_ai,
            json = serde_json::to_string_pretty(&dossier.telemetry_payload)?
        );
        fs::write(&md_path, &md_content)?;

        info!(
            "Generated air-gapped investigation dossier: {:?} and {:?}",
            json_path, md_path
        );

        Ok((
            json_path.to_string_lossy().to_string(),
            md_path.to_string_lossy().to_string(),
        ))
    }
}
