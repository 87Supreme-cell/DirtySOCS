use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: &'static str,
    pub standard: &'static str, // "CIS RHEL 9", "NIST SP 800-53", "CISSP"
    pub control_id: &'static str,
    pub title: &'static str,
    pub plain_english_description: &'static str,
    pub technical_rationale: &'static str,
    pub default_mitre_technique: &'static str,
    pub default_severity: &'static str,
}

pub struct ComplianceCorpus;

impl ComplianceCorpus {
    pub const RULES: &'static [ComplianceRule] = &[
        ComplianceRule {
            id: "RULE-CIS-1.1.2",
            standard: "CIS RHEL 9",
            control_id: "1.1.2",
            title: "Ensure /tmp is mounted with noexec",
            plain_english_description: "A program was caught executing from a temporary directory (/tmp or /dev/shm). Temporary storage is meant for scratch files, not running applications. Attackers commonly download and run malware here.",
            technical_rationale: "Binaries launched from world-writable directories bypass normal software management controls. Execution violates CIS-RHEL-9-1.1.2 mount options.",
            default_mitre_technique: "T1204 - User Execution / T1059.004 - Unix Shell",
            default_severity: "CRITICAL",
        },
        ComplianceRule {
            id: "RULE-CIS-1.6",
            standard: "CIS RHEL 9",
            control_id: "1.6",
            title: "AppArmor / SELinux Mandatory Access Control Mediation",
            plain_english_description: "A desktop service or application attempted an action that was blocked by Linux security confinement (AppArmor). This usually indicates a sandboxed app exceeding its permissions or a security profile mismatch.",
            technical_rationale: "D-Bus mediation denial emitted when an application queries restricted desktop portal interfaces without explicit profile entitlement.",
            default_mitre_technique: "T1068 - Exploitation for Privilege Escalation",
            default_severity: "HIGH",
        },
        ComplianceRule {
            id: "RULE-CIS-4.1.4",
            standard: "CIS RHEL 9",
            control_id: "4.1.4",
            title: "Record Events That Modify User/Group Information",
            plain_english_description: "An unprivileged or suspicious process attempted to read or modify password databases (/etc/shadow or /etc/passwd).",
            technical_rationale: "Ring-0 openat syscall intercepted targeting restricted identity databases. Potential credential harvesting attempt.",
            default_mitre_technique: "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow",
            default_severity: "CRITICAL",
        },
        ComplianceRule {
            id: "RULE-NIST-AC-6",
            standard: "NIST SP 800-53 Rev 5",
            control_id: "AC-6",
            title: "Least Privilege Enforcement",
            plain_english_description: "A process attempted to perform high-privilege operations or elevate permissions outside its assigned role.",
            technical_rationale: "System call execution detected with unexpected effective UID transition or sensitive capability acquisition.",
            default_mitre_technique: "T1548 - Abuse Elevation Control Mechanism",
            default_severity: "HIGH",
        },
        ComplianceRule {
            id: "RULE-NIST-AU-6",
            standard: "NIST SP 800-53 Rev 5",
            control_id: "AU-6",
            title: "Audit Record Review, Analysis, and Reporting",
            plain_english_description: "Anomalous process churn or abnormal service failure rate detected, triggering automatic audit review.",
            technical_rationale: "Automated threshold gate triggered by sliding-window rate metrics crossing deterministic baseline limits.",
            default_mitre_technique: "T1082 - System Information Discovery",
            default_severity: "MEDIUM",
        },
    ];

    pub fn find_rule_for_exec(path: &str) -> Option<&'static ComplianceRule> {
        if path.starts_with("/tmp") || path.starts_with("/dev/shm") || path.starts_with("/var/tmp") {
            Self::RULES.iter().find(|r| r.id == "RULE-CIS-1.1.2")
        } else {
            None
        }
    }

    pub fn find_rule_for_openat(path: &str) -> Option<&'static ComplianceRule> {
        if path.contains("shadow") || path.contains("sudoers") || path.contains(".ssh") {
            Self::RULES.iter().find(|r| r.id == "RULE-CIS-4.1.4")
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn find_rule_for_apparmor() -> &'static ComplianceRule {
        Self::RULES.iter().find(|r| r.id == "RULE-CIS-1.6").unwrap()
    }
}
