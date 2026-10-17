use regex::Regex;
use sha2::{Digest, Sha256};
use soc_common::TelemetryEvent;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// PII & Token Scrubber enforcing deterministic data redaction before export
pub struct PiiScrubber {
    home_dir_regex: Regex,
    root_dir_regex: Regex,
    bearer_token_regex: Regex,
    private_key_regex: Regex,
    password_regex: Regex,
    aws_key_regex: Regex,
    aws_slice_regex: Regex,
    jwt_regex: Regex,
    jwt_query_regex: Regex,
    ipv4_regex: Regex,
    hex_ipv4_regex: Regex,
    octal_ipv4_regex: Regex,
    dword_ipv4_regex: Regex,
    salt: String,
}

impl PiiScrubber {
    pub fn new() -> Self {
        let salt = format!("{:x}", rand_u64());
        Self {
            home_dir_regex: Regex::new(r"/home/[a-zA-Z0-9_\-]+").unwrap(),
            root_dir_regex: Regex::new(r"(?:^|[\s/])\.{0,2}/?root(?:\b|/[^\s,;]+)").unwrap(),
            bearer_token_regex: Regex::new(r"(?i)(Bearer|token|api_key|secret)\s*[:=\s]\s*([a-zA-Z0-9_\-\.]{12,})").unwrap(),
            private_key_regex: Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----").unwrap(),
            password_regex: Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)").unwrap(),
            aws_key_regex: Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{4,16}\b").unwrap(),
            aws_slice_regex: Regex::new(r"(?i)TOK_[A-Z]+\s*=\s*[^\s;]+").unwrap(),
            jwt_regex: Regex::new(r"(?i)\beyJ[a-zA-Z0-9_\-]{4,}\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b").unwrap(),
            jwt_query_regex: Regex::new(r"(?i)jwt=([^\s&,;]+)").unwrap(),
            ipv4_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            hex_ipv4_regex: Regex::new(r"\b0x[0-9a-fA-F]{1,2}\.0x[0-9a-fA-F]{1,2}\.0x[0-9a-fA-F]{1,2}\.0x[0-9a-fA-F]{1,2}\b").unwrap(),
            octal_ipv4_regex: Regex::new(r"\b0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\b").unwrap(),
            dword_ipv4_regex: Regex::new(r"\b([1-9][0-9]{8,9})\b").unwrap(),
            salt,
        }
    }

    /// Redacts file paths, command strings, and log messages
    pub fn scrub_text(&self, text: &str) -> String {
        // 1. Private keys & credentials
        let step1 = self.private_key_regex.replace_all(text, "[REDACTED_PRIVATE_KEY]");
        let step2 = self.jwt_regex.replace_all(&step1, "[REDACTED_JWT]");
        let step3 = self.jwt_query_regex.replace_all(&step2, "jwt=[REDACTED_JWT]");
        let step4 = self.aws_key_regex.replace_all(&step3, "[REDACTED_AWS_KEY]");
        let step5 = self.aws_slice_regex.replace_all(&step4, "[REDACTED_ENV_TOKEN]");
        let step6 = self.bearer_token_regex.replace_all(&step5, "$1=[REDACTED_TOKEN]");
        let step7 = self.password_regex.replace_all(&step6, "$1=[REDACTED_SECRET]");

        // 2. Directory paths & root traversals
        let step8 = self.home_dir_regex.replace_all(&step7, "/home/<user>");
        let step9 = self.root_dir_regex.replace_all(&step8, " /<user_home>");

        // 3. Hexadecimal IPv4 normalization & pseudonymization
        let step10 = self.hex_ipv4_regex.replace_all(&step9, |caps: &regex::Captures| {
            let parts: Vec<&str> = caps[0].split('.').collect();
            if parts.len() == 4 {
                let octets: Option<Vec<u8>> = parts.iter().map(|p| u8::from_str_radix(p.trim_start_matches("0x"), 16).ok()).collect();
                if let Some(o) = octets {
                    return self.hash_ip(&format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]));
                }
            }
            self.hash_ip(&caps[0])
        });

        // 4. Octal IPv4 normalization & pseudonymization
        let step11 = self.octal_ipv4_regex.replace_all(&step10, |caps: &regex::Captures| {
            let parts: Vec<&str> = caps[0].split('.').collect();
            if parts.len() == 4 {
                let octets: Option<Vec<u8>> = parts.iter().map(|p| u8::from_str_radix(p, 8).ok()).collect();
                if let Some(o) = octets {
                    return self.hash_ip(&format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]));
                }
            }
            self.hash_ip(&caps[0])
        });

        // 5. Dword / Integer 32-bit IPv4 pseudonymization (16777216..4294967295)
        let step12 = self.dword_ipv4_regex.replace_all(&step11, |caps: &regex::Captures| {
            if let Ok(num) = caps[1].parse::<u32>() {
                if num >= 16_777_216 {
                    let b = num.to_be_bytes();
                    return self.hash_ip(&format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
                }
            }
            caps[0].to_string()
        });

        // 6. Standard dotted-decimal IPv4
        let step13 = self.ipv4_regex.replace_all(&step12, |caps: &regex::Captures| {
            self.hash_ip(&caps[0])
        });

        step13.into_owned()
    }

    /// Pseudonymizes IP addresses using salted SHA-256 to allow correlation without exposing topology
    pub fn hash_ip(&self, ip_str: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.salt.as_bytes());
        hasher.update(ip_str.as_bytes());
        let hash = hasher.finalize();
        format!("ip-{}", hex::encode(&hash[..6]))
    }
}

fn rand_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x42424242)
}

/// 60-Second Sliding Window Deduplicator
/// Collapses thousands of noisy events (e.g. desktop CSS parse warnings or repeated D-Bus pings) into counts
pub struct SlidingWindowAggregator {
    window_duration: Duration,
    buckets: Mutex<HashMap<String, AggregatedEntry>>,
}

struct AggregatedEntry {
    event: TelemetryEvent,
    first_seen: Instant,
    last_seen: Instant,
    count: u32,
}

impl SlidingWindowAggregator {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            window_duration,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Ingests an event into the sliding window. Returns (event, is_new_or_threshold_crossed)
    pub fn record(&self, mut event: TelemetryEvent) -> Option<TelemetryEvent> {
        let mut buckets = self.buckets.lock().unwrap();
        let key = format!("{}:{}:{:?}", event.subsystem, event.event_type, event.process);

        let now = Instant::now();

        if let Some(entry) = buckets.get_mut(&key) {
            if now.duration_since(entry.first_seen) < self.window_duration {
                entry.count += event.count;
                entry.last_seen = now;
                return None; // Deduplicated, keep in sliding buffer
            } else {
                // Window expired: flush aggregated summary
                let flushed_count = entry.count;
                entry.first_seen = now;
                entry.last_seen = now;
                entry.count = event.count;
                event.count = flushed_count;
                return Some(event);
            }
        } else {
            buckets.insert(
                key,
                AggregatedEntry {
                    event: event.clone(),
                    first_seen: now,
                    last_seen: now,
                    count: event.count,
                },
            );
            Some(event)
        }
    }

    /// Drains current sliding window snapshots for dossier packaging
    pub fn snapshot(&self) -> Vec<TelemetryEvent> {
        let buckets = self.buckets.lock().unwrap();
        buckets
            .values()
            .map(|entry| {
                let mut ev = entry.event.clone();
                ev.count = entry.count;
                ev
            })
            .collect()
    }
}
