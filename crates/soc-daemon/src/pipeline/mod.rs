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
    jwt_regex: Regex,
    ipv4_regex: Regex,
    salt: String,
}

impl PiiScrubber {
    pub fn new() -> Self {
        let salt = format!("{:x}", rand_u64());
        Self {
            home_dir_regex: Regex::new(r"/home/[a-zA-Z0-9_\-]+").unwrap(),
            root_dir_regex: Regex::new(r"/(root|var/home/[a-zA-Z0-9_\-]+|Users/[a-zA-Z0-9_\-]+)").unwrap(),
            bearer_token_regex: Regex::new(r"(?i)(Bearer|token|api_key|secret)\s*[:=\s]\s*([a-zA-Z0-9_\-\.]{12,})").unwrap(),
            private_key_regex: Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]+-----END [A-Z ]+PRIVATE KEY-----").unwrap(),
            password_regex: Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)").unwrap(),
            aws_key_regex: Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            jwt_regex: Regex::new(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b").unwrap(),
            ipv4_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            salt,
        }
    }

    /// Redacts file paths, command strings, and log messages
    pub fn scrub_text(&self, text: &str) -> String {
        let step1 = self.private_key_regex.replace_all(text, "[REDACTED_PRIVATE_KEY]");
        let step2 = self.jwt_regex.replace_all(&step1, "[REDACTED_JWT]");
        let step3 = self.aws_key_regex.replace_all(&step2, "[REDACTED_AWS_KEY]");
        let step4 = self.bearer_token_regex.replace_all(&step3, "$1=[REDACTED_TOKEN]");
        let step5 = self.password_regex.replace_all(&step4, "$1=[REDACTED_SECRET]");
        let step6 = self.home_dir_regex.replace_all(&step5, "/home/<user>");
        let step7 = self.root_dir_regex.replace_all(&step6, "/<user_home>");
        let step8 = self.ipv4_regex.replace_all(&step7, |caps: &regex::Captures| {
            self.hash_ip(&caps[0])
        });
        step8.into_owned()
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
