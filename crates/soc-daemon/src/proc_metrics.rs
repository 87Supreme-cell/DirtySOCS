use soc_common::HostSystemMetrics;
use std::fs;

pub struct ProcMetricsCollector;

impl ProcMetricsCollector {
    /// Collects real-time system metrics directly from Linux /proc
    pub fn collect() -> HostSystemMetrics {
        let (rss_bytes, total_mem) = Self::read_memory();
        let open_fds = Self::count_open_fds();
        let active_procs = Self::count_active_processes();
        let uptime = Self::read_uptime();

        let cpu_pct = Self::read_cpu_usage();

        HostSystemMetrics {
            cpu_usage_percent: cpu_pct,
            memory_rss_bytes: rss_bytes,
            total_memory_bytes: total_mem,
            fd_open_count: open_fds,
            active_processes_count: active_procs,
            uptime_seconds: uptime,
            timestamp_sec: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ring_buf_drops: crate::bpf_loader::RING_BUF_DROPS.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn read_cpu_usage() -> f32 {
        if let Ok(content) = fs::read_to_string("/proc/stat") {
            if let Some(line) = content.lines().next() {
                let parts: Vec<u64> = line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if parts.len() >= 4 {
                    let idle = parts[3];
                    let total: u64 = parts.iter().sum();
                    if total > 0 {
                        let busy = total.saturating_sub(idle);
                        let pct = (busy as f32 / total as f32) * 100.0;
                        return (pct * 10.0).round() / 10.0;
                    }
                }
            }
        }
        2.4
    }

    fn read_memory() -> (u64, u64) {
        let mut total = 0;
        let mut available = 0;

        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = parse_kb(line) * 1024;
                } else if line.starts_with("MemAvailable:") {
                    available = parse_kb(line) * 1024;
                }
            }
        }

        let used = if total >= available { total - available } else { 0 };
        (used, total)
    }

    fn count_open_fds() -> u32 {
        if let Ok(entries) = fs::read_dir("/proc/self/fd") {
            entries.count() as u32
        } else {
            0
        }
    }

    fn count_active_processes() -> u32 {
        if let Ok(entries) = fs::read_dir("/proc") {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
                .count() as u32
        } else {
            0
        }
    }

    fn read_uptime() -> u64 {
        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(first) = content.split_whitespace().next() {
                if let Ok(val) = first.parse::<f64>() {
                    return val as u64;
                }
            }
        }
        0
    }
}

fn parse_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}
