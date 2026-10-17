use soc_common::TelemetryEvent;
use soc_daemon::pipeline::SlidingWindowAggregator;
use std::time::Duration;

#[test]
fn test_sliding_window_collapses_noise() {
    let aggregator = SlidingWindowAggregator::new(Duration::from_secs(60));

    // Simulate 1,000 repetitive desktop CSS parsing warnings
    for i in 0..1000 {
        let ev = TelemetryEvent {
            subsystem: "journal".to_string(),
            event_type: "css_parse_warn".to_string(),
            process: Some("gnome-shell".to_string()),
            pid: Some(1840),
            ppid: None,
            target_interface: None,
            target_path: Some("desktop-styling.css".to_string()),
            target_network: None,
            unit: None,
            exit_code: None,
            count: 1,
            details: Some(format!("Error parsing css line {}", i)),
        };

        let result = aggregator.record(ev);
        if i == 0 {
            // First event is registered
            assert!(result.is_some());
        } else {
            // Subsequent 999 events are collapsed into the sliding window
            assert!(result.is_none());
        }
    }

    // Snapshot verifies total collapsed count is exactly 1,000
    let snapshot = aggregator.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].count, 1000);
    assert_eq!(snapshot[0].process.as_deref(), Some("gnome-shell"));
}
