//! 불안정 판정 입력(W4): 시험용 강제 건강 값.

use vh_guard::forced_health_from;
use vh_model::HealthLevel;

#[test]
fn forced_health_needs_allow_pids_present() {
    assert_eq!(forced_health_from(Some("watch"), None), None);
    assert_eq!(forced_health_from(Some("critical"), None), None);
}

#[test]
fn forced_health_reads_watch_and_critical_when_allow_pids_present_even_empty() {
    assert_eq!(
        forced_health_from(Some("watch"), Some("")),
        Some(HealthLevel::Watch)
    );
    assert_eq!(
        forced_health_from(Some(" CRITICAL "), Some("1,2")),
        Some(HealthLevel::Critical)
    );
}

#[test]
fn forced_health_ignores_ok_unknown_and_missing_values() {
    assert_eq!(forced_health_from(Some("ok"), Some("")), None);
    assert_eq!(forced_health_from(None, Some("")), None);
    assert_eq!(forced_health_from(Some(""), Some("1")), None);
    assert_eq!(forced_health_from(Some("panic"), Some("1")), None);
}
