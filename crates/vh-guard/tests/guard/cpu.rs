//! GUARD_3 연속 스캔 CPU%.

use vh_guard::AutoLevel;
use vh_guard::cpu::{fill_cpu_pct, next_scan_interval_ms, remember};
use vh_guard::fake::*;
use vh_guard::memory::GuardMemory;

use crate::common::*;

#[test]
fn fills_from_previous_scan_and_sets_interval() {
    let mut p = proc_(101, 1, UID, OLD, "a");
    p.cpu_time_ns = Some(1_000_000_000);
    let s1 = snapshot(SELF_PID, UID, T0, vec![p.clone()]);
    let mut m = GuardMemory::new(AutoLevel::Safe);
    assert_eq!(fill_cpu_pct(&mut s1.clone(), &m), None);
    remember(&mut m, &s1);

    p.cpu_time_ns = Some(2_500_000_000);
    let mut s2 = snapshot(SELF_PID, UID, T0 + 5000, vec![p]);
    assert_eq!(fill_cpu_pct(&mut s2, &m), Some(5000));
    assert_eq!(s2.processes[0].cpu_pct, Some(30.0));
    assert_eq!(s2.cpu_sample_interval_ms, Some(5000));
}

#[test]
fn first_scan_pid_reuse_and_missing_cpu_time_are_none() {
    let mut p = proc_(101, 1, UID, OLD, "a");
    p.cpu_time_ns = Some(1_000_000_000);
    let s1 = snapshot(SELF_PID, UID, T0, vec![p.clone()]);
    let mut m = GuardMemory::new(AutoLevel::Safe);
    remember(&mut m, &s1);

    let mut reused = proc_(101, 1, UID, OLD + 1, "a");
    reused.cpu_time_ns = Some(9_000_000_000);
    let mut no_cpu = proc_(102, 1, UID, OLD, "b");
    no_cpu.cpu_time_ns = None;
    let mut s2 = snapshot(SELF_PID, UID, T0 + 5000, vec![reused, no_cpu]);
    assert_eq!(fill_cpu_pct(&mut s2, &m), Some(5000));
    assert_eq!(
        s2.processes[0].cpu_pct, None,
        "start_time이 다르면 다른 ProcRef"
    );
    assert_eq!(s2.processes[1].cpu_pct, None);

    let mut same_time = snapshot(SELF_PID, UID, T0, vec![p]);
    assert_eq!(fill_cpu_pct(&mut same_time, &m), None, "Δ0이면 계산 불가");
    assert_eq!(same_time.cpu_sample_interval_ms, None);
}

#[test]
fn interval_by_pressure() {
    let p = safe();
    assert_eq!(next_scan_interval_ms(&p, false), 5000, "정상");
    assert_eq!(
        next_scan_interval_ms(&p, true),
        2000,
        "불안정(W4: 압력 2 이상만이 아님)"
    );
}
