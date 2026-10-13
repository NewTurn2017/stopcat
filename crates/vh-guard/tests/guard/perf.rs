//! GUARD_7 성능: 합성 2,000 프로세스 `decide` ≤ 5ms. `--nocapture`로 실측값을 찍는다.

use std::time::Instant;

use vh_analyze::synth::synth_snapshot;
use vh_guard::decide::decide;
use vh_guard::memory::GuardMemory;
use vh_guard::{AutoLevel, cpu};

use crate::common::safe;

#[test]
fn perf_decide_2000_under_5ms() {
    let mut s1 = synth_snapshot(2000, 42);
    let mut m = GuardMemory::new(AutoLevel::Safe);
    cpu::remember(&mut m, &s1);
    let mut s2 = synth_snapshot(2000, 42);
    s2.taken_at_unix_ms = s1.taken_at_unix_ms + 5000;
    for p in &mut s2.processes {
        p.cpu_time_ns = p.cpu_time_ns.map(|n| n + 500_000_000);
    }
    cpu::fill_cpu_pct(&mut s2, &m);
    let r2 = vh_analyze::analyze(&s2);
    let now = s2.taken_at_unix_ms;
    let policy = safe();
    let mut samples_us = Vec::new();
    for _ in 0..5 {
        let mut runs = Vec::new();
        for _ in 0..20 {
            let t = Instant::now();
            let d = decide(&m, &s2, &r2, &policy, now);
            runs.push(t.elapsed().as_micros());
            std::hint::black_box(d);
        }
        runs.sort_unstable();
        samples_us.push(runs[runs.len() / 2]);
    }
    samples_us.sort_unstable();
    let p50 = samples_us[samples_us.len() / 2];
    eprintln!(
        "decide 2000 procs ({} findings, {} classified): 5회 p50 = {} µs, 전체 {:?} µs, build={}",
        r2.findings.len(),
        r2.classified.len(),
        p50,
        samples_us,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    assert!(p50 <= 5_000, "decide p50 {p50} µs > 5ms");
    cpu::fill_cpu_pct(&mut s1, &GuardMemory::new(AutoLevel::Safe));
}
