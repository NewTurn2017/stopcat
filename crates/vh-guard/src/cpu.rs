//! 연속 스캔 CPU%: 250ms 대기 없이 한 번만 수집하고, 직전 스캔의 `cpu_time_ns`와 비교한다.

use vh_model::{GuardPolicy, ProcRef, Snapshot};

use crate::memory::GuardMemory;

/// 직전 스캔의 `cpu_time_ns`(같은 ProcRef)와 비교해 `cpu_pct`를 채운다.
///
/// `cpu_pct = (cpu_now − cpu_prev) ns / (Δms × 1e6) × 100` (코어 1개 = 100, 음수는 0).
/// 이전 스캔이 있으면 `snapshot.cpu_sample_interval_ms = Some(Δms)`로 채워 vh-analyze의
/// Runaway·Heavy 판정이 돌게 한다(의미는 '두 샘플 간격'으로 같다). 반환: Δms(이전 스캔이 없거나
/// Δms == 0이면 None, 그때 cpu_pct는 전부 None).
pub fn fill_cpu_pct(snapshot: &mut Snapshot, prev: &GuardMemory) -> Option<u32> {
    let prev_at = prev.prev_taken_at_unix_ms?;
    let delta_ms = snapshot.taken_at_unix_ms.saturating_sub(prev_at);
    if delta_ms == 0 {
        for p in &mut snapshot.processes {
            p.cpu_pct = None;
        }
        snapshot.cpu_sample_interval_ms = None;
        return None;
    }
    let wall_ns = delta_ms as f64 * 1_000_000.0;
    for p in &mut snapshot.processes {
        let r = ProcRef {
            pid: p.pid,
            start_time_unix_ms: p.start_time_unix_ms,
        };
        p.cpu_pct = match (p.cpu_time_ns, prev.prev_cpu_time_ns.get(&r)) {
            (Some(now), Some(&before)) => {
                Some((now.saturating_sub(before) as f64 / wall_ns * 100.0) as f32)
            }
            _ => None,
        };
    }
    let delta = u32::try_from(delta_ms).unwrap_or(u32::MAX);
    snapshot.cpu_sample_interval_ms = Some(delta);
    Some(delta)
}

/// 이번 스냅샷의 `cpu_time_ns`·시각을 다음 스캔을 위해 기억한다.
pub fn remember(mem: &mut GuardMemory, snapshot: &Snapshot) {
    mem.prev_taken_at_unix_ms = Some(snapshot.taken_at_unix_ms);
    mem.prev_cpu_time_ns.clear();
    for p in &snapshot.processes {
        if let Some(ns) = p.cpu_time_ns {
            mem.prev_cpu_time_ns.insert(
                ProcRef {
                    pid: p.pid,
                    start_time_unix_ms: p.start_time_unix_ms,
                },
                ns,
            );
        }
    }
}

/// 평소 `scan_interval_ms`, `memory.pressure_level >= 2`면 `pressure_scan_interval_ms`.
pub fn next_scan_interval_ms(policy: &GuardPolicy, pressure_level: u32) -> u32 {
    if pressure_level >= 2 {
        policy.pressure_scan_interval_ms
    } else {
        policy.scan_interval_ms
    }
}
