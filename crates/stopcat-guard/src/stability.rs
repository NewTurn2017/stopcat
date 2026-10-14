//! 지킴이의 '불안정' 판정(W4). 순수 함수와, 스캔마다 기억을 갱신하는 [`observe`].
//!
//! 불안정 = 유효 건강(실제 `Report.health`와 시험용 강제 값 중 높은 쪽)이 주의 이상이거나, 스왑이 빠르게 늘어남.
//! 스왑 증가 = 창(`swap_window_ms`) 안 기록이 `swap_min_span_ms` 이상 쌓였고 최신값 − 창 안 최솟값 ≥ `swap_growth_bytes`.

use stopcat_model::{GuardPolicy, HealthLevel, ProcRef, Report, Snapshot, UnstableReason, UsageState};

use crate::memory::{GuardMemory, MAX_IDLE_TRACKED};

/// 한 스캔의 안정 판단.
#[derive(Debug, Clone, PartialEq)]
pub struct Stability {
    pub unstable: bool,
    /// 유효 건강(강제 포함).
    pub health: HealthLevel,
    pub reasons: Vec<UnstableReason>,
    /// 창 안 최신 − 최솟값. 이력이 `swap_min_span_ms` 미만이면 None.
    pub swap_delta_bytes: Option<i64>,
}

impl Stability {
    /// 판단 전(첫 스캔 전) 기본값.
    pub fn stable() -> Self {
        Stability {
            unstable: false,
            health: HealthLevel::Ok,
            reasons: Vec::new(),
            swap_delta_bytes: None,
        }
    }
}

/// `STOPCAT_E2E_FORCE_HEALTH` 해석. `STOPCAT_E2E_ALLOW_PIDS`가 있을 때만(값이 비어 있어도 '있음') 읽는다.
/// 값은 `watch`·`critical`(대소문자·앞뒤 공백 무시)만 받고, 그 밖(ok·빈 값·모르는 값)은 None.
pub fn forced_health_from(force: Option<&str>, allow_pids: Option<&str>) -> Option<HealthLevel> {
    allow_pids?;
    match force?.trim().to_ascii_lowercase().as_str() {
        "watch" => Some(HealthLevel::Watch),
        "critical" => Some(HealthLevel::Critical),
        _ => None,
    }
}

fn rank(h: HealthLevel) -> u8 {
    match h {
        HealthLevel::Ok => 0,
        HealthLevel::Watch => 1,
        HealthLevel::Critical => 2,
    }
}

/// 둘 중 높은 건강 수준.
pub fn max_health(a: HealthLevel, b: HealthLevel) -> HealthLevel {
    if rank(b) > rank(a) { b } else { a }
}

/// 스캔 결과를 기억에 반영한다(판정 전에 부른다). 엔진과 실험실 그림자 판정이 같이 쓴다.
/// - 강제 건강 값을 기록한다.
/// - 스왑 사용량을 창 안 기록에 더한다.
/// - `idle_since`: 분류의 사용 상태가 Idle이면 처음 본 시각을 남기고, Idle이 아니거나(Active·Unknown)
///   분류가 없거나 스냅샷에서 사라진 대상은 지운다. 건강과 관계없이(정상일 때도) 유지한다.
///   상한 `MAX_IDLE_TRACKED`를 넘는 새 대상은 넣지 않는다(기록 없음 = 자동 후보 아님, 닫힌 쪽).
pub fn observe(
    mem: &mut GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    forced: Option<HealthLevel>,
    policy: &GuardPolicy,
    now_ms: u64,
) {
    mem.forced_health = forced;
    mem.swap_samples
        .push_back((snapshot.taken_at_unix_ms, snapshot.memory.swap_used_bytes));
    let floor = snapshot
        .taken_at_unix_ms
        .saturating_sub(policy.swap_window_ms);
    while mem.swap_samples.front().is_some_and(|&(t, _)| t < floor) {
        mem.swap_samples.pop_front();
    }
    let idle: std::collections::HashSet<ProcRef> = report
        .classified
        .iter()
        .filter(|c| c.usage.state == UsageState::Idle)
        .map(|c| c.target)
        .collect();
    mem.idle_since.retain(|t, _| idle.contains(t));
    for t in idle {
        if mem.idle_since.len() >= MAX_IDLE_TRACKED && !mem.idle_since.contains_key(&t) {
            continue;
        }
        mem.idle_since.entry(t).or_insert(now_ms);
    }
}

/// 이번 스캔의 안정 판단(순수). `observe`가 반영된 기억을 받는다.
pub fn stability(prev: &GuardMemory, report: &Report, policy: &GuardPolicy) -> Stability {
    let health = match prev.forced_health {
        Some(f) => max_health(report.health.level, f),
        None => report.health.level,
    };
    let mut reasons = Vec::new();
    match health {
        HealthLevel::Ok => {}
        HealthLevel::Watch => reasons.push(UnstableReason::HealthWatch),
        HealthLevel::Critical => reasons.push(UnstableReason::HealthCritical),
    }
    let swap_delta_bytes = swap_delta(prev, policy);
    if swap_delta_bytes.is_some_and(|d| d >= policy.swap_growth_bytes as i64) {
        reasons.push(UnstableReason::SwapGrowing);
    }
    Stability {
        unstable: !reasons.is_empty(),
        health,
        reasons,
        swap_delta_bytes,
    }
}

fn swap_delta(prev: &GuardMemory, policy: &GuardPolicy) -> Option<i64> {
    let first = prev.swap_samples.front()?;
    let last = prev.swap_samples.back()?;
    if last.0.saturating_sub(first.0) < policy.swap_min_span_ms {
        return None;
    }
    let min = prev.swap_samples.iter().map(|&(_, b)| b).min()?;
    Some(last.1 as i64 - min as i64)
}
