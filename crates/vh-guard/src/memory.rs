//! 이전 스캔들의 기억. 순수 [`crate::decide`]의 입력이고, 엔진만 갱신한다.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use vh_model::{AutoLevel, Confidence, FindingKind, ProcRef};

use crate::decide::SkipReason;

/// 자동 종료 후보의 연속 확인.
#[derive(Debug, Clone, PartialEq)]
pub struct Streak {
    pub finding_id: String,
    pub finding_kind: FindingKind,
    pub confidence: Confidence,
    pub include_descendants: bool,
    /// 연속으로 같은 판정을 받은 스캔 수(이번 스캔 포함).
    pub seen: u32,
    pub first_seen_at_unix_ms: u64,
}

/// 폭주(CPU) 연속 확인.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuStreak {
    pub seen: u32,
    pub last_pct: f32,
}

/// 이 세션이 우선순위를 낮춘 대상.
#[derive(Debug, Clone, PartialEq)]
pub struct Demoted {
    pub at_unix_ms: u64,
    pub label_ko: String,
    pub finding_id: String,
}

/// 지킴이 기억.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardMemory {
    /// 완료한 스캔 수.
    pub scan_seq: u64,
    /// 직전 스냅샷 시각(연속 스캔 CPU% 계산용).
    pub prev_taken_at_unix_ms: Option<u64>,
    /// 직전 스냅샷의 `cpu_time_ns`(ProcRef = pid + start_time).
    pub prev_cpu_time_ns: HashMap<ProcRef, u64>,
    pub term_streak: HashMap<ProcRef, Streak>,
    pub cpu_streak: HashMap<ProcRef, CpuStreak>,
    /// 이 세션이 낮춘 것(종료 때 되돌린다). 화면에서 확인한 정리(RunPlan)의 Demote도 들어간다.
    pub demoted: BTreeMap<ProcRef, Demoted>,
    /// 자동 종료 "시도" 시각(`rate_window_ms` 안 것만 유지). 수동 RunPlan은 세지 않는다.
    pub terminations: VecDeque<u64>,
    pub circuit_open: bool,
    pub circuit_opened_at_unix_ms: Option<u64>,
    pub paused: bool,
    pub level: AutoLevel,
    /// 이미 알린 (대상, 사유). 같은 알림을 스캔마다 반복하지 않는다.
    pub notified: HashSet<(ProcRef, SkipReason)>,
    /// 계획·실행 단계에서 거부되거나 실패한 대상. 다시 시도·기록하지 않는다(수준 변경·차단기 해제 때 비움).
    pub refused: HashSet<ProcRef>,
    /// 사라진 것으로 보여 되돌리려다 실패한 낮춘 대상. 스캔마다 다시 시도하지 않고 종료 때만 다시 시도한다
    /// (`demoted`에서 빠지면 함께 지운다).
    pub undemote_failed: HashSet<ProcRef>,
}

impl GuardMemory {
    pub fn new(level: AutoLevel) -> Self {
        GuardMemory {
            scan_seq: 0,
            prev_taken_at_unix_ms: None,
            prev_cpu_time_ns: HashMap::new(),
            term_streak: HashMap::new(),
            cpu_streak: HashMap::new(),
            demoted: BTreeMap::new(),
            terminations: VecDeque::new(),
            circuit_open: false,
            circuit_opened_at_unix_ms: None,
            paused: false,
            level,
            notified: HashSet::new(),
            refused: HashSet::new(),
            undemote_failed: HashSet::new(),
        }
    }

    /// 창 안 자동 종료 시도 수.
    pub fn terminations_in_window(&self, now_ms: u64, window_ms: u64) -> u32 {
        let floor = now_ms.saturating_sub(window_ms);
        self.terminations.iter().filter(|&&t| t >= floor).count() as u32
    }

    /// 창 밖 기록을 버린다.
    pub fn prune_window(&mut self, now_ms: u64, window_ms: u64) {
        let floor = now_ms.saturating_sub(window_ms);
        while self.terminations.front().is_some_and(|&t| t < floor) {
            self.terminations.pop_front();
        }
    }

    /// 연속 확인·거부·알림 기억을 비운다(일시정지·수준 변경·차단기 해제 뒤 다시 N번 확인하게).
    pub fn reset_streaks(&mut self) {
        self.term_streak.clear();
        self.cpu_streak.clear();
        self.refused.clear();
        self.notified.clear();
    }
}
