//! 이전 스캔들의 기억. 순수 [`crate::decide`]의 입력이고, 엔진(과 [`crate::stability::observe`])만 갱신한다.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use vh_model::{AutoLevel, Confidence, FindingKind, HealthLevel, ProcRef};

/// `idle_since`에 두는 대상 수 상한. 넘는 새 대상은 기록하지 않는다(자동 후보가 되지 않는 닫힌 쪽).
pub const MAX_IDLE_TRACKED: usize = 8192;

/// 자동 종료 후보의 연속 확인(불안정한 스캔끼리만 센다).
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

/// 이 세션이 우선순위를 낮춘 대상(화면에서 직접 낮춘 것만, W4부터 자동 낮추기 없음).
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
    /// 직전 스냅샷 시각(연속 스캔 CPU%·디스크 증가량 계산용).
    pub prev_taken_at_unix_ms: Option<u64>,
    /// 직전 스냅샷의 `cpu_time_ns`(ProcRef = pid + start_time).
    pub prev_cpu_time_ns: HashMap<ProcRef, u64>,
    /// 직전 스냅샷의 디스크 읽기+쓰기 누적 바이트.
    pub prev_disk_bytes: HashMap<ProcRef, u64>,
    pub term_streak: HashMap<ProcRef, Streak>,
    /// 이 세션이 낮춘 것(종료 때 되돌린다). 화면에서 확인한 정리(RunPlan)의 Demote.
    pub demoted: BTreeMap<ProcRef, Demoted>,
    /// 자동 종료 "시도" 시각(`rate_window_ms` 안 것만 유지). 수동 RunPlan은 세지 않는다.
    pub terminations: VecDeque<u64>,
    pub circuit_open: bool,
    pub circuit_opened_at_unix_ms: Option<u64>,
    pub paused: bool,
    pub level: AutoLevel,
    /// 계획·실행 단계에서 거부되거나 실패한 대상. 다시 시도·기록하지 않는다(수준 변경·차단기 해제 때 비움).
    pub refused: HashSet<ProcRef>,
    /// 사라진 것으로 보여 되돌리려다 실패한 낮춘 대상. 스캔마다 다시 시도하지 않고 종료 때만 다시 시도한다.
    pub undemote_failed: HashSet<ProcRef>,
    /// 시험용 강제 건강 값(스캔마다 백엔드에서 받는다).
    pub forced_health: Option<HealthLevel>,
    /// (스냅샷 시각, 스왑 사용 바이트). `swap_window_ms` 안 것만.
    pub swap_samples: VecDeque<(u64, u64)>,
    /// 지킴이가 직접 본 '안 쓰고 있음(Idle)' 시작 시각. 정상일 때도 유지하고, Idle이 아니면 지운다.
    pub idle_since: HashMap<ProcRef, u64>,
    /// 불안정으로 바뀐 시각(정상이면 None).
    pub unstable_since_unix_ms: Option<u64>,
    /// 마지막 자동 정리 회차 시각(정착 시간 기준). 정상으로 돌아오면 지운다.
    pub last_round_at_unix_ms: Option<u64>,
    /// 마지막 불안정 알림 시각(쿨다운).
    pub last_unstable_notified_at_unix_ms: Option<u64>,
}

impl GuardMemory {
    pub fn new(level: AutoLevel) -> Self {
        GuardMemory {
            scan_seq: 0,
            prev_taken_at_unix_ms: None,
            prev_cpu_time_ns: HashMap::new(),
            prev_disk_bytes: HashMap::new(),
            term_streak: HashMap::new(),
            demoted: BTreeMap::new(),
            terminations: VecDeque::new(),
            circuit_open: false,
            circuit_opened_at_unix_ms: None,
            paused: false,
            level,
            refused: HashSet::new(),
            undemote_failed: HashSet::new(),
            forced_health: None,
            swap_samples: VecDeque::new(),
            idle_since: HashMap::new(),
            unstable_since_unix_ms: None,
            last_round_at_unix_ms: None,
            last_unstable_notified_at_unix_ms: None,
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

    /// 연속 확인·거부 기억을 비운다(일시정지·수준 변경·차단기 해제 뒤 다시 N번 확인하게).
    /// `idle_since`는 관찰이라 비우지 않는다.
    pub fn reset_streaks(&mut self) {
        self.term_streak.clear();
        self.refused.clear();
    }
}
