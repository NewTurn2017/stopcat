//! 조치 타입 (vh-act가 만든다).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::report::ProcRef;

/// 사다리 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Cont,
    Term,
    Kill,
    Demote,
    /// `setpriority(PRIO_DARWIN_PROCESS, pid, 0)`: Demote를 되돌린다(W2).
    Undemote,
}

/// 계획된 조치 한 건.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedAction {
    /// Finding id 또는 "direct:<pid>:<start_ms>".
    pub finding_id: String,
    pub target: ProcRef,
    pub include_descendants: bool,
    /// 계획 시점 스냅샷 기준.
    pub descendant_count: u32,
    pub steps: Vec<Step>,
    pub grace_ms: u32,
    pub reason_ko: String,
    pub est_reclaim_bytes: u64,
}

/// 보호 규칙에 걸려 거부된 대상.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Refusal {
    pub target: ProcRef,
    pub rule: String,
    pub reason_ko: String,
}

/// 조치 계획.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionPlan {
    pub created_at_unix_ms: u64,
    pub total_deadline_ms: u64,
    pub items: Vec<PlannedAction>,
    pub refused: Vec<Refusal>,
}

/// 조치 뒤 대상의 최종 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalState {
    Exited,
    StillAlive,
    Skipped,
    Refused,
    Vanished,
    Reused,
}

/// 단계 한 번의 결과.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepResult {
    pub step: Step,
    pub pid: i32,
    pub at_unix_ms: u64,
    pub ok: bool,
    pub errno: Option<i32>,
}

/// 조치 한 건의 결과.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub action: PlannedAction,
    pub steps: Vec<StepResult>,
    pub final_state: FinalState,
    pub note_ko: String,
}

/// 종료 전에 저장하는 부활 기록. W1은 기록만 한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviveRecord {
    pub target: ProcRef,
    pub exe: Option<String>,
    /// 원문(로컬 파일에만, 권한 0600). 화면 표시는 `redact_argv`.
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// 허용 목록만.
    pub env: BTreeMap<String, String>,
    pub recorded_at_unix_ms: u64,
}
