//! 화면과 지킴이 사이의 경계. 화면은 이 trait만 보고, 실제 연결은 vh-guard의 `GuardHandle`,
//! 테스트는 가짜다.

use std::path::PathBuf;
use std::sync::Arc;

use vh_model::{
    ActionOutcome, ActionPlan, AutoLevel, GuardEvent, GuardPolicy, GuardStatus, ProcRef, Report,
    Snapshot,
};

/// 지킴이가 스캔마다 보내는 갱신.
#[derive(Debug, Clone)]
pub struct Update {
    pub snapshot: Arc<Snapshot>,
    pub report: Arc<Report>,
    pub policy: Arc<GuardPolicy>,
    pub status: GuardStatus,
    pub new_events: Vec<GuardEvent>,
    pub manual_result: Option<ManualResult>,
}

/// 화면에서 확인한 정리(`RunPlan`)의 결과.
#[derive(Debug, Clone)]
pub struct ManualResult {
    pub request_id: u64,
    pub outcomes: Vec<ActionOutcome>,
    pub state_dir: PathBuf,
}

/// 화면 → 지킴이 명령. 보내기는 막히지 않는다.
#[derive(Debug, Clone)]
pub enum Cmd {
    Pause,
    Resume,
    SetLevel(AutoLevel),
    SetScanInterval(u32),
    ResetCircuit,
    UndoDemote(ProcRef),
    ScanNow,
    RunPlan {
        request_id: u64,
        plan: ActionPlan,
        snapshot: Arc<Snapshot>,
    },
}

/// 끝낼 때 지킴이가 되돌린 것.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShutdownSummary {
    pub undemoted: Vec<ProcRef>,
    pub failed: Vec<(ProcRef, i32)>,
}

/// 받을 갱신이 없을 때와 지킴이 스레드가 사라졌을 때를 구분한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    Empty,
    Disconnected,
}

pub trait GuardLink: Send {
    fn send(&mut self, cmd: Cmd);
    fn try_recv(&mut self) -> Result<Update, RecvState>;
    /// 낮춘 우선순위를 되돌리고 지킴이 스레드가 끝날 때까지 기다린다.
    fn shutdown(self: Box<Self>) -> ShutdownSummary;
}
