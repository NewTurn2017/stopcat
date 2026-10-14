//! stopcat-guard: 화면이 열려 있는 동안 도는 지킴이(W2, GUARD 레인 소유).
//!
//! 안전 바닥: 이 크레이트는 `kill`·`setpriority`를 직접 부르지 않는다. 모든 신호는
//! `stopcat_act::plan` / `stopcat_act::plan_priority` → `stopcat_act::execute` 안에서만(보호 규칙 R01~R19와
//! 신호 직전 start_time 재확인을 거쳐) 나간다. 알림은 `osascript`에 argv로만 전달한다.
//!
//! W4 정책: 평소(건강 정상)에는 자동 조치·항목 알림·자동 예정이 0이고 보고만 한다. 맥이 불안정할 때만
//! (건강 주의 이상 또는 스왑 빠른 증가, [`stability`]) 구역 unneeded·쓰고 있지 않음인 것을 큰 것부터,
//! 정착 시간을 두며 정상으로 돌아올 때까지만 정리한다. 우선순위 자동 낮추기는 없다(화면 직접 낮추기만).
//!
//! 구조:
//! - [`decide`]: 순수 판정(이전 기억 + 스냅샷 + 리포트 + 정책 → 이번 스캔에 할 일).
//! - [`engine::Engine`]: 동기 엔진(수집 → CPU%·디스크 증가량 보간 → 분석 → 관찰 기억 → 판정 → 계획·실행 → 이벤트·알림).
//! - [`handle::GuardHandle`]: 엔진을 백그라운드 스레드 하나에 올리고 명령·갱신 채널로 잇는다.
//! - [`backend::GuardBackend`]: 수집·분석·계획·실행·알림·시계를 바꿔 끼우는 trait(테스트는 [`fake`]).

pub mod backend;
pub mod config;
pub mod cpu;
pub mod decide;
pub mod engine;
pub mod fake;
pub mod handle;
pub mod lock;
pub mod mailbox;
pub mod memory;
pub mod notify;
pub mod snap;
pub mod stability;

pub use stopcat_model::{
    AutoLevel, DemotedProc, GuardEvent, GuardEventKind, GuardPolicy, GuardStatus, PendingAction,
    StopcatConfig,
};

pub use backend::{GuardBackend, RealGuardBackend};
pub use cpu::{fill_cpu_pct, fill_disk_delta, next_scan_interval_ms};
pub use decide::{Candidate, Decisions, Skip, SkipReason, decide, decide_lean};
pub use engine::Engine;
pub use handle::{
    GuardCommand, GuardGone, GuardHandle, GuardUpdate, ManualRunResult, ShutdownReport,
};
pub use lock::AllowListSignaler;
pub use mailbox::{UpdateReceiver, UpdateSender, mailbox};
pub use memory::{Demoted, GuardMemory, MAX_IDLE_TRACKED, Streak};
pub use notify::{
    Notifier, NotifyBatcher, NullNotifier, OsascriptNotifier, notify_name, osascript_argv,
};
pub use stability::{Stability, forced_health_from, observe, stability};

/// 환경 변수 이름.
pub mod env {
    /// `notify|safe|aggressive`. 설정 파일보다 우선, 화면에서 못 바꿈.
    pub const GUARD_LEVEL: &str = "STOPCAT_GUARD_LEVEL";
    /// `off`면 실제 macOS 알림을 보내지 않는다.
    pub const NOTIFY: &str = "STOPCAT_NOTIFY";
    /// 쉼표 구분 pid 목록. 있으면 목록 밖 pid에는 어떤 신호도 가지 않는다.
    pub const E2E_ALLOW_PIDS: &str = "STOPCAT_E2E_ALLOW_PIDS";
    /// 상태 폴더(stopcat-act와 같다).
    pub const STATE_DIR: &str = "STOPCAT_STATE_DIR";
    /// 시험용 강제 불안정 `watch|critical`. `STOPCAT_E2E_ALLOW_PIDS`가 있을 때만 읽는다(W4).
    pub const E2E_FORCE_HEALTH: &str = "STOPCAT_E2E_FORCE_HEALTH";
}
