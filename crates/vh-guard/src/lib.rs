//! vh-guard: 화면이 열려 있는 동안 도는 지킴이(W2, GUARD 레인 소유).
//!
//! 안전 바닥: 이 크레이트는 `kill`·`setpriority`를 직접 부르지 않는다. 모든 신호는
//! `vh_act::plan` / `vh_act::plan_priority` → `vh_act::execute` 안에서만(보호 규칙 R01~R17과
//! 신호 직전 start_time 재확인을 거쳐) 나간다. 알림은 `osascript`에 argv로만 전달한다.
//!
//! 구조:
//! - [`decide`]: 순수 판정(이전 기억 + 스냅샷 + 리포트 + 정책 → 이번 스캔에 할 일).
//! - [`engine::Engine`]: 동기 엔진(수집 → CPU% 보간 → 분석 → 판정 → 계획·실행 → 이벤트·알림).
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

pub use vh_model::{
    AutoLevel, DemotedProc, GuardEvent, GuardEventKind, GuardPolicy, GuardStatus, PendingAction,
    VhConfig,
};

pub use backend::{GuardBackend, RealGuardBackend};
pub use cpu::{fill_cpu_pct, next_scan_interval_ms};
pub use decide::{Candidate, Decisions, NotifyItem, Skip, SkipReason, decide, decide_lean};
pub use engine::Engine;
pub use handle::{
    GuardCommand, GuardGone, GuardHandle, GuardUpdate, ManualRunResult, ShutdownReport,
};
pub use lock::AllowListSignaler;
pub use mailbox::{UpdateReceiver, UpdateSender, mailbox};
pub use memory::{CpuStreak, Demoted, GuardMemory, Streak};
pub use notify::{
    Notifier, NotifyBatcher, NullNotifier, OsascriptNotifier, notify_name, osascript_argv,
};

/// 환경 변수 이름.
pub mod env {
    /// `notify|safe|aggressive`. 설정 파일보다 우선, 화면에서 못 바꿈.
    pub const GUARD_LEVEL: &str = "VH_GUARD_LEVEL";
    /// `off`면 실제 macOS 알림을 보내지 않는다.
    pub const NOTIFY: &str = "VH_NOTIFY";
    /// 쉼표 구분 pid 목록. 있으면 목록 밖 pid에는 어떤 신호도 가지 않는다.
    pub const E2E_ALLOW_PIDS: &str = "VH_E2E_ALLOW_PIDS";
    /// 상태 폴더(vh-act와 같다).
    pub const STATE_DIR: &str = "VH_STATE_DIR";
}
