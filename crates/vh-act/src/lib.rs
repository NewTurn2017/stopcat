//! vh-act: 정리 계획과 단계적 종료 사다리 (ACT 소유).
//!
//! 사용자 맥의 프로세스에 신호를 보내는 유일한 코드다. 신호는 [`Signaler`] 구현을 거쳐서만
//! 나가고, 보내기 전에 보호 규칙(R01~R15)과 `start_time` 재확인을 통과해야 한다.
//! 이 크레이트는 사용자에게 묻지 않는다(확인은 CLI 몫).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

mod exec;
mod fake;
mod planner;
mod protect;
mod real;
pub mod rule;
mod store;

use vh_model::{
    ActionOutcome, ActionPlan, Confidence, Kind, Proc, ProcRef, Refusal, Report, Snapshot,
};

/// 어떤 Finding·대상을 실행 후보로 삼을지. CLI가 채운다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Selection {
    /// 비어 있으면 `Report.findings` 전체가 후보.
    pub finding_ids: Vec<String>,
    /// `vh fix --only <pid>`(여러 번 가능). 비어 있으면 제한 없음. `finding_ids`와 AND.
    pub pids: Vec<i32>,
    /// `--min-confidence`. 이보다 낮은 Finding은 조용히 제외(R13). `direct`에는 적용하지 않는다.
    pub min_confidence: Confidence,
    /// `vh kill <pid|:port>`: Finding 없이 대상 직접 지정. 비어 있지 않으면 나머지 필드는 무시.
    pub direct: Vec<DirectTarget>,
}

impl Default for Selection {
    fn default() -> Self {
        Selection {
            finding_ids: Vec::new(),
            pids: Vec::new(),
            min_confidence: Confidence::Likely,
            direct: Vec::new(),
        }
    }
}

/// 직접 지정 대상(`vh kill`). finding_id는 `direct:<pid>:<start_ms>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectTarget {
    pub target: ProcRef,
    /// `--tree`
    pub include_descendants: bool,
}

/// 실행 정책.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// TERM 뒤 KILL까지 기다리는 시간. 기본 3000.
    pub grace_ms: u32,
    /// `None` = Finding 제안의 `include_descendants`를 따른다. `Some(false)` = `--no-descendants`,
    /// `Some(true)` = `--tree`.
    pub include_descendants: Option<bool>,
    /// `Suggestion::Demote`를 실행 항목으로 만들지. 기본 false(`--demote`).
    pub allow_demote: bool,
    /// 한 번의 execute가 쓸 수 있는 총 시간. 기본 60_000. `ActionPlan.total_deadline_ms`로 실린다.
    pub total_deadline_ms: u64,
    /// 한 계획의 최대 항목 수. 기본 50.
    pub max_actions: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            grace_ms: 3000,
            include_descendants: None,
            allow_demote: false,
            total_deadline_ms: 60_000,
            max_actions: 50,
        }
    }
}

/// 실행 시점 생사.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Alive,
    /// SZOMB: 끝났지만 부모가 아직 회수하지 않음. 종료로 본다.
    Zombie,
    Gone,
}

/// 실행 시점에 커널에서 읽은 한 프로세스(`sysctl KERN_PROC_PID` + `proc_pidpath`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveProc {
    pub pid: i32,
    pub liveness: Liveness,
    /// `p_starttime.tv_sec * 1000 + p_starttime.tv_usec / 1000`
    pub start_time_unix_ms: u64,
    pub ppid: i32,
    pub pgid: i32,
    /// `e_ucred.cr_uid`
    pub uid: u32,
    /// `p_stat == SSTOP`
    pub stopped: bool,
    /// `proc_pidpath` (좀비·권한 없음이면 None)
    pub exe: Option<String>,
}

impl LiveProc {
    /// 없는 프로세스.
    pub fn gone(pid: i32) -> Self {
        LiveProc {
            pid,
            liveness: Liveness::Gone,
            start_time_unix_ms: 0,
            ppid: 0,
            pgid: 0,
            uid: 0,
            stopped: false,
            exe: None,
        }
    }

    /// 살아 있는 프로세스(가짜 세계·테스트용).
    pub fn alive(
        pid: i32,
        start_time_unix_ms: u64,
        ppid: i32,
        uid: u32,
        exe: Option<&str>,
    ) -> Self {
        LiveProc {
            pid,
            liveness: Liveness::Alive,
            start_time_unix_ms,
            ppid,
            pgid: pid,
            uid,
            stopped: false,
            exe: exe.map(str::to_string),
        }
    }
}

/// 커널 읽기(신호 아님).
pub trait Prober {
    /// 없으면 `Liveness::Gone`.
    fn probe(&self, pid: i32) -> LiveProc;
    /// 직접 자식 pid(`proc_listchildpids`). 실패하면 빈 Vec.
    fn children(&self, pid: i32) -> Vec<i32>;
    fn self_pid(&self) -> i32;
    /// `geteuid`
    fn self_uid(&self) -> u32;
    /// 실행 시점 조상 체인: `getppid` → ppid → … (최대 64단, 1 포함).
    fn ancestors_of_self(&self) -> Vec<i32>;
    /// `getpriority(PRIO_DARWIN_PROCESS, pid)`. Err(errno).
    /// 주의(2026-10-13 실측): pid가 자기 자신이 아니면 대상의 DARWIN_BG 상태가 아니라 0을 돌려준다.
    /// demote가 걸렸는지는 대상 task 우선순위(`PROC_PIDTASKINFO.pti_priority` = 4)로 확인한다.
    fn get_bg(&self, pid: i32) -> Result<i32, i32>;
    fn now_unix_ms(&self) -> u64;
    /// 가짜는 시계만 전진.
    fn sleep_ms(&self, ms: u64);
}

/// 신호 보내기. 커널에 쓰는 것은 이 trait 구현뿐이다.
pub trait Signaler {
    /// `kill(pid, sig)`, sig ∈ {SIGCONT, SIGTERM, SIGKILL}. Err(errno).
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32>;
    /// `setpriority(PRIO_DARWIN_PROCESS, pid, PRIO_DARWIN_BG)`. Err(errno).
    fn demote(&self, pid: i32) -> Result<(), i32>;
}

/// 진짜 커널 읽기.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealProber;

/// 진짜 신호.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSignaler;

/// 가짜 세계: 가짜 prober·signaler가 같이 보는 프로세스 표.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FakeWorld {
    pub procs: BTreeMap<i32, LiveProc>,
    pub children: BTreeMap<i32, Vec<i32>>,
    /// demote된 pid → 우선순위 값.
    pub bg: BTreeMap<i32, i32>,
    /// SIGTERM을 무시하는 pid.
    pub ignore_term: BTreeSet<i32>,
    /// 첫 SIGTERM을 받으면 이 자식들을 새로 띄운다(fork 시나리오).
    pub spawn_on_term: BTreeMap<i32, Vec<LiveProc>>,
}

/// 가짜 세계 공유 핸들.
pub type SharedWorld = Rc<RefCell<FakeWorld>>;

/// 테스트용 가짜 prober. 커널 호출 0회.
#[derive(Debug, Default)]
pub struct FakeProber {
    pub world: SharedWorld,
    pub self_pid: i32,
    pub self_uid: u32,
    pub ancestors: Vec<i32>,
    pub clock_ms: Cell<u64>,
}

/// 테스트용 가짜 signaler. 보낸 신호를 기록만 한다(커널 호출 0회).
/// `world`가 있으면 그 표에 신호 효과(TERM·KILL로 사라짐, CONT로 재개)를 반영한다.
#[derive(Debug, Default)]
pub struct FakeSignaler {
    pub world: Option<SharedWorld>,
    pub sent: RefCell<Vec<(i32, i32)>>,
    pub demoted: RefCell<Vec<i32>>,
    /// Some(errno)면 모든 호출이 그 errno로 실패.
    pub fail_with: Option<i32>,
}

/// execute 실행 환경.
pub struct ExecEnv<'a> {
    pub signaler: &'a dyn Signaler,
    pub prober: &'a dyn Prober,
    /// 감사 로그·부활 기록 폴더. CLI는 [`state_dir`]로, 테스트는 임시 폴더로 채운다.
    pub state_dir: PathBuf,
    /// plan에 쓴 것과 같은 스냅샷(부활 기록의 exe·argv·cwd·env 원본).
    pub snapshot: &'a Snapshot,
    /// 감사 로그 `run_id`.
    pub run_id: String,
}

/// 보호 규칙 평가 입력.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectCtx<'a> {
    pub target: ProcRef,
    /// 신호 직전 확인이면 Some.
    pub live: Option<&'a LiveProc>,
    /// 스냅샷의 같은 ProcRef.
    pub snap: Option<&'a Proc>,
    /// `Report.classified`의 Kind(계획 때만).
    pub kind: Option<Kind>,
    pub self_pid: i32,
    pub self_uid: u32,
    pub self_ancestors: &'a [i32],
    /// 대상의 스냅샷 자손과 그 Kind(R09).
    pub subtree_kinds: &'a [(ProcRef, Kind)],
}

/// 감사 로그 한 줄(`<state>/audit.jsonl`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at_unix_ms: u64,
    pub run_id: String,
    pub finding_id: String,
    pub target: ProcRef,
    /// 실제로 신호·확인한 pid(자손이면 자손 pid).
    pub subject_pid: i32,
    pub event: AuditEvent,
    pub ok: bool,
    pub errno: Option<i32>,
    pub reason_ko: String,
}

/// 감사 이벤트 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    PlanItem,
    PlanRefused,
    ExecStart,
    ReviveSaved,
    Precheck,
    Cont,
    Term,
    Kill,
    Demote,
    Exited,
    StillAlive,
    Reused,
    Vanished,
    Skipped,
    ExecEnd,
}

/// 상태 폴더: `VH_STATE_DIR`(비어 있지 않으면) → 없으면 `$HOME/Library/Application Support/vibe-health`.
/// 폴더가 없으면 0700으로 만든다.
pub fn state_dir() -> std::io::Result<PathBuf> {
    store::state_dir()
}

/// `<state>/audit.jsonl`
pub fn audit_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("audit.jsonl")
}

/// `<state>/revive`
pub fn revive_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("revive")
}

/// 계획을 만든다. 신호 0회. 계획 시점 보호 규칙을 적용해 items·refused를 채운다.
pub fn plan(s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
    planner::plan(s, r, sel, policy)
}

/// 계획을 실행한다. 사용자에게 묻지 않는다. 결과는 `plan.items`와 같은 순서·개수.
pub fn execute(plan: &ActionPlan, env: &ExecEnv<'_>) -> Vec<ActionOutcome> {
    exec::execute(plan, env)
}

/// 보호 규칙 평가(순수 함수). 처음 걸린 규칙(R01→R10 순)을 돌려준다.
pub fn check_protection(ctx: &ProtectCtx<'_>) -> Option<Refusal> {
    protect::check(ctx)
}
