//! 분석 결과 타입 (vh-analyze가 만들고 CLI가 그린다).
//!
//! Report의 문자열 필드(`*_ko`, `title`)에 argv 조각을 넣을 때는 `redact_argv` 결과만 쓴다.

use serde::{Deserialize, Serialize};

use crate::snapshot::Listener;

/// 대상 지정. PID만으로 대상을 가리키지 않는다(PID 재사용).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcRef {
    pub pid: i32,
    pub start_time_unix_ms: u64,
}

/// 도감 분류.
///
/// `AgentCli` = 대화형 에이전트 세션(claude, codex, omo). 절대 정리 대상이 아니다.
/// `AgentHelper` = 대화 맥락이 없는 에이전트 백엔드(codex app-server, codex-code-mode-host,
/// claude daemon, claude bg-*). 주인이 죽었으면 정리 대상이 될 수 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    System,
    AppHelper,
    GuiApp,
    AgentCli,
    AgentHelper,
    McpServer,
    DevServer,
    LanguageServer,
    Watcher,
    BuildTool,
    HeadlessBrowser,
    Emulator,
    VirtualMachine,
    LocalLlm,
    Database,
    TestTool,
    Tunnel,
    DevRuntime,
    Other,
}

/// 프로세스 한 개의 분류 결과.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classified {
    pub target: ProcRef,
    pub kind: Kind,
    pub label_ko: String,
    pub signature_id: Option<String>,
    pub project: Option<String>,
    /// 살아 있는 주인 세션일 때만.
    pub owner_session: Option<ProcRef>,
    /// 주인 PID(죽었어도). env CLAUDE_PID 값 등.
    pub owner_pid: Option<i32>,
    /// "lineage" | "env:CLAUDE_PID" | "env:CMUX_CLAUDE_PID" | "env:SENPI_PY_KERNEL_PARENT_PID" | "argv:spawned_by" | "tmp_cwd" …
    pub owner_source: Option<String>,
    /// "Claude 세션" 등.
    pub owner_label_ko: Option<String>,
    pub owner_alive: Option<bool>,
    /// 사용 판정. vh-analyze만 계산하고 GUARD·TUI는 다시 계산하지 않는다.
    pub usage: Usage,
}

/// 쓰고 있는지.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageState {
    /// 쓰고 있음 근거가 하나 이상.
    Active,
    /// 모든 축(CPU·디스크·연결·터미널·나이)이 측정됐고 전부 안 씀.
    Idle,
    /// 쓰고 있음 근거는 없지만 측정 못 한 축이 있음. 쓰고 있음으로 다룬다.
    Unknown,
}

/// 주인 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerState {
    /// `owner_alive == Some(true)`.
    Alive,
    /// 주인 pid·임시 세션이 끝남.
    Ended,
    /// 주인 정보가 없음. 구역표에서는 `Ended` 칸.
    Unknown,
    /// 주인 세션 없이 사용자·시스템이 직접 띄운 것(앱·시스템·launchd 잡·에이전트 세션 자신·터미널).
    /// 구역표에서는 `Alive` 칸.
    User,
}

/// 사용 판정 근거 코드. `Usage::reasons`에는 선언 순서로 중복 없이 들어간다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReason {
    /// 보호 근거(기록만, state를 Active로 만들지 않음).
    OwnerAlive,
    /// 보호 근거(기록만, state를 Active로 만들지 않음).
    UserOwned,
    HasTty,
    PeerOutsideSubtree,
    PeerExternal,
    PeerUnresolved,
    CpuActive,
    DiskActive,
    Young,
    NoPeers,
    InfraPeersOnly,
    CpuIdle,
    DiskIdle,
    /// 한 방향 보조 근거(기록만, state를 바꾸지 않음).
    LifetimeCpuLow,
    CpuUnknown,
    DiskUnknown,
    PeersUnknown,
}

/// 프로세스 한 개(자손 합산)의 사용 판정.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub state: UsageState,
    pub owner: OwnerState,
    pub reasons: Vec<UsageReason>,
    /// 자기 포함, 좀비 뺀 자손 수.
    pub subtree_procs: u32,
    /// 자기+자손 cpu_pct 합. 자기 cpu_pct가 None이면 None.
    pub subtree_cpu_pct: Option<f32>,
    /// 자기+자손 disk_io_delta_bytes 합. 자기 값이 None이면 None.
    pub subtree_disk_delta_bytes: Option<u64>,
    /// 자손 밖·기반 시설 아닌 loopback 상대 pid 수(중복 제거).
    pub outside_peer_count: u32,
}

impl Default for Usage {
    fn default() -> Self {
        Usage {
            state: UsageState::Unknown,
            owner: OwnerState::Unknown,
            reasons: Vec::new(),
            subtree_procs: 0,
            subtree_cpu_pct: None,
            subtree_disk_delta_bytes: None,
            outside_peer_count: 0,
        }
    }
}

impl Usage {
    /// '쓰고 있음'의 단일 정의: Idle이 아니면 쓰고 있다(Unknown 포함, 닫힌 쪽).
    /// GUARD 후보 조건, vh-act R18, TUI `c`, `vh fix` 기본 대상은 이 함수만 쓴다.
    pub fn in_use(&self) -> bool {
        self.state != UsageState::Idle
    }
}

/// 보고 구역. 화면·`--plain`·`--json`·지킴이는 이 값만 읽고 kind·신뢰도로 구역을 다시 만들지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// 필요 없음.
    Unneeded,
    /// 확인 필요.
    Check,
    /// 일하는 중(건드리지 않음).
    Working,
    /// 직접 하면 확보.
    Manual,
    /// 포트·한도·메모리 압력 같은 정보.
    Info,
}

/// 건강 수준.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    Ok,
    Watch,
    Critical,
}

/// 건강 요약.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub level: HealthLevel,
    pub headline_ko: String,
    pub reasons_ko: Vec<String>,
}

/// 묶음 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Project,
    AgentSession,
    App,
    System,
    Other,
}

/// 프로세스 묶음.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub kind: GroupKind,
    pub title: String,
    pub root: Option<String>,
    pub members: Vec<ProcRef>,
    pub footprint_bytes: u64,
    pub cpu_pct: Option<f32>,
}

/// 발견 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Orphan,
    LogicalOrphan,
    Duplicate,
    Zombie,
    Stopped,
    /// 순간 CPU가 코어 1개(100%) 이상. 구역은 사용 판정과 주인으로 정해진다.
    HighCpu,
    HeavyProcess,
    HeavyAgentSession,
    HeadlessBrowserLeftover,
    ExposedListener,
    KnownPortConflict,
    LimitNearing,
    MemoryPressure,
}

/// 신뢰도. 비교는 `Ord`가 아니라 `rank`·`meets`로 한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Likely,
    Possible,
}

impl Confidence {
    /// Confirmed=3, Likely=2, Possible=1
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Confirmed => 3,
            Confidence::Likely => 2,
            Confidence::Possible => 1,
        }
    }

    /// `self.rank() >= min.rank()`
    pub fn meets(self, min: Confidence) -> bool {
        self.rank() >= min.rank()
    }
}

/// 제안. JSON은 내부 태그: `{"type":"terminate","include_descendants":true}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Suggestion {
    None,
    Terminate {
        include_descendants: bool,
    },
    Demote,
    Resume,
    RestartParent {
        parent: ProcRef,
    },
    /// AgentCli. 절대 Terminate로 바꾸지 않는다.
    HandoffThenRestart,
    Review,
}

/// 발견 한 건.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// 결정적.
    pub id: String,
    pub kind: FindingKind,
    pub confidence: Confidence,
    pub targets: Vec<ProcRef>,
    pub title_ko: String,
    /// 한 줄 묶음용 짧은 이름(예: "appium :4723", "headless Chrome 7시간").
    pub short_ko: String,
    pub detail_ko: String,
    pub reason_codes: Vec<String>,
    pub reclaim_bytes: u64,
    /// 자손 포함일 때 자손 수, 아니면 0.
    pub descendant_count: u32,
    pub suggestion: Suggestion,
    /// 보고 구역(vh-analyze만 정한다).
    pub section: Section,
}

/// 포트 화면용 대기 소켓.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListenerView {
    pub listener: Listener,
    pub kind: Kind,
    pub label_ko: String,
    pub project: Option<String>,
    pub exposure_ko: Option<String>,
}

/// reclaimable_confirmed_bytes = Confirmed ∧ Terminate finding 대상(+자손)의 footprint, ProcRef 단위 중복 제거 합.
/// reclaimable_likely_bytes   = Likely ∧ Terminate 만(Confirmed 미포함). 화면 "최대 약 N GB" = 두 값의 합.
/// HandoffThenRestart·Review·Demote·Heavy*는 합계에 넣지 않는다.
///
/// 구역별 값(`unneeded_bytes`·`check_bytes`·`manual_bytes`)은 구역별 reclaim 대상(대상 + 자손 포함이면 자손)의
/// footprint 합, ProcRef 단위 중복 제거. 한 ProcRef가 여러 구역에 나오면 unneeded > check > manual 순으로
/// 한 곳에만 센다. working·info는 세지 않는다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub reclaimable_confirmed_bytes: u64,
    pub reclaimable_likely_bytes: u64,
    pub unneeded_bytes: u64,
    pub check_bytes: u64,
    pub manual_bytes: u64,
}

/// 분석 결과 전체.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub taken_at_unix_ms: u64,
    pub health: Health,
    pub classified: Vec<Classified>,
    pub groups: Vec<Group>,
    pub findings: Vec<Finding>,
    pub listeners: Vec<ListenerView>,
    pub totals: Totals,
}

/// 계보 한 칸.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainNode {
    pub target: ProcRef,
    pub name: String,
    pub label_ko: String,
}

/// `vh why` 설명.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Explanation {
    pub target: ProcRef,
    pub chain: Vec<ChainNode>,
    pub kind: Kind,
    pub label_ko: String,
    pub project: Option<String>,
    pub owner_ko: Option<String>,
    pub finding_ids: Vec<String>,
    pub listeners: Vec<Listener>,
    pub summary_ko: String,
}
