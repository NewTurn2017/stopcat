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
    Runaway,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub reclaimable_confirmed_bytes: u64,
    pub reclaimable_likely_bytes: u64,
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
