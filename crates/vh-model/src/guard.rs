//! 지킴이 타입 (W2 추가분, vh-guard가 만들고 CLI가 그린다).
//!
//! 문자열 필드(`*_ko`)에 argv 조각을 넣을 때는 `redact_argv` 결과만 쓴다.

use serde::{Deserialize, Serialize};

use crate::action::Step;
use crate::report::{Confidence, Kind, ProcRef};

/// 지킴이 자동 처리 수준.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoLevel {
    NotifyOnly,
    Safe,
    Aggressive,
}

impl AutoLevel {
    /// `VH_GUARD_LEVEL` 값 해석(대소문자 무시): "notify"·"notify_only" → NotifyOnly,
    /// "safe" → Safe, "aggressive" → Aggressive. 그 밖은 None — 호출하는 쪽은 NotifyOnly로 내려가고 경고한다.
    pub fn from_env_value(s: &str) -> Option<AutoLevel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "notify" | "notify_only" => Some(AutoLevel::NotifyOnly),
            "safe" => Some(AutoLevel::Safe),
            "aggressive" => Some(AutoLevel::Aggressive),
            _ => None,
        }
    }
}

/// 지킴이 정책. 기본값은 `for_level`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardPolicy {
    pub level: AutoLevel,
    pub min_confidence: Confidence,
    pub auto_demote: bool,
    /// 압력 4(위험)이면 회수량 큰 것부터.
    pub pressure_largest_first: bool,
    pub scan_interval_ms: u32,
    /// memory.pressure_level >= 2일 때.
    pub pressure_scan_interval_ms: u32,
    /// 같은 ProcRef가 연속 N번 스캔에서 같은 판정이어야 자동 조치.
    pub persistence_scans: u32,
    pub min_process_age_ms: u64,
    pub auto_terminate_kinds: Vec<Kind>,
    pub notify_only_kinds: Vec<Kind>,
    /// 코어 1개 = 100. 비교는 `>=`.
    pub runaway_cpu_pct: f32,
    pub runaway_sustained_scans: u32,
    /// `rate_window_ms` 안 자동 종료 "시도" 수 상한.
    pub max_auto_terminations: u32,
    pub rate_window_ms: u64,
    pub grace_ms: u32,
    pub notify_min_interval_ms: u64,
}

const SAFE_AUTO_KINDS: [Kind; 6] = [
    Kind::McpServer,
    Kind::DevServer,
    Kind::LanguageServer,
    Kind::Watcher,
    Kind::HeadlessBrowser,
    Kind::AgentHelper,
];

const NOTIFY_KINDS: [Kind; 5] = [
    Kind::Emulator,
    Kind::VirtualMachine,
    Kind::Database,
    Kind::LocalLlm,
    Kind::Tunnel,
];

const AGGRESSIVE_EXTRA_KINDS: [Kind; 6] = [
    Kind::BuildTool,
    Kind::TestTool,
    Kind::DevRuntime,
    Kind::Emulator,
    Kind::LocalLlm,
    Kind::Tunnel,
];

impl GuardPolicy {
    /// 수준별 기본값(계약 W2 확정본의 표). System·AppHelper·GuiApp·AgentCli·Other는 어느 목록에도 없다.
    pub fn for_level(level: AutoLevel) -> GuardPolicy {
        let (min_confidence, auto_demote, pressure_largest_first, auto, notify) = match level {
            AutoLevel::NotifyOnly => (
                Confidence::Confirmed,
                false,
                false,
                Vec::new(),
                NOTIFY_KINDS.to_vec(),
            ),
            AutoLevel::Safe => (
                Confidence::Confirmed,
                true,
                false,
                SAFE_AUTO_KINDS.to_vec(),
                NOTIFY_KINDS.to_vec(),
            ),
            AutoLevel::Aggressive => (
                Confidence::Likely,
                true,
                true,
                SAFE_AUTO_KINDS
                    .iter()
                    .chain(AGGRESSIVE_EXTRA_KINDS.iter())
                    .copied()
                    .collect(),
                vec![Kind::VirtualMachine, Kind::Database],
            ),
        };
        GuardPolicy {
            level,
            min_confidence,
            auto_demote,
            pressure_largest_first,
            scan_interval_ms: 5_000,
            pressure_scan_interval_ms: 2_000,
            persistence_scans: 2,
            min_process_age_ms: 600_000,
            auto_terminate_kinds: auto,
            notify_only_kinds: notify,
            runaway_cpu_pct: 100.0,
            runaway_sustained_scans: 3,
            max_auto_terminations: 5,
            rate_window_ms: 600_000,
            grace_ms: 3_000,
            notify_min_interval_ms: 30_000,
        }
    }
}

/// 자동 처리 기록 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardEventKind {
    AutoTerminated,
    Demoted,
    Undemoted,
    Notified,
    Skipped,
    Refused,
    CircuitOpen,
    CircuitReset,
    Paused,
    Resumed,
    LevelChanged,
    ScanError,
}

/// 자동 처리 기록 한 건.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardEvent {
    pub at_unix_ms: u64,
    pub kind: GuardEventKind,
    pub target: Option<ProcRef>,
    pub finding_id: Option<String>,
    /// 감사 로그 run과 연결.
    pub run_id: Option<String>,
    pub label_ko: String,
    pub detail_ko: String,
    pub reclaimed_bytes: u64,
}

/// 자동 조치 조건을 기다리는 대상(화면의 "자동 예정 n/N").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingAction {
    pub target: ProcRef,
    pub finding_id: String,
    pub kind: Kind,
    pub label_ko: String,
    /// Term(사다리) 또는 Demote.
    pub step: Step,
    pub seen_scans: u32,
    pub needed_scans: u32,
    /// 조건이 다 차기까지 남은 대략 시간.
    pub eta_ms: Option<u64>,
}

/// 이 세션이 우선순위를 낮춘 대상(종료 때 되돌림).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DemotedProc {
    pub target: ProcRef,
    pub label_ko: String,
    pub at_unix_ms: u64,
}

/// 지킴이 상태.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardStatus {
    pub level: AutoLevel,
    /// `VH_GUARD_LEVEL`로 고정(화면에서 못 바꿈).
    pub level_locked_by_env: bool,
    pub paused: bool,
    /// 속도 제한을 넘어 알림만으로 내려간 상태.
    pub circuit_open: bool,
    pub circuit_opened_at_unix_ms: Option<u64>,
    pub terminations_in_window: u32,
    pub scan_seq: u64,
    pub scan_error_streak: u32,
    pub last_scan_at_unix_ms: u64,
    pub last_scan_ms: f64,
    pub next_scan_at_unix_ms: u64,
    pub demoted: Vec<DemotedProc>,
    pub pending: Vec<PendingAction>,
}

/// `<state_dir>/config.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VhConfig {
    pub schema_version: u32,
    pub auto_level: AutoLevel,
    pub first_run_done: bool,
    pub scan_interval_ms: Option<u32>,
}

impl Default for VhConfig {
    fn default() -> Self {
        VhConfig {
            schema_version: 1,
            auto_level: AutoLevel::Safe,
            first_run_done: false,
            scan_interval_ms: None,
        }
    }
}
