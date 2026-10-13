//! 화면 상태 기계. 키와 지킴이 갱신을 받아 상태를 바꾸고, 바깥에서 할 일([`Effect`])을 돌려준다.
//! 신호를 보내지 않는다(미리보기 `vh_act::plan`·설명 `vh_analyze`는 읽기만 한다).

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use vh_act::{Policy, Selection};
use vh_model::{
    ActionPlan, AutoLevel, Classified, Confidence, Finding, FindingKind, GuardEvent,
    GuardEventKind, GuardPolicy, GuardStatus, Kind, ProcRef, Report, Snapshot, Step, Suggestion,
    VhConfig,
};

use super::link::{Cmd, ManualResult, Update};
use crate::fmt;
use crate::render::status::{Bucket, bucket};

use crate::render::{Lookup, action, confidence_ko, scope_ko, why};
use crate::target::Target;

/// 입력 대기 틱(TUI_5: ≤ 250ms).
pub const TICK_MS: u64 = 250;
pub const MAX_EVENTS: usize = 500;
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;
/// 설정 화면에서 고를 수 있는 확인 간격.
pub const INTERVALS_MS: [u32; 3] = [5_000, 10_000, 30_000];
/// 대화상자 안쪽 폭(테두리·여백 제외).
pub const DIALOG_INNER: usize = 72;
const R13: &str = "R13_below_confidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Findings,
    Ports,
    Log,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Findings, Tab::Ports, Tab::Log, Tab::Settings];

    pub fn index(self) -> usize {
        match self {
            Tab::Findings => 0,
            Tab::Ports => 1,
            Tab::Log => 2,
            Tab::Settings => 3,
        }
    }

    fn step(self, d: isize) -> Tab {
        Tab::ALL[(self.index() as isize + d).rem_euclid(4) as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    FirstRun,
    Loading,
    Main,
    Quitting,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Dialog {
    Preview {
        plan: ActionPlan,
        lines: Vec<String>,
    },
    Busy {
        request_id: u64,
    },
    Result {
        lines: Vec<String>,
    },
    Level {
        cursor: usize,
    },
    ConfirmAggressive,
    Help,
    Why {
        lines: Vec<String>,
        scroll: usize,
    },
    Notice {
        title: String,
        lines: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub enum Effect {
    Send(Cmd),
    SaveConfig(VhConfig),
    StartGuard {
        level: AutoLevel,
        interval_ms: Option<u32>,
    },
    /// 지킴이를 정상 종료(낮춘 것 되돌리기)하고 끝낸다.
    Quit,
    /// 끝내는 중 Ctrl+C를 한 번 더: 기다리지 않고 끝낸다.
    ForceQuit,
}

/// 목록 한 줄에서 지킴이가 그 대상을 어떻게 다루는지.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    AutoPending(u32, u32),
    DemotePending(u32, u32),
    Demoted,
    CircuitHold,
    Manual,
    NotifyOnly,
    Never(&'static str),
}

impl Mark {
    fn rank(self) -> u8 {
        match self {
            Mark::AutoPending(..) => 0,
            Mark::DemotePending(..) => 1,
            Mark::Demoted => 2,
            Mark::CircuitHold => 3,
            Mark::Manual => 4,
            Mark::NotifyOnly => 5,
            Mark::Never(_) => 6,
        }
    }

    pub fn text(self) -> String {
        match self {
            Mark::AutoPending(s, n) => format!("자동 예정 {s}/{n}"),
            Mark::DemotePending(s, n) => format!("낮춤 예정 {s}/{n}"),
            Mark::Demoted => "우선순위 낮춤".to_string(),
            Mark::CircuitHold => "차단기: 알림만".to_string(),
            Mark::Manual => "직접 정리".to_string(),
            Mark::NotifyOnly => "알림만".to_string(),
            Mark::Never(s) => s.to_string(),
        }
    }

    pub fn explain(self) -> String {
        match self {
            Mark::AutoPending(s, n) => {
                format!("{n}번 연속 확인되면 자동으로 정리해요(지금 {s}/{n}).")
            }
            Mark::DemotePending(s, n) => format!(
                "CPU 폭주가 계속되면 끄지 않고 우선순위만 낮춰요(지금 {s}/{n}). 화면을 닫으면 되돌려요."
            ),
            Mark::Demoted => "우선순위를 낮춰 두었어요. u 를 누르면 되돌려요.".to_string(),
            Mark::CircuitHold => {
                "차단기가 열려 자동 종료를 멈췄어요. r 을 누르면 다시 켜져요.".to_string()
            }
            Mark::Manual => {
                "자동 대상이 아니에요. 직접 끄려면 스페이스로 고른 뒤 Enter.".to_string()
            }
            Mark::NotifyOnly => {
                "일부러 띄웠을 수 있어 자동으로 끄지 않고 알림만 해요. 직접 끄려면 스페이스 → Enter."
                    .to_string()
            }
            Mark::Never(_) => "vh가 끄지 않는 대상이에요. w 로 누가 띄웠는지 볼 수 있어요.".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub finding_id: String,
    pub tag: &'static str,
    pub label: String,
    pub size: Option<u64>,
    pub confidence: Option<Confidence>,
    pub mark: Mark,
    pub actionable: bool,
    pub target: Option<ProcRef>,
    /// 대상이 하나일 때만: 나이 칸은 그릴 때 스냅샷 시각에서 뺀다(다시 만들지 않아도 나이가 흐른다).
    pub started_unix_ms: Option<u64>,
    /// 프로젝트 폴더 이름.
    pub project: Option<String>,
    /// (이름, 내용) — 자세히 칸의 '무엇'·'왜'. '대상'·'지킴이'는 그릴 때 붙인다.
    pub detail: Vec<(&'static str, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortRow {
    pub port: u16,
    pub target: ProcRef,
    pub label: String,
    pub project: String,
    pub scope: String,
    pub flag: &'static str,
    pub detail: Vec<String>,
}

/// 가장 최근 지킴이 갱신.
#[derive(Debug, Clone)]
pub struct Latest {
    pub snapshot: Arc<Snapshot>,
    pub report: Arc<Report>,
    pub policy: Arc<GuardPolicy>,
    pub status: GuardStatus,
}

/// 목록에 쓰는 발견 대상 하나의 이름·종류·프로젝트·포트(갱신마다 이것만 찾는다).
#[derive(Debug, Clone, PartialEq)]
pub struct TargetInfo {
    pub target: ProcRef,
    pub kind: Option<Kind>,
    pub label: String,
    pub project: Option<String>,
    pub port: Option<u16>,
}

/// 이번 화면 세션에서 지킴이가 한 일 합계(기록 탭 첫 줄·끝낼 때 요약).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub auto_terminated: u32,
    pub reclaimed_bytes: u64,
    pub demoted: u32,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub mode: Mode,
    pub tab: Tab,
    pub cursor: [usize; 4],
    pub selected: BTreeSet<String>,
    pub dialog: Option<Dialog>,
    pub latest: Option<Latest>,
    pub rows: Vec<Row>,
    pub ports: Vec<PortRow>,
    pub events: VecDeque<GuardEvent>,
    pub tally: Tally,
    pub flash: Option<String>,
    /// `<state_dir>/config.json`에서 읽은(또는 첫 실행에서 고른) 값.
    pub config: VhConfig,
    /// `VH_GUARD_LEVEL`이 있으면 그 해석 결과(화면에서 바꿀 수 없음).
    pub env_level: Option<AutoLevel>,
    /// `VH_GUARD_LEVEL` 값이 이상해 알림만으로 내려갔을 때의 경고.
    pub env_warning: Option<String>,
    pub e2e_lock: bool,
    pub no_color: bool,
    pub guard_dead: Option<String>,
    pub width: u16,
    pub height: u16,
    pub config_path: String,
    /// 목록 행을 다시 만든 횟수(같은 보고서면 그대로).
    pub rebuilds: u64,
    /// 포트 행을 다시 만든 횟수.
    pub port_rebuilds: u64,
    targets: Vec<TargetInfo>,
    next_request: u64,
}

pub fn level_ko(l: AutoLevel) -> &'static str {
    match l {
        AutoLevel::NotifyOnly => "알림만",
        AutoLevel::Safe => "안전 자동",
        AutoLevel::Aggressive => "적극 자동",
    }
}

const LEVELS: [AutoLevel; 3] = [
    AutoLevel::NotifyOnly,
    AutoLevel::Safe,
    AutoLevel::Aggressive,
];

pub const NOT_ACTIONABLE: &str =
    "AI 세션·좀비 같은 줄은 vh가 끄지 않아요. w 로 자세히 볼 수 있어요.";
pub const CIRCUIT_CLOSED: &str = "차단기는 닫혀 있어요. 자동 종료가 켜져 있어요.";
pub const NOT_DEMOTED: &str = "지킴이가 우선순위를 낮춘 대상이 아니에요.";
pub const UNDO_SENT: &str = "우선순위를 되돌리라고 지킴이에게 보냈어요.";

impl Model {
    pub fn new(config: Option<VhConfig>, env_raw: Option<&str>, e2e_lock: bool) -> Model {
        let (env_level, env_warning) = match env_raw {
            None => (None, None),
            Some(raw) => match AutoLevel::from_env_value(raw) {
                Some(l) => (Some(l), None),
                None => (
                    Some(AutoLevel::NotifyOnly),
                    Some(format!(
                        "VH_GUARD_LEVEL='{raw}' 을 알아볼 수 없어 알림만으로 실행해요"
                    )),
                ),
            },
        };
        let first_run = config.as_ref().is_none_or(|c| !c.first_run_done);
        let flash = env_warning.clone();
        Model {
            mode: if first_run {
                Mode::FirstRun
            } else {
                Mode::Loading
            },
            tab: Tab::Findings,
            cursor: [0; 4],
            selected: BTreeSet::new(),
            dialog: None,
            latest: None,
            rows: Vec::new(),
            ports: Vec::new(),
            events: VecDeque::new(),
            tally: Tally::default(),
            flash,
            config: config.unwrap_or_default(),
            env_level,
            env_warning,
            e2e_lock,
            no_color: false,
            guard_dead: None,
            width: MIN_WIDTH,
            height: MIN_HEIGHT,
            config_path: String::new(),
            rebuilds: 0,
            port_rebuilds: 0,
            targets: Vec::new(),
            next_request: 1,
        }
    }

    /// 지킴이를 띄울 수준: 환경 변수 > 설정 파일.
    pub fn effective_level(&self) -> AutoLevel {
        self.env_level.unwrap_or(self.config.auto_level)
    }

    pub fn start_effect(&self) -> Effect {
        Effect::StartGuard {
            level: self.effective_level(),
            interval_ms: self.config.scan_interval_ms,
        }
    }

    pub fn too_small(&self) -> bool {
        self.width < MIN_WIDTH || self.height < MIN_HEIGHT
    }

    pub fn set_size(&mut self, w: u16, h: u16) {
        self.width = w;
        self.height = h;
    }

    pub fn guard_died(&mut self, msg: Option<String>) {
        if self.guard_dead.is_none() {
            self.guard_dead = Some(msg.unwrap_or_else(|| "이유를 알 수 없어요".to_string()));
        }
        if let Some(Dialog::Busy { .. }) = self.dialog {
            self.dialog = None;
        }
    }

    fn list_len(&self, tab: Tab) -> usize {
        match tab {
            Tab::Findings => self.rows.len(),
            Tab::Ports => self.ports.len(),
            Tab::Log => self.events.len(),
            Tab::Settings => 2,
        }
    }

    pub fn cursor_row(&self) -> Option<&Row> {
        self.rows.get(self.cursor[Tab::Findings.index()])
    }

    pub fn cursor_port(&self) -> Option<&PortRow> {
        self.ports.get(self.cursor[Tab::Ports.index()])
    }

    pub fn cursor_event(&self) -> Option<&GuardEvent> {
        self.events.get(self.cursor[Tab::Log.index()])
    }

    /// 지킴이 갱신을 반영한다. 돌려준 효과는 바깥에서 실행한다.
    pub fn apply(&mut self, u: Update) -> Vec<Effect> {
        let keep_id = self.cursor_row().map(|r| r.finding_id.clone());
        for e in u.new_events.into_iter() {
            if e.kind == GuardEventKind::Skipped {
                continue;
            }
            let dup = self.events.front().is_some_and(|f| {
                f.kind == e.kind && f.target == e.target && f.detail_ko == e.detail_ko
            });
            if dup {
                continue;
            }
            match e.kind {
                GuardEventKind::AutoTerminated => {
                    self.tally.auto_terminated += 1;
                    self.tally.reclaimed_bytes += e.reclaimed_bytes;
                }
                GuardEventKind::Demoted => self.tally.demoted += 1,
                _ => {}
            }
            self.events.push_front(e);
        }
        self.events.truncate(MAX_EVENTS);
        let same_arc = self.latest.as_ref().is_some_and(|l| {
            Arc::ptr_eq(&l.report, &u.report) && Arc::ptr_eq(&l.snapshot, &u.snapshot)
        });
        let same_report = same_arc || {
            let fresh = target_infos(&u.snapshot, &u.report);
            let same = self.latest.as_ref().is_some_and(|l| {
                l.report.findings == u.report.findings
                    && l.report.listeners == u.report.listeners
                    && self.targets == fresh
            });
            self.targets = fresh;
            same
        };
        let same_marks = self
            .latest
            .as_ref()
            .is_some_and(|l| same_marks(l, &u.policy, &u.status));
        if !(same_report && same_marks) {
            self.rows = rows_from(&u.report, &self.targets, &u.policy, &u.status);
            self.rebuilds += 1;
            let ids: BTreeSet<&str> = self.rows.iter().map(|r| r.finding_id.as_str()).collect();
            self.selected.retain(|id| ids.contains(id.as_str()));
            if let Some(id) = keep_id
                && let Some(i) = self.rows.iter().position(|r| r.finding_id == id)
            {
                self.cursor[0] = i;
            }
        }
        if !same_report {
            self.ports = build_ports(&u.report);
            self.port_rebuilds += 1;
        }
        for t in Tab::ALL {
            let n = self.list_len(t);
            let c = &mut self.cursor[t.index()];
            *c = (*c).min(n.saturating_sub(1));
        }
        let latest = Latest {
            snapshot: u.snapshot,
            report: u.report,
            policy: u.policy,
            status: u.status,
        };
        let mut fx = Vec::new();
        if let Some(m) = u.manual_result
            && let Some(Dialog::Busy { request_id }) = self.dialog
            && m.request_id == request_id
        {
            self.dialog = Some(Dialog::Result {
                lines: result_lines(&latest, &m),
            });
            self.selected.clear();
            fx.push(Effect::Send(Cmd::ScanNow));
        }
        self.latest = Some(latest);
        if self.mode == Mode::Loading {
            self.mode = Mode::Main;
        }
        fx
    }

    fn quit(&mut self) -> Vec<Effect> {
        self.mode = Mode::Quitting;
        self.dialog = None;
        vec![Effect::Quit]
    }

    pub fn on_key(&mut self, k: KeyEvent) -> Vec<Effect> {
        if k.kind != KeyEventKind::Press {
            return Vec::new();
        }
        let before = self.flash.take();
        let fx = self.on_press(k);
        if self.mode == Mode::Quitting && self.flash.is_none() {
            self.flash = before;
        }
        fx
    }

    fn on_press(&mut self, k: KeyEvent) -> Vec<Effect> {
        let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
        if self.mode == Mode::Quitting {
            return if ctrl_c {
                vec![Effect::ForceQuit]
            } else {
                Vec::new()
            };
        }
        if ctrl_c {
            return self.quit();
        }
        if self.too_small() {
            return match k.code {
                KeyCode::Char('q') | KeyCode::Esc => self.quit(),
                _ => Vec::new(),
            };
        }
        if self.mode == Mode::FirstRun {
            return match k.code {
                KeyCode::Enter => self.choose_first(AutoLevel::Safe),
                KeyCode::Char('n') | KeyCode::Char('N') => self.choose_first(AutoLevel::NotifyOnly),
                KeyCode::Char('q') | KeyCode::Esc => self.quit(),
                _ => Vec::new(),
            };
        }
        if self.dialog.is_some() {
            return self.on_dialog_key(k);
        }
        match k.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit(),
            KeyCode::Char('?') => {
                self.dialog = Some(Dialog::Help);
                Vec::new()
            }
            KeyCode::Tab | KeyCode::Right => {
                self.tab = self.tab.step(1);
                Vec::new()
            }
            KeyCode::BackTab | KeyCode::Left => {
                self.tab = self.tab.step(-1);
                Vec::new()
            }
            KeyCode::Char(c @ '1'..='4') => {
                self.tab = Tab::ALL[(c as u8 - b'1') as usize];
                Vec::new()
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_cursor(-1);
                Vec::new()
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_cursor(1);
                Vec::new()
            }
            _ if self.latest.is_none() => Vec::new(),
            KeyCode::Char(' ') if self.tab == Tab::Findings => {
                self.toggle();
                Vec::new()
            }
            KeyCode::Enter if self.tab == Tab::Findings => {
                self.preview();
                Vec::new()
            }
            KeyCode::Enter if self.tab == Tab::Settings => self.settings_enter(),
            KeyCode::Char('a') => {
                self.open_level();
                Vec::new()
            }
            KeyCode::Char('p') => {
                let paused = self.latest.as_ref().is_some_and(|l| l.status.paused);
                vec![Effect::Send(if paused { Cmd::Resume } else { Cmd::Pause })]
            }
            KeyCode::Char('r') => {
                if self.latest.as_ref().is_some_and(|l| l.status.circuit_open) {
                    vec![Effect::Send(Cmd::ResetCircuit)]
                } else {
                    self.flash = Some(CIRCUIT_CLOSED.to_string());
                    Vec::new()
                }
            }
            KeyCode::Char('u') => self.undo_demote(),
            KeyCode::Char('w') => {
                self.why();
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn choose_first(&mut self, level: AutoLevel) -> Vec<Effect> {
        self.config = VhConfig {
            schema_version: 1,
            auto_level: level,
            first_run_done: true,
            scan_interval_ms: self.config.scan_interval_ms,
        };
        self.mode = Mode::Loading;
        vec![Effect::SaveConfig(self.config.clone()), self.start_effect()]
    }

    fn move_cursor(&mut self, d: isize) {
        if let Some(Dialog::Level { cursor }) = &mut self.dialog {
            *cursor = (*cursor as isize + d).clamp(0, 2) as usize;
            return;
        }
        let n = self.list_len(self.tab);
        let c = &mut self.cursor[self.tab.index()];
        *c = (*c as isize + d).clamp(0, n.saturating_sub(1) as isize) as usize;
    }

    fn toggle(&mut self) {
        let Some(row) = self.cursor_row() else { return };
        if !row.actionable {
            self.flash = Some(NOT_ACTIONABLE.to_string());
            return;
        }
        let id = row.finding_id.clone();
        if !self.selected.remove(&id) {
            self.selected.insert(id);
        }
    }

    /// 고른 것(없으면 커서 줄)으로 정리 미리보기. 직접 고른 것은 신뢰도와 상관없이(W1 `--only`와 같음),
    /// 보호 규칙은 그대로.
    fn preview(&mut self) {
        let Some(l) = &self.latest else { return };
        let ids: Vec<String> = if self.selected.is_empty() {
            match self.cursor_row() {
                Some(r) if r.actionable => vec![r.finding_id.clone()],
                Some(_) => {
                    self.flash = Some(NOT_ACTIONABLE.to_string());
                    return;
                }
                None => return,
            }
        } else {
            self.selected.iter().cloned().collect()
        };
        let sel = selection_for(&l.report, &ids);
        let policy = Policy {
            allow_demote: true,
            ..Policy::default()
        };
        let plan = vh_act::plan(&l.snapshot, &l.report, &sel, &policy);
        let lines = preview_lines(l, &plan, &sel.pids);
        self.dialog = Some(Dialog::Preview { plan, lines });
    }

    fn on_dialog_key(&mut self, k: KeyEvent) -> Vec<Effect> {
        let Some(d) = self.dialog.clone() else {
            return Vec::new();
        };
        match d {
            Dialog::Preview { plan, .. } => {
                if plan.items.is_empty() {
                    self.dialog = None;
                    return Vec::new();
                }
                match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        let Some(l) = &self.latest else {
                            return Vec::new();
                        };
                        let request_id = self.next_request;
                        self.next_request += 1;
                        let snapshot = l.snapshot.clone();
                        self.dialog = Some(Dialog::Busy { request_id });
                        vec![Effect::Send(Cmd::RunPlan {
                            request_id,
                            plan,
                            snapshot,
                        })]
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        self.dialog = None;
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            }
            Dialog::Busy { .. } => match k.code {
                KeyCode::Char('q') => self.quit(),
                _ => Vec::new(),
            },
            Dialog::Level { cursor } => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_cursor(-1);
                    Vec::new()
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_cursor(1);
                    Vec::new()
                }
                KeyCode::Enter => {
                    let level = LEVELS[cursor];
                    if level == AutoLevel::Aggressive && self.effective_level() != level {
                        self.dialog = Some(Dialog::ConfirmAggressive);
                        Vec::new()
                    } else {
                        self.set_level(level)
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.dialog = None;
                    Vec::new()
                }
                _ => Vec::new(),
            },
            Dialog::ConfirmAggressive => match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.set_level(AutoLevel::Aggressive),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.dialog = None;
                    Vec::new()
                }
                _ => Vec::new(),
            },
            Dialog::Why { lines, scroll } => match k.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.dialog = Some(Dialog::Why {
                        lines,
                        scroll: scroll.saturating_sub(1),
                    });
                    Vec::new()
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let max = lines.len().saturating_sub(1);
                    self.dialog = Some(Dialog::Why {
                        lines,
                        scroll: (scroll + 1).min(max),
                    });
                    Vec::new()
                }
                _ => {
                    self.dialog = None;
                    Vec::new()
                }
            },
            Dialog::Result { .. } | Dialog::Help | Dialog::Notice { .. } => {
                self.dialog = None;
                Vec::new()
            }
        }
    }

    fn set_level(&mut self, level: AutoLevel) -> Vec<Effect> {
        self.dialog = None;
        if self.env_level.is_some() {
            return Vec::new();
        }
        self.config.auto_level = level;
        vec![
            Effect::Send(Cmd::SetLevel(level)),
            Effect::SaveConfig(self.config.clone()),
        ]
    }

    fn open_level(&mut self) {
        if let Some(l) = self.env_level {
            self.dialog = Some(Dialog::Notice {
                title: "지킴이 수준".to_string(),
                lines: vec![
                    format!(
                        "VH_GUARD_LEVEL 환경 변수로 '{}'에 고정돼 있어요.",
                        level_ko(l)
                    ),
                    "화면에서는 바꿀 수 없어요.".to_string(),
                    "바꾸려면 VH_GUARD_LEVEL 없이 vh 를 실행하세요.".to_string(),
                    String::new(),
                    "아무 키나 누르면 닫혀요".to_string(),
                ],
            });
            return;
        }
        let cur = self.effective_level();
        let cursor = LEVELS.iter().position(|l| *l == cur).unwrap_or(1);
        self.dialog = Some(Dialog::Level { cursor });
    }

    fn settings_enter(&mut self) -> Vec<Effect> {
        if self.cursor[Tab::Settings.index()] == 0 {
            self.open_level();
            return Vec::new();
        }
        let cur = self.current_interval();
        let next = INTERVALS_MS
            .iter()
            .position(|v| *v == cur)
            .map(|i| INTERVALS_MS[(i + 1) % INTERVALS_MS.len()])
            .unwrap_or(INTERVALS_MS[0]);
        let mut fx = vec![Effect::Send(Cmd::SetScanInterval(next))];
        self.config.scan_interval_ms = Some(next);
        if self.env_level.is_none() {
            fx.push(Effect::SaveConfig(self.config.clone()));
        }
        fx
    }

    pub fn current_interval(&self) -> u32 {
        self.config
            .scan_interval_ms
            .or_else(|| self.latest.as_ref().map(|l| l.policy.scan_interval_ms))
            .unwrap_or(INTERVALS_MS[0])
    }

    /// 커서 줄 대상(① 목록 또는 ③ 기록)을 지킴이가 낮췄으면 되돌리라고 보낸다.
    fn undo_demote(&mut self) -> Vec<Effect> {
        let target = match self.tab {
            Tab::Findings => self.cursor_row().and_then(|r| r.target),
            Tab::Log => self.cursor_event().and_then(|e| e.target),
            _ => None,
        };
        let demoted = |t: ProcRef| {
            self.latest
                .as_ref()
                .is_some_and(|l| l.status.demoted.iter().any(|d| d.target == t))
        };
        match target {
            Some(t) if demoted(t) => {
                self.flash = Some(UNDO_SENT.to_string());
                vec![Effect::Send(Cmd::UndoDemote(t))]
            }
            _ => {
                self.flash = Some(NOT_DEMOTED.to_string());
                Vec::new()
            }
        }
    }

    fn why(&mut self) {
        let Some(l) = &self.latest else { return };
        let (t, exps) = match self.tab {
            Tab::Ports => {
                let Some(p) = self.cursor_port() else { return };
                (
                    Target::Port(p.port),
                    vh_analyze::explain_port(&l.snapshot, &l.report, p.port),
                )
            }
            _ => {
                let target = match self.tab {
                    Tab::Log => self.cursor_event().and_then(|e| e.target),
                    _ => self.cursor_row().and_then(|r| r.target),
                };
                let Some(t) = target else { return };
                (
                    Target::Pid(t.pid),
                    vh_analyze::explain_pid(&l.snapshot, &l.report, t.pid)
                        .into_iter()
                        .collect(),
                )
            }
        };
        if exps.is_empty() {
            self.flash = Some(format!(
                "{} 은(는) 지금 없어요. 이미 끝났을 수 있어요.",
                t.display()
            ));
            return;
        }
        let text = why::render(&l.snapshot, &l.report, t, &exps, false);
        self.dialog = Some(Dialog::Why {
            lines: text.lines().map(str::to_string).collect(),
            scroll: 0,
        });
    }
}

/// 프로젝트 폴더 경로 → 화면에 쓰는 폴더 이름("/Users/a/dev/shop" → "shop").
pub fn project_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// 직접 고른 Finding들 → vh-act Selection(대상 pid까지 넣어 Review도 실행 항목이 된다).
pub fn selection_for(r: &Report, ids: &[String]) -> Selection {
    let mut pids: Vec<i32> = Vec::new();
    for f in r.findings.iter().filter(|f| ids.contains(&f.id)) {
        for t in &f.targets {
            if !pids.contains(&t.pid) {
                pids.push(t.pid);
            }
        }
    }
    Selection {
        finding_ids: ids.to_vec(),
        pids,
        min_confidence: Confidence::Possible,
        direct: Vec::new(),
    }
}

/// 발견들의 첫 대상만 이름·종류·프로젝트·가장 작은 대기 포트를 찾는다. 전체 프로세스로 색인(HashMap)을
/// 만들지 않고 보고서·스냅샷을 한 번씩 훑어 발견 수만큼만 담는다(갱신마다 프로세스 수에 비례한 할당을 피함).
pub fn target_infos(s: &Snapshot, r: &Report) -> Vec<TargetInfo> {
    let mut refs: Vec<ProcRef> = r
        .findings
        .iter()
        .filter_map(|f| f.targets.first().copied())
        .collect();
    refs.sort();
    refs.dedup();
    let mut cls: Vec<Option<&Classified>> = vec![None; refs.len()];
    for c in &r.classified {
        if let Ok(i) = refs.binary_search(&c.target) {
            cls[i] = Some(c);
        }
    }
    let mut names: Vec<Option<&str>> = vec![None; refs.len()];
    for p in &s.processes {
        let t = ProcRef {
            pid: p.pid,
            start_time_unix_ms: p.start_time_unix_ms,
        };
        if let Ok(i) = refs.binary_search(&t) {
            names[i] = Some(p.name.as_str());
        }
    }
    let mut ports: Vec<Option<u16>> = vec![None; refs.len()];
    for v in &r.listeners {
        let t = ProcRef {
            pid: v.listener.pid,
            start_time_unix_ms: v.listener.start_time_unix_ms,
        };
        if let Ok(i) = refs.binary_search(&t) {
            let port = v.listener.port;
            ports[i] = Some(ports[i].map_or(port, |p| p.min(port)));
        }
    }
    refs.into_iter()
        .enumerate()
        .map(|(i, t)| {
            let c = cls[i];
            let label = match c.filter(|c| !c.label_ko.is_empty()) {
                Some(c) => c.label_ko.clone(),
                None => names[i]
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{}번 프로세스", t.pid)),
            };
            TargetInfo {
                target: t,
                kind: c.map(|c| c.kind),
                label,
                project: c.and_then(|c| c.project.as_deref()).map(project_name),
                port: ports[i],
            }
        })
        .collect()
}

/// 목록 대상 칸 이름. 크기·나이가 붙는 짧은 이름을 쓰던 종류는 분류 이름(+ 대기 포트)만 쓰고
/// 크기·나이는 각 칸에 둔다. CPU %·개수처럼 다른 칸이 없는 정보를 담은 종류는 그대로.
fn list_name(f: &Finding, b: Bucket, info: Option<&TargetInfo>) -> String {
    let by_name = f.targets.len() == 1
        && matches!(
            f.kind,
            FindingKind::Orphan
                | FindingKind::LogicalOrphan
                | FindingKind::HeadlessBrowserLeftover
                | FindingKind::HeavyAgentSession
                | FindingKind::HeavyProcess
        );
    match info {
        Some(i) if by_name => match i.port {
            Some(p) => format!("{} :{p}", i.label),
            None => i.label.clone(),
        },
        _ if b == Bucket::Watch || f.short_ko.is_empty() => f.title_ko.clone(),
        _ => f.short_ko.clone(),
    }
}

/// 표시 상태(지킴이 표시에 쓰는 것)가 직전 갱신과 같은지.
fn same_marks(l: &Latest, policy: &GuardPolicy, st: &GuardStatus) -> bool {
    let pending_same = l.status.pending.len() == st.pending.len()
        && l.status.pending.iter().zip(&st.pending).all(|(a, b)| {
            a.finding_id == b.finding_id
                && a.step == b.step
                && a.seen_scans == b.seen_scans
                && a.needed_scans == b.needed_scans
        });
    pending_same
        && l.status.circuit_open == st.circuit_open
        && l.status.demoted == st.demoted
        && l.policy.auto_terminate_kinds == policy.auto_terminate_kinds
        && l.policy.notify_only_kinds == policy.notify_only_kinds
}

pub fn build_rows(s: &Snapshot, r: &Report, policy: &GuardPolicy, st: &GuardStatus) -> Vec<Row> {
    rows_from(r, &target_infos(s, r), policy, st)
}

fn rows_from(
    r: &Report,
    targets: &[TargetInfo],
    policy: &GuardPolicy,
    st: &GuardStatus,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for f in &r.findings {
        let target = f.targets.first().copied();
        let info = target.and_then(|t| {
            targets
                .binary_search_by(|x| x.target.cmp(&t))
                .ok()
                .map(|i| &targets[i])
        });
        let kind = info.and_then(|i| i.kind);
        let Some(b) = bucket(f, kind) else { continue };
        let tag = match b {
            Bucket::Watch => "주의",
            Bucket::Orphan => "고아",
            Bucket::Leftover => "잔재",
            Bucket::Exposed | Bucket::Conflict => continue,
        };
        if matches!(b, Bucket::Orphan | Bucket::Leftover) && !f.confidence.meets(Confidence::Likely)
        {
            continue;
        }
        let actionable = matches!(
            f.suggestion,
            Suggestion::Terminate { .. }
                | Suggestion::Demote
                | Suggestion::Resume
                | Suggestion::Review
        );
        let in_kinds = |ks: &[Kind]| kind.is_some_and(|k| ks.contains(&k));
        let mark = if !actionable {
            match f.suggestion {
                Suggestion::RestartParent { .. } => Mark::Never("앱 재시작 필요"),
                _ => Mark::Never("끄지 않음"),
            }
        } else if st.demoted.iter().any(|d| f.targets.contains(&d.target)) {
            Mark::Demoted
        } else if let Some(p) = st.pending.iter().find(|p| p.finding_id == f.id) {
            if p.step == Step::Demote {
                Mark::DemotePending(p.seen_scans, p.needed_scans)
            } else {
                Mark::AutoPending(p.seen_scans, p.needed_scans)
            }
        } else if in_kinds(&policy.notify_only_kinds) {
            Mark::NotifyOnly
        } else if st.circuit_open && in_kinds(&policy.auto_terminate_kinds) {
            Mark::CircuitHold
        } else {
            Mark::Manual
        };
        let label = list_name(f, b, info);
        let mut detail: Vec<(&'static str, String)> = vec![("무엇", f.title_ko.clone())];
        if !f.detail_ko.is_empty() {
            detail.push(("왜", f.detail_ko.clone()));
        }
        rows.push(Row {
            finding_id: f.id.clone(),
            tag,
            label,
            size: (f.reclaim_bytes > 0).then_some(f.reclaim_bytes),
            confidence: (f.suggestion != Suggestion::HandoffThenRestart).then_some(f.confidence),
            mark,
            actionable,
            target,
            started_unix_ms: (f.targets.len() == 1)
                .then(|| target.map(|t| t.start_time_unix_ms))
                .flatten(),
            project: info.and_then(|i| i.project.clone()),
            detail,
        });
    }
    rows.sort_by(|a, b| {
        a.mark
            .rank()
            .cmp(&b.mark.rank())
            .then(b.size.unwrap_or(0).cmp(&a.size.unwrap_or(0)))
            .then(a.finding_id.cmp(&b.finding_id))
    });
    rows
}

/// 포트 행. 나이 줄은 그릴 때 붙인다.
pub fn build_ports(r: &Report) -> Vec<PortRow> {
    let mut out: Vec<PortRow> = Vec::new();
    for v in &r.listeners {
        let l = &v.listener;
        if out
            .iter()
            .any(|p| p.port == l.port && p.target.pid == l.pid)
        {
            continue;
        }
        let same: Vec<_> = r
            .listeners
            .iter()
            .map(|x| &x.listener)
            .filter(|x| x.port == l.port && x.pid == l.pid)
            .collect();
        let target = ProcRef {
            pid: l.pid,
            start_time_unix_ms: l.start_time_unix_ms,
        };
        let conflict = r.findings.iter().find(|f| {
            f.kind == FindingKind::KnownPortConflict && f.targets.iter().any(|t| t.pid == l.pid)
        });
        let (flag, detail) = if let Some(e) = &v.exposure_ko {
            ("노출", e.clone())
        } else if let Some(f) = conflict {
            ("충돌", f.detail_ko.clone())
        } else {
            ("", format!("{} · pid {}", v.label_ko, l.pid))
        };
        let detail = vec![detail];
        out.push(PortRow {
            port: l.port,
            target,
            label: v.label_ko.clone(),
            project: v
                .project
                .as_deref()
                .map(project_name)
                .unwrap_or_else(|| "-".to_string()),
            scope: scope_ko(&same),
            flag,
            detail,
        });
    }
    out.sort_by(|a, b| {
        let rank = |f: &str| match f {
            "노출" => 0,
            "충돌" => 1,
            _ => 2,
        };
        rank(a.flag).cmp(&rank(b.flag)).then(a.port.cmp(&b.port))
    });
    out
}

fn preview_lines(l: &Latest, plan: &ActionPlan, picked_pids: &[i32]) -> Vec<String> {
    let lk = Lookup::new(&l.snapshot, &l.report);
    let w = DIALOG_INNER;
    let mut out = Vec::new();
    if plan.items.is_empty() {
        out.push("정리할 수 있는 것이 없어요".to_string());
    } else {
        let total: u64 = plan.items.iter().map(|i| i.est_reclaim_bytes).sum();
        out.push(format!(
            "정리 미리보기 — {}건, 최대 약 {} 회수 예상",
            plan.items.len(),
            fmt::bytes(total)
        ));
        out.push("기준: 직접 고른 것만 · 보호 규칙은 그대로".to_string());
        for (i, a) in plan.items.iter().enumerate() {
            let conf = lk
                .finding(&a.finding_id)
                .map(|f| confidence_ko(f.confidence))
                .unwrap_or("");
            let left = fmt::truncate(
                &format!("{}. {}", i + 1, action::item_label(&lk, a)),
                w - 22,
            );
            out.push(format!(
                "{}{}  {conf}",
                fmt::pad(&left, w - 21),
                fmt::lpad(&fmt::bytes(a.est_reclaim_bytes), 7)
            ));
            out.extend(fmt::wrap(&action::ladder(a), w, "   방법: ", "         "));
        }
    }
    for rf in &plan.refused {
        if rf.rule == R13 || !picked_pids.contains(&rf.target.pid) {
            continue;
        }
        out.push(fmt::truncate(
            &format!("끄지 않아요: {}", lk.label(rf.target)),
            w,
        ));
        out.extend(fmt::wrap(&rf.reason_ko, w, "  ", "  "));
    }
    out.push(String::new());
    out.push(if plan.items.is_empty() {
        "아무 키나 누르면 닫혀요".to_string()
    } else {
        "y 정리하기     n 취소".to_string()
    });
    out
}

fn result_lines(l: &Latest, m: &ManualResult) -> Vec<String> {
    use vh_model::FinalState;
    let lk = Lookup::new(&l.snapshot, &l.report);
    let w = DIALOG_INNER;
    let n = |st: FinalState| m.outcomes.iter().filter(|x| x.final_state == st).count();
    let exited = n(FinalState::Exited);
    let reclaimed: u64 = m
        .outcomes
        .iter()
        .filter(|x| x.final_state == FinalState::Exited)
        .map(|x| x.action.est_reclaim_bytes)
        .sum();
    let mut head = format!("정리 결과 — {}건 중 {exited}건 종료", m.outcomes.len());
    if exited > 0 && reclaimed > 0 {
        head.push_str(&format!(", 예상 회수 약 {}", fmt::bytes(reclaimed)));
    }
    let mut out = vec![head];
    for x in &m.outcomes {
        out.push(fmt::truncate(
            &format!(
                "  {}  {} — {}",
                fmt::pad(action::state_ko(x.final_state), 8),
                action::item_label(&lk, &x.action),
                action::how(x)
            ),
            w,
        ));
    }
    let audit = vh_act::audit_log_path(&m.state_dir);
    out.push(fmt::truncate(
        &format!("기록: {}", lk.path(&audit.to_string_lossy())),
        w,
    ));
    if exited > 0 {
        out.push("되살릴 때 필요한 정보도 같은 폴더에 저장했어요.".to_string());
    }
    out.push(String::new());
    out.push("아무 키나 누르면 닫혀요".to_string());
    out
}
