//! 화면 그리기(순수). 모든 줄은 `fmt` 폭 계산(한글 2칸)으로 칸 폭 안에 맞춘 Span 조각으로 쌓는다.
//!
//! 배치(80×24 기준): 머리 2줄(왼쪽 STOPCAT 로고, 오른쪽 메모리 상태·확보량) · 빈 줄 · 탭 1줄 ·
//! 본문 · 지킴이 상태 막대 1줄 · 키 안내 1줄. 대화상자는 뒤를 어둡게 하고 위에 띄운다.

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};
use stopcat_model::{AutoLevel, Finding, GuardEventKind, HealthLevel, Section};

use super::state::{DIALOG_INNER, Dialog, Mark, Mode, Model, Row, Tab, level_ko};
use super::theme::{Theme, Tone};
use crate::fmt::{self, lpad, pad, truncate, width};
use crate::render::confidence_ko;
use crate::render::section as sec;

pub const KEYS_FINDINGS: &str =
    "↑↓ 이동  스페이스 고르기  Enter 정리  c 추천 전부 정리  w 자세히  ? 도움말  q 끝";
pub const KEYS_FINDINGS_CIRCUIT: &str =
    "↑↓ 이동  스페이스 고르기  Enter 정리  c 추천 전부 정리  r 차단기 풀기  q 끝";
pub const KEYS_PORTS: &str = "↑↓ 이동  w 자세히  Tab 화면  a 수준  p 멈춤  ? 도움말  q 끝";
pub const KEYS_LOG: &str = "↑↓ 이동  u 우선순위 되돌리기  Tab 화면  a 수준  p 멈춤  ? 도움말  q 끝";
pub const KEYS_SETTINGS: &str = "↑↓ 이동  Enter 바꾸기  Tab 화면  a 수준  p 멈춤  ? 도움말  q 끝";
pub const KEYS_EMPTY: &str = "Tab 화면  a 수준  p 멈춤  ? 도움말  q 끝";
pub const KEYS_FIRST_RUN: &str =
    "Enter 안정화 자동으로 시작  n 보고만(자동으로 정리하지 않음)  q 끝";
pub const TOO_SMALL: &str = "창을 조금 키워 주세요.";

/// 2줄 블록 글자 로고(26칸).
pub const LOGO: [&str; 2] = ["█▀ ▀█▀ █▀█ █▀█ █▀▀ ▄▀█ ▀█▀", "▄█  █  █▄█ █▀▀ █▄▄ █▀█  █ "];
const LOGO_W: usize = 26;
/// 로고와 오른쪽 상태 글 사이.
const HEAD_GAP: usize = 2;
pub const TAGLINE: &str = "필요 없는 것만 멈추는 맥 정리 도구";
pub const CREDIT: &str = "Made by Withgenie";

pub const HELP_LINES: [&str; 12] = [
    "↑↓ 또는 j k   목록에서 이동",
    "스페이스      여러 개 고르기(다시 누르면 풀기)",
    "Enter         고른 것 정리: 미리보기 → y 실행 / n 취소",
    "c             추천 전부 정리('필요 없음'만): 미리보기 → y / n",
    "Tab ← → 1~4   화면 바꾸기(보고·포트·기록·설정)",
    "w             고른 줄을 누가 왜 띄웠는지 자세히",
    "d             고른 줄의 우선순위 낮추기(끄지 않음, 미리보기 → y)",
    "u             직접 낮춘 우선순위 되돌리기",
    "a             지킴이 수준 바꾸기",
    "p             지킴이 잠깐 멈춤 / 다시 시작",
    "r             차단기 풀기(자동 정리 다시 켜기)",
    "q Esc Ctrl+C  끝내기(낮춘 우선순위는 되돌리고 끝나요)",
];
/// 도움말 키 칸 폭.
const HELP_KEY_W: usize = 14;

pub const FIRST_RUN_TITLE: &str = "지킴이 — 처음 한 번만 정해 주세요";
pub const FIRST_RUN_LINES: [&str; 12] = [
    "화면을 띄워 두는 동안 지킴이가 5초마다 맥을 확인해요.",
    "평소에는 보고만 해요. 필요 없는 것과 되찾을 수 있는 양을 근거와 함께",
    "보여 주고, c 한 번으로 추천 항목을 모두 정리할 수 있어요(미리보기 → y).",
    "",
    "안정화 자동(추천)으로 시작하면 맥이 불안정할 때만 스스로 정리해요",
    "  '필요 없음'이 확실한 것만, 정상으로 돌아올 만큼만(10분에 5개까지).",
    "지금 쓰고 있는 것은 CPU 100%여도 끄지도, 느리게 하지도 않아요.",
    "",
    "절대 끄지 않는 것: AI 대화 세션·앱·가상 머신·DB·시스템",
    "자동으로 한 일은 '자동 처리 기록' 화면과 macOS 알림으로 남아요.",
    "",
    "설정 화면(4)에서 언제든 바꿀 수 있어요.",
];

pub const LEVEL_DESC: [&str; 3] = [
    "자동으로 정리하지 않아요. 보고만 해요.",
    "불안정할 때만 '필요 없음' 확실한 것 정리",
    "불안정할 때 '가능성 높음'까지 정리(재확인)",
];

pub const LEVEL_NOTE: [&str; 2] = [
    "어느 수준이든 평소(맥이 정상일 때)에는 보고만 하고, 쓰고 있는 것은",
    "끄지도 느리게 하지도 않아요.",
];

pub const AGGRESSIVE_LINES: [&str; 8] = [
    "적극 자동으로 바꿀까요?",
    "",
    "맥이 불안정할 때 '가능성 높음'과 더 넓은 종류까지 자동으로 정리합니다.",
    "에뮬레이터처럼 일부러 띄워 둔 것도 꺼질 수 있습니다.",
    "쓰고 있는 것, AI 대화 세션·앱·가상 머신·DB는 이 수준에서도 끄지 않아요.",
    "평소(맥이 정상일 때)에는 이 수준에서도 보고만 해요.",
    "",
    "y 적극 자동으로 바꾸기     n 그대로 두기",
];

/// 모두 빈 보고 화면의 고양이(잠자는 중).
pub const EMPTY_CAT: [&str; 3] = ["   /\\_/\\", "  ( -.- )  z z", "   > ^ <"];
pub const EMPTY_BODY: [&str; 6] = [
    "",
    "  지금 정리할 것이 없어요. 맥 상태가 좋아요.",
    "",
    "  지킴이가 계속 확인하고 있어요. 필요 없는 것이 생기면 근거와 함께 보여 드려요.",
    "  평소에는 보고만 하고, 맥이 불안정할 때만 '필요 없음'을 자동으로 정리해요.",
    "  지금 쓰고 있는 것은 어떤 경우에도 끄지도, 느리게 하지도 않아요.",
];
pub const EMPTY_NOT_OK: &str = "  지금 stopcat이 정리할 것은 없어요.";
pub const UNNEEDED_EMPTY_LINE: &str = "  지금 정리 추천할 것이 없어요.";
/// 첫 보고(측정 간격 없음) 동안 보고 탭 본문 맨 위.
pub const FIRST_REPORT: &str = "  처음 확인 중이에요. 몇 초 뒤 근거가 채워져요.";
/// 첫 보고 동안 확보량 자리(단정하지 않음).
pub const RECLAIM_FIRST: &str = "처음 확인 중이에요";
pub const LOADING_HEAD: &str = "메모리 확인 중…";

pub const SETTINGS_LINES: [&str; 9] = [
    "",
    "  안정화 자동이 하는 일",
    "    평소(맥이 정상): 보고만 해요. 자동 정리 0",
    "    불안정할 때: '필요 없음'이 확실한 것만, 정상으로 돌아올 만큼만 정리",
    "    정리한 뒤에는 효과가 보일 때까지 기다리고, 10분에 5개를 넘지 않아요",
    "  지금 쓰고 있는 것: 어떤 수준에서도 끄지도, 느리게 하지도 않아요",
    "  보고만 하는 것: 확인 필요·일하는 중·에뮬레이터·가상 머신·DB·로컬 LLM",
    "  절대 끄지 않는 것: AI 대화 세션·앱·시스템",
    "",
];

pub const LOG_EMPTY: [&str; 5] = [
    "",
    "  아직 자동으로 처리한 일이 없어요.",
    "",
    "  평소에는 보고만 해요. 맥이 불안정해지면 지킴이가 '필요 없음' 항목을",
    "  정리하고, 그 일이 여기와 macOS 알림에 남아요. 직접 정리·낮춘 것도 남아요.",
];

pub const STATE_NORMAL: &str = "평소 보고만";
pub const STATE_UNSTABLE_AUTO: &str = "불안정 — 자동 정리 중";
pub const STATE_UNSTABLE_NOTIFY: &str = "불안정 — 보고만(자동 정리 안 함)";
pub const STATE_SETTLING: &str = "불안정 — 정리 뒤 지켜보는 중";
pub const STATE_PAUSED: &str = "일시정지(p 다시 시작)";
pub const STATE_CIRCUIT: &str = "차단기 열림(보고만)";
pub const STATE_FIRST_SCAN: &str = "켜짐 · 첫 확인 중";

pub const QUITTING: [&str; 2] = [
    "끝내는 중… 직접 낮춘 우선순위를 되돌리고 있어요.",
    "Ctrl+C 를 한 번 더 누르면 기다리지 않고 끝내요.",
];

/// 커서 줄 표시.
const CURSOR: &str = "❯";

/// Span 조각으로 한 줄을 쌓는다. 폭은 `fmt::width`로 재고, 넘치는 조각은 "…"로 자른다.
struct Ln {
    spans: Vec<Span<'static>>,
    w: usize,
    max: usize,
}

impl Ln {
    fn new(max: usize) -> Ln {
        Ln {
            spans: Vec::new(),
            w: 0,
            max,
        }
    }

    fn room(&self) -> usize {
        self.max.saturating_sub(self.w)
    }

    fn push(&mut self, s: &str, st: Style) -> &mut Ln {
        let room = self.room();
        if s.is_empty() || room == 0 {
            return self;
        }
        let t = if width(s) > room {
            truncate(s, room)
        } else {
            s.to_string()
        };
        self.w += width(&t);
        self.spans.push(Span::styled(t, st));
        self
    }

    /// `col`칸까지 공백으로 채운다.
    fn pad_to(&mut self, col: usize, st: Style) -> &mut Ln {
        let col = col.min(self.max);
        if col > self.w {
            let n = col - self.w;
            self.push(&" ".repeat(n), st);
        }
        self
    }

    /// 줄 끝까지 채운다(바탕색을 끝까지 칠할 때).
    fn fill(&mut self, st: Style) -> &mut Ln {
        let max = self.max;
        self.pad_to(max, st)
    }

    /// 모든 조각에 같은 바탕을 덧씌운다(커서 줄).
    fn over(&mut self, st: Style) {
        for s in &mut self.spans {
            s.style = s.style.patch(st);
        }
    }

    fn text(&self) -> String {
        self.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn line(self) -> Line<'static> {
        Line::from(self.spans)
    }
}

struct Screen {
    w: usize,
    lines: Vec<Line<'static>>,
}

impl Screen {
    fn new(w: u16) -> Self {
        Screen {
            w: w as usize,
            lines: Vec::new(),
        }
    }

    fn push(&mut self, l: Ln) {
        self.lines.push(l.line());
    }

    fn text(&mut self, s: &str, st: Style) {
        let mut l = Ln::new(self.w);
        l.push(s, st);
        self.push(l);
    }

    fn blank(&mut self) {
        self.lines.push(Line::default());
    }

    fn fill_to(&mut self, n: usize) {
        while self.lines.len() < n {
            self.lines.push(Line::default());
        }
        self.lines.truncate(n);
    }
}

pub fn draw(f: &mut Frame, m: &Model) {
    let area = f.area();
    let t = m.theme();
    if m.too_small() {
        draw_too_small(f, m, area, t);
        return;
    }
    let mut s = Screen::new(area.width);
    let h = area.height as usize;
    if m.mode == Mode::FirstRun {
        first_run(&mut s, m, t, h);
        f.render_widget(Paragraph::new(s.lines), area);
        return;
    }
    header(&mut s, m, t);
    // 로고와 탭 사이 숨 쉴 한 줄.
    s.blank();
    tabs_line(&mut s, m, t);
    let body_h = h - 6;
    let start = s.lines.len();
    match m.tab {
        Tab::Findings => findings_body(&mut s, m, t, body_h, h),
        Tab::Ports => ports_body(&mut s, m, t, body_h, h),
        Tab::Log => log_body(&mut s, m, t, body_h, h),
        Tab::Settings => settings_body(&mut s, m, t),
    }
    s.fill_to(start + body_h);
    let bar = status_bar(m, t, s.w);
    s.push(bar);
    let keys = match &m.flash {
        Some(msg) => {
            let mut l = Ln::new(s.w);
            l.push(msg, t.bold(Tone::Warn));
            l
        }
        None => key_hints(keys_for(m), t, s.w),
    };
    s.push(keys);
    f.render_widget(Paragraph::new(s.lines), area);
    if let Some(d) = &m.dialog {
        draw_dialog(f, m, d, area, t);
    } else if m.mode == Mode::Quitting {
        let lines: Vec<Line> = QUITTING
            .iter()
            .map(|l| plain_line(l, Style::new(), DIALOG_INNER))
            .collect();
        draw_box(f, area, t, "끝내는 중", Tone::Warn, lines);
    }
}

fn env_name(l: AutoLevel) -> &'static str {
    match l {
        AutoLevel::NotifyOnly => "notify",
        AutoLevel::Safe => "safe",
        AutoLevel::Aggressive => "aggressive",
    }
}

fn keys_for(m: &Model) -> &'static str {
    match m.tab {
        Tab::Findings if m.rows.is_empty() => KEYS_EMPTY,
        Tab::Findings if m.latest.as_ref().is_some_and(|l| l.status.circuit_open) => {
            KEYS_FINDINGS_CIRCUIT
        }
        Tab::Findings => KEYS_FINDINGS,
        Tab::Ports => KEYS_PORTS,
        Tab::Log if m.events.is_empty() => KEYS_EMPTY,
        Tab::Log => KEYS_LOG,
        Tab::Settings => KEYS_SETTINGS,
    }
}

/// 키 안내 글("키 설명  키 설명")을 키는 강조색, 설명은 보조색으로. 글자는 그대로 둔다.
/// 두 칸 이상의 공백이 묶음 사이 구분이고, 묶음의 첫 낱말이 키다.
fn key_hints(text: &str, t: Theme, w: usize) -> Ln {
    let mut l = Ln::new(w);
    let mut rest = text;
    while !rest.is_empty() {
        let lead = rest.len() - rest.trim_start_matches(' ').len();
        if lead > 0 {
            l.push(&rest[..lead], Style::new());
            rest = &rest[lead..];
        }
        let end = rest.find("  ").unwrap_or(rest.len());
        let group = &rest[..end];
        match group.split_once(' ') {
            Some((k, _)) if !is_key(k) => {
                l.push(group, t.muted());
            }
            Some((k, label)) => {
                l.push(k, t.key());
                l.push(" ", Style::new());
                l.push(label, t.muted());
            }
            None => {
                l.push(group, t.key());
            }
        }
        rest = &rest[end..];
    }
    l
}

/// 키 안내 묶음의 첫 낱말이 키인지(한글 낱말은 '스페이스'만 키).
fn is_key(w: &str) -> bool {
    w == "스페이스" || !w.chars().any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c))
}

/// 지킴이 상태 한 마디(평소 보고만·불안정·일시정지·차단기).
pub fn guard_state(m: &Model) -> String {
    guard_state_tone(m).0
}

fn guard_state_tone(m: &Model) -> (String, Tone) {
    if let Some(msg) = &m.guard_dead {
        return (format!("멈췄어요({msg})"), Tone::Danger);
    }
    let Some(l) = &m.latest else {
        return (STATE_FIRST_SCAN.to_string(), Tone::Info);
    };
    let st = &l.status;
    let (s, tone) = if st.paused {
        (STATE_PAUSED, Tone::Muted)
    } else if st.circuit_open {
        (STATE_CIRCUIT, Tone::Danger)
    } else if st.unstable {
        if st
            .settle_until_unix_ms
            .is_some_and(|t| t > st.last_scan_at_unix_ms)
        {
            (STATE_SETTLING, Tone::Warn)
        } else if st.level == AutoLevel::NotifyOnly {
            (STATE_UNSTABLE_NOTIFY, Tone::Warn)
        } else {
            (STATE_UNSTABLE_AUTO, Tone::Danger)
        }
    } else {
        (STATE_NORMAL, Tone::Ok)
    };
    (s.to_string(), tone)
}

/// 지킴이 상태 막대의 글(색 없이 이어 붙인 모양, 테스트·lab 검사용).
pub fn guard_line(m: &Model) -> String {
    let (head, state, rest) = guard_parts(m);
    let mut s = format!(" {head}  {state} ");
    for r in rest {
        s.push_str(&format!("  {r}"));
    }
    s
}

/// (수준 구간, 상태 구간, 나머지 조각들).
fn guard_parts(m: &Model) -> (String, String, Vec<String>) {
    let level = m
        .latest
        .as_ref()
        .map(|l| l.status.level)
        .unwrap_or_else(|| m.effective_level());
    let lock = if m.env_warning.is_some() {
        "(STOPCAT_GUARD_LEVEL 값을 몰라 보고만)"
    } else if m.env_level.is_some() {
        "(STOPCAT_GUARD_LEVEL 고정)"
    } else {
        ""
    };
    let head = format!("지킴이 {}{lock}", level_ko(level));
    let mut rest = Vec::new();
    if m.guard_dead.is_none()
        && let Some(l) = &m.latest
    {
        let st = &l.status;
        if st.unstable || st.circuit_open || st.terminations_in_window > 0 {
            rest.push(auto_count(l));
        }
    }
    if m.e2e_lock {
        rest.push("STOPCAT_E2E_ALLOW_PIDS 잠금".to_string());
    }
    if m.guard_dead.is_none()
        && let Some(l) = &m.latest
    {
        rest.push(format!(
            "확인 {}",
            fmt::hhmmss(l.status.last_scan_at_unix_ms)
        ));
    }
    (head, guard_state(m), rest)
}

fn status_bar(m: &Model, t: Theme, w: usize) -> Ln {
    let (head, _, rest) = guard_parts(m);
    let (state, tone) = guard_state_tone(m);
    let mut l = Ln::new(w);
    l.push(&format!(" {head} "), t.chip_light(Tone::Violet));
    let state_style = if tone == Tone::Danger || tone == Tone::Muted {
        t.chip_light(tone)
    } else {
        t.chip(tone)
    };
    l.push(&format!(" {state} "), state_style);
    for r in &rest {
        l.push(&format!("  {r}"), t.bar());
    }
    l.fill(t.bar());
    l
}

fn auto_count(l: &super::state::Latest) -> String {
    format!(
        "자동 종료 {}/{}({}분)",
        l.status.terminations_in_window,
        l.policy.max_auto_terminations,
        l.policy.rate_window_ms / 60_000
    )
}

/// 첫 보고인지: 지킴이가 이전 스캔이 없어 CPU를 재지 못하면 `snapshot.cpu_sample_interval_ms`를
/// 비워 둔다(stopcat-guard `fill_cpu_pct`). 그때는 CPU·디스크 근거가 모두 '모름'이다.
pub fn first_report(m: &Model) -> bool {
    m.latest
        .as_ref()
        .is_some_and(|l| l.snapshot.cpu_sample_interval_ms.is_none())
}

/// 머리 둘째 줄 확보량 글(색 없이). 첫 보고에서 '필요 없음'이 0이면 단정하지 않는다.
pub fn reclaim_line(m: &Model) -> String {
    match &m.latest {
        Some(l) if first_report(m) && l.report.totals.unneeded_bytes == 0 => {
            RECLAIM_FIRST.to_string()
        }
        Some(l) => {
            sec::reclaim_text(&l.report.totals).unwrap_or_else(|| sec::RECLAIM_NOTHING.to_string())
        }
        None => String::new(),
    }
}

fn logo_row(l: &mut Ln, row: usize, t: Theme) {
    for (i, c) in LOGO[row].chars().enumerate() {
        let st = if c == ' ' {
            Style::new()
        } else {
            t.gradient(i, LOGO_W)
        };
        l.push(&c.to_string(), st);
    }
}

fn header(s: &mut Screen, m: &Model, t: Theme) {
    for row in 0..2 {
        let mut l = Ln::new(s.w);
        logo_row(&mut l, row, t);
        l.pad_to(LOGO_W + HEAD_GAP, Style::new());
        if row == 0 {
            health_spans(&mut l, m, t);
        } else {
            reclaim_spans(&mut l, m, t);
        }
        s.push(l);
    }
}

fn health_tone(level: HealthLevel) -> Tone {
    match level {
        HealthLevel::Ok => Tone::Ok,
        HealthLevel::Watch => Tone::Warn,
        HealthLevel::Critical => Tone::Danger,
    }
}

/// "● 메모리 정상  압력 1 · 압축 41GB · …": 상태는 건강 색, 조각은 들어가는 만큼만(통째로).
fn health_spans(l: &mut Ln, m: &Model, t: Theme) {
    let Some(latest) = &m.latest else {
        l.push("◌ ", t.muted());
        l.push(LOADING_HEAD, t.muted());
        return;
    };
    let health = &latest.report.health;
    let tone = health_tone(health.level);
    let head = health.headline_ko.as_str();
    let (state, rest) = head.split_once(" — ").unwrap_or((head, ""));
    l.push("● ", t.fg(tone));
    l.push(state, t.bold(tone));
    for part in rest.split(" · ").filter(|p| !p.is_empty()) {
        let sep = " · ";
        if width(sep) + width(part) > l.room() {
            break;
        }
        l.push(sep, t.muted());
        match part.rsplit_once(' ') {
            Some((k, v)) => {
                l.push(k, t.muted());
                l.push(" ", Style::new());
                l.push(v, Style::new().add_modifier(Modifier::BOLD));
            }
            None => {
                l.push(part, Style::new());
            }
        }
    }
}

/// "확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB": 값은 목록 구역 색과 같게.
fn reclaim_spans(l: &mut Ln, m: &Model, t: Theme) {
    let Some(latest) = &m.latest else { return };
    let tt = &latest.report.totals;
    if first_report(m) && tt.unneeded_bytes == 0 {
        l.push(RECLAIM_FIRST, t.muted());
        return;
    }
    if tt.unneeded_bytes == 0 && tt.check_bytes == 0 && tt.manual_bytes == 0 {
        l.push(sec::RECLAIM_NOTHING, t.muted());
        return;
    }
    let mut parts = vec![(
        "확보 가능 ",
        if tt.unneeded_bytes == 0 {
            "0".to_string()
        } else {
            fmt::bytes(tt.unneeded_bytes)
        },
        Tone::Brand,
    )];
    if tt.check_bytes > 0 {
        parts.push((
            "확인하면 ",
            format!("+{}", fmt::bytes(tt.check_bytes)),
            Tone::Warn,
        ));
    }
    if tt.manual_bytes > 0 {
        parts.push((
            "직접 하면 ",
            format!("+{}", fmt::bytes(tt.manual_bytes)),
            Tone::Violet,
        ));
    }
    for (i, (k, v, tone)) in parts.iter().enumerate() {
        let sep = if i == 0 { "" } else { " · " };
        if width(sep) + width(k) + width(v) > l.room() {
            break;
        }
        l.push(sep, t.muted());
        l.push(k, t.muted());
        l.push(v, t.bold(*tone));
    }
}

fn tabs_line(s: &mut Screen, m: &Model, t: Theme) {
    let count = |n: usize| {
        if m.latest.is_some() {
            format!(" {n}")
        } else {
            String::new()
        }
    };
    let names = [
        format!("1 보고{}", count(m.rows.len())),
        format!("2 포트{}", count(m.ports.len())),
        format!("3 자동 처리 기록{}", count(m.events.len())),
        "4 설정".to_string(),
    ];
    let mut l = Ln::new(s.w);
    for (i, n) in names.iter().enumerate() {
        let st = if i == m.tab.index() {
            t.chip(Tone::Brand)
        } else {
            t.muted()
        };
        l.push(&format!(" {n} "), st);
        l.push(" ", Style::new());
    }
    credit(&mut l, t);
    s.push(l);
}

/// 줄 오른쪽 끝에 "Made by Withgenie"(남은 폭이 모자라면 넣지 않는다).
fn credit(l: &mut Ln, t: Theme) {
    let cw = width(CREDIT);
    if l.room() < cw + 2 {
        return;
    }
    let at = l.max - cw;
    l.pad_to(at, Style::new());
    let it = |st: Style| st.add_modifier(Modifier::ITALIC);
    l.push("Made by ", it(t.muted()));
    l.push("Withgenie", it(t.fg(Tone::Brand)));
}

fn list_window(cursor: usize, n: usize, rows: usize) -> (usize, usize) {
    let off = cursor.saturating_sub(rows.saturating_sub(1));
    (off, n.min(off + rows))
}

/// 자세히 칸 안쪽 줄 수(80×24에서 4, 화면이 4줄 커질 때마다 1).
fn detail_h(h: usize) -> usize {
    4 + h.saturating_sub(24) / 4
}

/// 이름 칸(8칸) + 값. 이름은 보조색, 값은 `vst`.
fn wrap_pairs(pairs: &[(&str, String, Style)], w: usize, max: usize, t: Theme) -> Vec<Ln> {
    let mut out = Vec::new();
    for (name, text, vst) in pairs {
        let first = pad(name, 8);
        for (i, line) in fmt::wrap(text, w, &first, "        ")
            .into_iter()
            .enumerate()
        {
            let mut l = Ln::new(w);
            let body = if i == 0 {
                l.push(&first, t.muted());
                line.strip_prefix(first.as_str())
                    .unwrap_or(&line)
                    .to_string()
            } else {
                l.push("        ", Style::new());
                line.trim_start_matches(' ').to_string()
            };
            l.push(&body, *vst);
            out.push(l);
        }
    }
    out.truncate(max);
    out
}

/// 둥근 테두리 칸(제목 + 안쪽 줄 `inner_h`개, 모자라면 빈 줄).
fn panel(s: &mut Screen, t: Theme, title: &str, title_st: Style, body: Vec<Ln>, inner_h: usize) {
    let w = s.w;
    let b = t.border();
    let mut top = Ln::new(w);
    top.push("╭─ ", b);
    top.push(&truncate(title, w.saturating_sub(6)), title_st);
    top.push(" ", b);
    let rest = w.saturating_sub(top.w + 1);
    top.push(&"─".repeat(rest), b);
    top.push("╮", b);
    s.push(top);
    let cw = w.saturating_sub(4);
    let mut body = body.into_iter();
    for _ in 0..inner_h {
        let mut l = Ln::new(w);
        l.push("│ ", b);
        if let Some(c) = body.next() {
            for sp in c.spans {
                let st = sp.style;
                l.push(&sp.content, st);
            }
        }
        l.pad_to(cw + 2, Style::new());
        l.push(" │", b);
        s.push(l);
    }
    let mut bot = Ln::new(w);
    bot.push("╰", b);
    bot.push(&"─".repeat(w.saturating_sub(2)), b);
    bot.push("╯", b);
    s.push(bot);
}

/// 80칸에서 대상 칸 폭. 넓은 창에서는 늘어난 만큼 더한다.
const NAME_W: usize = 21;
/// 나이 칸(가장 긴 '23시간' 6칸 + 근거 칸과의 공백 1칸).
const AGE_W: usize = 7;
const EVIDENCE_W: usize = 24;
/// 커서·고르기 칸("❯ ○ ").
const LEAD_W: usize = 4;

pub fn column_header(w: usize) -> String {
    format!(
        "{}{}{}  {}{}지킴이",
        " ".repeat(LEAD_W),
        pad("대상", NAME_W + w.saturating_sub(80)),
        lpad("크기", 6),
        pad("나이", AGE_W),
        pad("근거", EVIDENCE_W)
    )
}

fn section_tone(s: Section) -> Tone {
    match s {
        Section::Unneeded => Tone::Brand,
        Section::Check => Tone::Warn,
        Section::Working => Tone::Ok,
        Section::Manual => Tone::Violet,
        Section::Info => Tone::Info,
    }
}

/// 지킴이 칸 앞 기호와 색.
pub fn mark_glyph(mk: Mark) -> (&'static str, Tone) {
    match mk {
        Mark::AutoPending(s, n) => {
            let g = match (s * 4).checked_div(n).unwrap_or(0) {
                0 => "○",
                1 => "◔",
                2 => "◑",
                3 => "◕",
                _ => "●",
            };
            (g, Tone::Danger)
        }
        Mark::CircuitHold => ("⊘", Tone::Danger),
        Mark::StandbyAuto => ("◷", Tone::Violet),
        Mark::Recommend => ("◆", Tone::Brand),
        Mark::Demoted => ("▽", Tone::Info),
        Mark::Check => ("▲", Tone::Warn),
        Mark::Working => ("●", Tone::Ok),
        Mark::Manual => ("◇", Tone::Violet),
        Mark::RestartApp => ("↻", Tone::Muted),
        Mark::Info => ("", Tone::Muted),
    }
}

fn size_style(b: Option<u64>, t: Theme) -> Style {
    const MIB: u64 = 1024 * 1024;
    match b {
        Some(b) if b >= 1024 * MIB => t.bold(Tone::BrandEnd),
        Some(b) if b >= 100 * MIB => Style::new(),
        _ => t.muted(),
    }
}

fn finding_ln(r: &Row, cur: bool, picked: bool, w: usize, now_unix_ms: u64, t: Theme) -> Ln {
    let lw = NAME_W + w.saturating_sub(80);
    let label = truncate(&r.label, lw - 1);
    let size = r.size.map(fmt::bytes).unwrap_or_default();
    let age = r
        .started_unix_ms
        .map(|s| fmt::age_short(now_unix_ms.saturating_sub(s)))
        .unwrap_or_default();
    let (boxed, box_st) = if !r.actionable {
        (" ", Style::new())
    } else if picked {
        ("◉", t.bold(Tone::Brand))
    } else {
        ("○", t.muted())
    };
    let mut l = Ln::new(w);
    l.push(if cur { CURSOR } else { " " }, t.bold(Tone::Brand));
    l.push(" ", Style::new());
    l.push(boxed, box_st);
    l.push(" ", Style::new());
    let name_st = if picked || cur {
        Style::new().add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };
    l.push(&pad(&label, lw), name_st);
    l.push(&lpad(&size, 6), size_style(r.size, t));
    l.push("  ", Style::new());
    l.push(&pad(&age, AGE_W), t.muted());
    l.push(
        &pad(
            &truncate(&r.evidence(now_unix_ms), EVIDENCE_W - 1),
            EVIDENCE_W,
        ),
        t.muted(),
    );
    let (g, tone) = mark_glyph(r.mark);
    if !g.is_empty() {
        l.push(g, t.fg(tone));
        l.push(" ", Style::new());
        l.push(&r.mark.text(), t.fg(tone));
    }
    if cur {
        l.fill(Style::new());
        l.over(t.selection());
    }
    l
}

/// 목록 한 줄의 글자(색 없이). `now_unix_ms`는 스냅샷 시각(나이 칸).
pub fn finding_row(r: &Row, cur: bool, picked: bool, w: usize, now_unix_ms: u64) -> String {
    finding_ln(
        r,
        cur,
        picked,
        w,
        now_unix_ms,
        Theme::new(super::theme::ColorMode::None),
    )
    .text()
    .trim_end()
    .to_string()
}

/// 자세히 칸: 무엇·근거·대상(또는 방법)·지킴이·왜. `f`는 그 줄의 발견(제목·설명).
pub fn finding_detail(
    r: &Row,
    f: Option<&Finding>,
    now_unix_ms: u64,
) -> Vec<(&'static str, String)> {
    let title = f
        .map(|f| f.title_ko.clone())
        .unwrap_or_else(|| r.label.clone());
    let detail_ko = f.map(|f| f.detail_ko.as_str()).unwrap_or("");
    let mut d = vec![("무엇", title)];
    let mut ev = r.evidence_long(now_unix_ms);
    if let Some(c) = r.confidence {
        if !ev.is_empty() {
            ev.push_str(" · ");
        }
        ev.push_str(&format!("신뢰도 {}", confidence_ko(c)));
    }
    if !ev.is_empty() {
        d.push(("근거", ev));
    }
    if r.section == Section::Manual {
        let how = if detail_ko.is_empty() {
            r.hint.to_string()
        } else {
            detail_ko.to_string()
        };
        d.push(("방법", how));
    } else if let Some(t) = r.target {
        let mut info = format!(
            "pid {} · {}째",
            t.pid,
            fmt::duration(now_unix_ms.saturating_sub(t.start_time_unix_ms))
        );
        if let Some(p) = &r.project {
            info.push_str(&format!(" · 프로젝트 {p}"));
        }
        d.push(("대상", info));
    }
    d.push(("지킴이", r.mark.explain()));
    if r.section != Section::Manual && !detail_ko.is_empty() {
        d.push(("왜", detail_ko.to_string()));
    }
    d
}

/// 구역 머리줄 글. 그릴 때는 첫 조각(이름·개수)을 색 칩으로 만든다.
pub fn section_header(sect: Section, n: usize, bytes: u64) -> String {
    let b = fmt::bytes(bytes);
    match sect {
        Section::Unneeded if bytes > 0 => {
            format!("필요 없음 {n} · 정리하면 약 {b} · c 로 전부 정리")
        }
        Section::Unneeded if n > 0 => format!("필요 없음 {n} · c 로 전부 정리"),
        Section::Unneeded => "필요 없음 0".to_string(),
        Section::Check if bytes > 0 => {
            format!("확인 필요 {n} · 쓰고 있는지 확실하지 않아 보고만 · 확인하면 약 {b}")
        }
        Section::Check => format!("확인 필요 {n} · 쓰고 있는지 확실하지 않아 보고만"),
        Section::Working => format!("일하는 중 {n} · 건드리지 않음"),
        Section::Manual if bytes > 0 => format!("직접 하면 확보 {n} · 약 {b} · 방법은 w"),
        Section::Manual => format!("직접 하면 확보 {n} · 방법은 w"),
        Section::Info => format!("알아 둘 것 {n}"),
    }
}

fn section_ln(text: &str, sect: Section, t: Theme, w: usize) -> Ln {
    let tone = section_tone(sect);
    let (name, rest) = text.split_once(" · ").unwrap_or((text, ""));
    let mut l = Ln::new(w);
    let chip = if tone == Tone::Violet || tone == Tone::Info {
        t.chip_light(tone)
    } else {
        t.chip(tone)
    };
    l.push(&format!(" {name} "), chip);
    if !rest.is_empty() {
        l.push("  ", Style::new());
        l.push(rest, t.fg(tone));
    }
    l
}

pub fn more_below(n: usize) -> String {
    format!("  ↓ {n}줄 더 있어요(↓ 로 내려 보기)")
}

pub fn more_above(n: usize) -> String {
    format!("  ↑ {n}줄 더 있어요(↑ 로 올려 보기)")
}

enum Disp {
    Header(Section, String),
    Text(&'static str),
    Row(usize),
}

fn report_lines(m: &Model) -> Vec<Disp> {
    let totals = m.latest.as_ref().map(|l| &l.report.totals);
    let first = first_report(m);
    let mut out = Vec::new();
    for sect in sec::ORDER {
        let idx: Vec<usize> = (0..m.rows.len())
            .filter(|&i| m.rows[i].section == sect)
            .collect();
        if idx.is_empty() && (sect != Section::Unneeded || first) {
            continue;
        }
        let bytes = match (sect, totals) {
            (Section::Unneeded, Some(t)) => t.unneeded_bytes,
            (Section::Check, Some(t)) => t.check_bytes,
            (Section::Manual, Some(t)) => t.manual_bytes,
            _ => 0,
        };
        out.push(Disp::Header(sect, section_header(sect, idx.len(), bytes)));
        if idx.is_empty() {
            out.push(Disp::Text(UNNEEDED_EMPTY_LINE));
        }
        out.extend(idx.into_iter().map(Disp::Row));
    }
    out
}

/// 넘칠 때 첫/끝 줄을 위·아래 표시로 쓰고, 커서 행이 보이는 가장 위 창을 고른다.
/// 돌려주는 값: (시작, 보일 개수, 위 표시, 아래 표시).
fn report_window(total: usize, cursor_line: usize, room: usize) -> (usize, usize, bool, bool) {
    if total <= room {
        return (0, total, false, false);
    }
    let mut off = 0;
    loop {
        let top = off > 0;
        let mut content = room - usize::from(top);
        let bottom = off + content < total;
        if bottom {
            content -= 1;
        }
        if cursor_line < off + content || off + content >= total {
            return (off, content, top, bottom);
        }
        off += 1;
    }
}

fn muted_italic(t: Theme) -> Style {
    t.muted().add_modifier(Modifier::ITALIC)
}

fn empty_report(s: &mut Screen, m: &Model, t: Theme) {
    let ok = m
        .latest
        .as_ref()
        .is_some_and(|l| l.report.health.level == HealthLevel::Ok);
    s.blank();
    for c in EMPTY_CAT {
        s.text(&format!("  {c}"), t.fg(Tone::Brand));
    }
    for (i, l) in EMPTY_BODY.iter().enumerate() {
        if i == 1 {
            let (txt, tone) = if ok {
                (*l, Tone::Ok)
            } else {
                (EMPTY_NOT_OK, Tone::Warn)
            };
            s.text(txt, t.bold(tone));
        } else {
            s.text(l, t.muted());
        }
    }
}

fn findings_body(s: &mut Screen, m: &Model, t: Theme, body_h: usize, h: usize) {
    if m.latest.is_none() {
        s.blank();
        s.text("  맥 상태를 확인하고 있어요…", muted_italic(t));
        return;
    }
    let first = first_report(m);
    if first {
        s.text(FIRST_REPORT, muted_italic(t));
    }
    if m.rows.is_empty() {
        if !first {
            empty_report(s, m, t);
        }
        return;
    }
    let dh = detail_h(h);
    let list_h = body_h - 1 - (dh + 2) - usize::from(first);
    let now = m.latest.as_ref().map_or(0, |l| l.snapshot.taken_at_unix_ms);
    s.text(&column_header(s.w), t.muted());
    let disp = report_lines(m);
    let cur = m.cursor[0];
    let cursor_line = disp
        .iter()
        .position(|d| matches!(d, Disp::Row(i) if *i == cur))
        .unwrap_or(0);
    let (off, n, top, bottom) = report_window(disp.len(), cursor_line, list_h);
    let start = s.lines.len();
    if top {
        s.text(&more_above(off), muted_italic(t));
    }
    for d in disp.iter().skip(off).take(n) {
        match d {
            Disp::Header(sect, text) => {
                let l = section_ln(text, *sect, t, s.w);
                s.push(l);
            }
            Disp::Text(text) => s.text(text, t.muted()),
            Disp::Row(i) => {
                let r = &m.rows[*i];
                let l = finding_ln(
                    r,
                    *i == cur,
                    m.selected.contains(&r.finding_id),
                    s.w,
                    now,
                    t,
                );
                s.push(l);
            }
        }
    }
    if bottom {
        s.text(&more_below(disp.len() - off - n), muted_italic(t));
    }
    // 목록이 짧으면 자세히 칸을 목록 바로 아래(빈 줄 하나 띄움)로 올리고 남는 줄을 자세히에 준다.
    let used = s.lines.len() - start;
    let spare = list_h.saturating_sub(used + 1);
    s.fill_to(start + list_h - spare);
    if let Some(r) = m.rows.get(cur) {
        let f = m
            .latest
            .as_ref()
            .and_then(|l| l.report.findings.iter().find(|f| f.id == r.finding_id));
        let mark_tone = mark_glyph(r.mark).1;
        let pairs: Vec<(&str, String, Style)> = finding_detail(r, f, now)
            .into_iter()
            .map(|(k, v)| {
                let st = match k {
                    "무엇" => Style::new().add_modifier(Modifier::BOLD),
                    "지킴이" => t.fg(mark_tone),
                    _ => Style::new(),
                };
                (k, v, st)
            })
            .collect();
        let body = wrap_pairs(&pairs, s.w - 4, dh + spare, t);
        let inner = body.len().clamp(4, dh + spare);
        panel(
            s,
            t,
            &format!("자세히 · {}", r.label),
            t.bold(Tone::Brand),
            body,
            inner,
        );
    }
}

fn flag_chip(flag: &str, t: Theme) -> Style {
    match flag {
        "노출" => t.chip_light(Tone::Danger),
        _ => t.chip(Tone::Warn),
    }
}

fn ports_body(s: &mut Screen, m: &Model, t: Theme, body_h: usize, h: usize) {
    if m.ports.is_empty() {
        s.blank();
        s.text("  기다리는 포트가 없어요.", t.muted());
        return;
    }
    let dh = detail_h(h) + 1;
    let list_h = body_h - 1 - (dh + 2);
    let lw = 30 + s.w.saturating_sub(80);
    s.text(
        &format!(
            "  {}{}{}열린 범위",
            pad("포트", 8),
            pad("프로그램", lw),
            pad("프로젝트", 14)
        ),
        t.muted(),
    );
    let cur = m.cursor[1];
    let (from, to) = list_window(cur, m.ports.len(), list_h);
    for (i, p) in m.ports.iter().enumerate().take(to).skip(from) {
        let mut l = Ln::new(s.w);
        l.push(if i == cur { CURSOR } else { " " }, t.bold(Tone::Brand));
        l.push(" ", Style::new());
        l.push(&pad(&format!(":{}", p.port), 8), t.bold(Tone::Info));
        l.push(&pad(&truncate(&p.label, lw - 1), lw), Style::new());
        l.push(&pad(&truncate(&p.project, 13), 14), t.muted());
        l.push(&p.scope, Style::new());
        if !p.flag.is_empty() {
            l.push("  ", Style::new());
            l.push(&format!(" {} ", p.flag), flag_chip(p.flag, t));
        }
        if i == cur {
            l.fill(Style::new());
            l.over(t.selection());
        }
        s.push(l);
    }
    let start = s.lines.len();
    s.fill_to(start + (list_h - (to - from)));
    if let Some(p) = m.ports.get(cur) {
        let cw = s.w - 4;
        let mut out: Vec<Ln> = Vec::new();
        for d in &p.detail {
            for x in fmt::wrap(d, cw, "", "") {
                let mut l = Ln::new(cw);
                l.push(&x, Style::new());
                out.push(l);
            }
        }
        if let Some(l) = &m.latest {
            let age = l
                .snapshot
                .taken_at_unix_ms
                .saturating_sub(p.target.start_time_unix_ms);
            let mut x = Ln::new(cw);
            x.push(&format!("{}째 실행 중", fmt::duration(age)), t.muted());
            out.push(x);
        }
        out.truncate(dh);
        panel(
            s,
            t,
            &format!(":{} {}", p.port, p.label),
            t.bold(Tone::Info),
            out,
            dh,
        );
    }
}

pub fn event_kind_ko(k: GuardEventKind) -> &'static str {
    match k {
        GuardEventKind::AutoTerminated => "자동 종료",
        GuardEventKind::Demoted => "우선순위 낮춤(직접)",
        GuardEventKind::Undemoted => "우선순위 되돌림",
        GuardEventKind::Notified => "알림",
        GuardEventKind::Skipped => "건너뜀",
        GuardEventKind::Refused => "끄지 않음",
        GuardEventKind::CircuitOpen => "차단기 열림",
        GuardEventKind::CircuitReset => "차단기 풂",
        GuardEventKind::Paused => "일시정지",
        GuardEventKind::Resumed => "다시 시작",
        GuardEventKind::LevelChanged => "수준 바꿈",
        GuardEventKind::ScanError => "확인 오류",
        GuardEventKind::Unstable => "불안정 시작",
        GuardEventKind::Stable => "정상으로 돌아옴",
    }
}

fn event_tone(k: GuardEventKind) -> Tone {
    match k {
        GuardEventKind::AutoTerminated => Tone::Brand,
        GuardEventKind::Demoted | GuardEventKind::Undemoted | GuardEventKind::Notified => {
            Tone::Info
        }
        GuardEventKind::CircuitOpen | GuardEventKind::ScanError | GuardEventKind::Unstable => {
            Tone::Danger
        }
        GuardEventKind::Refused => Tone::Warn,
        GuardEventKind::Stable | GuardEventKind::CircuitReset | GuardEventKind::Resumed => Tone::Ok,
        GuardEventKind::LevelChanged => Tone::Violet,
        GuardEventKind::Skipped | GuardEventKind::Paused => Tone::Muted,
    }
}

fn log_body(s: &mut Screen, m: &Model, t: Theme, body_h: usize, h: usize) {
    if m.events.is_empty() {
        for (i, l) in LOG_EMPTY.iter().enumerate() {
            s.text(
                l,
                if i == 1 {
                    Style::new().add_modifier(Modifier::BOLD)
                } else {
                    t.muted()
                },
            );
        }
        return;
    }
    let tl = m.tally;
    let mut sum = Ln::new(s.w);
    sum.push("  이번에 자동으로 정리한 양 약 ", t.muted());
    sum.push(&fmt::bytes(tl.reclaimed_bytes), t.bold(Tone::Ok));
    sum.push(" · 자동 종료 ", t.muted());
    sum.push(&format!("{}건", tl.auto_terminated), t.bold(Tone::Brand));
    sum.push(" · 직접 낮춤 ", t.muted());
    sum.push(&format!("{}건", tl.demoted), t.bold(Tone::Info));
    s.push(sum);
    let dh = detail_h(h) + 1;
    let list_h = body_h - 2 - (dh + 2);
    let lw = 34 + s.w.saturating_sub(80);
    s.text(
        &format!(
            "  {}{}{}{}",
            pad("시각", 10),
            pad("한 일", 16),
            pad("대상", lw),
            lpad("회수", 7)
        ),
        t.muted(),
    );
    let cur = m.cursor[2];
    let (from, to) = list_window(cur, m.events.len(), list_h);
    for (i, e) in m.events.iter().enumerate().take(to).skip(from) {
        let rc = if e.reclaimed_bytes > 0 {
            fmt::bytes(e.reclaimed_bytes)
        } else {
            String::new()
        };
        let mut l = Ln::new(s.w);
        l.push(if i == cur { CURSOR } else { " " }, t.bold(Tone::Brand));
        l.push(" ", Style::new());
        l.push(&pad(&fmt::hhmmss(e.at_unix_ms), 10), t.muted());
        l.push(&pad(event_kind_ko(e.kind), 16), t.fg(event_tone(e.kind)));
        l.push(&pad(&truncate(&e.label_ko, lw - 1), lw), Style::new());
        l.push(&lpad(&rc, 7), t.bold(Tone::Ok));
        if i == cur {
            l.fill(Style::new());
            l.over(t.selection());
        }
        s.push(l);
    }
    let start = s.lines.len();
    s.fill_to(start + (list_h - (to - from)));
    if let Some(e) = m.events.get(cur) {
        let mut pairs = vec![("내용", e.detail_ko.clone(), Style::new())];
        if e.reclaimed_bytes > 0 {
            pairs.push((
                "회수",
                format!("약 {}", fmt::bytes(e.reclaimed_bytes)),
                t.bold(Tone::Ok),
            ));
        }
        let body = wrap_pairs(&pairs, s.w - 4, dh, t);
        panel(
            s,
            t,
            &format!(
                "{} {} — {}",
                fmt::hhmmss(e.at_unix_ms),
                event_kind_ko(e.kind),
                e.label_ko
            ),
            t.bold(event_tone(e.kind)),
            body,
            dh,
        );
    }
}

fn settings_body(s: &mut Screen, m: &Model, t: Theme) {
    let cur = m.cursor[3];
    let level = m.effective_level();
    let lock = if m.env_level.is_some() {
        "STOPCAT_GUARD_LEVEL로 고정"
    } else {
        "Enter 바꾸기"
    };
    let rows = [
        (
            "지킴이 수준",
            format!("[{}]", level_ko(level)),
            lock.to_string(),
        ),
        (
            "확인 간격",
            format!("[{}]", fmt::secs(m.current_interval())),
            "Enter 바꾸기(5·10·30초)".to_string(),
        ),
    ];
    for (i, (name, val, hint)) in rows.iter().enumerate() {
        let mut l = Ln::new(s.w);
        l.push(if i == cur { CURSOR } else { " " }, t.bold(Tone::Brand));
        l.push(" ", Style::new());
        l.push(&pad(name, 19), Style::new().add_modifier(Modifier::BOLD));
        l.push(&pad(val, 14), t.bold(Tone::Violet));
        l.push(hint, t.muted());
        if i == cur {
            l.fill(Style::new());
            l.over(t.selection());
        }
        s.push(l);
    }
    s.text(
        "  로그인 시 자동 실행 — 다음 버전(아직 쓸 수 없어요)",
        muted_italic(t),
    );
    for l in SETTINGS_LINES {
        let st = if l.starts_with("    ") {
            t.muted()
        } else if let Some(rest) = l.strip_prefix("  ")
            && !rest.contains(':')
        {
            Style::new().add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        match l.split_once(": ") {
            Some((k, v)) if !l.starts_with("    ") => {
                let mut x = Ln::new(s.w);
                x.push(&format!("{k}: "), Style::new().add_modifier(Modifier::BOLD));
                x.push(v, t.muted());
                s.push(x);
            }
            _ => s.text(l, st),
        }
    }
    if let Some(l) = &m.latest {
        let (state, tone) = guard_state_tone(m);
        let mut x = Ln::new(s.w);
        x.push("  지킴이 상태  ", Style::new().add_modifier(Modifier::BOLD));
        x.push(&state, t.bold(tone));
        x.push(
            &format!(
                " · {} · 확인 {}",
                auto_count(l),
                fmt::hhmmss(l.status.last_scan_at_unix_ms)
            ),
            t.muted(),
        );
        s.push(x);
    }
    if !m.config_path.is_empty() {
        let mut x = Ln::new(s.w);
        x.push("  설정 파일  ", Style::new().add_modifier(Modifier::BOLD));
        x.push(&m.config_path, t.muted());
        s.push(x);
    }
}

/// 가운데 맞춤 한 줄.
fn centered(s: &mut Screen, text: &str, st: Style) {
    let pad_l = s.w.saturating_sub(width(text)) / 2;
    let mut l = Ln::new(s.w);
    l.pad_to(pad_l, Style::new());
    l.push(text, st);
    s.push(l);
}

fn centered_logo(s: &mut Screen, t: Theme) {
    let pad_l = s.w.saturating_sub(LOGO_W) / 2;
    for row in 0..2 {
        let mut l = Ln::new(s.w);
        l.pad_to(pad_l, Style::new());
        logo_row(&mut l, row, t);
        s.push(l);
    }
}

fn first_run(s: &mut Screen, m: &Model, t: Theme, h: usize) {
    s.blank();
    centered_logo(s, t);
    centered(s, TAGLINE, t.muted());
    s.blank();
    let cw = s.w - 4;
    let mut body: Vec<Ln> = FIRST_RUN_LINES
        .iter()
        .map(|l| {
            let mut x = Ln::new(cw);
            match l.split_once(": ") {
                Some((k, v)) => {
                    x.push(&format!("{k}: "), t.bold(Tone::Ok));
                    x.push(v, Style::new());
                }
                None if l.starts_with("안정화 자동(추천)") => {
                    x.push(l, Style::new().add_modifier(Modifier::BOLD));
                }
                None => {
                    x.push(l, Style::new());
                }
            }
            x
        })
        .collect();
    if let Some(l) = m.env_level {
        body.push(Ln::new(cw));
        let mut x = Ln::new(cw);
        x.push(
            &format!(
                "지금은 STOPCAT_GUARD_LEVEL={} 로 실행 중이라 고른 값은 저장만 해요.",
                env_name(l)
            ),
            t.bold(Tone::Warn),
        );
        body.push(x);
    }
    let room = h.saturating_sub(s.lines.len() + 4);
    let inner = body.len().min(room);
    body.truncate(inner);
    panel(s, t, FIRST_RUN_TITLE, t.bold(Tone::Violet), body, inner);
    s.fill_to(h - 2);
    let mut c = Ln::new(s.w);
    credit(&mut c, t);
    s.push(c);
    let keys = key_hints(KEYS_FIRST_RUN, t, s.w);
    s.push(keys);
}

fn draw_too_small(f: &mut Frame, m: &Model, area: Rect, t: Theme) {
    let mut s = Screen::new(area.width);
    let h = area.height as usize;
    let show_logo = s.w >= LOGO_W + 2 && h >= 9;
    let content = 4 + if show_logo { 3 } else { 0 };
    s.fill_to(h.saturating_sub(content) / 2);
    if show_logo {
        centered_logo(&mut s, t);
        s.blank();
    }
    centered(&mut s, TOO_SMALL, t.bold(Tone::Warn));
    centered(
        &mut s,
        &format!("지금 {}×{}, 필요 80×24 이상", m.width, m.height),
        t.muted(),
    );
    s.blank();
    let keys = key_hints("q 끝", t, s.w);
    let pad_l = s.w.saturating_sub(keys.w) / 2;
    let mut l = Ln::new(s.w);
    l.pad_to(pad_l, Style::new());
    for sp in keys.spans {
        let st = sp.style;
        l.push(&sp.content, st);
    }
    s.push(l);
    s.fill_to(h);
    f.render_widget(Paragraph::new(s.lines), area);
}

/// 대화상자 뒤 화면을 어둡게(색이 없으면 흐리게).
fn backdrop(f: &mut Frame, t: Theme) {
    let dim = t.color(Tone::Backdrop);
    let buf = f.buffer_mut();
    let a = buf.area;
    for y in a.y..a.y + a.height {
        for x in a.x..a.x + a.width {
            if let Some(c) = buf.cell_mut((x, y)) {
                match dim {
                    Some(d) => {
                        c.fg = d;
                        c.bg = Color::Reset;
                        c.modifier = Modifier::empty();
                    }
                    None => c.modifier = Modifier::DIM,
                }
            }
        }
    }
}

fn plain_line(s: &str, st: Style, w: usize) -> Line<'static> {
    let mut l = Ln::new(w);
    l.push(s, st);
    l.line()
}

/// 확인·닫기 안내 줄인지(키 강조로 그린다).
fn is_hint_line(s: &str) -> bool {
    use super::state::{CLOSE_ANY, CONFIRM, CONFIRM_WITH_WARNING, DEMOTE_CONFIRM};
    [CONFIRM, CONFIRM_WITH_WARNING, DEMOTE_CONFIRM, CLOSE_ANY].contains(&s)
        || s == AGGRESSIVE_LINES[7]
        || s.starts_with("↑↓ ")
}

/// 미리보기·결과 줄 하나를 쓰임새에 맞는 색으로.
fn dialog_line(s: &str, t: Theme, w: usize) -> Line<'static> {
    if is_hint_line(s) {
        return key_hints(s, t, w).line();
    }
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let st = if s.starts_with("주의:") {
        t.bold(Tone::Warn)
    } else if s.starts_with("끄지 않아요") || s.starts_with("낮추지 않아요") {
        t.bold(Tone::Danger)
    } else if s.starts_with("   방법:") || s.starts_with("기준:") || s.starts_with("기록:") {
        t.muted()
    } else if s.contains("미리보기 —") || s.starts_with("정리 결과 —") {
        t.bold(Tone::Brand)
    } else if s.chars().next().is_some_and(|c| c.is_ascii_digit()) && s.contains(". ") {
        bold
    } else {
        Style::new()
    };
    plain_line(s, st, w)
}

/// 가운데 둥근 상자(그림자·여백 포함). `lines`는 안쪽 폭(`DIALOG_INNER` 이하)에 맞춘 줄.
fn draw_box(f: &mut Frame, area: Rect, t: Theme, title: &str, accent: Tone, lines: Vec<Line>) {
    backdrop(f, t);
    let inner_w = DIALOG_INNER.min(area.width as usize - 6);
    let w = (inner_w + 4) as u16;
    let h = ((lines.len() + 2) as u16).min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    // 좌우 1칸 더 지워 상자 가장자리에 걸친 넓은 글자의 반쪽이 남지 않게 한다.
    let clear = Rect {
        x: r.x.saturating_sub(1),
        y: r.y,
        width: (w + 2).min(area.width - r.x.saturating_sub(1)),
        height: h,
    };
    f.render_widget(Clear, clear);
    if t.colored() && r.y + h < area.y + area.height {
        let sh = t.color(Tone::Shadow).unwrap_or(Color::Reset);
        let buf = f.buffer_mut();
        for x in r.x + 1..(r.x + w + 1).min(area.x + area.width) {
            if let Some(c) = buf.cell_mut((x, r.y + h)) {
                c.set_symbol(" ");
                c.bg = sh;
            }
        }
        for y in r.y + 1..r.y + h {
            if let Some(c) = buf.cell_mut((r.x + w, y)) {
                c.set_symbol(" ");
                c.bg = sh;
            }
        }
    }
    let body: Vec<Line> = lines
        .into_iter()
        .take(h as usize - 2)
        .map(|l| {
            let mut spans = vec![Span::raw(" ")];
            spans.extend(l.spans);
            Line::from(spans)
        })
        .collect();
    let title_st = match accent {
        Tone::Violet | Tone::Info | Tone::Danger => t.chip_light(accent),
        _ => t.chip(accent),
    };
    f.render_widget(
        Paragraph::new(body).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(t.fg(accent))
                .title(Line::from(Span::styled(format!(" {title} "), title_st))),
        ),
        r,
    );
}

fn draw_dialog(f: &mut Frame, m: &Model, d: &Dialog, area: Rect, t: Theme) {
    let w = DIALOG_INNER;
    let styled = |lines: &[String]| -> Vec<Line<'static>> {
        lines.iter().map(|l| dialog_line(l, t, w)).collect()
    };
    match d {
        Dialog::Preview { lines, title, .. } => {
            let warn = lines.iter().any(|l| l.starts_with("주의:"));
            let accent = if warn { Tone::Warn } else { Tone::Brand };
            draw_box(f, area, t, title, accent, styled(lines));
        }
        Dialog::Busy { .. } => draw_box(
            f,
            area,
            t,
            "정리하는 중",
            Tone::Info,
            vec![
                plain_line(
                    "정리하는 중… 정상 종료 신호를 보내고 꺼지기를 기다리고 있어요.",
                    Style::new().add_modifier(Modifier::BOLD),
                    w,
                ),
                key_hints("q 를 누르면 이 정리를 마친 뒤 끝내요.", t, w).line(),
            ],
        ),
        Dialog::Result { lines } => draw_box(f, area, t, "정리 결과", Tone::Ok, styled(lines)),
        Dialog::Help => {
            let mut l: Vec<Line> = HELP_LINES
                .iter()
                .map(|h| {
                    let mut x = Ln::new(w);
                    let (k, v) = split_at_width(h, HELP_KEY_W);
                    x.push(&k, t.key());
                    x.push(&v, Style::new());
                    x.line()
                })
                .collect();
            l.push(Line::default());
            l.push(key_hints("아무 키나 누르면 닫혀요", t, w).line());
            draw_box(f, area, t, "도움말", Tone::Info, l);
        }
        Dialog::Notice { title, lines } => draw_box(f, area, t, title, Tone::Info, styled(lines)),
        Dialog::ConfirmAggressive => {
            let l: Vec<Line> = AGGRESSIVE_LINES
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if i == 0 {
                        plain_line(s, t.bold(Tone::Danger), w)
                    } else {
                        dialog_line(s, t, w)
                    }
                })
                .collect();
            draw_box(f, area, t, "한 번 더 확인", Tone::Danger, l);
        }
        Dialog::Level { cursor } => {
            let cur = m.effective_level();
            let mut l = Vec::new();
            for (i, lv) in [
                AutoLevel::NotifyOnly,
                AutoLevel::Safe,
                AutoLevel::Aggressive,
            ]
            .iter()
            .enumerate()
            {
                let mut x = Ln::new(w);
                x.push(if i == *cursor { CURSOR } else { " " }, t.bold(Tone::Brand));
                x.push(" ", Style::new());
                x.push(&pad(level_ko(*lv), 12), t.bold(Tone::Violet));
                x.push(LEVEL_DESC[i], Style::new());
                if *lv == cur {
                    x.push(" (지금)", t.bold(Tone::Ok));
                }
                if i == *cursor {
                    x.fill(Style::new());
                    x.over(t.selection());
                }
                l.push(x.line());
            }
            l.push(Line::default());
            l.extend(LEVEL_NOTE.iter().map(|s| plain_line(s, t.muted(), w)));
            l.push(Line::default());
            l.push(key_hints("↑↓ 고르기  Enter 바꾸기  Esc 그대로 두기", t, w).line());
            draw_box(f, area, t, "지킴이 수준", Tone::Violet, l);
        }
        Dialog::Why { lines, scroll } => {
            let r = Rect {
                x: area.x,
                y: area.y + 4,
                width: area.width,
                height: area.height - 4,
            };
            let mut s = Screen::new(area.width);
            let inner = r.height as usize - 3;
            let cw = s.w - 4;
            let mut body: Vec<Ln> = lines
                .iter()
                .skip(*scroll)
                .take(inner - 1)
                .map(|l| {
                    let mut x = Ln::new(cw);
                    x.push(l, Style::new());
                    x
                })
                .collect();
            while body.len() < inner - 1 {
                body.push(Ln::new(cw));
            }
            body.push(key_hints("↑↓ 넘기기  아무 키나 누르면 닫혀요", t, cw));
            panel(&mut s, t, "자세히", t.bold(Tone::Info), body, inner);
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(s.lines), r);
        }
    }
}

/// 표시 폭 `w`에서 둘로 나눈다(넓은 글자를 쪼개지 않는다).
fn split_at_width(s: &str, w: usize) -> (String, String) {
    let mut acc = 0;
    for (i, c) in s.char_indices() {
        if acc >= w {
            return (s[..i].to_string(), s[i..].to_string());
        }
        acc += fmt::char_width(c);
    }
    (s.to_string(), String::new())
}

/// TestBackend 버퍼 → 화면 글자 줄(넓은 글자의 뒤 칸은 건너뛴다, 오른쪽 공백은 지운다).
pub fn buffer_lines(buf: &Buffer) -> Vec<String> {
    let a = buf.area;
    let mut out = Vec::new();
    for y in a.y..a.y + a.height {
        let mut line = String::new();
        let mut x = a.x;
        while x < a.x + a.width {
            let sym = buf[(x, y)].symbol();
            line.push_str(sym);
            x += width(sym).max(1) as u16;
        }
        out.push(line.trim_end().to_string());
    }
    out
}
