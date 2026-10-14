//! 화면 그리기(순수). 모든 줄은 `fmt` 폭 계산(한글 2칸)으로 칸 폭 안에 맞춘 뒤 그린다.

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use stopcat_model::{AutoLevel, Finding, GuardEventKind, HealthLevel, Section};

use super::state::{DIALOG_INNER, Dialog, Mode, Model, Row, Tab, level_ko};
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

pub const FIRST_RUN_LINES: [&str; 16] = [
    "",
    "  stopcat 지킴이 — 처음 한 번만 정해 주세요",
    "",
    "  화면을 띄워 두는 동안 지킴이가 5초마다 맥을 확인해요.",
    "  평소에는 보고만 해요. 필요 없는 것과 되찾을 수 있는 양을 근거와 함께",
    "  보여 주고, c 한 번으로 추천 항목을 모두 정리할 수 있어요(미리보기 → y).",
    "",
    "  안정화 자동(추천)으로 시작하면 맥이 불안정할 때만 스스로 정리해요",
    "    '필요 없음'이 확실한 것만, 정상으로 돌아올 만큼만(10분에 5개까지).",
    "  지금 쓰고 있는 것은 CPU 100%여도 끄지도, 느리게 하지도 않아요.",
    "",
    "  절대 끄지 않는 것: AI 대화 세션·앱·가상 머신·DB·시스템",
    "  자동으로 한 일은 '자동 처리 기록' 화면과 macOS 알림으로 남아요.",
    "",
    "  설정 화면(4)에서 언제든 바꿀 수 있어요.",
    "",
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
/// 첫 보고 동안 확보량 줄(단정하지 않음).
pub const RECLAIM_FIRST: &str = "         처음 확인 중이에요";

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

    fn text(&mut self, s: &str) {
        self.styled(s, Style::default());
    }

    fn styled(&mut self, s: &str, st: Style) {
        self.lines
            .push(Line::from(Span::styled(truncate(s, self.w), st)));
    }

    fn rule(&mut self) {
        self.text(&"─".repeat(self.w));
    }

    fn section(&mut self, title: &str) {
        let head = truncate(&format!("─ {title} "), self.w);
        let rest = self.w.saturating_sub(width(&head));
        self.text(&format!("{head}{}", "─".repeat(rest)));
    }

    fn fill_to(&mut self, n: usize) {
        while self.lines.len() < n {
            self.lines.push(Line::default());
        }
        self.lines.truncate(n);
    }
}

fn color(m: &Model, c: Color) -> Style {
    if m.no_color {
        Style::default()
    } else {
        Style::default().fg(c)
    }
}

fn cursor_style() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

pub fn draw(f: &mut Frame, m: &Model) {
    let area = f.area();
    if m.too_small() {
        draw_too_small(f, m, area);
        return;
    }
    let mut s = Screen::new(area.width);
    let h = area.height as usize;
    if m.mode == Mode::FirstRun {
        s.text("stopcat  처음 실행");
        s.rule();
        let mut body: Vec<String> = FIRST_RUN_LINES.iter().map(|l| l.to_string()).collect();
        if let Some(l) = m.env_level {
            body.push(String::new());
            body.push(format!(
                "  지금은 STOPCAT_GUARD_LEVEL={} 로 실행 중이라 고른 값은 저장만 해요.",
                env_name(l)
            ));
        }
        for l in body.iter().take(h - 4) {
            s.text(l);
        }
        s.fill_to(h - 2);
        s.rule();
        s.text(KEYS_FIRST_RUN);
        f.render_widget(Paragraph::new(s.lines), area);
        return;
    }
    status_lines(&mut s, m);
    tabs_line(&mut s, m);
    s.rule();
    let body_h = h - 6;
    let start = s.lines.len();
    match m.tab {
        Tab::Findings => findings_body(&mut s, m, body_h),
        Tab::Ports => ports_body(&mut s, m, body_h),
        Tab::Log => log_body(&mut s, m, body_h),
        Tab::Settings => settings_body(&mut s, m),
    }
    s.fill_to(start + body_h);
    s.section(&guard_line(m));
    let keys = match &m.flash {
        Some(f) => f.as_str(),
        None => keys_for(m),
    };
    s.text(keys);
    f.render_widget(Paragraph::new(s.lines), area);
    if let Some(d) = &m.dialog {
        draw_dialog(f, m, d, area);
    } else if m.mode == Mode::Quitting {
        draw_box(f, area, "끝내는 중", &QUITTING.map(str::to_string));
    }
}

pub const QUITTING: [&str; 2] = [
    "끝내는 중… 직접 낮춘 우선순위를 되돌리고 있어요.",
    "Ctrl+C 를 한 번 더 누르면 기다리지 않고 끝내요.",
];

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

/// 지킴이 상태 한 마디(평소 보고만·불안정·일시정지·차단기).
pub fn guard_state(m: &Model) -> String {
    if let Some(msg) = &m.guard_dead {
        return format!("멈췄어요({msg})");
    }
    let Some(l) = &m.latest else {
        return STATE_FIRST_SCAN.to_string();
    };
    let st = &l.status;
    if st.paused {
        STATE_PAUSED
    } else if st.circuit_open {
        STATE_CIRCUIT
    } else if st.unstable {
        if st
            .settle_until_unix_ms
            .is_some_and(|t| t > st.last_scan_at_unix_ms)
        {
            STATE_SETTLING
        } else if st.level == AutoLevel::NotifyOnly {
            STATE_UNSTABLE_NOTIFY
        } else {
            STATE_UNSTABLE_AUTO
        }
    } else {
        STATE_NORMAL
    }
    .to_string()
}

/// 키 줄 바로 위 지킴이 줄(─ 모양 머리 안의 글).
pub fn guard_line(m: &Model) -> String {
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
    let mut parts = vec![format!("지킴이 {}{lock}", level_ko(level)), guard_state(m)];
    if m.guard_dead.is_none()
        && let Some(l) = &m.latest
    {
        let st = &l.status;
        if st.unstable || st.circuit_open || st.terminations_in_window > 0 {
            parts.push(auto_count(l));
        }
    }
    if m.e2e_lock {
        parts.push("STOPCAT_E2E_ALLOW_PIDS 잠금".to_string());
    }
    if m.guard_dead.is_none()
        && let Some(l) = &m.latest
    {
        parts.push(format!(
            "확인 {}",
            fmt::hhmmss(l.status.last_scan_at_unix_ms)
        ));
    }
    parts.join(" · ")
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

/// 맨 위 둘째 줄: 확보량. 첫 보고에서 '필요 없음'이 0이면 단정하지 않는다.
pub fn reclaim_line(m: &Model) -> String {
    match &m.latest {
        Some(l) if first_report(m) && l.report.totals.unneeded_bytes == 0 => {
            RECLAIM_FIRST.to_string()
        }
        Some(l) => format!(
            "         {}",
            sec::reclaim_text(&l.report.totals).unwrap_or_else(|| sec::RECLAIM_NOTHING.to_string())
        ),
        None => String::new(),
    }
}

fn status_lines(s: &mut Screen, m: &Model) {
    match &m.latest {
        Some(l) => {
            let c = match l.report.health.level {
                HealthLevel::Ok => Color::Green,
                HealthLevel::Watch => Color::Yellow,
                HealthLevel::Critical => Color::Red,
            };
            s.styled(&format!("stopcat  {}", l.report.health.headline_ko), color(m, c));
        }
        None => s.text("stopcat  메모리 확인 중…"),
    }
    s.text(&reclaim_line(m));
}

fn tabs_line(s: &mut Screen, m: &Model) {
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
    let mut spans = Vec::new();
    for (i, n) in names.iter().enumerate() {
        if i == m.tab.index() {
            spans.push(Span::styled(
                format!("[{n}]"),
                Style::default().add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::raw(format!(" {n} ")));
        }
        spans.push(Span::raw(" "));
    }
    s.lines.push(Line::from(spans));
}

fn list_window(cursor: usize, n: usize, rows: usize) -> (usize, usize) {
    let off = cursor.saturating_sub(rows.saturating_sub(1));
    (off, n.min(off + rows))
}

/// 보고 탭 자세히 칸 줄 수.
fn detail_h(body_h: usize) -> usize {
    4 + body_h.saturating_sub(18) / 4
}

fn wrap_pairs(s: &mut Screen, pairs: &[(&str, String)], max: usize) {
    let mut out: Vec<String> = Vec::new();
    for (name, text) in pairs {
        let first = pad(name, 8);
        out.extend(fmt::wrap(text, s.w, &first, "        "));
    }
    for l in out.into_iter().take(max) {
        s.text(&l);
    }
}

/// 80칸에서 대상 칸 폭. 넓은 창에서는 늘어난 만큼 더한다.
const NAME_W: usize = 21;
/// 나이 칸(가장 긴 '23시간' 6칸 + 근거 칸과의 공백 1칸).
const AGE_W: usize = 7;
const EVIDENCE_W: usize = 24;

pub fn column_header(w: usize) -> String {
    format!(
        "      {}{}  {}{}지킴이",
        pad("대상", NAME_W + w.saturating_sub(80)),
        lpad("크기", 6),
        pad("나이", AGE_W),
        pad("근거", EVIDENCE_W)
    )
}

/// 목록 한 줄. `now_unix_ms`는 스냅샷 시각(나이 칸).
pub fn finding_row(r: &Row, cur: bool, picked: bool, w: usize, now_unix_ms: u64) -> String {
    let lw = NAME_W + w.saturating_sub(80);
    let label = truncate(&r.label, lw - 1);
    let size = r.size.map(fmt::bytes).unwrap_or_default();
    let age = r
        .started_unix_ms
        .map(|s| fmt::age_short(now_unix_ms.saturating_sub(s)))
        .unwrap_or_default();
    let boxed = if !r.actionable {
        "    "
    } else if picked {
        "[x] "
    } else {
        "[ ] "
    };
    format!(
        "{}{}{}{}  {}{}{}",
        if cur { "> " } else { "  " },
        boxed,
        pad(&label, lw),
        lpad(&size, 6),
        pad(&age, AGE_W),
        pad(
            &truncate(&r.evidence(now_unix_ms), EVIDENCE_W - 1),
            EVIDENCE_W
        ),
        r.mark.text()
    )
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

/// 구역 머리줄.
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

pub fn more_below(n: usize) -> String {
    format!("  ↓ {n}줄 더 있어요(↓ 로 내려 보기)")
}

pub fn more_above(n: usize) -> String {
    format!("  ↑ {n}줄 더 있어요(↑ 로 올려 보기)")
}

enum Disp {
    Header(String),
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
        out.push(Disp::Header(section_header(sect, idx.len(), bytes)));
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

fn findings_body(s: &mut Screen, m: &Model, body_h: usize) {
    if m.latest.is_none() {
        s.text("");
        s.text("  맥 상태를 확인하고 있어요…");
        return;
    }
    let first = first_report(m);
    if first {
        s.text(FIRST_REPORT);
    }
    if m.rows.is_empty() {
        if first {
            return;
        }
        let ok = m
            .latest
            .as_ref()
            .is_some_and(|l| l.report.health.level == HealthLevel::Ok);
        for (i, l) in EMPTY_BODY.iter().enumerate() {
            s.text(if i == 1 && !ok { EMPTY_NOT_OK } else { l });
        }
        return;
    }
    let dh = detail_h(body_h);
    let list_h = body_h - 2 - dh - usize::from(first);
    let now = m.latest.as_ref().map_or(0, |l| l.snapshot.taken_at_unix_ms);
    s.text(&column_header(s.w));
    let disp = report_lines(m);
    let cur = m.cursor[0];
    let cursor_line = disp
        .iter()
        .position(|d| matches!(d, Disp::Row(i) if *i == cur))
        .unwrap_or(0);
    let (off, n, top, bottom) = report_window(disp.len(), cursor_line, list_h);
    let start = s.lines.len();
    if top {
        s.text(&more_above(off));
    }
    for d in disp.iter().skip(off).take(n) {
        match d {
            Disp::Header(t) => s.styled(t, Style::default().add_modifier(Modifier::BOLD)),
            Disp::Text(t) => s.text(t),
            Disp::Row(i) => {
                let r = &m.rows[*i];
                let line = finding_row(r, *i == cur, m.selected.contains(&r.finding_id), s.w, now);
                let st = if *i == cur {
                    cursor_style()
                } else {
                    Style::default()
                };
                s.styled(&line, st);
            }
        }
    }
    if bottom {
        s.text(&more_below(disp.len() - off - n));
    }
    s.fill_to(start + list_h);
    if let Some(r) = m.rows.get(cur) {
        s.section(&format!("자세히: {}", r.label));
        let f = m
            .latest
            .as_ref()
            .and_then(|l| l.report.findings.iter().find(|f| f.id == r.finding_id));
        wrap_pairs(s, &finding_detail(r, f, now), dh);
    }
}

fn ports_body(s: &mut Screen, m: &Model, body_h: usize) {
    if m.ports.is_empty() {
        s.text("");
        s.text("  기다리는 포트가 없어요.");
        return;
    }
    let dh = 5 + body_h.saturating_sub(18) / 4;
    let list_h = body_h - 2 - dh;
    let lw = 30 + s.w.saturating_sub(80);
    s.text(&format!(
        "  {}{}{}열린 범위",
        pad("포트", 8),
        pad("프로그램", lw),
        pad("프로젝트", 14)
    ));
    let cur = m.cursor[1];
    let (from, to) = list_window(cur, m.ports.len(), list_h);
    for (i, p) in m.ports.iter().enumerate().take(to).skip(from) {
        let line = format!(
            "{}{}{}{}{}  {}",
            if i == cur { "> " } else { "  " },
            pad(&format!(":{}", p.port), 8),
            pad(&truncate(&p.label, lw - 1), lw),
            pad(&truncate(&p.project, 13), 14),
            p.scope,
            p.flag
        );
        let st = if i == cur {
            cursor_style()
        } else {
            Style::default()
        };
        s.styled(line.trim_end(), st);
    }
    let start = s.lines.len();
    s.fill_to(start + (list_h - (to - from)));
    if let Some(p) = m.ports.get(cur) {
        s.section(&format!(":{} {}", p.port, p.label));
        let mut out = Vec::new();
        for d in &p.detail {
            out.extend(fmt::wrap(d, s.w, "", ""));
        }
        if let Some(l) = &m.latest {
            let age = l
                .snapshot
                .taken_at_unix_ms
                .saturating_sub(p.target.start_time_unix_ms);
            out.push(format!("{}째 실행 중", fmt::duration(age)));
        }
        for l in out.into_iter().take(dh) {
            s.text(&l);
        }
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

fn log_body(s: &mut Screen, m: &Model, body_h: usize) {
    if m.events.is_empty() {
        for l in LOG_EMPTY {
            s.text(l);
        }
        return;
    }
    let t = m.tally;
    s.text(&format!(
        "  이번에 자동으로 정리한 양 약 {} · 자동 종료 {}건 · 직접 낮춤 {}건",
        fmt::bytes(t.reclaimed_bytes),
        t.auto_terminated,
        t.demoted
    ));
    let dh = 5 + body_h.saturating_sub(18) / 4;
    let list_h = body_h - 4 - dh;
    let lw = 34 + s.w.saturating_sub(80);
    s.text(&format!(
        "  {}{}{}{}",
        pad("시각", 10),
        pad("한 일", 16),
        pad("대상", lw),
        lpad("회수", 7)
    ));
    let cur = m.cursor[2];
    let (from, to) = list_window(cur, m.events.len(), list_h);
    for (i, e) in m.events.iter().enumerate().take(to).skip(from) {
        let rc = if e.reclaimed_bytes > 0 {
            fmt::bytes(e.reclaimed_bytes)
        } else {
            String::new()
        };
        let line = format!(
            "{}{}{}{}{}",
            if i == cur { "> " } else { "  " },
            pad(&fmt::hhmmss(e.at_unix_ms), 10),
            pad(event_kind_ko(e.kind), 16),
            pad(&truncate(&e.label_ko, lw - 1), lw),
            lpad(&rc, 7)
        );
        let st = if i == cur {
            cursor_style()
        } else {
            Style::default()
        };
        s.styled(line.trim_end(), st);
    }
    let start = s.lines.len();
    s.fill_to(start + (list_h - (to - from)));
    if let Some(e) = m.events.get(cur) {
        s.section(&format!(
            "{} {} — {}",
            fmt::hhmmss(e.at_unix_ms),
            event_kind_ko(e.kind),
            e.label_ko
        ));
        let mut pairs = vec![("내용", e.detail_ko.clone())];
        if e.reclaimed_bytes > 0 {
            pairs.push(("회수", format!("약 {}", fmt::bytes(e.reclaimed_bytes))));
        }
        wrap_pairs(s, &pairs, dh);
    }
}

fn settings_body(s: &mut Screen, m: &Model) {
    let cur = m.cursor[3];
    let level = m.effective_level();
    let lock = if m.env_level.is_some() {
        "STOPCAT_GUARD_LEVEL로 고정"
    } else {
        "Enter 바꾸기"
    };
    let rows = [
        format!(
            "{}{}{}{lock}",
            if cur == 0 { "> " } else { "  " },
            pad("지킴이 수준", 19),
            pad(&format!("[{}]", level_ko(level)), 14)
        ),
        format!(
            "{}{}{}Enter 바꾸기(5·10·30초)",
            if cur == 1 { "> " } else { "  " },
            pad("확인 간격", 19),
            pad(&format!("[{}]", fmt::secs(m.current_interval())), 14)
        ),
    ];
    for (i, r) in rows.iter().enumerate() {
        let st = if i == cur {
            cursor_style()
        } else {
            Style::default()
        };
        s.styled(r, st);
    }
    s.styled(
        "  로그인 시 자동 실행 — 다음 버전(아직 쓸 수 없어요)",
        Style::default().add_modifier(Modifier::DIM),
    );
    for l in SETTINGS_LINES {
        s.text(l);
    }
    if let Some(l) = &m.latest {
        s.text(&format!(
            "  지킴이 상태  {} · {} · 확인 {}",
            guard_state(m),
            auto_count(l),
            fmt::hhmmss(l.status.last_scan_at_unix_ms)
        ));
    }
    if !m.config_path.is_empty() {
        s.text(&format!("  설정 파일  {}", m.config_path));
    }
}

fn draw_too_small(f: &mut Frame, m: &Model, area: Rect) {
    let mut s = Screen::new(area.width);
    let h = area.height as usize;
    s.text("stopcat");
    s.fill_to(h.saturating_sub(5) / 2);
    s.text(&format!("   {TOO_SMALL}"));
    s.text(&format!(
        "   지금 {}×{}, 필요 80×24 이상",
        m.width, m.height
    ));
    s.text("");
    s.text("   q 끝");
    s.fill_to(h);
    f.render_widget(Paragraph::new(s.lines), area);
}

fn draw_box(f: &mut Frame, area: Rect, title: &str, lines: &[String]) {
    let inner_w = DIALOG_INNER.min(area.width as usize - 4);
    let w = (inner_w + 4) as u16;
    let h = ((lines.len() + 2) as u16).min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    let body: Vec<Line> = lines
        .iter()
        .take(h as usize - 2)
        .map(|l| Line::from(format!(" {}", truncate(l, inner_w))))
        .collect();
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(body).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        ),
        r,
    );
}

fn draw_dialog(f: &mut Frame, m: &Model, d: &Dialog, area: Rect) {
    match d {
        Dialog::Preview { lines, title, .. } => draw_box(f, area, title, lines),
        Dialog::Busy { .. } => draw_box(
            f,
            area,
            "정리하는 중",
            &[
                "정리하는 중… 정상 종료 신호를 보내고 꺼지기를 기다리고 있어요.".to_string(),
                "q 를 누르면 이 정리를 마친 뒤 끝내요.".to_string(),
            ],
        ),
        Dialog::Result { lines } => draw_box(f, area, "정리 결과", lines),
        Dialog::Help => {
            let mut l: Vec<String> = HELP_LINES.iter().map(|s| s.to_string()).collect();
            l.push(String::new());
            l.push("아무 키나 누르면 닫혀요".to_string());
            draw_box(f, area, "도움말", &l);
        }
        Dialog::Notice { title, lines } => draw_box(f, area, title, lines),
        Dialog::ConfirmAggressive => {
            let l: Vec<String> = AGGRESSIVE_LINES.iter().map(|s| s.to_string()).collect();
            draw_box(f, area, "한 번 더 확인", &l);
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
                let now = if *lv == cur { " (지금)" } else { "" };
                l.push(format!(
                    "{}{}{}{now}",
                    if i == *cursor { "> " } else { "  " },
                    pad(level_ko(*lv), 12),
                    LEVEL_DESC[i]
                ));
            }
            l.push(String::new());
            l.extend(LEVEL_NOTE.iter().map(|s| s.to_string()));
            l.push(String::new());
            l.push("↑↓ 고르기  Enter 바꾸기  Esc 그대로 두기".to_string());
            draw_box(f, area, "지킴이 수준", &l);
        }
        Dialog::Why { lines, scroll } => {
            let r = Rect {
                x: area.x,
                y: area.y + 3,
                width: area.width,
                height: area.height - 3,
            };
            let mut s = Screen::new(area.width);
            s.section("자세히");
            let rows = r.height as usize - 3;
            for l in lines.iter().skip(*scroll).take(rows) {
                s.text(l);
            }
            s.fill_to(rows + 1);
            s.rule();
            s.text("↑↓ 넘기기  아무 키나 누르면 닫혀요");
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(s.lines), r);
        }
    }
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
