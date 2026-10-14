//! TUI 테스트 도우미: 합성 지킴이 갱신, 키, TestBackend 그리기.
#![allow(dead_code)]

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::text::Line;
use stopcat_cli::fmt;
use stopcat_cli::tui::link::{ManualResult, Update};
use stopcat_cli::tui::state::Model;
use stopcat_cli::tui::view;
use stopcat_model::*;

use crate::common::*;

pub fn status(level: AutoLevel) -> GuardStatus {
    GuardStatus {
        level,
        level_locked_by_env: false,
        paused: false,
        circuit_open: false,
        circuit_opened_at_unix_ms: None,
        terminations_in_window: 0,
        scan_seq: 1,
        scan_error_streak: 0,
        last_scan_at_unix_ms: T0,
        last_scan_ms: 38.0,
        next_scan_at_unix_ms: T0 + 5_000,
        demoted: vec![],
        pending: vec![],
        health: HealthLevel::Ok,
        health_forced: None,
        unstable: false,
        unstable_reasons: Vec::new(),
        unstable_since_unix_ms: None,
        settle_until_unix_ms: None,
        swap_delta_bytes: None,
    }
}

pub fn finding_id(rep: &Report, pid: i32) -> String {
    rep.findings
        .iter()
        .find(|f| f.targets.first().is_some_and(|t| t.pid == pid))
        .expect("finding for pid")
        .id
        .clone()
}

pub fn codex_pending(s: &Snapshot, rep: &Report) -> PendingAction {
    PendingAction {
        target: r(51234, s),
        finding_id: finding_id(rep, 51234),
        kind: Kind::AgentHelper,
        label_ko: "codex app-server".into(),
        step: Step::Term,
        seen_scans: 1,
        needed_scans: 2,
        eta_ms: Some(5_000),
        wait: PendingWait::Confirming,
    }
}

pub fn update_from(
    rep: Report,
    level: AutoLevel,
    f: impl FnOnce(&Snapshot, &mut GuardStatus),
) -> Update {
    let s = snapshot();
    let mut st = status(level);
    f(&s, &mut st);
    Update {
        snapshot: Arc::new(s),
        report: Arc::new(rep),
        policy: Arc::new(GuardPolicy::for_level(level)),
        status: st,
        new_events: vec![],
        manual_result: None,
    }
}

/// 안정화 자동, codex가 자동 예정 1/2.
pub fn normal_update() -> Update {
    let s = snapshot();
    let rep = report(&s);
    let p = codex_pending(&s, &rep);
    update_from(rep, AutoLevel::Safe, |_, st| st.pending = vec![p])
}

pub fn done_config(level: AutoLevel) -> StopcatConfig {
    StopcatConfig {
        schema_version: 1,
        auto_level: level,
        first_run_done: true,
        scan_interval_ms: None,
    }
}

pub fn main_model() -> Model {
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(normal_update());
    m.no_color = true;
    m
}

pub fn event(
    kind: GuardEventKind,
    label: &str,
    detail: &str,
    reclaimed: u64,
    target: Option<ProcRef>,
) -> GuardEvent {
    GuardEvent {
        at_unix_ms: T0,
        kind,
        target,
        finding_id: None,
        run_id: None,
        label_ko: label.into(),
        detail_ko: detail.into(),
        reclaimed_bytes: reclaimed,
    }
}

pub fn manual(request_id: u64, outcomes: Vec<ActionOutcome>) -> ManualResult {
    ManualResult {
        request_id,
        outcomes,
        state_dir: "/Users/demo/Library/Application Support/stopcat".into(),
        refused: vec![],
    }
}

pub fn key(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

pub fn ch(c: char) -> KeyEvent {
    key(KeyCode::Char(c))
}

pub fn ctrl_c() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
}

pub fn render(m: &mut Model, w: u16, h: u16) -> Vec<String> {
    m.set_size(w, h);
    let mut t = Terminal::new(TestBackend::new(w, h)).expect("terminal");
    t.draw(|f| view::draw(f, m)).expect("draw");
    view::buffer_lines(t.backend().buffer())
}

/// 넘침 없음 + 두 폭 계산(stopcat `fmt`·ratatui unicode-width)이 같은지.
pub fn check_widths(lines: &[String], w: usize) {
    for l in lines {
        assert!(fmt::width(l) <= w, "폭 {} > {w}: {l}", fmt::width(l));
        assert_eq!(
            fmt::width(l),
            Line::from(l.as_str()).width(),
            "폭 계산 불일치: {l}"
        );
    }
}

pub fn has(lines: &[String], needle: &str) -> bool {
    lines.iter().any(|l| l.contains(needle))
}

/// 색까지 담은 버퍼(미리보기용).
pub fn render_buffer(m: &mut Model, w: u16, h: u16) -> ratatui::buffer::Buffer {
    m.set_size(w, h);
    let mut t = Terminal::new(TestBackend::new(w, h)).expect("terminal");
    t.draw(|f| view::draw(f, m)).expect("draw");
    t.backend().buffer().clone()
}

/// 버퍼 → HTML 격자(칸마다 고정 폭 상자, 넓은 글자는 2칸). 글꼴 폭에 기대지 않고 정렬을 그대로 보인다.
/// `light`면 밝은 배경 터미널을 흉내 낸다.
pub fn buffer_html(buf: &ratatui::buffer::Buffer, title: &str, light: bool) -> String {
    use ratatui::style::{Color, Modifier};
    let (dfg, dbg) = if light {
        ("#1f2328", "#ffffff")
    } else {
        ("#d8dee9", "#14161c")
    };
    let hex = |c: Color, d: &str| -> String {
        match c {
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
            Color::Reset => d.to_string(),
            Color::Indexed(i) => format!("var(--c{i})"),
            Color::Black => "#000".into(),
            Color::White => "#fff".into(),
            other => format!("{other:?}").to_lowercase(),
        }
    };
    let a = buf.area;
    let mut rows = String::new();
    for y in a.y..a.y + a.height {
        rows.push_str("<div class=r>");
        let mut x = a.x;
        while x < a.x + a.width {
            let c = &buf[(x, y)];
            let sym = c.symbol();
            let w = fmt::width(sym).max(1) as u16;
            let (mut fg, mut bg) = (hex(c.fg, dfg), hex(c.bg, dbg));
            if c.modifier.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let mut st = format!("color:{fg};background:{bg};width:{}px;", 9 * w);
            if c.modifier.contains(Modifier::BOLD) {
                st.push_str("font-weight:700;");
            }
            if c.modifier.contains(Modifier::DIM) {
                st.push_str("opacity:.55;");
            }
            if c.modifier.contains(Modifier::ITALIC) {
                st.push_str("font-style:italic;");
            }
            if c.modifier.contains(Modifier::UNDERLINED) {
                st.push_str("text-decoration:underline;");
            }
            let s = match sym {
                "<" => "&lt;",
                ">" => "&gt;",
                "&" => "&amp;",
                " " => "&nbsp;",
                o => o,
            };
            rows.push_str(&format!("<span style=\"{st}\">{s}</span>"));
            x += w;
        }
        rows.push_str("</div>\n");
    }
    format!(
        "<!doctype html><meta charset=utf-8><title>{title}</title><style>\
body{{margin:0;padding:16px;background:{dbg};font:15px/19px 'SF Mono',Menlo,'Apple SD Gothic Neo',monospace}}\
.r{{display:flex;height:19px;white-space:pre}}.r span{{display:inline-block;text-align:center;overflow:visible;flex:none}}\
h1{{font:12px sans-serif;color:#888;margin:0 0 8px}}</style><h1>{title}</h1>\n{rows}"
    )
}

/// 버퍼 → ANSI 글(트루컬러 SGR). 실제 터미널 에뮬레이터로 다시 그려 볼 때 쓴다.
pub fn buffer_ansi(buf: &ratatui::buffer::Buffer) -> String {
    use ratatui::style::{Color, Modifier};
    let sgr = |c: Color, fg: bool| -> String {
        let base = if fg { 38 } else { 48 };
        match c {
            Color::Rgb(r, g, b) => format!("{base};2;{r};{g};{b}"),
            Color::Indexed(i) => format!("{base};5;{i}"),
            _ => (if fg { "39" } else { "49" }).to_string(),
        }
    };
    let a = buf.area;
    let mut out = String::new();
    for y in a.y..a.y + a.height {
        let mut x = a.x;
        while x < a.x + a.width {
            let c = &buf[(x, y)];
            let mut codes = vec!["0".to_string(), sgr(c.fg, true), sgr(c.bg, false)];
            for (m, n) in [
                (Modifier::BOLD, "1"),
                (Modifier::DIM, "2"),
                (Modifier::ITALIC, "3"),
                (Modifier::UNDERLINED, "4"),
                (Modifier::REVERSED, "7"),
            ] {
                if c.modifier.contains(m) {
                    codes.push(n.to_string());
                }
            }
            out.push_str(&format!("\x1b[{}m{}", codes.join(";"), c.symbol()));
            x += fmt::width(c.symbol()).max(1) as u16;
        }
        out.push_str("\x1b[0m");
        if y + 1 < a.y + a.height {
            out.push_str("\r\n");
        }
    }
    out
}
