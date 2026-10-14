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
