//! 키 상태 기계(PLAN keys.state_machine) — 화면 없이 Model만.

mod common;
mod tui_common;

use common::*;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use tui_common::*;
use vh_cli::tui::link::Cmd;
use vh_cli::tui::state::{
    Dialog, Effect, MAX_EVENTS, Mode, Model, NOT_ACTIONABLE, NOT_DEMOTED, Tab, selection_for,
};
use vh_model::*;

fn sends(fx: &[Effect]) -> Vec<&Cmd> {
    fx.iter()
        .filter_map(|e| match e {
            Effect::Send(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn run_plans(fx: &[Effect]) -> usize {
    sends(fx)
        .iter()
        .filter(|c| matches!(c, Cmd::RunPlan { .. }))
        .count()
}

fn saved(fx: &[Effect]) -> Vec<VhConfig> {
    fx.iter()
        .filter_map(|e| match e {
            Effect::SaveConfig(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn cursor_to(m: &mut Model, pid: i32) {
    let i = m
        .rows
        .iter()
        .position(|r| r.target.is_some_and(|t| t.pid == pid))
        .expect("row");
    m.cursor[0] = i;
}

#[test]
fn first_run_choices() {
    let mut m = Model::new(None, None, false);
    assert_eq!(m.mode, Mode::FirstRun);
    let fx = m.on_key(key(KeyCode::Enter));
    let cfg = &saved(&fx)[0];
    assert_eq!(cfg.auto_level, AutoLevel::Safe);
    assert!(cfg.first_run_done);
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::StartGuard {
            level: AutoLevel::Safe,
            ..
        }
    )));
    assert_eq!(m.mode, Mode::Loading);
    m.apply(normal_update());
    assert_eq!(m.mode, Mode::Main);

    let mut n = Model::new(None, None, false);
    let fx = n.on_key(ch('n'));
    assert_eq!(saved(&fx)[0].auto_level, AutoLevel::NotifyOnly);

    let mut env = Model::new(None, Some("notify"), false);
    let fx = env.on_key(key(KeyCode::Enter));
    assert_eq!(saved(&fx)[0].auto_level, AutoLevel::Safe, "고른 값은 저장");
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::StartGuard {
            level: AutoLevel::NotifyOnly,
            ..
        }
    )));

    let mut q = Model::new(None, None, false);
    let fx = q.on_key(ch('q'));
    assert!(saved(&fx).is_empty());
    assert!(matches!(fx[..], [Effect::Quit]));
    assert!(!fx.iter().any(|e| matches!(e, Effect::StartGuard { .. })));

    let mut done = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    assert_eq!(done.mode, Mode::Loading);
    assert!(done.on_key(ch('x')).is_empty());
}

#[test]
fn space_selects_only_actionable_rows() {
    let mut m = main_model();
    cursor_to(&mut m, 51234);
    m.on_key(ch(' '));
    assert_eq!(m.selected.len(), 1);
    m.on_key(ch(' '));
    assert!(m.selected.is_empty());
    cursor_to(&mut m, 2001);
    m.on_key(ch(' '));
    assert!(m.selected.is_empty());
    assert_eq!(m.flash.as_deref(), Some(NOT_ACTIONABLE));
    let fx = m.on_key(key(KeyCode::Enter));
    assert!(
        fx.is_empty() && m.dialog.is_none(),
        "AI 세션 줄 Enter는 미리보기 없음"
    );
}

#[test]
fn enter_preview_then_y_runs_exactly_once() {
    let mut m = main_model();
    cursor_to(&mut m, 51234);
    assert!(m.on_key(key(KeyCode::Enter)).is_empty());
    assert!(matches!(m.dialog, Some(Dialog::Preview { .. })));
    assert_eq!(run_plans(&m.on_key(ch('n'))), 0);
    assert!(m.dialog.is_none());

    m.on_key(key(KeyCode::Enter));
    assert_eq!(run_plans(&m.on_key(key(KeyCode::Esc))), 0);
    assert!(m.dialog.is_none() && m.mode == Mode::Main, "Esc는 닫기만");

    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    let fx = m.on_key(ch('y'));
    assert_eq!(run_plans(&fx), 1);
    let Some(Dialog::Busy { request_id }) = m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert_eq!(run_plans(&m.on_key(ch('y'))), 0, "Busy 중 y 무시");

    let mut other = normal_update();
    other.manual_result = Some(manual(request_id + 7, vec![]));
    m.apply(other);
    assert!(
        matches!(m.dialog, Some(Dialog::Busy { .. })),
        "다른 요청 결과는 무시"
    );

    let mut u = normal_update();
    u.manual_result = Some(manual(request_id, vec![]));
    let fx = m.apply(u);
    assert!(matches!(m.dialog, Some(Dialog::Result { .. })));
    assert!(m.selected.is_empty());
    assert!(matches!(sends(&fx)[..], [Cmd::ScanNow]));
    assert!(m.on_key(ch('z')).is_empty());
    assert!(m.dialog.is_none());
}

#[test]
fn empty_plan_preview_never_runs() {
    let mut m = main_model();
    m.dialog = Some(Dialog::Preview {
        title: "정리 미리보기",
        bulk: false,
        plan: ActionPlan {
            created_at_unix_ms: T0,
            total_deadline_ms: 60_000,
            items: vec![],
            refused: vec![],
        },
        lines: vec![],
    });
    assert_eq!(run_plans(&m.on_key(ch('y'))), 0);
    assert!(m.dialog.is_none());
}

#[test]
fn selection_is_hand_picked_semantics() {
    let s = snapshot();
    let rep = report(&s);
    let id = finding_id(&rep, 51234);
    let sel = selection_for(&rep, std::slice::from_ref(&id));
    assert_eq!(sel.finding_ids, vec![id]);
    assert_eq!(sel.pids, vec![51234]);
    assert_eq!(sel.min_confidence, Confidence::Possible);
    assert!(sel.direct.is_empty());
}

#[test]
fn level_change_needs_second_confirm_for_aggressive() {
    let mut m = main_model();
    assert!(m.on_key(ch('a')).is_empty());
    assert!(matches!(m.dialog, Some(Dialog::Level { cursor: 1 })));
    m.on_key(key(KeyCode::Down));
    assert!(m.on_key(key(KeyCode::Enter)).is_empty());
    assert!(matches!(m.dialog, Some(Dialog::ConfirmAggressive)));
    assert!(m.on_key(ch('n')).is_empty());
    assert_eq!(m.config.auto_level, AutoLevel::Safe);

    m.on_key(ch('a'));
    m.on_key(key(KeyCode::Down));
    m.on_key(key(KeyCode::Enter));
    let fx = m.on_key(ch('y'));
    assert!(matches!(
        sends(&fx)[..],
        [Cmd::SetLevel(AutoLevel::Aggressive)]
    ));
    assert_eq!(saved(&fx)[0].auto_level, AutoLevel::Aggressive);

    m.on_key(ch('a'));
    m.on_key(key(KeyCode::Up));
    m.on_key(key(KeyCode::Up));
    let fx = m.on_key(key(KeyCode::Enter));
    assert!(matches!(
        sends(&fx)[..],
        [Cmd::SetLevel(AutoLevel::NotifyOnly)]
    ));
}

#[test]
fn env_lock_blocks_level_change_and_saving() {
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), Some("notify"), false);
    m.apply(normal_update());
    assert!(m.on_key(ch('a')).is_empty());
    assert!(matches!(m.dialog, Some(Dialog::Notice { .. })));
    m.on_key(ch('x'));
    m.on_key(ch('4'));
    assert!(m.on_key(key(KeyCode::Enter)).is_empty());
    assert!(matches!(m.dialog, Some(Dialog::Notice { .. })));
    m.on_key(ch('x'));
    m.on_key(key(KeyCode::Down));
    let fx = m.on_key(key(KeyCode::Enter));
    assert!(matches!(sends(&fx)[..], [Cmd::SetScanInterval(10_000)]));
    assert!(saved(&fx).is_empty(), "env가 있으면 저장 안 함");

    let mut free = main_model();
    free.on_key(ch('4'));
    free.on_key(key(KeyCode::Down));
    let fx = free.on_key(key(KeyCode::Enter));
    assert!(matches!(sends(&fx)[..], [Cmd::SetScanInterval(10_000)]));
    assert_eq!(saved(&fx)[0].scan_interval_ms, Some(10_000));
    let fx = free.on_key(key(KeyCode::Enter));
    assert!(matches!(sends(&fx)[..], [Cmd::SetScanInterval(30_000)]));
    let fx = free.on_key(key(KeyCode::Enter));
    assert!(matches!(sends(&fx)[..], [Cmd::SetScanInterval(5_000)]));
}

#[test]
fn pause_circuit_and_undo_demote() {
    let mut m = main_model();
    assert!(matches!(sends(&m.on_key(ch('p')))[..], [Cmd::Pause]));
    let mut paused = normal_update();
    paused.status.paused = true;
    m.apply(paused);
    assert!(matches!(sends(&m.on_key(ch('p')))[..], [Cmd::Resume]));

    assert!(m.on_key(ch('r')).is_empty());
    let mut open = normal_update();
    open.status.circuit_open = true;
    m.apply(open);
    assert!(matches!(sends(&m.on_key(ch('r')))[..], [Cmd::ResetCircuit]));

    cursor_to(&mut m, 51234);
    assert!(m.on_key(ch('u')).is_empty());
    assert_eq!(m.flash.as_deref(), Some(NOT_DEMOTED));
    let s = snapshot();
    let t = r(51234, &s);
    let mut d = normal_update();
    d.status.demoted = vec![DemotedProc {
        target: t,
        label_ko: "codex".into(),
        at_unix_ms: T0,
    }];
    m.apply(d);
    cursor_to(&mut m, 51234);
    assert!(matches!(sends(&m.on_key(ch('u')))[..], [Cmd::UndoDemote(x)] if *x == t));
}

#[test]
fn tabs_cursor_and_quit_keys() {
    let mut m = main_model();
    m.on_key(key(KeyCode::Tab));
    assert_eq!(m.tab, Tab::Ports);
    m.on_key(key(KeyCode::Left));
    m.on_key(key(KeyCode::Left));
    assert_eq!(m.tab, Tab::Settings);
    m.on_key(key(KeyCode::BackTab));
    assert_eq!(m.tab, Tab::Log);
    m.on_key(key(KeyCode::Right));
    m.on_key(ch('1'));
    assert_eq!(m.tab, Tab::Findings);
    for _ in 0..20 {
        m.on_key(ch('j'));
    }
    assert_eq!(m.cursor[0], m.rows.len() - 1);
    for _ in 0..20 {
        m.on_key(key(KeyCode::Up));
    }
    assert_eq!(m.cursor[0], 0);

    let release = KeyEvent {
        kind: KeyEventKind::Release,
        ..ch('q')
    };
    assert!(m.on_key(release).is_empty());
    m.on_key(ch('?'));
    assert!(m.on_key(key(KeyCode::Esc)).is_empty());
    assert_eq!(m.mode, Mode::Main);

    for k in [ch('q'), key(KeyCode::Esc), ctrl_c()] {
        let mut m = main_model();
        assert!(matches!(m.on_key(k)[..], [Effect::Quit]));
        assert_eq!(m.mode, Mode::Quitting);
        assert!(m.on_key(ch('q')).is_empty());
        assert!(matches!(m.on_key(ctrl_c())[..], [Effect::ForceQuit]));
    }
    let mut busy = main_model();
    busy.on_key(key(KeyCode::Enter));
    busy.on_key(ch('y'));
    assert!(matches!(busy.on_key(ctrl_c())[..], [Effect::Quit]));
}

#[test]
fn too_small_only_quits() {
    let mut m = main_model();
    m.set_size(70, 20);
    assert!(m.on_key(key(KeyCode::Enter)).is_empty());
    assert!(m.on_key(ch('a')).is_empty());
    assert!(m.dialog.is_none());
    assert!(matches!(m.on_key(ch('q'))[..], [Effect::Quit]));
}

#[test]
fn updates_prune_selection_keep_cursor_and_cap_events() {
    let mut m = main_model();
    cursor_to(&mut m, 40200);
    m.on_key(ch(' '));
    let id = m.rows[m.cursor[0]].finding_id.clone();
    let s = snapshot();
    let mut rep = report(&s);
    rep.findings.retain(|f| f.targets[0].pid != 40200);
    m.apply(update_from(rep, AutoLevel::Safe, |_, _| {}));
    assert!(m.selected.is_empty(), "사라진 발견은 고름에서 빠짐");
    assert!(m.rows.iter().all(|r| r.finding_id != id));

    let mut m = main_model();
    cursor_to(&mut m, 40001);
    m.apply(update_from(report(&s), AutoLevel::Safe, |_, _| {}));
    assert_eq!(
        m.rows[m.cursor[0]].target.unwrap().pid,
        40001,
        "같은 id 유지"
    );

    let mut u = normal_update();
    u.new_events = (0..MAX_EVENTS as u64 + 20)
        .map(|i| {
            event(
                GuardEventKind::Notified,
                "Android 에뮬레이터",
                &format!("알림 {i}"),
                0,
                None,
            )
        })
        .collect();
    u.new_events
        .push(event(GuardEventKind::Skipped, "x", "건너뜀", 0, None));
    let dup = event(
        GuardEventKind::Notified,
        "Android 에뮬레이터",
        "알림 같음",
        0,
        None,
    );
    u.new_events.push(dup.clone());
    u.new_events.push(dup);
    m.apply(u);
    assert_eq!(m.events.len(), MAX_EVENTS);
    assert!(m.events.iter().all(|e| e.kind != GuardEventKind::Skipped));
    assert_eq!(m.events[0].detail_ko, "알림 같음");
    assert_ne!(m.events[1].detail_ko, "알림 같음");
}

fn origin_of(fx: &[Effect]) -> Option<vh_act::PlanOrigin> {
    sends(fx).into_iter().find_map(|c| match c {
        Cmd::RunPlan { origin, .. } => Some(*origin),
        _ => None,
    })
}

fn plan_of(fx: &[Effect]) -> Option<&ActionPlan> {
    sends(fx).into_iter().find_map(|c| match c {
        Cmd::RunPlan { plan, .. } => Some(plan),
        _ => None,
    })
}

/// c: 확인 필요·일하는 중·직접 하면 확보가 섞이고, 그중 일부를 미리 골라 둬도 '필요 없음'만 계획한다.
#[test]
fn c_plans_only_unneeded_even_with_other_rows_selected() {
    let mut m = main_model();
    for pid in [40001, 3000] {
        cursor_to(&mut m, pid);
        m.on_key(ch(' '));
    }
    assert_eq!(m.selected.len(), 2);
    assert!(m.on_key(ch('c')).is_empty());
    let Some(Dialog::Preview { bulk, plan, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert!(*bulk);
    let rep = m.latest.as_ref().unwrap().report.clone();
    let want: std::collections::BTreeSet<ProcRef> = rep
        .findings
        .iter()
        .filter(|f| f.section == Section::Unneeded)
        .flat_map(|f| f.targets.iter().copied())
        .collect();
    let got: std::collections::BTreeSet<ProcRef> = plan.items.iter().map(|a| a.target).collect();
    assert_eq!(got, want);
    for f in rep
        .findings
        .iter()
        .filter(|f| f.section != Section::Unneeded)
    {
        for t in &f.targets {
            assert!(
                !plan.items.iter().any(|a| a.target == *t),
                "{:?}",
                f.section
            );
            assert!(
                !plan.refused.iter().any(|x| x.target == *t),
                "{:?}",
                f.section
            );
        }
    }
    let fx = m.on_key(ch('y'));
    assert_eq!(run_plans(&fx), 1);
    assert_eq!(origin_of(&fx), Some(vh_act::PlanOrigin::Bulk));
    assert_eq!(plan_of(&fx).unwrap().items.len(), want.len());
    assert_eq!(m.selected.len(), 2, "c는 고른 것을 바꾸지 않는다");
}

#[test]
fn c_with_nothing_unneeded_opens_nothing() {
    let s = snapshot();
    let mut rep = report(&s);
    for f in &mut rep.findings {
        if f.section == Section::Unneeded {
            f.section = Section::Check;
        }
    }
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(rep, AutoLevel::Safe, |_, _| {}));
    assert!(m.on_key(ch('c')).is_empty());
    assert!(m.dialog.is_none());
    assert_eq!(m.flash.as_deref(), Some(vh_cli::tui::state::C_NOTHING));
}

#[test]
fn pointed_working_pick_runs_once_on_y() {
    let mut m = main_model();
    cursor_to(&mut m, 3000);
    m.on_key(ch(' '));
    assert_eq!(m.flash.as_deref(), Some(vh_cli::tui::state::PICK_WORKING));
    m.on_key(key(KeyCode::Enter));
    let Some(Dialog::Preview { bulk, lines, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert!(!*bulk);
    assert_eq!(lines[0], vh_cli::tui::state::WARN_WORKING);
    let fx = m.on_key(ch('y'));
    assert_eq!(run_plans(&fx), 1);
    assert_eq!(origin_of(&fx), Some(vh_act::PlanOrigin::Pointed));
    let pids: Vec<i32> = plan_of(&fx)
        .unwrap()
        .items
        .iter()
        .map(|a| a.target.pid)
        .collect();
    assert_eq!(
        pids,
        vec![3000],
        "직접 지목은 쓰고 있어도 R18로 막지 않는다(경고만)"
    );
}

#[test]
fn manual_rows_are_not_selectable() {
    let mut m = main_model();
    for pid in [2001, 8101] {
        cursor_to(&mut m, pid);
        m.on_key(ch(' '));
        assert!(m.selected.is_empty());
        assert_eq!(m.flash.as_deref(), Some(NOT_ACTIONABLE));
    }
}

#[test]
fn d_demotes_cursor_target_only_after_y() {
    let mut m = main_model();
    cursor_to(&mut m, 3000);
    assert!(m.on_key(ch('d')).is_empty());
    let Some(Dialog::Preview { title, plan, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert_eq!(*title, vh_cli::tui::state::DEMOTE_TITLE);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].steps, vec![Step::Demote]);
    assert_eq!(run_plans(&m.on_key(ch('n'))), 0);

    m.on_key(ch('d'));
    let fx = m.on_key(ch('y'));
    assert_eq!(run_plans(&fx), 1);
    assert_eq!(origin_of(&fx), Some(vh_act::PlanOrigin::Pointed));
    let p = plan_of(&fx).unwrap();
    assert_eq!(p.items[0].target.pid, 3000);
    assert!(p.items.iter().all(|a| a.steps == vec![Step::Demote]));

    let mut m = main_model();
    cursor_to(&mut m, 2001);
    m.on_key(ch('d'));
    let Some(Dialog::Preview { plan, lines, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert!(plan.items.is_empty(), "AI 세션은 낮추지 않음(보호 규칙)");
    assert!(
        lines.iter().any(|l| l.starts_with("낮추지 않아요: ")),
        "{lines:?}"
    );
    assert_eq!(run_plans(&m.on_key(ch('y'))), 0);
}
