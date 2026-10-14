//! 지킴이 갱신 반영: 같은 보고서·같은 표시 상태면 목록·포트 행을 다시 만들지 않고, 나이는 그릴 때
//! 계산한다. 합쳐진 갱신(이벤트 여러 개 + 정리 결과)도 잃지 않는다.

mod common;
mod tui_common;

use std::sync::Arc;

use common::*;
use crossterm::event::KeyCode;
use tui_common::*;
use vh_cli::tui::link::Update;
use vh_cli::tui::state::{Dialog, Model, build_ports, build_rows, target_infos};
use vh_model::*;

fn resend(m: &Model) -> Update {
    let l = m.latest.clone().expect("latest");
    Update {
        snapshot: l.snapshot,
        report: l.report,
        policy: l.policy,
        status: l.status,
        new_events: vec![],
        manual_result: None,
    }
}

#[test]
fn same_arc_no_rebuild() {
    let mut m = main_model();
    let (rows, ports) = (m.rows.clone(), m.ports.clone());
    let (n, p) = (m.rebuilds, m.port_rebuilds);
    assert_eq!((n, p), (1, 1));
    m.apply(resend(&m));
    assert_eq!((m.rebuilds, m.port_rebuilds), (n, p));
    assert_eq!(m.rows, rows);
    assert_eq!(m.ports, ports);
}

#[test]
fn equal_content_new_arc_no_rebuild() {
    let mut m = main_model();
    m.apply(normal_update());
    m.apply(normal_update());
    assert_eq!((m.rebuilds, m.port_rebuilds), (1, 1));
}

#[test]
fn pending_change_rebuilds_rows_only() {
    let mut m = main_model();
    let s = snapshot();
    let rep = report(&s);
    let mut p = codex_pending(&s, &rep);
    p.seen_scans = 2;
    m.apply(update_from(rep, AutoLevel::Safe, |_, st| {
        st.pending = vec![p]
    }));
    assert_eq!((m.rebuilds, m.port_rebuilds), (2, 1));
    assert_eq!(m.rows[0].mark.text(), "자동 예정 2/2");
}

#[test]
fn findings_change_rebuilds_and_retains_selection() {
    let mut m = main_model();
    let s = snapshot();
    let codex = finding_id(&report(&s), 51234);
    let appium = m
        .rows
        .iter()
        .find(|r| r.target.is_some_and(|t| t.pid == 40112))
        .expect("appium")
        .finding_id
        .clone();
    m.selected.insert(codex.clone());
    m.selected.insert(appium.clone());
    let mut rep = report(&s);
    rep.findings.retain(|f| f.id != codex);
    m.apply(update_from(rep, AutoLevel::Safe, |_, _| {}));
    assert_eq!((m.rebuilds, m.port_rebuilds), (2, 2));
    assert!(m.selected.contains(&appium) && !m.selected.contains(&codex));
    assert!(m.rows.iter().all(|r| r.finding_id != codex));
}

#[test]
fn age_advances_without_rebuild() {
    let mut m = main_model();
    let s = snapshot();
    let rep = report(&s);
    let p = codex_pending(&s, &rep);
    let mut u = update_from(rep, AutoLevel::Safe, |_, st| st.pending = vec![p]);
    let mut later = (*u.snapshot).clone();
    later.taken_at_unix_ms += DAY;
    u.snapshot = Arc::new(later);
    m.apply(u);
    assert_eq!((m.rebuilds, m.port_rebuilds), (1, 1));
    let l = render(&mut m, 80, 24);
    assert!(
        has(
            &l,
            "> [ ] codex app-server       1.0GB  4일   주인 끝남·CPU 0·연결 0  자동 예정 1/2"
        ),
        "{l:#?}"
    );
    assert!(has(&l, "pid 51234 · 4일 2시간째"));
}

/// 상관없는 프로세스가 아무리 많아도 목록·포트 행은 같다(발견 대상만 찾는다).
#[test]
fn rows_independent_of_unrelated_processes() {
    let s = snapshot();
    let rep = report(&s);
    let policy = GuardPolicy::for_level(AutoLevel::Safe);
    let st = tui_common::status(AutoLevel::Safe);
    let mut big = s.clone();
    let mut big_rep = rep.clone();
    for i in 0..2_000 {
        let mut p = s.processes[1].clone();
        p.pid = 100_000 + i;
        p.name = format!("helper-{i}");
        big_rep.classified.push(Classified {
            target: ProcRef {
                pid: p.pid,
                start_time_unix_ms: p.start_time_unix_ms,
            },
            kind: Kind::Other,
            label_ko: p.name.clone(),
            signature_id: None,
            project: None,
            owner_session: None,
            owner_pid: None,
            owner_source: None,
            owner_label_ko: None,
            owner_alive: None,
            usage: Usage::default(),
        });
        big.processes.push(p);
    }
    assert_eq!(
        build_rows(&big, &big_rep, &policy, &st),
        build_rows(&s, &rep, &policy, &st)
    );
    assert_eq!(build_ports(&big_rep), build_ports(&rep));
    let zombie = target_infos(&s, &rep)
        .into_iter()
        .find(|t| t.target.pid == 8101)
        .expect("zombie target");
    assert_eq!(zombie.label, "aside-daemon", "분류 없으면 프로세스 이름");
    let appium = target_infos(&s, &rep)
        .into_iter()
        .find(|t| t.target.pid == 40112)
        .expect("appium target");
    assert_eq!(appium.port, Some(4723));
}

#[test]
fn merged_update_keeps_events_and_manual_result() {
    let mut m = main_model();
    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    m.on_key(ch('y'));
    let Some(Dialog::Busy { request_id }) = m.dialog else {
        panic!("{:?}", m.dialog)
    };
    let before = m.events.len();
    let mut u = normal_update();
    u.new_events = ["가", "나", "다"]
        .iter()
        .map(|d| event(GuardEventKind::Notified, "알림", d, 0, None))
        .collect();
    u.manual_result = Some(manual(request_id, vec![]));
    m.apply(u);
    assert_eq!(m.events.len(), before + 3);
    assert!(matches!(m.dialog, Some(Dialog::Result { .. })));
}
