//! TUI 화면 문자열(TestBackend 80×24·120×40): 정상·주의·위기·첫 실행·작은 창·확인 대화상자·
//! 기록 탭·설정 탭·env 고정 안내, 넘침 없음, 한글 폭.

mod common;
mod tui_common;

use common::*;
use crossterm::event::KeyCode;
use tui_common::*;
use vh_cli::tui::state::{Dialog, Model, Tab};
use vh_cli::tui::view::{self, FIRST_RUN_LINES, KEYS_FIRST_RUN, TOO_SMALL};
use vh_model::*;

const SIZES: [(u16, u16); 2] = [(80, 24), (120, 40)];

fn both(m: &mut Model) -> Vec<Vec<String>> {
    SIZES
        .iter()
        .map(|(w, h)| {
            let l = render(m, *w, *h);
            assert_eq!(l.len(), *h as usize);
            check_widths(&l, *w as usize);
            l
        })
        .collect()
}

#[test]
fn normal_findings_tab() {
    let mut m = main_model();
    for l in both(&mut m) {
        assert!(l[0].starts_with("vh  메모리 정상 — 압력 1"), "{}", l[0]);
        assert!(l[1].contains("지킴이 안전 자동 · 켜짐 · 자동 종료 0/5(10분) · 확인 "));
        assert!(l[2].starts_with("[1 정리할 것 6]"), "{}", l[2]);
        assert!(has(&l, "codex app-server") && has(&l, "자동 예정 1/2"));
        assert!(has(&l, "Android 에뮬레이터 7.5GB") && has(&l, "알림만"));
        assert!(has(&l, "omo 세션(bun) 22GB, 5일째") && has(&l, "끄지 않음"));
        assert!(has(&l, "앱 재시작 필요"));
        assert!(!has(&l, "테스트 서버 :18788"), "가능성 있음은 숨김");
        assert!(has(&l, "─ 자세히: codex app-server"));
        assert_eq!(l.last().unwrap(), view::KEYS_FINDINGS);
    }
    let first = m.rows.first().unwrap();
    assert_eq!(first.mark.text(), "자동 예정 1/2", "자동 예정이 맨 위");
}

#[test]
fn watch_and_crisis_with_circuit_open() {
    let s = snapshot();
    let mut watch = report(&s);
    watch.health.level = HealthLevel::Watch;
    watch.health.headline_ko =
        "메모리 주의 — 압력 2 · 압축 52GB · 스왑 6.1/8GB · 부하 12/18코어".into();
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(watch, AutoLevel::Safe, |_, _| {}));
    for l in both(&mut m) {
        assert!(l[0].starts_with("vh  메모리 주의"));
        assert!(has(&l, "주의  omo 세션"));
    }

    let crisis = report_crisis(&s);
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(crisis, AutoLevel::Safe, |_, st| {
        st.circuit_open = true;
        st.terminations_in_window = 5;
    }));
    for l in both(&mut m) {
        assert!(l[0].starts_with("vh  메모리 위험 — 압력 4"));
        assert!(l[1].contains("차단기 열림(알림만) · 자동 종료 5/5(10분)"));
        assert!(
            has(&l, "차단기: 알림만"),
            "codex는 자동 대상인데 차단기로 보류"
        );
        assert_eq!(l.last().unwrap(), view::KEYS_FINDINGS_CIRCUIT);
    }
}

#[test]
fn first_run_screen_exact() {
    let mut m = Model::new(None, None, false);
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    let mut want = vec!["vh  처음 실행".to_string(), "─".repeat(80)];
    want.extend(FIRST_RUN_LINES.iter().map(|s| s.trim_end().to_string()));
    while want.len() < 22 {
        want.push(String::new());
    }
    want.push("─".repeat(80));
    want.push(KEYS_FIRST_RUN.to_string());
    assert_eq!(l, want);
    both(&mut m);

    let mut env = Model::new(None, Some("notify"), false);
    let l = render(&mut env, 80, 24);
    assert!(has(
        &l,
        "지금은 VH_GUARD_LEVEL=notify 로 실행 중이라 고른 값은 저장만 해요."
    ));
}

#[test]
fn too_small_window() {
    for (w, h) in [(79, 24), (80, 23), (64, 18)] {
        let mut m = main_model();
        let l = render(&mut m, w, h);
        check_widths(&l, w as usize);
        assert!(has(&l, TOO_SMALL), "{w}×{h}");
        assert!(has(&l, &format!("지금 {w}×{h}, 필요 80×24 이상")));
    }
    let mut m = main_model();
    assert!(!has(&render(&mut m, 80, 24), TOO_SMALL));
}

#[test]
fn confirm_dialog_preview() {
    let mut m = main_model();
    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    let Some(Dialog::Preview { plan, .. }) = &m.dialog else {
        panic!("미리보기 없음: {:?}", m.dialog)
    };
    assert_eq!(plan.items.len(), 1);
    for l in both(&mut m) {
        assert!(has(&l, "정리할까요?"));
        assert!(has(&l, "정리 미리보기 — 1건, 최대 약"));
        assert!(has(&l, "기준: 직접 고른 것만 · 보호 규칙은 그대로"));
        assert!(has(
            &l,
            "방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료"
        ));
        assert!(has(&l, "y 정리하기     n 취소"));
    }
}

#[test]
fn log_tab_with_and_without_events() {
    let mut m = main_model();
    m.on_key(ch('3'));
    for l in both(&mut m) {
        assert!(has(&l, "아직 자동으로 처리한 일이 없어요."));
    }
    let s = snapshot();
    let mut u = normal_update();
    u.new_events = vec![
        event(
            GuardEventKind::LevelChanged,
            "알림만 → 안전 자동",
            "사용자가 바꿈",
            0,
            None,
        ),
        event(
            GuardEventKind::AutoTerminated,
            "MCP 서버: chrome-devtools",
            "띄운 Claude 세션이 12분 전에 끝났고 2번 연속 확인됐어요",
            96 * MIB,
            Some(r(40200, &s)),
        ),
    ];
    m.apply(u);
    assert_eq!(m.tab, Tab::Log);
    for l in both(&mut m) {
        assert!(l[2].contains("[3 자동 처리 기록 2]"), "{}", l[2]);
        assert!(has(&l, "이번에 자동으로 정리한 양 약 96MB · 자동 종료 1건"));
        assert!(has(&l, "자동 종료") && has(&l, "MCP 서버: chrome-devtools"));
        assert!(has(&l, "수준 바꿈"));
        assert!(has(&l, "2번 연속 확인됐어요"));
        assert_eq!(l.last().unwrap(), view::KEYS_LOG);
    }
}

#[test]
fn settings_tab_and_env_lock_notice() {
    let mut m = main_model();
    m.on_key(ch('4'));
    for l in both(&mut m) {
        assert!(has(&l, "지킴이 수준") && has(&l, "[안전 자동]") && has(&l, "Enter 바꾸기"));
        assert!(has(&l, "[5초]"));
        assert!(has(
            &l,
            "로그인 시 자동 실행 — 다음 버전(아직 쓸 수 없어요)"
        ));
    }

    let mut env = Model::new(Some(done_config(AutoLevel::Safe)), Some("notify"), false);
    env.apply(normal_update());
    env.on_key(ch('4'));
    let l = render(&mut env, 80, 24);
    assert!(has(&l, "[알림만]") && has(&l, "VH_GUARD_LEVEL로 고정"));
    assert!(l[1].contains("VH_GUARD_LEVEL 고정"));
    env.on_key(ch('a'));
    for l in both(&mut env) {
        assert!(has(
            &l,
            "VH_GUARD_LEVEL 환경 변수로 '알림만'에 고정돼 있어요."
        ));
        assert!(has(&l, "화면에서는 바꿀 수 없어요."));
    }

    let mut bad = Model::new(Some(done_config(AutoLevel::Safe)), Some("turbo"), false);
    bad.apply(normal_update());
    let l = render(&mut bad, 120, 40);
    assert!(l[1].contains("지킴이 안전 자동(VH_GUARD_LEVEL 값을 몰라 알림만)"));
    assert_eq!(
        l.last().unwrap(),
        "VH_GUARD_LEVEL='turbo' 을 알아볼 수 없어 알림만으로 실행해요"
    );
}

#[test]
fn ports_tab() {
    let mut m = main_model();
    m.on_key(ch('2'));
    for l in both(&mut m) {
        assert!(has(&l, ":4723") && has(&l, "노출"));
        assert!(has(&l, ":6333"));
        assert_eq!(l.last().unwrap(), view::KEYS_PORTS);
    }
    assert_eq!(m.ports[0].flag, "노출");
}

#[test]
fn small_dialogs_help_level_aggressive_result_why() {
    let mut m = main_model();
    m.on_key(ch('?'));
    assert!(has(&render(&mut m, 80, 24), "q Esc Ctrl+C  끝내기"));
    m.on_key(ch('x'));
    m.on_key(ch('a'));
    let l = render(&mut m, 80, 24);
    assert!(has(&l, "> 안전 자동") && has(&l, "(지금)"));
    m.on_key(key(KeyCode::Down));
    m.on_key(key(KeyCode::Enter));
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert!(has(&l, "적극 자동으로 바꿀까요?"));
    m.on_key(ch('n'));

    m.on_key(ch('w'));
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert!(has(&l, "─ 자세히"), "{l:#?}");
    m.on_key(ch('x'));

    m.on_key(key(KeyCode::Enter));
    m.on_key(ch('y'));
    let Some(Dialog::Busy { request_id }) = m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert!(has(&render(&mut m, 80, 24), "정리하는 중"));
    let mut u = normal_update();
    u.manual_result = Some(manual(request_id, vec![]));
    m.apply(u);
    for l in both(&mut m) {
        assert!(has(&l, "정리 결과 — 0건 중 0건 종료"));
        assert!(has(
            &l,
            "기록: ~/Library/Application Support/vibe-health/audit.jsonl"
        ));
    }
}

#[test]
fn loading_before_first_update() {
    let mut m = Model::new(Some(done_config(AutoLevel::NotifyOnly)), None, false);
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert_eq!(l[0], "vh  메모리 확인 중…");
    assert!(l[1].contains("지킴이 알림만 · 켜짐 · 첫 확인 중"));
    assert!(has(&l, "맥 상태를 확인하고 있어요…"));
}

/// `cargo test -p vh-cli --test tui_render -- --nocapture print_screens`로 화면을 그대로 본다
/// (DONE 증거용). 넘침·폭 검사도 같이 한다.
#[test]
fn print_screens() {
    let mut shots: Vec<(String, Vec<String>)> = Vec::new();
    let mut m = Model::new(None, None, false);
    shots.push(("첫 실행".into(), render(&mut m, 80, 24)));
    let mut m = main_model();
    shots.push(("① 정상".into(), render(&mut m, 80, 24)));
    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    shots.push(("확인 대화상자".into(), render(&mut m, 80, 24)));
    let mut m = main_model();
    m.on_key(ch('2'));
    shots.push(("② 포트".into(), render(&mut m, 80, 24)));
    m.on_key(ch('4'));
    shots.push(("④ 설정".into(), render(&mut m, 80, 24)));
    let mut m = main_model();
    shots.push(("작은 창".into(), render(&mut m, 64, 18)));
    let mut m = main_model();
    shots.push(("① 정상 120×40".into(), render(&mut m, 120, 40)));
    for (name, l) in &shots {
        check_widths(l, 120);
        println!("[{name}]");
        for x in l {
            println!("{x}");
        }
    }
}
