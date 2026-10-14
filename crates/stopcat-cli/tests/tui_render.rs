//! TUI 화면 문자열(TestBackend 80×24·120×40): 정상·주의·위기·첫 실행·작은 창·확인 대화상자·
//! 기록 탭·설정 탭·env 고정 안내, 넘침 없음, 한글 폭.

mod common;
mod tui_common;

use common::*;
use crossterm::event::KeyCode;
use stopcat_cli::fmt;
use stopcat_cli::tui::state::{Dialog, Model, Tab};
use stopcat_cli::tui::view::{self, FIRST_RUN_LINES, KEYS_FIRST_RUN, TOO_SMALL};
use stopcat_model::*;
use tui_common::*;

const SIZES: [(u16, u16); 2] = [(80, 24), (120, 40)];

/// 평소(정상) 상태: 지킴이가 자동 예정을 만들지 않는다.
fn calm_model() -> Model {
    let s = snapshot();
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(report(&s), AutoLevel::Safe, |_, _| {}));
    m.no_color = true;
    m
}

/// 불안정(주의) 상태: codex가 자동 예정 1/2.
fn unstable_model(f: impl FnOnce(&mut GuardStatus)) -> Model {
    let s = snapshot();
    let mut rep = report(&s);
    rep.health.level = HealthLevel::Watch;
    rep.health.headline_ko =
        "메모리 주의 — 압력 2 · 압축 52GB · 스왑 6.1/8GB · 부하 12/18코어".into();
    let p = codex_pending(&s, &rep);
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(rep, AutoLevel::Safe, |_, st| {
        st.pending = vec![p];
        st.unstable = true;
        st.health = HealthLevel::Watch;
        st.unstable_reasons = vec![UnstableReason::HealthWatch];
        f(st);
    }));
    m.no_color = true;
    m
}

fn cursor_to_pid(m: &mut Model, pid: i32) {
    let i = m
        .rows
        .iter()
        .position(|r| r.target.is_some_and(|t| t.pid == pid))
        .expect("row for pid");
    m.cursor[0] = i;
}

/// 열 머리부터 목록 칸(80×24에서 13줄).
fn list_block(l: &[String]) -> Vec<String> {
    let i = l
        .iter()
        .position(|x| x.starts_with("    대상"))
        .expect("열 머리");
    l[i..i + 13].to_vec()
}

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

/// 목록 이름에 그 줄의 크기·나이 문자열이 들어 있지 않다(정상·위기, 두 크기).
#[test]
fn list_names_have_no_size_or_age() {
    let s = snapshot();
    let crisis = report_crisis(&s);
    let mut cm = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    cm.apply(update_from(crisis, AutoLevel::Safe, |_, st| {
        st.circuit_open = true;
    }));
    for mut m in [main_model(), cm] {
        assert!(!m.rows.is_empty());
        for r in &m.rows {
            if let Some(b) = r.size {
                assert!(!r.label.contains(&fmt::bytes(b)), "{}", r.label);
            }
            if let Some(st) = r.started_unix_ms {
                let ms = T0 - st;
                assert!(!r.label.contains(&fmt::age_short(ms)), "{}", r.label);
                assert!(!r.label.contains(&fmt::duration(ms)), "{}", r.label);
            }
        }
        for l in both(&mut m) {
            assert!(l.iter().any(|x| x.contains("크기  나이   근거")));
        }
    }
}

/// 평소 보고 화면 목록(열 머리 + 구역 머리 4 + 행 7 + 아래 표시), 80칸.
const LIST_80: [&str; 13] = [
    "    대상                   크기  나이   근거                    지킴이",
    " 필요 없음 3   정리하면 약 1.5GB · c 로 전부 정리",
    "❯ ○ codex app-server      1.0GB  3일    주인 끝남·CPU 0·연결 0  ◷ 불안정 시 자동",
    "  ○ headless Chrome (Ch…  380MB  7시간  주인 끝남·CPU 0·연결 0  ◆ 정리 추천",
    "  ○ npm exec               84MB  3일    주인 끝남·CPU 0·연결 0  ◆ 정리 추천",
    " 확인 필요 3   쓰고 있는지 확실하지 않아 보고만 · 확인하면 약 8.0GB",
    "  ○ Android 에뮬레이터 …  7.5GB  3일    주인 끝남·CPU 3%·연결 6 ▲ 확인 필요",
    "  ○ appium (앱 테스트) …  412MB  2일    주인 있음·안 쓰는 듯    ▲ 확인 필요",
    "  ○ 테스트 서버 (node) …   96MB  1일    주인 끝남·CPU 0·연결 …  ▲ 확인 필요",
    " 일하는 중 1   건드리지 않음",
    "  ○ Next.js 개발 서버            2시간  주인 있음·CPU 103%      ● 건드리지 않음",
    " 직접 하면 확보 2   약 22GB · 방법은 w",
    "  ↓ 2줄 더 있어요(↓ 로 내려 보기)",
];

#[test]
fn report_tab_normal() {
    let mut m = calm_model();
    for l in both(&mut m) {
        let h = l.len();
        assert!(l[0].starts_with(view::LOGO[0]), "{}", l[0]);
        assert!(
            l[0].contains("● 메모리 정상 · 압력 1 · 압축 41GB"),
            "{}",
            l[0]
        );
        assert!(
            l[1].ends_with("확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB"),
            "{}",
            l[1]
        );
        assert!(l[2].starts_with(" 1 보고 9 "), "{}", l[2]);
        assert!(l[2].ends_with(view::CREDIT), "{}", l[2]);
        assert!(
            l[h - 2].starts_with(" 지킴이 안정화 자동  평소 보고만   확인 "),
            "{}",
            l[h - 2]
        );
        assert!(
            !l[h - 2].contains("자동 종료"),
            "평소에는 자동 종료 수를 보이지 않음"
        );
        assert_eq!(l[h - 1], view::KEYS_FINDINGS);
        let order = [
            " 필요 없음 3   정리하면 약 1.5GB · c 로 전부 정리",
            " 확인 필요 3   쓰고 있는지 확실하지 않아 보고만 · 확인하면 약 8.0GB",
            " 일하는 중 1   건드리지 않음",
            " 직접 하면 확보 2   약 22GB · 방법은 w",
        ];
        let pos: Vec<usize> = order
            .iter()
            .map(|t| l.iter().position(|x| x == t).expect(t))
            .collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "구역 순서: {pos:?}");
        assert!(has(&l, "│ 근거    주인 끝남 · CPU 0% · 연결 0"));
    }
    assert_eq!(list_block(&render(&mut m, 80, 24)), LIST_80);
    let l = render(&mut m, 120, 40);
    assert!(has(&l, "omo 세션(bun)") && has(&l, "핸드오프 저장 후 재시작 ◇ 직접 하면 확보"));
    assert!(has(&l, "aside 좀비 20개") && has(&l, "↻ 앱 재시작 필요"));
    assert!(has(&l, "왜      띄운 Claude 세션이 이미 끝났어요"));
}

#[test]
fn report_tab_unstable_pending_and_settling() {
    let mut m = unstable_model(|_| {});
    for l in both(&mut m) {
        let h = l.len();
        assert!(l[0].contains("● 메모리 주의 · 압력 2"), "{}", l[0]);
        assert!(has(&l, "❯ ○ codex app-server") && has(&l, "◑ 자동 예정 1/2"));
        assert!(has(
            &l,
            "맥이 불안정해 2번 연속 확인되면 자동으로 정리해요(지금 1/2)."
        ));
        assert!(
            l[h - 2].contains(" 지킴이 안정화 자동  불안정 — 자동 정리 중   자동 종료 0/5(10분)"),
            "{}",
            l[h - 2]
        );
    }
    let mut m = unstable_model(|st| st.settle_until_unix_ms = Some(T0 + 60_000));
    assert!(render(&mut m, 80, 24)[22].contains(view::STATE_SETTLING));
    let s = snapshot();
    let mut n = Model::new(Some(done_config(AutoLevel::NotifyOnly)), None, false);
    n.apply(update_from(report(&s), AutoLevel::NotifyOnly, |_, st| {
        st.unstable = true;
    }));
    let l = render(&mut n, 80, 24);
    assert!(
        l[22].contains(" 지킴이 보고만  불안정 — 보고만(자동 정리 안 함) "),
        "{}",
        l[22]
    );
    assert!(
        !has(&l, "불안정 시 자동"),
        "보고만 수준에는 자동 대기 표시 없음"
    );
}

#[test]
fn report_tab_circuit_open() {
    let mut m = unstable_model(|st| {
        st.circuit_open = true;
        st.terminations_in_window = 5;
    });
    for l in both(&mut m) {
        let h = l.len();
        assert!(has(&l, "⊘ 차단기: 보고만"));
        assert!(
            l[h - 2].contains(" 차단기 열림(보고만)   자동 종료 5/5(10분)"),
            "{}",
            l[h - 2]
        );
        assert_eq!(l[h - 1], view::KEYS_FINDINGS_CIRCUIT);
    }
    assert_eq!(m.rows[0].mark.text(), "차단기: 보고만");
}

#[test]
fn report_tab_scrolls_to_manual_rows() {
    let mut m = calm_model();
    let l = render(&mut m, 80, 24);
    assert_eq!(l[15], view::more_below(2));
    cursor_to_pid(&mut m, 8101);
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert_eq!(l[4], view::more_above(2));
    assert!(l[15].starts_with("❯   aside 좀비 20개"), "{}", l[15]);
    assert!(has(&l, "방법    띄운 앱 다시 시작"));
    assert!(has(&l, "지킴이  이미 끝난 프로세스예요."));
}

#[test]
fn report_tab_all_empty() {
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(report_empty(), AutoLevel::Safe, |_, _| {}));
    for l in both(&mut m) {
        assert!(l[1].ends_with("지금 확보할 것이 없어요"), "{}", l[1]);
        assert!(l[2].starts_with(" 1 보고 0 "), "{}", l[2]);
        assert!(has(&l, view::EMPTY_CAT[1]));
        for t in view::EMPTY_BODY.iter().filter(|t| !t.is_empty()) {
            assert!(has(&l, t), "{t}");
        }
        assert_eq!(l.last().unwrap(), view::KEYS_EMPTY);
    }
}

#[test]
fn report_tab_unneeded_empty() {
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(no_unneeded(), AutoLevel::Safe, |_, _| {}));
    for l in both(&mut m) {
        assert!(
            l[1].ends_with("확보 가능 0 · 확인하면 +8.0GB · 직접 하면 +22GB"),
            "{}",
            l[1]
        );
        let i = l
            .iter()
            .position(|x| x == " 필요 없음 0")
            .expect("필요 없음 머리");
        assert_eq!(l[i + 1], view::UNNEEDED_EMPTY_LINE);
        assert!(l[i + 2].starts_with(" 확인 필요 3"));
    }
    m.on_key(ch('c'));
    assert!(m.dialog.is_none());
    assert_eq!(m.flash.as_deref(), Some(stopcat_cli::tui::state::C_NOTHING));
}

#[test]
fn c_preview_lists_unneeded_only() {
    let mut m = calm_model();
    m.on_key(ch('c'));
    let Some(Dialog::Preview { title, plan, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert_eq!(*title, "추천 전부 정리");
    let pids: Vec<i32> = plan.items.iter().map(|a| a.target.pid).collect();
    assert_eq!(pids.len(), 3);
    for p in [51234, 40200, 51230] {
        assert!(pids.contains(&p), "{pids:?}");
    }
    for l in both(&mut m) {
        assert!(has(&l, "추천 전부 정리 미리보기 — 3건"));
        assert!(has(&l, stopcat_cli::tui::state::C_BASIS));
        assert!(has(&l, "y 정리하기     n 취소"));
        assert!(!has(&l, "주의:"), "추천 전부에는 경고할 항목이 없다");
    }
}

#[test]
fn pointed_preview_warns_first_with_evidence() {
    let mut m = calm_model();
    cursor_to_pid(&mut m, 3000);
    m.on_key(ch(' '));
    assert_eq!(
        m.flash.as_deref(),
        Some(stopcat_cli::tui::state::PICK_WORKING)
    );
    cursor_to_pid(&mut m, 40112);
    m.on_key(ch(' '));
    assert_eq!(
        m.flash.as_deref(),
        Some(stopcat_cli::tui::state::PICK_CHECK)
    );
    m.on_key(key(KeyCode::Enter));
    let Some(Dialog::Preview { lines, .. }) = &m.dialog else {
        panic!("{:?}", m.dialog)
    };
    assert_eq!(lines[0], stopcat_cli::tui::state::WARN_WORKING);
    assert_eq!(lines[1], "  Next.js 개발 서버: 주인 있음 · CPU 103%");
    assert_eq!(lines[2], stopcat_cli::tui::state::WARN_CHECK);
    assert!(lines[3].starts_with("  appium (앱 테스트): 주인 있음 · CPU 0% · 연결 0"));
    assert!(lines[4].starts_with("정리 미리보기 — 2건"));
    assert_eq!(
        lines.last().unwrap(),
        stopcat_cli::tui::state::CONFIRM_WITH_WARNING
    );
    for l in both(&mut m) {
        assert!(has(
            &l,
            "주의: 일하는 중 — 지금 쓰고 있어요. 정리하면 하던 일이 끊겨요"
        ));
        assert!(has(&l, "일하는 중") && has(&l, "확인 필요"));
    }
}

/// W4에서 없앤 문구가 어느 화면에도 없다.
#[test]
fn removed_strings_never_render() {
    let mut screens: Vec<Vec<String>> = Vec::new();
    let mut fr = Model::new(None, None, false);
    screens.push(render(&mut fr, 80, 24));
    for mut m in [
        calm_model(),
        unstable_model(|_| {}),
        unstable_model(|st| st.circuit_open = true),
    ] {
        for k in ['1', '2', '3', '4'] {
            m.on_key(ch(k));
            screens.extend(both(&mut m));
        }
        m.on_key(ch('1'));
        for k in ['?', 'a', 'c', 'd'] {
            m.on_key(ch(k));
            screens.extend(both(&mut m));
            m.on_key(key(KeyCode::Esc));
            m.dialog = None;
        }
    }
    for l in &screens {
        for bad in [
            "낮춤 예정",
            concat!("폭", "주"),
            "정리할 것 ",
            "알림만",
            "안전 자동",
            "주의  ",
            "고아  ",
            "잔재  ",
        ] {
            assert!(!has(l, bad), "'{bad}' 이 화면에 남음: {l:#?}");
        }
    }
}

/// 나이 칸이 꽉 차도('19시간') 근거 칸과 붙지 않는다(PM-W4-2).
#[test]
fn full_age_keeps_one_space_before_evidence() {
    let mut m = calm_model();
    let mut u = update_from(report(&snapshot()), AutoLevel::Safe, |_, _| {});
    let mut later = (*u.snapshot).clone();
    later.taken_at_unix_ms += 12 * HOUR;
    u.snapshot = std::sync::Arc::new(later);
    m.apply(u);
    for (w, h) in SIZES {
        let l = render(&mut m, w, h);
        check_widths(&l, w as usize);
        assert!(has(&l, "19시간 주인 끝남·CPU 0·연결 0"), "{l:#?}");
        assert!(has(&l, "14시간 주인 있음·CPU 103%"), "{l:#?}");
        for x in &l {
            for glued in ["시간주", "일주", "분주", "시간앱", "일앱"] {
                assert!(!x.contains(glued), "나이·근거가 붙음: {x}");
            }
        }
    }
}

/// 지킴이 첫 확인(측정 간격 없음 → CPU·디스크 모름) 보고서.
fn first_scan_update(rep: Report) -> stopcat_cli::tui::link::Update {
    let mut u = update_from(rep, AutoLevel::Safe, |_, _| {});
    let mut s = (*u.snapshot).clone();
    s.cpu_sample_interval_ms = None;
    for p in &mut s.processes {
        p.cpu_pct = None;
    }
    u.snapshot = std::sync::Arc::new(s);
    u
}

/// PM-W4-1: 첫 보고에는 안내 한 줄을 보이고 '필요 없음 0'·'맥 상태가 좋아요' 같은 단정은 숨긴다.
/// 구역 값은 그대로 그린다(닫힌 쪽).
#[test]
fn first_report_shows_notice_and_hides_definite_lines() {
    let s = snapshot();
    let mut rep = report(&s);
    for f in &mut rep.findings {
        if f.section == Section::Unneeded {
            f.section = Section::Check;
        }
    }
    for c in &mut rep.classified {
        c.usage.state = UsageState::Unknown;
        c.usage.reasons = vec![UsageReason::CpuUnknown, UsageReason::DiskUnknown];
    }
    rep.totals.unneeded_bytes = 0;
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(first_scan_update(rep.clone()));
    assert!(view::first_report(&m));
    for l in both(&mut m) {
        assert!(l[1].ends_with(view::RECLAIM_FIRST), "{}", l[1]);
        assert_eq!(l[3], view::FIRST_REPORT);
        assert!(!has(&l, "필요 없음 0") && !has(&l, view::UNNEEDED_EMPTY_LINE));
        assert!(!has(&l, "확보 가능 0") && !has(&l, "맥 상태가 좋아요"));
        assert!(has(&l, "확인 필요 ") && has(&l, "주인 끝남·CPU 모름"));
    }

    m.apply(update_from(rep, AutoLevel::Safe, |_, _| {}));
    assert!(
        !view::first_report(&m),
        "두 번째 확인(측정 간격 있음)부터는 안내 없음"
    );
    let l = render(&mut m, 80, 24);
    assert!(!has(&l, view::FIRST_REPORT));
    assert!(has(&l, "필요 없음 0") && has(&l, view::UNNEEDED_EMPTY_LINE));
    assert!(l[1].ends_with("확보 가능 0 · 확인하면 +8.0GB · 직접 하면 +22GB"));

    let mut e = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    e.apply(first_scan_update(report_empty()));
    for l in both(&mut e) {
        assert!(l[1].ends_with(view::RECLAIM_FIRST), "{}", l[1]);
        assert_eq!(l[3], view::FIRST_REPORT);
        assert!(!has(&l, "맥 상태가 좋아요") && !has(&l, "지금 확보할 것이 없어요"));
    }
}

#[test]
fn first_run_screen_exact() {
    let mut m = Model::new(None, None, false);
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert_eq!(l[1].trim(), view::LOGO[0].trim());
    assert_eq!(l[2].trim(), view::LOGO[1].trim());
    assert_eq!(l[3].trim(), view::TAGLINE);
    assert!(
        l[5].starts_with(&format!("╭─ {} ─", view::FIRST_RUN_TITLE)),
        "{}",
        l[5]
    );
    for (i, want) in FIRST_RUN_LINES.iter().enumerate() {
        let got = &l[6 + i];
        assert!(got.starts_with(&format!("│ {want}")), "{got}");
        assert!(got.ends_with('│'), "{got}");
    }
    assert!(l[6 + FIRST_RUN_LINES.len()].starts_with('╰'));
    assert!(l[22].ends_with(view::CREDIT), "{}", l[22]);
    assert_eq!(l[23], KEYS_FIRST_RUN);
    both(&mut m);

    let mut env = Model::new(None, Some("notify"), false);
    let l = render(&mut env, 80, 24);
    assert!(has(
        &l,
        "지금은 STOPCAT_GUARD_LEVEL=notify 로 실행 중이라 고른 값은 저장만 해요."
    ));
}

#[test]
fn too_small_window() {
    for (w, h) in [(79, 24), (80, 23), (64, 18), (60, 20)] {
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
        assert!(l[2].contains(" 3 자동 처리 기록 2 "), "{}", l[2]);
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
        assert!(has(&l, "지킴이 수준") && has(&l, "[안정화 자동]") && has(&l, "Enter 바꾸기"));
        assert!(has(
            &l,
            "  지킴이 상태  평소 보고만 · 자동 종료 0/5(10분) · 확인 "
        ));
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
    assert!(has(&l, "[보고만]") && has(&l, "STOPCAT_GUARD_LEVEL로 고정"));
    assert!(l[22].contains("(STOPCAT_GUARD_LEVEL 고정)"), "{}", l[22]);
    env.on_key(ch('a'));
    for l in both(&mut env) {
        assert!(has(
            &l,
            "STOPCAT_GUARD_LEVEL 환경 변수로 '보고만'에 고정돼 있어요."
        ));
        assert!(has(&l, "화면에서는 바꿀 수 없어요."));
    }

    let mut bad = Model::new(Some(done_config(AutoLevel::Safe)), Some("turbo"), false);
    bad.apply(normal_update());
    let l = render(&mut bad, 120, 40);
    assert!(
        l[38].contains("지킴이 안정화 자동(STOPCAT_GUARD_LEVEL 값을 몰라 보고만)"),
        "{}",
        l[38]
    );
    assert_eq!(
        l.last().unwrap(),
        "STOPCAT_GUARD_LEVEL='turbo' 을 알아볼 수 없어 보고만으로 실행해요"
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
    assert!(has(&l, "❯ 안정화 자동") && has(&l, "(지금)"));
    assert!(has(&l, view::LEVEL_NOTE[0]) && has(&l, view::LEVEL_NOTE[1]));
    assert!(has(
        &l,
        "  보고만      자동으로 정리하지 않아요. 보고만 해요."
    ));
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
            "기록: ~/Library/Application Support/stopcat/audit.jsonl"
        ));
    }
}

#[test]
fn loading_before_first_update() {
    let mut m = Model::new(Some(done_config(AutoLevel::NotifyOnly)), None, false);
    let l = render(&mut m, 80, 24);
    check_widths(&l, 80);
    assert!(l[0].ends_with("◌ 메모리 확인 중…"), "{}", l[0]);
    assert!(
        l[22].contains(" 지킴이 보고만  켜짐 · 첫 확인 중"),
        "{}",
        l[22]
    );
    assert!(has(&l, "맥 상태를 확인하고 있어요…"));
}

/// `cargo test -p stopcat-cli --test tui_render -- --nocapture print_screens`로 화면을 그대로 본다
/// (DONE·README 증거용). 넘침·폭 검사도 같이 한다.
#[test]
fn print_screens() {
    let mut shots: Vec<(String, Vec<String>)> = Vec::new();
    let mut m = Model::new(None, None, false);
    shots.push(("첫 실행".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    shots.push(("① 보고 정상".into(), render(&mut m, 80, 24)));
    let mut m = unstable_model(|_| {});
    shots.push(("① 보고 불안정".into(), render(&mut m, 80, 24)));
    let mut m = unstable_model(|st| {
        st.circuit_open = true;
        st.terminations_in_window = 5;
    });
    shots.push(("① 보고 차단기".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    cursor_to_pid(&mut m, 8101);
    shots.push(("① 보고 스크롤".into(), render(&mut m, 80, 24)));
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(report_empty(), AutoLevel::Safe, |_, _| {}));
    shots.push(("① 보고 모두 빔".into(), render(&mut m, 80, 24)));
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(no_unneeded(), AutoLevel::Safe, |_, _| {}));
    shots.push(("① 보고 필요 없음 빔".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    m.on_key(ch('c'));
    shots.push(("c 추천 전부 정리".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    cursor_to_pid(&mut m, 3000);
    m.on_key(ch(' '));
    cursor_to_pid(&mut m, 40112);
    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    shots.push(("직접 지목 경고".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    cursor_to_pid(&mut m, 3000);
    m.on_key(ch('d'));
    shots.push(("d 우선순위 낮추기".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    m.on_key(ch('a'));
    shots.push(("수준 대화상자".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    m.on_key(ch('4'));
    shots.push(("④ 설정".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    m.on_key(ch('3'));
    shots.push(("③ 기록 빔".into(), render(&mut m, 80, 24)));
    let mut m = calm_model();
    shots.push(("작은 창".into(), render(&mut m, 64, 18)));
    let mut m = calm_model();
    shots.push(("① 보고 120×40".into(), render(&mut m, 120, 40)));
    for (name, l) in &shots {
        check_widths(l, 120);
        println!("[{name}]");
        for x in l {
            println!("{x}");
        }
    }
}

/// 필요 없음이 하나도 없는 보고서(나머지 구역은 그대로).
fn no_unneeded() -> Report {
    let s = snapshot();
    let mut rep = report(&s);
    rep.findings.retain(|f| f.section != Section::Unneeded);
    rep.totals.unneeded_bytes = 0;
    rep
}

/// 색 화면 미리보기: `STOPCAT_SHOTS=<폴더> cargo test -p stopcat-cli --test tui_render -- --ignored write_html_screens`
/// 로 HTML 격자를 만든다(디자인 확인·README 스크린샷용).
#[test]
#[ignore = "STOPCAT_SHOTS 폴더에 HTML을 쓴다"]
fn write_html_screens() {
    let Some(dir) = std::env::var_os("STOPCAT_SHOTS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let color = |mut m: Model| {
        m.no_color = false;
        m
    };
    let mut shots: Vec<(&str, Model, u16, u16)> = Vec::new();
    shots.push(("first-run", Model::new(None, None, false), 80, 24));
    shots.push(("report-80", color(calm_model()), 80, 24));
    shots.push(("report-120", color(calm_model()), 120, 40));
    shots.push(("report-100", color(calm_model()), 100, 30));
    shots.push(("unstable-80", color(unstable_model(|_| {})), 80, 24));
    let mut m = color(unstable_model(|st| {
        st.circuit_open = true;
        st.terminations_in_window = 5;
    }));
    m.on_key(ch('j'));
    shots.push(("circuit-80", m, 80, 24));
    let mut m = color(calm_model());
    m.on_key(ch('c'));
    shots.push(("bulk-preview", m, 100, 30));
    let mut m = color(calm_model());
    cursor_to_pid(&mut m, 3000);
    m.on_key(ch(' '));
    cursor_to_pid(&mut m, 40112);
    m.on_key(ch(' '));
    m.on_key(key(KeyCode::Enter));
    shots.push(("warn-preview", m, 100, 30));
    let mut m = color(calm_model());
    m.on_key(ch('a'));
    shots.push(("level", m, 100, 30));
    let mut m = color(calm_model());
    m.on_key(ch('?'));
    shots.push(("help", m, 100, 30));
    let mut m = color(calm_model());
    m.on_key(ch('2'));
    shots.push(("ports", m, 100, 30));
    let mut m = color(calm_model());
    m.on_key(ch('4'));
    shots.push(("settings", m, 100, 30));
    let mut m = color(main_model());
    m.on_key(ch('w'));
    shots.push(("why", m, 100, 30));
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    m.apply(update_from(report_empty(), AutoLevel::Safe, |_, _| {}));
    shots.push(("empty", m, 100, 30));
    shots.push(("small", color(calm_model()), 64, 18));
    let mut m = Model::new(Some(done_config(AutoLevel::Safe)), None, false);
    let mut u = normal_update();
    let s = snapshot();
    u.new_events = vec![
        event(
            GuardEventKind::LevelChanged,
            "보고만 → 안정화 자동",
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
    m.on_key(ch('3'));
    shots.push(("log", m, 100, 30));
    let mut idx = String::from(
        "<!doctype html><meta charset=utf-8><body style='background:#222;color:#ccc;font:14px sans-serif'>",
    );
    for (name, mut m, w, h) in shots {
        let buf = render_buffer(&mut m, w, h);
        std::fs::write(dir.join(format!("{name}-{w}x{h}.ans")), buffer_ansi(&buf)).unwrap();
        for (suffix, light) in [("", false), ("-light", true)] {
            let html = buffer_html(&buf, &format!("{name} {w}×{h}"), light);
            std::fs::write(dir.join(format!("{name}{suffix}.html")), html).unwrap();
        }
        idx.push_str(&format!(
            "<p><a href='{name}.html'>{name}</a> · <a href='{name}-light.html'>light</a></p>"
        ));
    }
    std::fs::write(dir.join("index.html"), idx).unwrap();
}
