//! 화면 18종 렌더링 문자열(합성 데이터)과 80칸 검사.

mod common;

use std::path::Path;

use common::*;
use stopcat_cli::fmt::{WIDTH, width};
use stopcat_cli::render::{action, ports, status, why};
use stopcat_cli::target::Target;
use stopcat_model::*;

fn planned(s: &Snapshot, rep: &Report, pid: i32, desc: bool) -> PlannedAction {
    let f = rep
        .findings
        .iter()
        .find(|f| f.targets[0].pid == pid && matches!(f.suggestion, Suggestion::Terminate { .. }))
        .expect("terminate finding");
    PlannedAction {
        finding_id: f.id.clone(),
        target: r(pid, s),
        include_descendants: desc,
        descendant_count: if desc { f.descendant_count } else { 0 },
        steps: vec![Step::Term, Step::Kill],
        grace_ms: 3000,
        reason_ko: f.title_ko.clone(),
        est_reclaim_bytes: f.reclaim_bytes,
    }
}

fn fix_plan(s: &Snapshot, rep: &Report) -> ActionPlan {
    ActionPlan {
        created_at_unix_ms: T0,
        total_deadline_ms: 60_000,
        items: vec![
            planned(s, rep, 51234, true),
            planned(s, rep, 40200, false),
            planned(s, rep, 51230, false),
        ],
        refused: vec![],
    }
}

fn outcome(a: &PlannedAction, st: FinalState, killed: bool) -> ActionOutcome {
    let mut steps = vec![StepResult {
        step: Step::Term,
        pid: a.target.pid,
        at_unix_ms: T0,
        ok: true,
        errno: None,
    }];
    if killed {
        steps.push(StepResult {
            step: Step::Kill,
            pid: a.target.pid,
            at_unix_ms: T0 + 3000,
            ok: true,
            errno: None,
        });
    }
    ActionOutcome {
        action: a.clone(),
        steps,
        final_state: st,
        note_ko: String::new(),
    }
}

fn kill_plan(s: &Snapshot) -> ActionPlan {
    let t = r(61822, s);
    ActionPlan {
        created_at_unix_ms: T0,
        total_deadline_ms: 60_000,
        items: vec![PlannedAction {
            finding_id: format!("direct:{}:{}", t.pid, t.start_time_unix_ms),
            target: t,
            include_descendants: false,
            descendant_count: 0,
            steps: vec![Step::Term, Step::Kill],
            grace_ms: 3000,
            reason_ko: "사용자가 직접 지정".into(),
            est_reclaim_bytes: 96 * MIB,
        }],
        refused: vec![],
    }
}

const AUDIT: &str = "/Users/demo/Library/Application Support/stopcat/audit.jsonl";

/// (화면 이름, 출력) 18종.
fn screens() -> Vec<(&'static str, String)> {
    let s = snapshot();
    let rep = report(&s);
    let (e_pid, e_port) = explanations(&s, &rep);
    let plan = fix_plan(&s, &rep);
    let basis = stopcat_cli::flow::basis_ko(stopcat_cli::flow::Basis::Confirm, Confidence::Likely);
    let all_exited: Vec<_> = plan
        .items
        .iter()
        .enumerate()
        .map(|(i, a)| outcome(a, FinalState::Exited, i == 2))
        .collect();
    let partial = vec![
        outcome(&plan.items[0], FinalState::Exited, false),
        outcome(&plan.items[2], FinalState::StillAlive, true),
        outcome(&plan.items[1], FinalState::Vanished, false),
    ];
    let kp = kill_plan(&s);
    let empty_plan = ActionPlan {
        created_at_unix_ms: T0,
        total_deadline_ms: 60_000,
        items: vec![],
        refused: vec![],
    };

    let be = Synth::new();
    let why_bad = run(&be, &["why", "abc"], false, "");
    let why_missing_pid = run(&be, &["why", "4821"], false, "");
    let why_missing_port = run(&be, &["why", ":5001"], false, "");
    let usage = run(&be, &["--bogus"], false, "");
    let non_tty = run(&be, &["fix"], false, "");
    let declined = run(&be, &["fix"], true, "n\n");
    let refused = run(&be, &["kill", "2001"], false, "");
    let mut failing = Synth::new();
    failing.fail_exec = true;
    let internal = run(&failing, &["fix", "--yes"], false, "");

    vec![
        ("stopcat (정상, 주의 항목 있음)", status::render(&s, &rep, false)),
        (
            "stopcat (정상, 정리할 것 없음)",
            status::render(&s, &report_empty(), false),
        ),
        ("stopcat (위기)", status::render(&s, &report_crisis(&s), false)),
        (
            "stopcat why 51234",
            why::render(&s, &rep, Target::Pid(51234), &[e_pid], false),
        ),
        (
            "stopcat why :4723",
            why::render(&s, &rep, Target::Port(4723), &[e_port], false),
        ),
        (
            "stopcat why (오류·없음)",
            format!(
                "{}{}{}",
                why_bad.err, why_missing_pid.err, why_missing_port.err
            ),
        ),
        ("stopcat ports", ports::render(&s, &rep, false)),
        (
            "stopcat fix (미리보기)",
            format!(
                "{}{}",
                action::fix_preview(&s, &rep, &plan, &basis, &[], false),
                action::FIX_PROMPT
            ),
        ),
        ("stopcat fix (비 TTY)", non_tty.out),
        ("stopcat fix (확인에서 N)", declined.out),
        (
            "stopcat fix (실행 결과)",
            action::results(&s, &rep, "정리 결과", &all_exited, Path::new(AUDIT), false),
        ),
        (
            "stopcat fix (일부 실패 결과)",
            action::results(&s, &rep, "정리 결과", &partial, Path::new(AUDIT), false),
        ),
        (
            "stopcat fix (정리할 것 없음)",
            action::fix_preview(&s, &report_empty(), &empty_plan, &basis, &[], false),
        ),
        (
            "stopcat kill :18788 (미리보기)",
            format!(
                "{}{}",
                action::kill_preview(&s, &rep, &kp, Target::Port(18788), false),
                action::KILL_PROMPT
            ),
        ),
        (
            "stopcat kill :18788 (실행 결과)",
            action::results(
                &s,
                &rep,
                "끄기 결과",
                &[outcome(&kp.items[0], FinalState::Exited, false)],
                Path::new(AUDIT),
                false,
            ),
        ),
        ("stopcat kill (보호 규칙으로 거부)", refused.out),
        ("사용법 오류", usage.err),
        ("내부 오류", internal.err),
    ]
}

fn expect(name: &str, got: &str, want: &[&str]) {
    let got_lines: Vec<&str> = got.lines().collect();
    assert_eq!(got_lines, want, "화면 '{name}' 이 다름:\n{got}");
}

#[test]
fn eighteen_screens_fit_80_columns() {
    let all = screens();
    assert_eq!(all.len(), 18);
    for (name, text) in &all {
        assert!(!text.trim().is_empty(), "{name} 비어 있음");
        for l in text.lines() {
            assert!(width(l) <= WIDTH, "{name}: {} 칸 > 80: {l}", width(l));
        }
    }
}

fn screen(name: &str) -> String {
    screens()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| t)
        .unwrap()
}

#[test]
fn status_normal() {
    expect(
        "stopcat (정상, 주의 항목 있음)",
        &screen("stopcat (정상, 주의 항목 있음)"),
        &[
            "메모리 정상 — 압력 1 · 압축 41GB · 스왑 1.6/2GB · 부하 5.8/18코어",
            "확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB",
            "필요 없음  codex app-server 1.0GB — 주인 끝남·CPU 0·연결 0",
            "필요 없음  npm exec 84MB — 주인 끝남·CPU 0·연결 0",
            "필요 없음  headless Chrome (Chrome for Testing) 380MB — 주인 끝남·CPU 0·연결 0",
            "확인 필요  Android 에뮬레이터 (qemu) 7.5GB — 주인 끝남·CPU 3%·연결 6",
            "확인 필요  appium (앱 테스트) 412MB — 주인 있음·안 쓰는 듯",
            "확인 필요  테스트 서버 (node) 96MB — 주인 끝남·CPU 0·연결 모름",
            "일하는 중  Next.js 개발 서버 — 주인 있음·CPU 103% · 건드리지 않음",
            "직접 하면  omo 세션(bun) 22GB — 핸드오프 저장 후 재시작",
            "직접 하면  aside 좀비 20개 — 띄운 앱 다시 시작",
            "노출  Qdrant 0.0.0.0:6333 · appium *:4723",
            "충돌  AirPlay :5000·:7000",
            "→ stopcat fix 로 '필요 없음' 약 1.5GB 정리 (미리보기 → 확인)",
        ],
    );
}

#[test]
fn status_nothing() {
    expect(
        "stopcat (정상, 정리할 것 없음)",
        &screen("stopcat (정상, 정리할 것 없음)"),
        &[
            "메모리 정상 — 압력 1 · 압축 3.2GB · 스왑 없음 · 부하 2.1/18코어",
            "지금 확보할 것이 없어요",
            "지금 정리할 것이 없어요. 맥 상태가 좋아요.",
        ],
    );
}

#[test]
fn status_crisis() {
    expect(
        "stopcat (위기)",
        &screen("stopcat (위기)"),
        &[
            "메모리 위험 — 압력 4 · 압축 58GB · 스왑 14.2/16GB · 부하 31.5/18코어",
            "  스왑을 많이 쓰고 있어요. 앱이 멈추거나 아주 느려질 수 있어요.",
            "확보 가능 1.5GB · 확인하면 +8.0GB · 직접 하면 +22GB",
            "필요 없음  codex app-server 1.0GB — 주인 끝남·CPU 0·연결 0",
            "필요 없음  npm exec 84MB — 주인 끝남·CPU 0·연결 0",
            "필요 없음  headless Chrome (Chrome for Testing) 380MB — 주인 끝남·CPU 0·연결 0",
            "확인 필요  npm exec — 주인 끝남·CPU 0·연결 0",
            "확인 필요  테스트 서버 (node) — 주인 끝남·CPU 0·연결 모름",
            "확인 필요  Android 에뮬레이터 (qemu) 7.5GB — 주인 끝남·CPU 3%·연결 6",
            "  … 외 2건(전체: stopcat --json)",
            "일하는 중  Next.js 개발 서버 — 주인 있음·CPU 103% · 건드리지 않음",
            "일하는 중  Next.js 개발 서버 — 주인 있음·CPU 103% · 건드리지 않음",
            "직접 하면  omo 세션(bun) 22GB — 핸드오프 저장 후 재시작",
            "직접 하면  aside 좀비 20개 — 띄운 앱 다시 시작",
            "노출  Qdrant 0.0.0.0:6333 · appium *:4723",
            "충돌  AirPlay :5000·:7000",
            "→ stopcat fix 로 '필요 없음' 약 1.5GB 정리 (미리보기 → 확인)",
        ],
    );
}

#[test]
fn why_pid() {
    expect(
        "stopcat why 51234",
        &screen("stopcat why 51234"),
        &[
            "codex — AI 코딩 도구 서버",
            "  프로젝트   ~/dev/warmtalent-ai",
            "  띄운 곳    Claude 세션(pid 33298)이 띄웠고 그 세션은 이미 종료됐어요",
            "  실행 시간  3일 2시간 · 메모리 1.0GB (자식 29개 포함)",
            "누가 띄웠나 (자신 → 부모 → … → 시스템)",
            "  51234  codex — codex app-server        120MB   3일 2시간",
            "  51230  node — npm exec                  84MB   3일 2시간",
            "      1  launchd — macOS 시스템",
            "발견",
            "  고아(띄운 세션 종료)  확실 — codex app-server — 띄운 Claude 세션 종료됨, 자식…",
            "구역: 필요 없음 — 주인 끝남 · CPU 0% · 연결 0 · 디스크 0 · 평생 CPU 낮음",
            "요약: Claude 세션이 끝난 뒤 남은 codex 서버예요. stopcat fix 로 정리할 수",
            "      있어요.",
        ],
    );
}

#[test]
fn why_port() {
    expect(
        "stopcat why :4723",
        &screen("stopcat why :4723"),
        &[
            ":4723 — appium (모바일 앱 테스트 도구)",
            "  열린 곳    모든 네트워크(*:4723) — 같은 와이파이의 다른 기기도 접속 가능",
            "  프로젝트   ~/dev/shop-app",
            "  띄운 곳    띄운 터미널이 닫혀 시스템(launchd)이 맡고 있어요",
            "  실행 시간  2일 5시간 · 메모리 412MB",
            "누가 띄웠나 (자신 → 부모 → … → 시스템)",
            "  40112  node — appium                   412MB   2일 5시간",
            "      1  launchd — macOS 시스템",
            "발견",
            "  고아  가능성 높음 — appium이 혼자 남음",
            "  노출  확실 — 이 맥 밖에서도 접속할 수 있어요",
            "구역: 확인 필요 — 주인 있음 · CPU 0% · 연결 0 · 디스크 0 · 안 쓰는 듯",
            "요약: 테스트가 끝난 뒤 남은 appium이에요. 같은 와이파이의 다른 기기에서도 접속할",
            "      수 있으니, 쓰지 않으면 stopcat kill :4723 으로 끄세요.",
        ],
    );
}

#[test]
fn why_errors() {
    expect(
        "stopcat why (오류·없음)",
        &screen("stopcat why (오류·없음)"),
        &[
            "stopcat: 대상을 알아볼 수 없어요: 'abc'",
            "    프로세스 번호(예: 4821)나 콜론을 붙인 포트(예: :5000)를 넣어 주세요.",
            "stopcat: 4821번 프로세스가 없어요. 이미 끝났을 수 있어요.",
            "stopcat: :5001 포트에서 기다리는 프로그램이 없어요.",
        ],
    );
}

#[test]
fn ports_screen() {
    expect(
        "stopcat ports",
        &screen("stopcat ports"),
        &[
            "기다리는 포트 6개 — 외부 노출 4 · 알려진 충돌 2",
            "포트   열린 곳        프로그램                 프로젝트",
            "3000   이 맥만        Next.js 개발 서버        ~/dev/shop",
            "4723   모든 네트워크  appium (앱 테스트)       ~/dev/shop-app",
            "       ! 같은 와이파이의 다른 기기에서도 접속할 수 있어요",
            "5000   모든 네트워크  AirPlay 수신 (제어 센터) —",
            "       ! Flask 기본 포트와 겹쳐요. 내 앱은 다른 포트(예: 5050)를 쓰세요",
            "6333   모든 네트워크  Qdrant 데이터베이스      ~/dev/rag",
            "       ! 같은 와이파이의 다른 기기에서도 접속할 수 있어요",
            "7000   모든 네트워크  AirPlay 수신 (제어 센터) —",
            "18788  이 맥만        테스트 서버 (node)       —",
            "자세히 보려면: stopcat why :<포트>",
        ],
    );
}

#[test]
fn fix_preview() {
    expect(
        "stopcat fix (미리보기)",
        &screen("stopcat fix (미리보기)"),
        &[
            "정리 미리보기 — 3건, 최대 약 1.5GB 회수 예상",
            "기준: '필요 없음'만 · 확실 + 가능성 높음 (확인하고 실행할 때 기본값)",
            "  1. codex app-server (자식 29개 포함)                 1.0GB  확실",
            "     이유: 띄운 Claude 세션이 이미 끝났어요",
            "     방법: 자식부터 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료",
            "  2. headless Chrome (Chrome for Testing)              380MB  가능성 높음",
            "     이유: 테스트용 브라우저가 7시간째 남아 있어요",
            "     방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료",
            "  3. npm exec                                           84MB  가능성 높음",
            "     이유: 띄운 터미널이 닫혔는데 남아 있어요",
            "     방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료",
            "건드리지 않는 것",
            "  omo 세션 22GB — AI 세션은 끄지 않아요. 핸드오프 저장 후 직접 재시작",
            "  Android 에뮬레이터 (qemu) — 확인 필요라 뺐어요. 직접: stopcat fix --only 40001",
            "  appium (앱 테스트) — 확인 필요라 뺐어요. 직접: stopcat fix --only 40112",
            "  aside 좀비 20개 — 끌 수 없어요. 띄운 앱을 다시 시작하세요",
            "  테스트 서버 (node) — 확인 필요라 뺐어요. 직접: stopcat fix --only 61822",
            "  … 외 1건",
            "정리할까요? [y/N] ",
        ],
    );
}

#[test]
fn fix_non_tty_tail() {
    let text = screen("stopcat fix (비 TTY)");
    let ls: Vec<&str> = text.lines().collect();
    assert_eq!(
        ls[ls.len() - 2..],
        [
            "확인 없이 실행하지 않았어요. 실행하려면: stopcat fix --yes",
            "  (--yes 로 실행하면 '필요 없음' 중 '확실'인 것만 정리해요)",
        ]
    );
    assert!(ls[0].starts_with("정리 미리보기 — "), "{text}");
}

#[test]
fn fix_declined_tail() {
    let text = screen("stopcat fix (확인에서 N)");
    assert_eq!(
        text.lines().last(),
        Some("취소했어요. 아무것도 끄지 않았어요.")
    );
}

#[test]
fn fix_results() {
    expect(
        "stopcat fix (실행 결과)",
        &screen("stopcat fix (실행 결과)"),
        &[
            "정리 결과 — 3건 중 3건 종료, 예상 회수 약 1.5GB",
            "  종료됨          codex app-server (자식 29개 포함) — 정상 종료",
            "  종료됨          headless Chrome (Chrome for Testing) — 정상 종료",
            "  종료됨          npm exec — 3초 뒤 강제 종료",
            "기록: ~/Library/Application Support/stopcat/audit.jsonl",
            "되살릴 때 필요한 정보도 같은 폴더에 저장했어요.",
        ],
    );
}

#[test]
fn fix_partial_results() {
    expect(
        "stopcat fix (일부 실패 결과)",
        &screen("stopcat fix (일부 실패 결과)"),
        &[
            "정리 결과 — 3건 중 1건 종료, 1건 남음, 1건 이미 없음, 예상 회수 약 1.0GB",
            "  종료됨          codex app-server (자식 29개 포함) — 정상 종료",
            "  아직 살아 있음  npm exec — 강제 종료 신호에도 남아 있어요",
            "  이미 없음       headless Chrome (Chrome for Testing) — 확인하는 사이에 스스로…",
            "기록: ~/Library/Application Support/stopcat/audit.jsonl",
            "되살릴 때 필요한 정보도 같은 폴더에 저장했어요.",
        ],
    );
}

#[test]
fn fix_nothing() {
    expect(
        "stopcat fix (정리할 것 없음)",
        &screen("stopcat fix (정리할 것 없음)"),
        &["정리할 것이 없어요."],
    );
}

#[test]
fn kill_preview() {
    expect(
        "stopcat kill :18788 (미리보기)",
        &screen("stopcat kill :18788 (미리보기)"),
        &[
            "끄기 미리보기 — :18788",
            "  테스트 서버 (node) · pid 61822 · 96MB · 1일 3시간째",
            "  폴더: /private/tmp/claude-501/abc/scratchpad/srv",
            "  방법: 정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료",
            "  자식 2개(48MB)는 그대로 둡니다. 함께 끄려면 --tree",
            "끌까요? [y/N] ",
        ],
    );
}

#[test]
fn kill_result() {
    expect(
        "stopcat kill :18788 (실행 결과)",
        &screen("stopcat kill :18788 (실행 결과)"),
        &[
            "끄기 결과 — 1건 중 1건 종료, 예상 회수 약 96MB",
            "  종료됨          테스트 서버 (node) — 정상 종료",
            "기록: ~/Library/Application Support/stopcat/audit.jsonl",
            "되살릴 때 필요한 정보도 같은 폴더에 저장했어요.",
        ],
    );
}

#[test]
fn kill_refused() {
    expect(
        "stopcat kill (보호 규칙으로 거부)",
        &screen("stopcat kill (보호 규칙으로 거부)"),
        &[
            "끄지 않았어요: omo 세션(bun)",
            "  에이전트 세션·GUI 앱·VM·데이터베이스는 강제로 끄지 않습니다(에이전트: 핸드오프",
            "  저장 후 재시작 권장, DB: 손상 위험)",
        ],
    );
}

#[test]
fn usage_error() {
    expect(
        "사용법 오류",
        &screen("사용법 오류"),
        &[
            "stopcat: 알 수 없는 옵션이에요: --bogus",
            "    도움말: stopcat --help",
        ],
    );
}

#[test]
fn internal_error() {
    expect(
        "내부 오류",
        &screen("내부 오류"),
        &[
            "stopcat: 정리를 실행하다가 문제가 생겼어요: 상태 폴더를 준비하지 못했어요: 권한",
            "    없음",
            "    다시 해 보고, 계속되면 stopcat snapshot --json 결과를 함께 알려 주세요.",
        ],
    );
}

#[test]
fn color_only_when_enabled() {
    let s = snapshot();
    let rep = report(&s);
    assert!(!status::render(&s, &rep, false).contains('\x1b'));
    let colored = status::render(&s, &rep, true);
    assert!(colored.contains("\x1b[32m"));
    assert!(stopcat_cli::color::enabled(false, false, true, false));
    assert!(!stopcat_cli::color::enabled(true, false, true, false));
    assert!(!stopcat_cli::color::enabled(false, true, true, false));
    assert!(!stopcat_cli::color::enabled(false, false, false, false));
    assert!(!stopcat_cli::color::enabled(false, false, true, true));
}

#[test]
fn same_short_names_collapse_and_pid_errors_are_quiet() {
    let mut s = snapshot();
    let mut rep = report(&s);
    let qdrant = rep
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::ExposedListener && f.targets[0].pid == 6333)
        .unwrap()
        .clone();
    let mut twin = qdrant.clone();
    twin.id.push_str(":twin");
    rep.findings.push(twin);
    s.collection_errors.push(CollectionError {
        pid: Some(40200),
        stage: "pidpath".into(),
        errno: Some(3),
        message: "proc_pidpath 실패".into(),
    });
    let text = status::render(&s, &rep, false);
    assert!(text.contains("노출  Qdrant 0.0.0.0:6333 ×2"), "{text}");
    assert!(!text.contains("읽지 못했어요"), "{text}");
    s.collection_errors.push(CollectionError {
        pid: None,
        stage: "launchd".into(),
        errno: None,
        message: "launchctl list 실패".into(),
    });
    let text = status::render(&s, &rep, false);
    assert!(text.contains("일부 정보를 읽지 못했어요(1건)"), "{text}");
}

#[test]
fn why_port_shows_only_that_port() {
    let s = snapshot();
    let rep = report(&s);
    let (_, mut e) = explanations(&s, &rep);
    e.listeners.push(s.listeners[0].clone());
    let text = why::render(&s, &rep, Target::Port(4723), &[e], false);
    assert!(text.contains("모든 네트워크(*:4723) —"), "{text}");
    assert!(!text.contains("3000"), "{text}");
}
