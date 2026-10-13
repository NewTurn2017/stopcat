//! fix·kill 흐름: 비 TTY는 실행하지 않음, 확인·--yes일 때만 가짜 신호기로 실행, 신뢰도 기본값.

mod common;

use std::collections::BTreeSet;

use common::*;
use vh_model::{Family, Listener};

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out.trim()).expect("JSON")
}

fn plan_pids(v: &serde_json::Value) -> BTreeSet<i64> {
    v["plan"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["target"]["pid"].as_i64().unwrap())
        .collect()
}

fn audit_exists(be: &Synth) -> bool {
    vh_act::audit_log_path(be.state.path()).exists()
}

#[test]
fn non_tty_fix_never_executes() {
    let be = Synth::new();
    let ran = run(&be, &["fix"], false, "y\n");
    assert_eq!(ran.code, 0);
    assert_eq!(be.exec_calls.get(), 0);
    assert!(be.sent.borrow().is_empty());
    assert!(!audit_exists(&be));
    assert!(ran.out.contains("확인 없이 실행하지 않았어요"));
    assert!(ran.err.is_empty(), "질문하지 않아야 함: {}", ran.err);

    let ran = run(&be, &["fix", "--json"], true, "y\n");
    assert_eq!(json(&ran.out)["mode"], "non_interactive_preview");
    assert_eq!(json(&ran.out)["outcomes"], serde_json::json!([]));
    assert_eq!(be.exec_calls.get(), 0);
}

#[test]
fn tty_answer_decides() {
    let be = Synth::new();
    let ran = run(&be, &["fix"], true, "\n");
    assert_eq!(ran.code, 0);
    assert_eq!(ran.err, "정리할까요? [y/N] ");
    assert_eq!(be.exec_calls.get(), 0);

    let ran = run(&be, &["fix"], true, "y\n");
    assert_eq!(ran.code, 0);
    assert_eq!(be.exec_calls.get(), 1);
    assert!(
        ran.out.contains("정리 결과 — 4건 중 4건 종료"),
        "{}",
        ran.out
    );
    let sent = be.sent.borrow();
    for pid in [40001, 51234, 40112, 40200] {
        assert!(sent.contains(&(pid, libc::SIGTERM)), "{pid}: {sent:?}");
    }
    assert!(
        !sent.iter().any(|(p, _)| [2001, 6333, 700].contains(p)),
        "{sent:?}"
    );
    assert!(audit_exists(&be));
}

#[test]
fn yes_runs_confirmed_only() {
    let be = Synth::new();
    let v = json(&run(&be, &["fix", "--yes", "--json"], false, "").out);
    assert_eq!(v["mode"], "executed");
    assert_eq!(plan_pids(&v), BTreeSet::from([51234]));
    assert_eq!(v["outcomes"][0]["final_state"], "exited");
    assert!(v["audit_log"].as_str().unwrap().ends_with("audit.jsonl"));
    assert_eq!(be.exec_calls.get(), 1);
}

#[test]
fn preview_default_is_likely() {
    let be = Synth::new();
    let v = json(&run(&be, &["fix", "--json"], false, "").out);
    assert_eq!(plan_pids(&v), BTreeSet::from([40001, 51234, 40112, 40200]));
}

#[test]
fn only_reaches_possible_and_explicit_wins() {
    let be = Synth::new();
    let v = json(&run(&be, &["fix", "--json", "--only", "61822"], false, "").out);
    assert_eq!(plan_pids(&v), BTreeSet::from([61822]));

    let text = run(&be, &["fix", "--only", "61822"], false, "").out;
    assert!(text.contains("직접 고른 대상이에요(--only)"), "{text}");
    assert!(text.contains("기준: 직접 고른 대상(--only)"), "{text}");

    let v = json(
        &run(
            &be,
            &[
                "fix",
                "--json",
                "--only",
                "61822",
                "--min-confidence",
                "likely",
            ],
            false,
            "",
        )
        .out,
    );
    assert_eq!(v["mode"], "nothing_to_do");
    assert!(plan_pids(&v).is_empty());
    assert_eq!(be.exec_calls.get(), 0);
}

#[test]
fn kill_port_with_two_processes_is_one_plan() {
    let mut be = Synth::new();
    let start = be
        .snap
        .processes
        .iter()
        .find(|p| p.pid == 3000)
        .unwrap()
        .start_time_unix_ms;
    be.snap.listeners.push(Listener {
        pid: 3000,
        start_time_unix_ms: start,
        family: Family::V6,
        local_addr: "::1".into(),
        port: 4723,
        all_interfaces: false,
        loopback: true,
        dual_stack: false,
    });
    let v = json(&run(&be, &["kill", ":4723", "--json"], false, "").out);
    assert_eq!(
        v["target"],
        serde_json::json!({"kind": "port", "value": 4723})
    );
    assert_eq!(plan_pids(&v), BTreeSet::from([40112, 3000]));
    assert_eq!(v["mode"], "non_interactive_preview");
    assert_eq!(be.exec_calls.get(), 0);
}

#[test]
fn kill_yes_executes_and_non_tty_does_not() {
    let be = Synth::new();
    let ran = run(&be, &["kill", ":18788"], false, "");
    assert_eq!(ran.code, 0);
    assert!(
        ran.out
            .contains("확인 없이 끄지 않았어요. 끄려면: vh kill :18788 --yes")
    );
    assert_eq!(be.exec_calls.get(), 0);

    let ran = run(&be, &["kill", ":18788", "--yes"], false, "");
    assert_eq!(ran.code, 0);
    assert!(ran.out.starts_with("끄기 미리보기 — :18788"), "{}", ran.out);
    assert!(
        ran.out.contains("\n끄기 결과 — 1건 중 1건 종료"),
        "{}",
        ran.out
    );
    assert!(be.sent.borrow().contains(&(61822, libc::SIGTERM)));
    assert!(
        !be.sent
            .borrow()
            .iter()
            .any(|(p, _)| *p == 61830 || *p == 61831)
    );
}

#[test]
fn kill_refused_agent_session_never_executes() {
    let be = Synth::new();
    let ran = run(&be, &["kill", "2001", "--yes"], false, "");
    assert_eq!(ran.code, 0);
    assert!(
        ran.out.starts_with("끄지 않았어요: omo 세션(bun)"),
        "{}",
        ran.out
    );
    assert_eq!(be.exec_calls.get(), 0);
}
