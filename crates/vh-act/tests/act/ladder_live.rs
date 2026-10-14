//! 실제 신호 테스트(ACT_7 ①②③④⑥⑧⑨⑩). 신호는 이 테스트가 띄운 자식과 그 자손에게만 간다:
//! `GuardedSignaler`가 허용 목록 밖 pid를 막고 기록하며, 각 테스트가 위반 0건을 단언한다.

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use vh_act::*;
use vh_model::*;

use crate::common::*;

struct LiveRun {
    outcomes: Vec<ActionOutcome>,
    audit: Vec<AuditEntry>,
    dir: tempfile::TempDir,
}

fn exec_live(snap: &Snapshot, plan: &ActionPlan, sig: &GuardedSignaler) -> LiveRun {
    let dir = tempfile::tempdir().unwrap();
    let env = ExecEnv {
        signaler: sig,
        prober: &RealProber,
        state_dir: dir.path().to_path_buf(),
        snapshot: snap,
        run_id: "live".into(),
    };
    let outcomes = execute(plan, &env);
    let audit = read_audit(dir.path());
    assert!(
        sig.violations.borrow().is_empty(),
        "허용 밖 pid로 신호 시도: {:?}",
        sig.violations.borrow()
    );
    LiveRun {
        outcomes,
        audit,
        dir,
    }
}

fn direct(snap: &Snapshot, t: ProcRef, tree: bool, policy: &Policy) -> ActionPlan {
    let sel = Selection {
        direct: vec![DirectTarget {
            target: t,
            include_descendants: tree,
        }],
        ..Selection::default()
    };
    let p = plan_idle(snap, &report(Vec::new(), Vec::new()), &sel, policy);
    assert!(p.refused.is_empty(), "{:?}", p.refused);
    assert_eq!(p.items.len(), 1);
    p
}

fn steps_of(o: &ActionOutcome) -> Vec<(Step, i32, bool)> {
    o.steps.iter().map(|s| (s.step, s.pid, s.ok)).collect()
}

#[test]
fn act7_1_sleep_child_exits_on_term() {
    let c = OwnedChild::spawn(&["/bin/sleep", "300"]);
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let p = direct(&snap, c.r, false, &Policy::default());
    assert_eq!(
        p.items[0].finding_id,
        format!("direct:{}:{}", c.r.pid, c.r.start_time_unix_ms)
    );
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    let o = &run.outcomes[0];
    assert_eq!(o.final_state, FinalState::Exited, "{}", o.note_ko);
    assert_eq!(steps_of(o), vec![(Step::Term, c.pid(), true)]);
    assert!(o.note_ko.contains("TERM"));
    assert!(is_gone(c.r));
}

#[test]
fn act7_2_term_ignoring_child_gets_kill_after_grace() {
    let c = OwnedChild::spawn(&[
        "/usr/bin/perl",
        "-e",
        "$SIG{TERM}='IGNORE'; $|=1; print \"ready\\n\"; sleep 300",
    ]);
    assert_eq!(c.line(), "ready");
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let policy = Policy {
        grace_ms: 300,
        ..Policy::default()
    };
    let p = direct(&snap, c.r, false, &policy);
    let sig = GuardedSignaler::allowing(c.all_pids());
    let t0 = Instant::now();
    let run = exec_live(&snap, &p, &sig);
    let elapsed = t0.elapsed().as_millis();
    let o = &run.outcomes[0];
    assert_eq!(o.final_state, FinalState::Exited, "{}", o.note_ko);
    assert_eq!(
        steps_of(o),
        vec![(Step::Term, c.pid(), true), (Step::Kill, c.pid(), true)]
    );
    assert!((300..3000).contains(&elapsed), "경과 {elapsed}ms");
    assert!(o.note_ko.contains("KILL"));
}

#[test]
fn act7_3_stopped_child_gets_cont_then_term() {
    let c = OwnedChild::spawn(&["/bin/sleep", "300"]);
    // SAFETY: 방금 띄운 자기 자식에게만 보낸다.
    assert_eq!(unsafe { libc::kill(c.pid(), libc::SIGSTOP) }, 0);
    let mut status = 0;
    // SAFETY: 자기 자식의 정지 이벤트를 기다린다(회수하지 않음).
    let w = unsafe { libc::waitpid(c.pid(), &mut status, libc::WUNTRACED) };
    assert_eq!(w, c.pid());
    assert!(libc::WIFSTOPPED(status));
    assert!(RealProber.probe(c.pid()).stopped);

    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let p = direct(&snap, c.r, false, &Policy::default());
    assert_eq!(p.items[0].steps, vec![Step::Cont, Step::Term, Step::Kill]);
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    let o = &run.outcomes[0];
    assert_eq!(o.final_state, FinalState::Exited, "{}", o.note_ko);
    assert_eq!(
        steps_of(o),
        vec![(Step::Cont, c.pid(), true), (Step::Term, c.pid(), true)]
    );
}

#[test]
fn act7_4_parent_with_two_children_terminated_bottom_up() {
    let mut c = OwnedChild::spawn(&["/bin/sh", "-c", "sleep 300 & sleep 300 & echo ready; wait"]);
    assert_eq!(c.line(), "ready");
    let kids = c.record_descendants();
    assert_eq!(kids.len(), 2, "{kids:?}");
    let mut procs = vec![c.proc_of(c.r, c.argv.clone())];
    procs.extend(
        kids.iter()
            .map(|k| c.proc_of(*k, vec!["sleep".into(), "300".into()])),
    );
    let snap = self_snapshot(procs);
    let p = direct(&snap, c.r, true, &Policy::default());
    assert_eq!(p.items[0].descendant_count, 2);
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    let o = &run.outcomes[0];
    assert_eq!(o.final_state, FinalState::Exited, "{}", o.note_ko);
    assert!(o.note_ko.contains("자손 2/2개"), "{}", o.note_ko);

    let mut kid_pids: Vec<i32> = kids.iter().map(|k| k.pid).collect();
    kid_pids.sort_unstable();
    let terms: Vec<i32> = run
        .audit
        .iter()
        .filter(|e| e.event == AuditEvent::Term)
        .map(|e| e.subject_pid)
        .collect();
    assert_eq!(terms[..2], kid_pids[..], "자손 먼저: {terms:?}");
    assert!(terms.len() == 2 || terms[2] == c.pid(), "{terms:?}");
    for r in kids.iter().chain([&c.r]) {
        assert!(is_gone(*r), "{r:?} 남음");
    }
}

#[test]
fn act7_6_already_exited_child_is_vanished_without_signal() {
    let mut c = OwnedChild::spawn(&["/bin/sleep", "300"]);
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    c.kill_and_reap();
    let p = direct(&snap, c.r, false, &Policy::default());
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    assert_eq!(run.outcomes[0].final_state, FinalState::Vanished);
    assert!(sig.sent.borrow().is_empty());
    assert!(!run.audit.iter().any(|e| e.event == AuditEvent::Term));
}

#[test]
fn act7_8_demote_sets_darwin_bg() {
    let c = OwnedChild::spawn(&["/bin/sleep", "300"]);
    let before = task_priority(c.pid()).expect("task 우선순위");
    assert!(before > 4, "시작 우선순위 {before}");
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let rep = report(
        Vec::new(),
        vec![finding(
            "demote",
            Confidence::Confirmed,
            vec![c.r],
            Suggestion::Demote,
        )],
    );
    let sel = Selection {
        finding_ids: vec!["demote".into()],
        ..Selection::default()
    };
    let policy = Policy {
        allow_demote: true,
        ..Policy::default()
    };
    let p = plan_idle(&snap, &rep, &sel, &policy);
    assert_eq!(p.items[0].steps, vec![Step::Demote]);
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    let o = &run.outcomes[0];
    assert_eq!(
        steps_of(o),
        vec![(Step::Demote, c.pid(), true)],
        "{}",
        o.note_ko
    );
    assert_eq!(o.final_state, FinalState::StillAlive);
    // getpriority(PRIO_DARWIN_PROCESS, <남의 pid>)는 대상이 아니라 호출자 쪽 상태를 돌려준다(2026-10-13 실측:
    // setpriority 성공 뒤에도 0). 그래서 대상 task의 실제 우선순위로 확인한다: DARWIN_BG = 4(MAXPRI_THROTTLE).
    assert_eq!(task_priority(c.pid()), Some(4));
    assert!(sig.sent.borrow().is_empty());
}

#[test]
fn act7_9_port0_listener_child_releases_port() {
    let c = OwnedChild::spawn(&[
        "/usr/bin/perl",
        "-MIO::Socket::INET",
        "-e",
        "$|=1; my $s=IO::Socket::INET->new(LocalAddr=>'127.0.0.1',LocalPort=>0,Listen=>1) or die; print $s->sockport,\"\\n\"; sleep 300",
    ]);
    let port: u16 = c.line().trim().parse().expect("포트 번호");
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_err(),
        "자식이 포트를 잡고 있어야 함"
    );
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let p = direct(&snap, c.r, false, &Policy::default());
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    assert_eq!(run.outcomes[0].final_state, FinalState::Exited);
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_ok(),
        "포트 {port} 해제"
    );
}

#[test]
fn act7_10_audit_and_revive_only_in_state_dir_with_0600() {
    let c = OwnedChild::spawn(&["/bin/sleep", "300"]);
    let mut proc = c.proc_of(c.r, vec!["/bin/sleep".into(), "300".into()]);
    proc.env.insert(ENV_ALLOWLIST[1].to_string(), "4242".into());
    proc.env.insert("VH_TEST_NOT_ALLOWED".into(), "x".into());
    let snap = self_snapshot(vec![proc]);
    let p = direct(&snap, c.r, false, &Policy::default());
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &p, &sig);
    assert_eq!(run.outcomes[0].final_state, FinalState::Exited);
    let dir = run.dir.path();

    let mut top: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, vec!["audit.jsonl", "revive"]);

    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&audit_log_path(dir)), 0o600);
    assert_eq!(mode(&revive_dir(dir)), 0o700);

    let name = format!("{}-{}.json", c.r.pid, c.r.start_time_unix_ms);
    let files: Vec<String> = fs::read_dir(revive_dir(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files, vec![name.clone()]);
    let rpath = revive_dir(dir).join(&name);
    assert_eq!(mode(&rpath), 0o600);
    let rec: ReviveRecord = serde_json::from_str(&fs::read_to_string(&rpath).unwrap()).unwrap();
    assert_eq!(rec.target, c.r);
    assert_eq!(rec.argv, vec!["/bin/sleep", "300"]);
    assert_eq!(rec.exe.as_deref(), Some("/bin/sleep"));
    assert_eq!(rec.env.keys().collect::<Vec<_>>(), vec![ENV_ALLOWLIST[1]]);

    let order = [
        AuditEvent::ExecStart,
        AuditEvent::ReviveSaved,
        AuditEvent::Term,
        AuditEvent::Exited,
        AuditEvent::ExecEnd,
    ];
    let events: Vec<AuditEvent> = run
        .audit
        .iter()
        .map(|e| e.event)
        .filter(|e| order.contains(e))
        .collect();
    assert_eq!(events, order);
    assert!(
        run.audit
            .iter()
            .all(|e| e.target == c.r && e.run_id == "live")
    );
}

#[test]
fn act7_11_w2_busy_child_demote_then_undemote_restores_priority() {
    let c = OwnedChild::spawn(&["/bin/sh", "-c", "while :; do :; done"]);
    let p0 = task_priority(c.pid()).expect("자식 task 우선순위");
    let snap = self_snapshot(vec![c.proc_of(c.r, c.argv.clone())]);
    let policy = Policy::default();
    let demote = plan_priority(
        &snap,
        None,
        &[PriorityTarget {
            target: c.r,
            step: Step::Demote,
            reason_ko: "테스트".into(),
        }],
        &policy,
    );
    assert_eq!(demote.items.len(), 1, "{:?}", demote.refused);
    let sig = GuardedSignaler::allowing(c.all_pids());
    let run = exec_live(&snap, &demote, &sig);
    assert_eq!(
        steps_of(&run.outcomes[0]),
        vec![(Step::Demote, c.pid(), true)]
    );
    let p_bg = task_priority(c.pid()).unwrap();
    assert!(p_bg < p0, "demote: {p0} → {p_bg}");

    let undemote = plan_priority(
        &snap,
        None,
        &[PriorityTarget {
            target: c.r,
            step: Step::Undemote,
            reason_ko: "테스트".into(),
        }],
        &policy,
    );
    let run2 = exec_live(&snap, &undemote, &sig);
    assert_eq!(
        steps_of(&run2.outcomes[0]),
        vec![(Step::Undemote, c.pid(), true)]
    );
    assert_eq!(run2.outcomes[0].final_state, FinalState::StillAlive);
    let p_back = task_priority(c.pid()).unwrap();
    assert_eq!(p_back, p0, "undemote 뒤 원래 값");
    eprintln!(
        "act7_11 live: pid {} pti_priority {p0} → {p_bg} → {p_back}",
        c.pid()
    );
    assert_eq!(*sig.undemoted.borrow(), vec![c.pid()]);
    assert!(
        run2.audit
            .iter()
            .any(|a| a.event == AuditEvent::Undemote && a.ok)
    );
    assert!(!is_gone(c.r), "자식은 살아 있고 Drop이 회수한다");
    drop(run);
}
