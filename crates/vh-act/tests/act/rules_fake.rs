//! 가짜 prober·signaler 테스트: 보호 규칙 R01~R15, 계획(ACT_1), Reused(⑤), fork(T12), 시간 상한.
//! 커널 호출 0회. 실제 pid 1·남의 pid에 진짜 신호가 나갈 길이 없다.

use vh_act::rule::*;
use vh_act::*;
use vh_model::*;

use crate::common::*;

const DEMO: &str = "/Users/demo/dev/shop/node_modules/.bin/vite";

struct Fx {
    snap: Snapshot,
    rep: Report,
}

impl Fx {
    fn new(procs: Vec<Proc>) -> Fx {
        Fx {
            snap: snapshot(SELF_PID, SELF_UID, procs),
            rep: report(Vec::new(), Vec::new()),
        }
    }

    fn plan_direct(&self, targets: &[ProcRef], tree: bool) -> ActionPlan {
        let sel = Selection {
            direct: targets
                .iter()
                .map(|t| DirectTarget {
                    target: *t,
                    include_descendants: tree,
                })
                .collect(),
            ..Selection::default()
        };
        plan(&self.snap, &self.rep, &sel, &Policy::default())
    }
}

struct FakeRun {
    outcomes: Vec<ActionOutcome>,
    sig: FakeSignaler,
    audit: Vec<AuditEntry>,
}

fn run_fake(fx: &Fx, plan: &ActionPlan, world: FakeWorld, ancestors: Vec<i32>) -> FakeRun {
    let world = world.shared();
    let mut prober = FakeProber::with_world(world.clone(), SELF_PID, SELF_UID);
    prober.ancestors = ancestors;
    prober.clock_ms.set(10_000_000);
    let sig = FakeSignaler::with_world(world);
    let dir = tempfile::tempdir().unwrap();
    let env = ExecEnv {
        signaler: &sig,
        prober: &prober,
        state_dir: dir.path().to_path_buf(),
        snapshot: &fx.snap,
        run_id: "t".into(),
    };
    let outcomes = execute(plan, &env);
    let audit = read_audit(dir.path());
    FakeRun {
        outcomes,
        sig,
        audit,
    }
}

fn refused_rule(p: &ActionPlan, t: ProcRef) -> Option<String> {
    p.refused
        .iter()
        .find(|r| r.target == t)
        .map(|r| r.rule.clone())
}

fn assert_plan_refuses(procs: Vec<Proc>, t: ProcRef, rule: &str) {
    let fx = Fx::new(procs);
    let p = fx.plan_direct(&[t], false);
    assert!(p.items.is_empty(), "{rule}: items={:?}", p.items);
    assert_eq!(refused_rule(&p, t).as_deref(), Some(rule));
    let w = world_from(&fx.snap);
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.sig.calls(), 0, "{rule}: 신호 0회");
    assert!(r.audit.iter().any(|e| e.event == AuditEvent::PlanRefused));
}

fn user(pid: i32, ppid: i32, start: u64) -> Proc {
    proc_(pid, ppid, SELF_UID, start, Some(DEMO))
}

#[test]
fn r01_pid_le_1() {
    assert_plan_refuses(
        vec![proc_(1, 0, SELF_UID, 1, Some(DEMO))],
        pref(1, 1),
        R01_PID_LE_1,
    );
    assert_plan_refuses(
        vec![proc_(0, 0, SELF_UID, 1, Some(DEMO))],
        pref(0, 1),
        R01_PID_LE_1,
    );
}

#[test]
fn r02_self() {
    assert_plan_refuses(vec![user(SELF_PID, 400, 5)], pref(SELF_PID, 5), R02_SELF);
}

#[test]
fn r03_self_ancestor_from_snapshot_chain() {
    let procs = vec![user(300, 1, 1), user(400, 300, 2), user(SELF_PID, 400, 3)];
    assert_plan_refuses(procs.clone(), pref(400, 2), R03_SELF_ANCESTOR);
    assert_plan_refuses(procs, pref(300, 1), R03_SELF_ANCESTOR);
}

#[test]
fn r03_self_ancestor_at_signal_time() {
    let fx = Fx::new(vec![user(2000, 1, 7)]);
    let p = fx.plan_direct(&[pref(2000, 7)], false);
    assert_eq!(p.items.len(), 1);
    let r = run_fake(&fx, &p, world_from(&fx.snap), vec![2000, 1]);
    assert_eq!(r.outcomes[0].final_state, FinalState::Refused);
    assert!(r.outcomes[0].note_ko.starts_with(R03_SELF_ANCESTOR));
    assert_eq!(r.sig.calls(), 0);
}

#[test]
fn r04_other_uid() {
    assert_plan_refuses(
        vec![proc_(2000, 1, 0, 7, Some(DEMO))],
        pref(2000, 7),
        R04_OTHER_UID,
    );
}

#[test]
fn r04_uid_changed_at_signal_time() {
    let fx = Fx::new(vec![user(2000, 1, 7)]);
    let p = fx.plan_direct(&[pref(2000, 7)], false);
    let mut w = world_from(&fx.snap);
    w.procs.get_mut(&2000).unwrap().uid = 0;
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Refused);
    assert!(r.outcomes[0].note_ko.starts_with(R04_OTHER_UID));
    assert_eq!(r.sig.calls(), 0);
}

#[test]
fn r05_system_paths() {
    for exe in [
        "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        "/usr/libexec/demo",
        "/usr/sbin/demo",
        "/sbin/demo",
        "/Library/Apple/System/demo",
    ] {
        assert_plan_refuses(
            vec![proc_(2000, 1, SELF_UID, 7, Some(exe))],
            pref(2000, 7),
            R05_SYSTEM_PATH,
        );
    }
}

#[test]
fn r06_xpc_and_appex() {
    for exe in [
        "/Applications/Demo.app/Contents/XPCServices/H.xpc/Contents/MacOS/H",
        "/Users/demo/Applications/Demo.app/Contents/PlugIns/W.appex/Contents/MacOS/W",
    ] {
        assert_plan_refuses(
            vec![proc_(2000, 1, SELF_UID, 7, Some(exe))],
            pref(2000, 7),
            R06_XPC_APPEX,
        );
    }
}

#[test]
fn r07_app_bundle() {
    for exe in [
        "/Applications/Demo.app/Contents/MacOS/Demo",
        "/Applications/Demo.app/Contents/Frameworks/Demo Helper.app/Contents/MacOS/Demo Helper",
        "/Library/Application Support/Demo/Demo.app/Contents/MacOS/Demo",
        "/Users/demo/Applications/Demo.app/Contents/MacOS/Demo",
        "/Applications/Demo.app/Contents/Resources/Python.app/Contents/MacOS/Python",
    ] {
        assert_plan_refuses(
            vec![proc_(2000, 1, SELF_UID, 7, Some(exe))],
            pref(2000, 7),
            R07_APP_BUNDLE,
        );
    }
}

#[test]
fn r05_r07_path_at_signal_time_uses_live_exe() {
    let fx = Fx::new(vec![user(2000, 1, 7)]);
    let p = fx.plan_direct(&[pref(2000, 7)], false);
    let mut w = world_from(&fx.snap);
    w.procs.get_mut(&2000).unwrap().exe = Some("/Applications/Demo.app/Contents/MacOS/Demo".into());
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Refused);
    assert!(r.outcomes[0].note_ko.starts_with(R07_APP_BUNDLE));
    assert_eq!(r.sig.calls(), 0);
}

#[test]
fn path_exceptions_are_actionable() {
    for exe in [
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
        "/Applications/Python 3.12/Python.app/Contents/MacOS/Python",
        "/opt/homebrew/Cellar/python@3.13/3.13.1/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python",
        "/Users/demo/Library/Caches/ms-playwright/chromium-1/chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        "/bin/sleep",
        "/usr/bin/perl",
    ] {
        let fx = Fx::new(vec![proc_(2000, 1, SELF_UID, 7, Some(exe))]);
        let p = fx.plan_direct(&[pref(2000, 7)], false);
        assert!(p.refused.is_empty(), "{exe}: {:?}", p.refused);
        assert_eq!(p.items.len(), 1, "{exe}");
    }
}

fn plan_with_kind(kind: Kind) -> ActionPlan {
    let t = pref(2000, 7);
    let mut fx = Fx::new(vec![user(2000, 1, 7)]);
    fx.rep = report(vec![classified(t, kind)], Vec::new());
    fx.plan_direct(&[t], false)
}

#[test]
fn r08_protected_kinds() {
    for kind in [
        Kind::AgentCli,
        Kind::GuiApp,
        Kind::VirtualMachine,
        Kind::Database,
    ] {
        let p = plan_with_kind(kind);
        assert!(p.items.is_empty(), "{kind:?}");
        assert_eq!(
            refused_rule(&p, pref(2000, 7)).as_deref(),
            Some(R08_KIND_PROTECTED)
        );
    }
}

#[test]
fn r08_agent_helper_is_not_protected() {
    let p = plan_with_kind(Kind::AgentHelper);
    assert_eq!(p.items.len(), 1);
    assert!(p.refused.is_empty());
}

#[test]
fn r09_protected_kind_in_subtree_refuses_even_without_descendants() {
    let shell = pref(2000, 7);
    let agent = pref(2001, 8);
    for kind in [
        Kind::AgentCli,
        Kind::GuiApp,
        Kind::VirtualMachine,
        Kind::Database,
    ] {
        let mut fx = Fx::new(vec![user(2000, 1, 7), user(2001, 2000, 8)]);
        fx.rep = report(vec![classified(agent, kind)], Vec::new());
        for tree in [false, true] {
            let p = fx.plan_direct(&[shell], tree);
            assert!(p.items.is_empty());
            assert_eq!(
                refused_rule(&p, shell).as_deref(),
                Some(R09_PROTECTED_IN_SUBTREE)
            );
        }
    }
}

#[test]
fn r10_zombie() {
    let mut z = user(2000, 1, 7);
    z.status = ProcStatus::Zombie;
    assert_plan_refuses(vec![z], pref(2000, 7), R10_ZOMBIE);
}

fn sugg_fx() -> Fx {
    let mut fx = Fx::new((0..7).map(|i| user(2000 + i, 1, 10 + i as u64)).collect());
    let t = |i: i32| vec![pref(2000 + i, 10 + i as u64)];
    fx.rep = report(
        Vec::new(),
        vec![
            finding(
                "term",
                Confidence::Confirmed,
                t(0),
                Suggestion::Terminate {
                    include_descendants: true,
                },
            ),
            finding("demote", Confidence::Confirmed, t(1), Suggestion::Demote),
            finding("resume", Confidence::Confirmed, t(2), Suggestion::Resume),
            finding(
                "handoff",
                Confidence::Confirmed,
                t(3),
                Suggestion::HandoffThenRestart,
            ),
            finding("review", Confidence::Possible, t(4), Suggestion::Review),
            finding(
                "parent",
                Confidence::Confirmed,
                t(5),
                Suggestion::RestartParent { parent: pref(1, 0) },
            ),
            finding("none", Confidence::Confirmed, t(6), Suggestion::None),
        ],
    );
    fx
}

fn ids(p: &ActionPlan) -> Vec<&str> {
    p.items.iter().map(|i| i.finding_id.as_str()).collect()
}

#[test]
fn act1_full_selection_skips_non_actionable_silently() {
    let fx = sugg_fx();
    let sel = Selection {
        min_confidence: Confidence::Possible,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &Policy::default());
    assert_eq!(ids(&p), vec!["term", "resume"]);
    assert!(p.refused.is_empty(), "{:?}", p.refused);
    assert_eq!(p.items[0].steps, vec![Step::Term, Step::Kill]);
    assert!(p.items[0].include_descendants);
    assert_eq!(p.items[1].steps, vec![Step::Cont]);
    assert_eq!(p.total_deadline_ms, 60_000);
}

#[test]
fn r11_explicit_finding_ids_refuse_non_actionable() {
    let fx = sugg_fx();
    let sel = Selection {
        finding_ids: vec![
            "handoff".into(),
            "review".into(),
            "parent".into(),
            "none".into(),
        ],
        min_confidence: Confidence::Possible,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &Policy::default());
    assert!(p.items.is_empty());
    assert_eq!(p.refused.len(), 4);
    assert!(
        p.refused
            .iter()
            .all(|r| r.rule == R11_SUGGESTION_NOT_ACTIONABLE)
    );
}

#[test]
fn r11_pointed_review_becomes_terminate() {
    let fx = sugg_fx();
    let sel = Selection {
        pids: vec![2004],
        min_confidence: Confidence::Possible,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &Policy::default());
    assert_eq!(ids(&p), vec!["review"]);
    assert_eq!(p.items[0].steps, vec![Step::Term, Step::Kill]);
    assert!(!p.items[0].include_descendants);

    let tree = Policy {
        include_descendants: Some(true),
        ..Policy::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &tree);
    assert!(p.items[0].include_descendants);

    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Exited);
    assert_eq!(*r.sig.sent.borrow(), vec![(2004, libc::SIGTERM)]);
}

#[test]
fn r11_pointed_handoff_restartparent_none_still_refused() {
    let fx = sugg_fx();
    let sel = Selection {
        pids: vec![2003, 2005, 2006],
        min_confidence: Confidence::Possible,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &Policy::default());
    assert!(p.items.is_empty());
    for pid in [2003, 2005, 2006] {
        let r = p.refused.iter().find(|r| r.target.pid == pid).unwrap();
        assert_eq!(r.rule, R11_SUGGESTION_NOT_ACTIONABLE);
    }
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    assert_eq!(r.sig.calls(), 0);
}

#[test]
fn r12_demote_needs_flag() {
    let fx = sugg_fx();
    let explicit = Selection {
        finding_ids: vec!["demote".into()],
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &explicit, &Policy::default());
    assert!(p.items.is_empty());
    assert_eq!(
        refused_rule(&p, pref(2001, 11)).as_deref(),
        Some(R12_DEMOTE_DISABLED)
    );

    let allow = Policy {
        allow_demote: true,
        ..Policy::default()
    };
    let p = plan(&fx.snap, &fx.rep, &explicit, &allow);
    assert_eq!(p.items[0].steps, vec![Step::Demote]);
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    assert_eq!(*r.sig.demoted.borrow(), vec![2001]);
    assert!(r.sig.sent.borrow().is_empty());
    assert_eq!(r.outcomes[0].final_state, FinalState::StillAlive);
}

#[test]
fn r13_below_confidence_excluded_silently() {
    let fx = sugg_fx();
    let sel = Selection {
        pids: vec![2004],
        min_confidence: Confidence::Likely,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &Policy::default());
    assert!(p.items.is_empty());
    assert!(p.refused.is_empty());
    let confirmed = Selection {
        min_confidence: Confidence::Confirmed,
        ..Selection::default()
    };
    let p = plan(&fx.snap, &fx.rep, &confirmed, &Policy::default());
    assert_eq!(ids(&p), vec!["term", "resume"]);
    let _ = R13_BELOW_CONFIDENCE;
}

#[test]
fn act1_only_pid_and_no_descendants_override() {
    let fx = sugg_fx();
    let sel = Selection {
        pids: vec![2000],
        ..Selection::default()
    };
    let no_desc = Policy {
        include_descendants: Some(false),
        grace_ms: 1234,
        total_deadline_ms: 9_000,
        ..Policy::default()
    };
    let p = plan(&fx.snap, &fx.rep, &sel, &no_desc);
    assert_eq!(ids(&p), vec!["term"]);
    assert!(!p.items[0].include_descendants);
    assert_eq!(p.items[0].grace_ms, 1234);
    assert_eq!(p.total_deadline_ms, 9_000);
}

#[test]
fn act1_descendant_count_reclaim_overlap_and_max_actions() {
    let mut procs = vec![user(2000, 1, 7), user(2001, 2000, 8), user(2002, 2001, 9)];
    procs.push(user(3000, 1, 7));
    let mut fx = Fx::new(procs);
    fx.rep = report(
        Vec::new(),
        vec![
            finding(
                "parent",
                Confidence::Confirmed,
                vec![pref(2000, 7)],
                Suggestion::Terminate {
                    include_descendants: true,
                },
            ),
            finding(
                "child",
                Confidence::Confirmed,
                vec![pref(2001, 8)],
                Suggestion::Terminate {
                    include_descendants: false,
                },
            ),
            finding(
                "other",
                Confidence::Confirmed,
                vec![pref(3000, 7)],
                Suggestion::Terminate {
                    include_descendants: false,
                },
            ),
        ],
    );
    let p = plan(&fx.snap, &fx.rep, &Selection::default(), &Policy::default());
    assert_eq!(ids(&p), vec!["parent", "other"]);
    assert_eq!(p.items[0].descendant_count, 2);
    assert_eq!(p.items[0].est_reclaim_bytes, 3_000_000);
    assert_eq!(p.items[1].descendant_count, 0);

    let one = Policy {
        max_actions: 1,
        ..Policy::default()
    };
    let p = plan(&fx.snap, &fx.rep, &Selection::default(), &one);
    assert_eq!(ids(&p), vec!["parent"]);
    assert_eq!(
        refused_rule(&p, pref(3000, 7)).as_deref(),
        Some(R16_MAX_ACTIONS)
    );
}

#[test]
fn r09_grandchild_database_refuses_and_agent_helper_does_not() {
    let procs = vec![user(2000, 1, 7), user(2001, 2000, 8), user(2002, 2001, 9)];
    let mut fx = Fx::new(procs);
    fx.rep = report(vec![classified(pref(2002, 9), Kind::Database)], Vec::new());
    let p = fx.plan_direct(&[pref(2000, 7)], true);
    assert!(p.items.is_empty());
    assert_eq!(
        refused_rule(&p, pref(2000, 7)).as_deref(),
        Some(R09_PROTECTED_IN_SUBTREE)
    );
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    assert_eq!(r.sig.calls(), 0);

    fx.rep = report(
        vec![classified(pref(2002, 9), Kind::AgentHelper)],
        Vec::new(),
    );
    let p = fx.plan_direct(&[pref(2000, 7)], true);
    assert_eq!(p.items.len(), 1);
    assert!(p.refused.is_empty());
}

#[test]
fn r16_items_over_max_actions_are_refused_not_dropped() {
    let mut fx = Fx::new((0..5).map(|i| user(2000 + i, 1, 10 + i as u64)).collect());
    fx.rep = report(
        Vec::new(),
        (0..5)
            .map(|i| {
                finding(
                    &format!("f{i}"),
                    Confidence::Confirmed,
                    vec![pref(2000 + i, 10 + i as u64)],
                    Suggestion::Terminate {
                        include_descendants: false,
                    },
                )
            })
            .collect(),
    );
    let policy = Policy {
        max_actions: 3,
        ..Policy::default()
    };
    let p = plan(&fx.snap, &fx.rep, &Selection::default(), &policy);
    assert_eq!(ids(&p), vec!["f0", "f1", "f2"]);
    let cut: Vec<(i32, &str, &str)> = p
        .refused
        .iter()
        .map(|r| (r.target.pid, r.rule.as_str(), r.reason_ko.as_str()))
        .collect();
    let reason = "한 번에 정리할 수 있는 개수(3)를 넘었어요";
    assert_eq!(
        cut,
        vec![
            (2003, R16_MAX_ACTIONS, reason),
            (2004, R16_MAX_ACTIONS, reason)
        ]
    );
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    let sent: Vec<i32> = r.sig.sent.borrow().iter().map(|(p, _)| *p).collect();
    assert_eq!(sent, vec![2000, 2001, 2002]);
}

#[test]
fn r14_plan_refuses_target_missing_from_snapshot() {
    let fx = Fx::new(vec![user(2000, 1, 7)]);
    let p = fx.plan_direct(&[pref(2000, 6), pref(2999, 1)], false);
    assert!(p.items.is_empty());
    assert_eq!(
        refused_rule(&p, pref(2000, 6)).as_deref(),
        Some(R14_START_TIME_MISMATCH)
    );
    assert_eq!(
        refused_rule(&p, pref(2999, 1)).as_deref(),
        Some(R14_START_TIME_MISMATCH)
    );
}

#[test]
fn act7_5_r14_start_time_changed_means_reused_and_no_signal() {
    let fx = Fx::new(vec![user(4242, 1, 999)]);
    let p = fx.plan_direct(&[pref(4242, 999)], true);
    assert_eq!(p.items.len(), 1);
    let mut w = FakeWorld::default();
    w.insert(LiveProc::alive(4242, 1000, 1, SELF_UID, Some(DEMO)));
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Reused);
    assert_eq!(r.sig.calls(), 0);
    assert_eq!(
        r.audit
            .iter()
            .filter(|e| e.event == AuditEvent::Reused)
            .count(),
        1
    );
}

#[test]
fn act7_6_fake_vanished_and_zombie_at_signal_time() {
    let fx = Fx::new(vec![user(2000, 1, 7), user(2001, 1, 8)]);
    let p = fx.plan_direct(&[pref(2000, 7), pref(2001, 8)], false);
    let mut w = FakeWorld::default();
    let mut z = LiveProc::alive(2001, 8, 1, SELF_UID, None);
    z.liveness = Liveness::Zombie;
    w.insert(z);
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Vanished);
    assert_eq!(r.outcomes[1].final_state, FinalState::Vanished);
    assert_eq!(r.sig.calls(), 0);
}

#[test]
fn r15_runtime_children_need_guard_and_later_start() {
    let fx = Fx::new(vec![user(2000, 1, 100)]);
    let p = fx.plan_direct(&[pref(2000, 100)], true);
    let mut w = world_from(&fx.snap);
    w.insert(LiveProc::alive(2001, 50, 2000, SELF_UID, Some(DEMO)));
    w.insert(LiveProc::alive(2002, 150, 2000, 0, Some(DEMO)));
    w.insert(LiveProc::alive(
        2003,
        150,
        2000,
        SELF_UID,
        Some("/usr/libexec/demo"),
    ));
    w.insert(LiveProc::alive(2004, 150, 2000, SELF_UID, Some(DEMO)));
    let r = run_fake(&fx, &p, w, Vec::new());
    let sent: Vec<i32> = r.sig.sent.borrow().iter().map(|(p, _)| *p).collect();
    assert_eq!(sent, vec![2004, 2000]);
    let skipped: Vec<i32> = r
        .audit
        .iter()
        .filter(|e| {
            e.event == AuditEvent::Skipped && e.reason_ko.starts_with(R15_RUNTIME_CHILD_GUARD)
        })
        .map(|e| e.subject_pid)
        .collect();
    assert_eq!(skipped, vec![2001, 2002, 2003]);
    assert_eq!(r.outcomes[0].final_state, FinalState::Exited);
}

#[test]
fn t12_fork_during_ladder_new_child_gets_term_then_kill() {
    let fx = Fx::new(vec![user(2000, 1, 100)]);
    let p = plan(
        &fx.snap,
        &fx.rep,
        &Selection {
            direct: vec![DirectTarget {
                target: pref(2000, 100),
                include_descendants: true,
            }],
            ..Selection::default()
        },
        &Policy {
            grace_ms: 300,
            ..Policy::default()
        },
    );
    let mut w = world_from(&fx.snap);
    w.ignore_term.extend([2000, 2005]);
    w.spawn_on_term.insert(
        2000,
        vec![LiveProc::alive(2005, 200, 2000, SELF_UID, Some(DEMO))],
    );
    let r = run_fake(&fx, &p, w, Vec::new());
    let sent = r.sig.sent.borrow().clone();
    assert_eq!(
        sent,
        vec![
            (2000, libc::SIGTERM),
            (2005, libc::SIGTERM),
            (2005, libc::SIGKILL),
            (2000, libc::SIGKILL),
        ]
    );
    assert_eq!(r.outcomes[0].final_state, FinalState::Exited);
    assert!(r.outcomes[0].note_ko.contains("KILL"));
    assert!(r.outcomes[0].note_ko.contains("자손 1/1개"));
}

#[test]
fn total_deadline_skips_remaining_items() {
    let fx = Fx::new(vec![user(2000, 1, 7), user(2001, 1, 8)]);
    let p = plan(
        &fx.snap,
        &fx.rep,
        &Selection {
            direct: vec![
                DirectTarget {
                    target: pref(2000, 7),
                    include_descendants: false,
                },
                DirectTarget {
                    target: pref(2001, 8),
                    include_descendants: false,
                },
            ],
            ..Selection::default()
        },
        &Policy {
            total_deadline_ms: 200,
            ..Policy::default()
        },
    );
    let mut w = world_from(&fx.snap);
    w.ignore_term.insert(2000);
    let r = run_fake(&fx, &p, w, Vec::new());
    assert_eq!(r.outcomes[0].final_state, FinalState::Exited);
    assert!(r.outcomes[0].note_ko.contains("KILL"));
    assert_eq!(r.outcomes[1].final_state, FinalState::Skipped);
    assert!(!r.sig.sent.borrow().iter().any(|(p, _)| *p == 2001));
}

#[test]
fn stopped_target_gets_cont_before_term() {
    let mut stopped = user(2000, 1, 7);
    stopped.status = ProcStatus::Stopped;
    let fx = Fx::new(vec![stopped]);
    let p = fx.plan_direct(&[pref(2000, 7)], false);
    assert_eq!(p.items[0].steps, vec![Step::Cont, Step::Term, Step::Kill]);
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    assert_eq!(
        *r.sig.sent.borrow(),
        vec![(2000, libc::SIGCONT), (2000, libc::SIGTERM)]
    );
}

#[test]
fn fake_audit_log_lines_parse_and_follow_order() {
    let fx = Fx::new(vec![user(2000, 1, 7), proc_(2001, 1, 0, 8, Some(DEMO))]);
    let p = fx.plan_direct(&[pref(2000, 7), pref(2001, 8)], false);
    let r = run_fake(&fx, &p, world_from(&fx.snap), Vec::new());
    let events: Vec<AuditEvent> = r.audit.iter().map(|e| e.event).collect();
    assert_eq!(
        events,
        vec![
            AuditEvent::PlanRefused,
            AuditEvent::PlanItem,
            AuditEvent::ExecStart,
            AuditEvent::Precheck,
            AuditEvent::ReviveSaved,
            AuditEvent::Term,
            AuditEvent::Exited,
            AuditEvent::ExecEnd,
        ]
    );
    assert!(r.audit.iter().all(|e| e.run_id == "t"));
    assert_eq!(r.audit[0].reason_ko.split(':').next(), Some(R04_OTHER_UID));
}
