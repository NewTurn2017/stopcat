//! GUARD_1·GUARD_2 판정(순수). 가짜 스냅샷·리포트만 쓴다(신호 0).

use vh_guard::decide::{SkipReason, decide, decide_lean};
use vh_guard::fake::*;
use vh_guard::memory::{CpuStreak, GuardMemory};
use vh_guard::{AutoLevel, GuardPolicy};
use vh_model::*;

use crate::common::*;

fn mem(level: AutoLevel) -> GuardMemory {
    GuardMemory::new(level)
}

fn apply(m: &mut GuardMemory, d: &vh_guard::Decisions) {
    m.term_streak = d.next_term_streak.clone();
    m.cpu_streak = d.next_cpu_streak.clone();
}

fn run_scans(
    scene: &Scene,
    policy: &GuardPolicy,
    n: usize,
) -> (GuardMemory, Vec<vh_guard::Decisions>) {
    let mut m = mem(policy.level);
    let mut out = Vec::new();
    for i in 0..n {
        let now = T0 + i as u64 * 5000;
        let (s, r) = scene.build(now);
        let d = decide(&m, &s, &r, policy, now);
        apply(&mut m, &d);
        out.push(d);
    }
    (m, out)
}

#[test]
fn safe_confirmed_mcp_terminates_after_two_scans() {
    let mut sc = Scene::new();
    let t = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (_, ds) = run_scans(&sc, &safe(), 2);
    assert!(ds[0].terminate.is_empty());
    assert_eq!(ds[0].pending.len(), 1);
    assert_eq!(
        (ds[0].pending[0].seen_scans, ds[0].pending[0].needed_scans),
        (1, 2)
    );
    assert_eq!(ds[0].pending[0].step, Step::Term);
    assert_eq!(ds[0].pending[0].eta_ms, Some(5000));
    assert_eq!(ds[1].terminate.len(), 1);
    assert_eq!(ds[1].terminate[0].target, t);
    assert_eq!(ds[1].terminate[0].step, Step::Term);
    assert!(ds[1].pending.is_empty());
    assert!(!ds[1].trip_circuit);
}

#[test]
fn one_scan_is_not_enough() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::DevServer, Confidence::Confirmed, OLD, None);
    let (_, ds) = run_scans(&sc, &safe(), 1);
    assert!(ds[0].terminate.is_empty());
    assert!(
        ds[0]
            .skipped
            .iter()
            .any(|s| s.reason == SkipReason::NotPersisted)
    );
}

#[test]
fn too_young_is_skipped_with_eta_and_no_streak() {
    let mut sc = Scene::new();
    let young = T0 - 9 * 60_000;
    sc.leftover(101, Kind::McpServer, Confidence::Confirmed, young, None);
    let (m, ds) = run_scans(&sc, &safe(), 3);
    for d in &ds {
        assert!(d.terminate.is_empty());
        assert!(d.skipped.iter().any(|s| s.reason == SkipReason::TooYoung));
        assert_eq!(d.pending[0].seen_scans, 0);
    }
    assert_eq!(ds[0].pending[0].eta_ms, Some(60_000));
    assert!(m.term_streak.is_empty());
}

#[test]
fn owner_alive_never_terminates_in_any_level() {
    for policy in [safe(), aggressive()] {
        let mut sc = Scene::new();
        sc.leftover(101, Kind::McpServer, Confidence::Confirmed, OLD, Some(true));
        let (_, ds) = run_scans(&sc, &policy, 3);
        assert!(
            ds.iter().all(|d| d.terminate.is_empty()),
            "{:?}",
            policy.level
        );
        assert!(
            ds[2]
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::OwnerAlive)
        );
    }
}

#[test]
fn safe_emulator_is_notify_only() {
    let mut sc = Scene::new();
    let t = sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, None);
    let (_, ds) = run_scans(&sc, &safe(), 3);
    assert!(
        ds.iter()
            .all(|d| d.terminate.is_empty() && d.pending.is_empty())
    );
    let n = &ds[0].notify;
    assert_eq!(n.len(), 1);
    assert_eq!((n[0].target, n[0].reason), (t, SkipReason::KindNotifyOnly));
}

#[test]
fn protected_kinds_never_in_any_level_not_even_notify() {
    for kind in [
        Kind::AgentCli,
        Kind::GuiApp,
        Kind::VirtualMachine,
        Kind::Database,
    ] {
        for policy in [notify_only(), safe(), aggressive()] {
            let mut sc = Scene::new();
            sc.leftover(101, kind, Confidence::Confirmed, OLD, Some(false));
            let (_, ds) = run_scans(&sc, &policy, 3);
            for d in &ds {
                assert!(d.terminate.is_empty(), "{kind:?} {:?}", policy.level);
                assert!(d.pending.is_empty(), "{kind:?} {:?}", policy.level);
                assert!(
                    d.skipped
                        .iter()
                        .any(|s| s.reason == SkipReason::KindProtected),
                    "{kind:?} {:?}",
                    policy.level
                );
            }
            let notified_vm_db = ds[0]
                .notify
                .iter()
                .any(|n| n.reason == SkipReason::KindNotifyOnly);
            assert!(
                !notified_vm_db,
                "보호 Kind는 알림 목록 전에 걸러진다: {kind:?}"
            );
        }
    }
}

#[test]
fn likely_is_safe_skip_but_aggressive_candidate_and_possible_never() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::DevServer, Confidence::Likely, OLD, Some(false));
    let (_, ds) = run_scans(&sc, &safe(), 2);
    assert!(ds[1].terminate.is_empty());
    assert!(
        ds[1]
            .skipped
            .iter()
            .any(|s| s.reason == SkipReason::ConfidenceBelow)
    );
    let (_, da) = run_scans(&sc, &aggressive(), 2);
    assert_eq!(da[1].terminate.len(), 1);

    let mut sp = Scene::new();
    sp.leftover(102, Kind::DevServer, Confidence::Possible, OLD, Some(false));
    for policy in [safe(), aggressive()] {
        let (_, dp) = run_scans(&sp, &policy, 3);
        assert!(
            dp.iter().all(|d| d.terminate.is_empty()),
            "{:?}",
            policy.level
        );
    }
}

#[test]
fn aggressive_takes_emulator_and_sorts_largest_first_under_pressure_4() {
    let mut sc = Scene::new();
    let small = sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    let big = sc.leftover(102, Kind::DevServer, Confidence::Likely, OLD, Some(false));
    sc.findings[1].reclaim_bytes = 7 * 1024 * 1024 * 1024;
    let policy = aggressive();
    let mut m = mem(policy.level);
    for i in 0..2 {
        let now = T0 + i * 5000;
        let (s, r) = sc.build_pressure(now, 4);
        let d = decide(&m, &s, &r, &policy, now);
        apply(&mut m, &d);
        if i == 1 {
            let order: Vec<ProcRef> = d.terminate.iter().map(|c| c.target).collect();
            assert_eq!(order, vec![big, small]);
        }
    }
    let (s, r) = sc.build_pressure(T0 + 10_000, 1);
    let d = decide(&m, &s, &r, &policy, T0 + 10_000);
    let order: Vec<ProcRef> = d.terminate.iter().map(|c| c.target).collect();
    assert_eq!(order, vec![small, big], "압력 1이면 리포트 순서");
}

#[test]
fn notify_only_level_has_no_actions_only_notify_items() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let r = sc.plain(102, Kind::DevServer, OLD);
    let mut policy = notify_only();
    policy.runaway_sustained_scans = 1;
    let mut m = mem(policy.level);
    for i in 0..3u64 {
        let now = T0 + i * 5000;
        let (mut s, rep) = sc.build(now);
        s.processes
            .iter_mut()
            .find(|p| p.pid == r.pid)
            .unwrap()
            .cpu_pct = Some(250.0);
        let d = decide(&m, &s, &rep, &policy, now);
        apply(&mut m, &d);
        assert!(d.terminate.is_empty() && d.demote.is_empty() && d.pending.is_empty());
        assert_eq!(d.notify.len(), 1);
        assert_eq!(d.notify[0].reason, SkipReason::LevelNotifyOnly);
    }
}

#[test]
fn paused_memory_yields_nothing() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let mut m = mem(AutoLevel::Safe);
    m.paused = true;
    let (s, r) = sc.build(T0);
    let d = decide(&m, &s, &r, &safe(), T0);
    assert!(d.terminate.is_empty() && d.pending.is_empty() && d.notify.is_empty());
    assert!(d.next_term_streak.is_empty());
}

fn cpu_scene(kind: Kind) -> (Scene, ProcRef) {
    let mut sc = Scene::new();
    let r = sc.plain(201, kind, OLD);
    (sc, r)
}

fn decide_cpu(
    sc: &Scene,
    m: &mut GuardMemory,
    policy: &GuardPolicy,
    pid: i32,
    pct: Option<f32>,
    now: u64,
) -> vh_guard::Decisions {
    let (mut s, r) = sc.build(now);
    s.processes
        .iter_mut()
        .find(|p| p.pid == pid)
        .unwrap()
        .cpu_pct = pct;
    let d = decide(m, &s, &r, policy, now);
    apply(m, &d);
    d
}

#[test]
fn runaway_three_scans_then_demote_and_a_dip_resets() {
    let (sc, r) = cpu_scene(Kind::DevServer);
    let policy = safe();
    let mut m = mem(policy.level);
    let d1 = decide_cpu(&sc, &mut m, &policy, r.pid, Some(150.0), T0);
    assert!(d1.demote.is_empty());
    assert_eq!(
        (d1.pending[0].step, d1.pending[0].seen_scans),
        (Step::Demote, 1)
    );
    let d2 = decide_cpu(&sc, &mut m, &policy, r.pid, Some(120.0), T0 + 5000);
    assert_eq!(d2.pending[0].seen_scans, 2);
    let d3 = decide_cpu(&sc, &mut m, &policy, r.pid, Some(100.0), T0 + 10_000);
    assert_eq!(d3.demote.len(), 1);
    assert_eq!(d3.demote[0].target, r);
    assert_eq!(d3.demote[0].step, Step::Demote);
    assert_eq!(
        d3.demote[0].finding_id,
        format!("guard-runaway:{}:{}", r.pid, r.start_time_unix_ms)
    );

    let mut m2 = mem(policy.level);
    decide_cpu(&sc, &mut m2, &policy, r.pid, Some(150.0), T0);
    decide_cpu(&sc, &mut m2, &policy, r.pid, Some(50.0), T0 + 5000);
    assert!(m2.cpu_streak.is_empty());
    let d = decide_cpu(&sc, &mut m2, &policy, r.pid, Some(150.0), T0 + 10_000);
    assert_eq!(d.pending[0].seen_scans, 1);
    assert_eq!(
        m2.cpu_streak[&r],
        CpuStreak {
            seen: 1,
            last_pct: 150.0
        }
    );
}

#[test]
fn runaway_cpu_pct_none_first_scan_counts_nothing() {
    let (sc, r) = cpu_scene(Kind::DevServer);
    let mut m = mem(AutoLevel::Safe);
    let d = decide_cpu(&sc, &mut m, &safe(), r.pid, None, T0);
    assert!(d.pending.is_empty() && d.demote.is_empty());
}

#[test]
fn runaway_protected_notify_only_and_app_helper_never_demote() {
    for kind in [
        Kind::AgentCli,
        Kind::GuiApp,
        Kind::VirtualMachine,
        Kind::Database,
        Kind::Emulator,
        Kind::LocalLlm,
        Kind::AppHelper,
    ] {
        let (sc, r) = cpu_scene(kind);
        let policy = safe();
        let mut m = mem(policy.level);
        let mut notified = 0;
        for i in 0..4u64 {
            let d = decide_cpu(&sc, &mut m, &policy, r.pid, Some(300.0), T0 + i * 5000);
            assert!(d.demote.is_empty(), "{kind:?}");
            assert!(d.pending.is_empty(), "{kind:?}");
            notified += d
                .notify
                .iter()
                .filter(|n| n.reason == SkipReason::RunawayNoDemote)
                .count();
        }
        assert_eq!(
            notified, 2,
            "{kind:?}: 3회째부터 매 스캔 알림 후보(엔진이 중복을 거른다)"
        );
    }
}

#[test]
fn runaway_already_demoted_is_not_redone() {
    let (sc, r) = cpu_scene(Kind::DevServer);
    let policy = safe();
    let mut m = mem(policy.level);
    m.demoted.insert(
        r,
        vh_guard::memory::Demoted {
            at_unix_ms: T0,
            label_ko: "x".into(),
            finding_id: "f".into(),
        },
    );
    for i in 0..4u64 {
        let d = decide_cpu(&sc, &mut m, &policy, r.pid, Some(300.0), T0 + i * 5000);
        assert!(d.demote.is_empty());
        assert!(
            d.skipped
                .iter()
                .any(|s| s.reason == SkipReason::AlreadyDemoted)
        );
    }
}

#[test]
fn notify_only_level_never_demotes() {
    let (sc, r) = cpu_scene(Kind::DevServer);
    let policy = notify_only();
    let mut m = mem(policy.level);
    for i in 0..4u64 {
        let d = decide_cpu(&sc, &mut m, &policy, r.pid, Some(300.0), T0 + i * 5000);
        assert!(d.demote.is_empty() && d.pending.is_empty());
    }
}

#[test]
fn quota_exceeded_executes_nothing_and_trips_circuit() {
    let mut sc = Scene::new();
    for pid in 101..=106 {
        sc.leftover(
            pid,
            Kind::McpServer,
            Confidence::Confirmed,
            OLD,
            Some(false),
        );
    }
    let (_, ds) = run_scans(&sc, &safe(), 2);
    let d = &ds[1];
    assert!(d.trip_circuit);
    assert!(d.terminate.is_empty());
    assert_eq!(
        d.notify
            .iter()
            .filter(|n| n.reason == SkipReason::QuotaExceeded)
            .count(),
        6
    );
}

#[test]
fn quota_counts_only_window_and_circuit_open_notifies_only() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let policy = safe();
    let mut m = mem(policy.level);
    for _ in 0..5 {
        m.terminations.push_back(T0 - 60_000);
    }
    let (s, r) = sc.build(T0);
    let d1 = decide(&m, &s, &r, &policy, T0);
    apply(&mut m, &d1);
    let (s, r) = sc.build(T0 + 5000);
    let d2 = decide(&m, &s, &r, &policy, T0 + 5000);
    assert!(d2.trip_circuit && d2.terminate.is_empty());

    let mut old = mem(policy.level);
    for _ in 0..5 {
        old.terminations.push_back(T0 - 11 * 60_000);
    }
    let (s, r) = sc.build(T0);
    let o1 = decide(&old, &s, &r, &policy, T0);
    apply(&mut old, &o1);
    let (s, r) = sc.build(T0 + 5000);
    let o2 = decide(&old, &s, &r, &policy, T0 + 5000);
    assert_eq!(o2.terminate.len(), 1, "창 밖 기록은 세지 않는다");

    let mut open = mem(policy.level);
    open.circuit_open = true;
    open.term_streak = m.term_streak.clone();
    let (s, r) = sc.build(T0 + 5000);
    let o = decide(&open, &s, &r, &policy, T0 + 5000);
    assert!(o.terminate.is_empty() && !o.trip_circuit);
    assert_eq!(o.notify[0].reason, SkipReason::CircuitOpen);
}

#[test]
fn pid_reuse_is_a_new_procref_and_restarts_the_streak() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let policy = safe();
    let mut m = mem(policy.level);
    let (s, r) = sc.build(T0);
    let d = decide(&m, &s, &r, &policy, T0);
    apply(&mut m, &d);
    let mut sc2 = Scene::new();
    sc2.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD - 1,
        Some(false),
    );
    let (s, r) = sc2.build(T0 + 5000);
    let d = decide(&m, &s, &r, &policy, T0 + 5000);
    assert!(d.terminate.is_empty());
    assert_eq!(d.pending[0].seen_scans, 1);
}

#[test]
fn self_and_ancestor_and_zombie_are_prefiltered() {
    let mut sc = Scene::new();
    let shell = proc_(300, 1, UID, OLD, "zsh");
    sc.procs.push(shell.clone());
    sc.procs[0].ppid = 300;
    let shell_ref = pref(&shell);
    sc.classified
        .push(classified(shell_ref, Kind::DevServer, "zsh", None));
    sc.findings.push(finding(
        "a",
        FindingKind::Orphan,
        Confidence::Confirmed,
        vec![shell_ref],
        term(false),
        0,
    ));
    let z = sc.leftover(301, Kind::McpServer, Confidence::Confirmed, OLD, None);
    sc.procs.iter_mut().find(|p| p.pid == 301).unwrap().status = ProcStatus::Zombie;
    let (_, ds) = run_scans(&sc, &safe(), 2);
    assert!(ds[1].terminate.is_empty());
    assert!(
        ds[1]
            .skipped
            .iter()
            .any(|s| s.target == shell_ref && s.reason == SkipReason::SelfOrAncestor)
    );
    assert!(
        ds[1]
            .skipped
            .iter()
            .any(|s| s.target == z && s.reason == SkipReason::NotInSnapshot)
    );
}

#[test]
fn non_terminate_suggestions_are_never_candidates() {
    let mut sc = Scene::new();
    let r = sc.plain(101, Kind::AgentHelper, OLD);
    for sugg in [
        Suggestion::HandoffThenRestart,
        Suggestion::Review,
        Suggestion::Demote,
        Suggestion::Resume,
        Suggestion::None,
        Suggestion::RestartParent { parent: r },
    ] {
        let mut s2 = Scene::new();
        s2.plain(101, Kind::AgentHelper, OLD);
        s2.findings.push(finding(
            "f",
            FindingKind::Orphan,
            Confidence::Confirmed,
            vec![r],
            sugg,
            0,
        ));
        let (_, ds) = run_scans(&s2, &aggressive(), 3);
        assert!(
            ds.iter()
                .all(|d| d.terminate.is_empty() && d.pending.is_empty())
        );
    }
}

#[test]
fn pressure_sets_scan_interval() {
    let sc = Scene::new();
    let m = mem(AutoLevel::Safe);
    let (s, r) = sc.build_pressure(T0, 2);
    assert_eq!(decide(&m, &s, &r, &safe(), T0).next_scan_interval_ms, 2000);
    let (s, r) = sc.build_pressure(T0, 1);
    assert_eq!(decide(&m, &s, &r, &safe(), T0).next_scan_interval_ms, 5000);
}

fn assert_same_but_skipped(full: &vh_guard::Decisions, lean: &vh_guard::Decisions) {
    assert_eq!(full.terminate, lean.terminate);
    assert_eq!(full.demote, lean.demote);
    assert_eq!(full.trip_circuit, lean.trip_circuit);
    assert_eq!(full.pending, lean.pending);
    assert_eq!(full.notify, lean.notify);
    assert_eq!(full.next_term_streak, lean.next_term_streak);
    assert_eq!(full.next_cpu_streak, lean.next_cpu_streak);
    assert_eq!(full.next_scan_interval_ms, lean.next_scan_interval_ms);
    assert!(lean.skipped.is_empty());
}

#[test]
fn decide_lean_matches_decide_without_skips() {
    let mut scenes = Vec::new();
    let mut a = Scene::new();
    a.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    a.leftover(
        102,
        Kind::McpServer,
        Confidence::Confirmed,
        T0 - 1000,
        Some(false),
    );
    a.leftover(103, Kind::AgentCli, Confidence::Confirmed, OLD, Some(false));
    a.leftover(104, Kind::McpServer, Confidence::Possible, OLD, Some(false));
    a.leftover(105, Kind::McpServer, Confidence::Confirmed, OLD, Some(true));
    scenes.push(a);
    let mut q = Scene::new();
    for pid in 101..=106 {
        q.leftover(
            pid,
            Kind::McpServer,
            Confidence::Confirmed,
            OLD,
            Some(false),
        );
    }
    scenes.push(q);
    let (c, _) = cpu_scene(Kind::DevServer);
    scenes.push(c);
    let mut skipped_seen = 0;
    for (si, sc) in scenes.iter().enumerate() {
        for policy in [safe(), aggressive(), notify_only()] {
            let mut m = mem(policy.level);
            for i in 0..4u64 {
                let now = T0 + i * 5000;
                let (mut s, r) = sc.build(now);
                if si == 2 {
                    s.processes
                        .iter_mut()
                        .find(|p| p.pid == 201)
                        .unwrap()
                        .cpu_pct = Some(150.0);
                }
                let full = decide(&m, &s, &r, &policy, now);
                let lean = decide_lean(&m, &s, &r, &policy, now);
                assert_same_but_skipped(&full, &lean);
                skipped_seen += full.skipped.len();
                apply(&mut m, &full);
            }
        }
    }
    assert!(skipped_seen > 0, "비교한 장면에 실제로 제외 사유가 있었다");
}
