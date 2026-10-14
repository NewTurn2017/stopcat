//! GUARD_1·GUARD_2 판정(순수). 가짜 스냅샷·리포트만 쓴다(신호 0).

use vh_guard::decide::{SkipReason, decide, decide_lean};
use vh_guard::fake::*;
use vh_guard::memory::GuardMemory;
use vh_guard::{AutoLevel, GuardPolicy};
use vh_model::*;

use crate::common::*;

fn mem(level: AutoLevel) -> GuardMemory {
    GuardMemory::new(level)
}

fn apply(m: &mut GuardMemory, d: &vh_guard::Decisions) {
    m.term_streak = d.next_term_streak.clone();
}

/// 지킴이가 이미 2분 넘게 '안 씀'을 본 기억에서 시작해 5초 간격으로 n번 판정한다(엔진과 같은 순서: observe → decide).
fn run_scans(
    scene: &Scene,
    policy: &GuardPolicy,
    n: usize,
) -> (GuardMemory, Vec<vh_guard::Decisions>) {
    let mut m = observed_idle_mem(scene, policy, T0);
    let mut out = Vec::new();
    for i in 0..n {
        let now = T0 + i as u64 * 5000;
        let (s, r) = scene.build(now);
        vh_guard::observe(&mut m, &s, &r, None, policy, now);
        let d = decide(&m, &s, &r, policy, now);
        apply(&mut m, &d);
        out.push(d);
    }
    (m, out)
}

#[test]
fn safe_confirmed_mcp_terminates_after_two_scans() {
    let mut sc = Scene::unstable();
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
    assert_eq!(
        ds[0].pending[0].eta_ms,
        Some(2000),
        "불안정 중 스캔 간격 2초"
    );
    assert_eq!(ds[1].terminate.len(), 1);
    assert_eq!(ds[1].terminate[0].target, t);
    assert_eq!(ds[1].terminate[0].step, Step::Term);
    assert!(ds[1].pending.is_empty());
    assert!(!ds[1].trip_circuit);
}

#[test]
fn one_scan_is_not_enough() {
    let mut sc = Scene::unstable();
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
    let mut sc = Scene::unstable();
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
        let mut sc = Scene::unstable();
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
fn safe_emulator_is_report_only_without_item_notification() {
    let mut sc = Scene::unstable();
    let t = sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, None);
    let (_, ds) = run_scans(&sc, &safe(), 3);
    assert!(
        ds.iter()
            .all(|d| d.terminate.is_empty() && d.pending.is_empty())
    );
    assert!(
        ds[0]
            .skipped
            .iter()
            .any(|s| s.target == t && s.reason == SkipReason::KindNotifyOnly)
    );
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
            let mut sc = Scene::unstable();
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
            assert!(
                !ds[0]
                    .skipped
                    .iter()
                    .any(|s| s.reason == SkipReason::KindNotifyOnly),
                "보호 Kind는 보고만 종류 판정 전에 걸러진다: {kind:?}"
            );
        }
    }
}

#[test]
fn likely_is_safe_skip_but_aggressive_candidate_and_possible_never() {
    let mut sc = Scene::unstable();
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

    let mut sp = Scene::unstable();
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
    let mut sc = Scene::unstable();
    let small = sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    let big = sc.leftover(102, Kind::DevServer, Confidence::Likely, OLD, Some(false));
    sc.findings[1].reclaim_bytes = 7 * 1024 * 1024 * 1024;
    sc.health = HealthLevel::Critical;
    let policy = aggressive();
    let mut m = observed_idle_mem(&sc, &policy, T0);
    for i in 0..2 {
        let now = T0 + i * 5000;
        let (s, r) = sc.build_pressure(now, 4);
        let d = decide(&m, &s, &r, &policy, now);
        apply(&mut m, &d);
        if i == 1 {
            let order: Vec<ProcRef> = d.terminate.iter().map(|c| c.target).collect();
            assert_eq!(order, vec![big, small], "위험: 할당량 안 전부, 큰 것부터");
        }
    }
    sc.health = HealthLevel::Watch;
    let (s, r) = sc.build_pressure(T0 + 10_000, 2);
    let d = decide(&m, &s, &r, &policy, T0 + 10_000);
    let order: Vec<ProcRef> = d.terminate.iter().map(|c| c.target).collect();
    assert_eq!(order, vec![big], "주의: 회차당 큰 것 1개(W4 Q3)");
    assert_eq!(d.pending.len(), 1);
    assert_eq!(
        (d.pending[0].target, d.pending[0].wait),
        (small, PendingWait::RoundLimit)
    );
}

#[test]
fn notify_only_level_has_no_actions_and_no_item_notification() {
    let mut sc = Scene::unstable();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let r = sc.plain(102, Kind::DevServer, OLD);
    let policy = notify_only();
    let mut m = observed_idle_mem(&sc, &policy, T0);
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
        assert!(
            d.skipped
                .iter()
                .any(|s| s.reason == SkipReason::LevelNotifyOnly)
        );
    }
}

#[test]
fn paused_memory_yields_nothing() {
    let mut sc = Scene::unstable();
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
    assert!(d.terminate.is_empty() && d.pending.is_empty());
    assert!(d.next_term_streak.is_empty());
}

fn cpu_scene(kind: Kind) -> (Scene, ProcRef) {
    let mut sc = Scene::unstable();
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
    for policy in [notify_only(), safe(), aggressive()] {
        for health in [HealthLevel::Ok, HealthLevel::Watch, HealthLevel::Critical] {
            let mut sc = cpu_scene(Kind::DevServer).0;
            sc.health = health;
            let mut m = mem(policy.level);
            for (i, pct) in [150.0, 120.0, 100.0, 50.0, 150.0, 300.0]
                .into_iter()
                .enumerate()
            {
                let d = decide_cpu(&sc, &mut m, &policy, r.pid, Some(pct), T0 + i as u64 * 5000);
                assert!(
                    d.demote.is_empty(),
                    "W4: CPU가 높아도 자동 낮추기 없음 {:?} {health:?}",
                    policy.level
                );
                assert!(d.pending.iter().all(|p| p.step == Step::Term));
            }
        }
    }
    let _ = sc;
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
        for i in 0..4u64 {
            let d = decide_cpu(&sc, &mut m, &policy, r.pid, Some(300.0), T0 + i * 5000);
            assert!(d.demote.is_empty(), "{kind:?}");
            assert!(d.pending.is_empty(), "{kind:?}");
            assert!(d.terminate.is_empty(), "{kind:?}");
        }
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
        assert!(d.demote.is_empty() && d.terminate.is_empty() && d.pending.is_empty());
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
    let mut sc = Scene::unstable();
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
        d.skipped
            .iter()
            .filter(|n| n.reason == SkipReason::QuotaExceeded)
            .count(),
        6
    );
}

#[test]
fn quota_counts_only_window_and_circuit_open_notifies_only() {
    let mut sc = Scene::unstable();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let policy = safe();
    let mut m = observed_idle_mem(&sc, &policy, T0);
    for _ in 0..5 {
        m.terminations.push_back(T0 - 60_000);
    }
    let (s, r) = sc.build(T0);
    let d1 = decide(&m, &s, &r, &policy, T0);
    apply(&mut m, &d1);
    let (s, r) = sc.build(T0 + 5000);
    let d2 = decide(&m, &s, &r, &policy, T0 + 5000);
    assert!(d2.trip_circuit && d2.terminate.is_empty());

    let mut old = observed_idle_mem(&sc, &policy, T0);
    for _ in 0..5 {
        old.terminations.push_back(T0 - 11 * 60_000);
    }
    let (s, r) = sc.build(T0);
    let o1 = decide(&old, &s, &r, &policy, T0);
    apply(&mut old, &o1);
    let (s, r) = sc.build(T0 + 5000);
    let o2 = decide(&old, &s, &r, &policy, T0 + 5000);
    assert_eq!(o2.terminate.len(), 1, "창 밖 기록은 세지 않는다");

    let mut open = observed_idle_mem(&sc, &policy, T0);
    open.circuit_open = true;
    open.term_streak = m.term_streak.clone();
    let (s, r) = sc.build(T0 + 5000);
    let o = decide(&open, &s, &r, &policy, T0 + 5000);
    assert!(o.terminate.is_empty() && !o.trip_circuit);
    assert!(
        o.skipped
            .iter()
            .any(|s| s.reason == SkipReason::CircuitOpen)
    );
}

#[test]
fn pid_reuse_is_a_new_procref_and_restarts_the_streak() {
    let mut sc = Scene::unstable();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let policy = safe();
    let mut m = observed_idle_mem(&sc, &policy, T0);
    let (s, r) = sc.build(T0);
    let d = decide(&m, &s, &r, &policy, T0);
    apply(&mut m, &d);
    let mut sc2 = Scene::unstable();
    sc2.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD - 1,
        Some(false),
    );
    let (s, r) = sc2.build(T0 + 5000);
    vh_guard::observe(&mut m, &s, &r, None, &policy, T0 + 5000);
    let d = decide(&m, &s, &r, &policy, T0 + 5000);
    assert!(d.terminate.is_empty());
    assert_eq!(d.pending[0].seen_scans, 1);
    assert_eq!(
        d.pending[0].wait,
        PendingWait::IdleConfirming,
        "새 ProcRef는 '안 씀' 관찰도 새로 시작"
    );
}

#[test]
fn self_and_ancestor_and_zombie_are_prefiltered() {
    let mut sc = Scene::unstable();
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
    sc.findings[0].section = Section::Unneeded;
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
    let mut sc = Scene::unstable();
    let r = sc.plain(101, Kind::AgentHelper, OLD);
    for sugg in [
        Suggestion::HandoffThenRestart,
        Suggestion::Review,
        Suggestion::Demote,
        Suggestion::Resume,
        Suggestion::None,
        Suggestion::RestartParent { parent: r },
    ] {
        let mut s2 = Scene::unstable();
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
    let m = mem(AutoLevel::Safe);
    let sc = Scene::unstable();
    let (s, r) = sc.build_pressure(T0, 2);
    assert_eq!(decide(&m, &s, &r, &safe(), T0).next_scan_interval_ms, 2000);
    let calm = Scene::new();
    let (s, r) = calm.build_pressure(T0, 1);
    assert_eq!(decide(&m, &s, &r, &safe(), T0).next_scan_interval_ms, 5000);
}

fn assert_same_but_skipped(full: &vh_guard::Decisions, lean: &vh_guard::Decisions) {
    assert_eq!(full.terminate, lean.terminate);
    assert_eq!(full.demote, lean.demote);
    assert_eq!(full.trip_circuit, lean.trip_circuit);
    assert_eq!(full.pending, lean.pending);
    assert_eq!(full.next_term_streak, lean.next_term_streak);
    assert_eq!(full.stability, lean.stability);
    assert_eq!(full.next_scan_interval_ms, lean.next_scan_interval_ms);
    assert!(lean.skipped.is_empty());
}

#[test]
fn decide_lean_matches_decide_without_skips() {
    let mut scenes = Vec::new();
    let mut a = Scene::unstable();
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
    let mut q = Scene::unstable();
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
            let mut m = observed_idle_mem(sc, &policy, T0);
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

const NINE_MIN_AGO: u64 = T0 - 9 * 60_000;

fn young_orphan(kind: Kind, owner_alive: Option<bool>) -> (Scene, ProcRef) {
    let mut sc = Scene::unstable();
    let p = proc_(101, 1, UID, NINE_MIN_AGO, "p101");
    let r = pref(&p);
    sc.procs.push(p);
    let mut c = classified(r, kind, &format!("{kind:?} 101"), owner_alive);
    c.usage.state = UsageState::Active;
    c.usage.reasons.push(UsageReason::Young);
    sc.classified.push(c);
    let mut f = finding(
        "orphan:101",
        FindingKind::Orphan,
        Confidence::Possible,
        vec![r],
        Suggestion::Review,
        100 * 1024 * 1024,
    );
    f.reason_codes = vec!["ppid_launchd".into(), "same_uid".into(), "young".into()];
    sc.findings.push(f);
    (sc, r)
}

#[test]
fn young_orphan_with_confirmed_grounds_is_pending_with_eta_but_not_executed() {
    let (sc, r) = young_orphan(Kind::McpServer, None);
    let policy = safe();
    let m = mem(policy.level);
    let (s, rep) = sc.build(T0);
    for d in [
        decide(&m, &s, &rep, &policy, T0),
        decide_lean(&m, &s, &rep, &policy, T0),
    ] {
        assert!(d.terminate.is_empty() && !d.trip_circuit);
        assert_eq!(d.pending.len(), 1, "{:?}", d.pending);
        let p = &d.pending[0];
        assert_eq!((p.target, p.step), (r, Step::Term));
        assert_eq!(p.wait, PendingWait::TooYoung);
        assert_eq!(p.finding_id, "orphan:101");
        assert_eq!((p.seen_scans, p.needed_scans), (0, 2));
        assert_eq!(p.eta_ms, Some(60_000), "10분 - 9분");
        assert!(d.next_term_streak.is_empty(), "연속 확인은 세지 않는다");
    }
    let (_, ds) = run_scans(&sc, &policy, 3);
    assert!(
        ds.iter().all(|d| d.terminate.is_empty()),
        "표시뿐, 실행 없음"
    );
}

#[test]
fn young_orphan_owner_dead_counts_as_grounds() {
    let (sc, _) = young_orphan(Kind::McpServer, Some(false));
    let (_, ds) = run_scans(&sc, &safe(), 1);
    assert_eq!(ds[0].pending.len(), 1);
}

#[test]
fn young_orphan_then_ten_minutes_follows_existing_flow() {
    let (young, r) = young_orphan(Kind::McpServer, None);
    let policy = safe();
    let mut m = mem(policy.level);
    let (s, rep) = young.build(T0);
    let d0 = decide(&m, &s, &rep, &policy, T0);
    apply(&mut m, &d0);
    assert_eq!(d0.pending[0].seen_scans, 0);

    let mut grown = Scene::unstable();
    let p = proc_(101, 1, UID, NINE_MIN_AGO, "p101");
    grown.procs.push(p);
    grown
        .classified
        .push(classified(r, Kind::McpServer, "McpServer 101", None));
    grown.findings.push(finding(
        "orphan:101",
        FindingKind::Orphan,
        Confidence::Confirmed,
        vec![r],
        term(false),
        100 * 1024 * 1024,
    ));
    grown.findings[0].section = Section::Unneeded;
    let t1 = NINE_MIN_AGO + 10 * 60_000;
    let (s, rep) = grown.build(t1);
    vh_guard::observe(&mut m, &s, &rep, None, &policy, t1);
    let d1 = decide(&m, &s, &rep, &policy, t1);
    apply(&mut m, &d1);
    assert!(d1.terminate.is_empty());
    assert_eq!(
        (d1.pending[0].seen_scans, d1.pending[0].wait),
        (1, PendingWait::IdleConfirming),
        "10분이 지나 안 씀이 된 순간부터 2분 관찰"
    );
    let t2 = t1 + 120_000;
    let (s, rep) = grown.build(t2);
    vh_guard::observe(&mut m, &s, &rep, None, &policy, t2);
    let d2 = decide(&m, &s, &rep, &policy, t2);
    assert_eq!(d2.terminate.len(), 1);
    assert_eq!(d2.terminate[0].target, r);
}

#[test]
fn young_orphan_without_confirmed_grounds_has_no_pending() {
    let cases: Vec<(&str, Kind, Option<bool>, GuardPolicy)> = vec![
        ("주인 생존", Kind::McpServer, Some(true), safe()),
        ("보호 Kind", Kind::AgentCli, None, aggressive()),
        ("알림만 Kind", Kind::Emulator, None, safe()),
        (
            "근거 없음(stdio 아님·주인 모름)",
            Kind::DevServer,
            None,
            safe(),
        ),
        ("알림만 수준", Kind::McpServer, None, notify_only()),
    ];
    for (why, kind, owner, policy) in cases {
        let (sc, _) = young_orphan(kind, owner);
        let (_, ds) = run_scans(&sc, &policy, 2);
        assert!(
            ds.iter()
                .all(|d| d.pending.is_empty() && d.terminate.is_empty()),
            "{why}: {:?}",
            ds[0].pending
        );
    }

    let (mut sc, _) = young_orphan(Kind::McpServer, None);
    sc.procs[1].has_tty = true;
    let (_, ds) = run_scans(&sc, &safe(), 1);
    assert!(ds[0].pending.is_empty(), "터미널 → Likely라 Safe 기준 미달");

    let (mut sc, _) = young_orphan(Kind::McpServer, None);
    sc.findings[0].reason_codes.retain(|c| c != "young");
    let (_, ds) = run_scans(&sc, &safe(), 1);
    assert!(
        ds[0].pending.is_empty(),
        "young 근거 없으면 표시하지 않는다"
    );

    let (mut sc, _) = young_orphan(Kind::McpServer, None);
    sc.procs[1].start_time_unix_ms = OLD;
    let (_, ds) = run_scans(&sc, &safe(), 1);
    assert!(ds[0].pending.is_empty(), "나이는 찼는데 Review면 다른 이유");
}
