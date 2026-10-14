//! W4 안정화 정책: 평소 보고만, 불안정할 때만 unneeded·안 씀 확인된 것을 큰 것부터 정착 시간을 두고 정리,
//! 쓰고 있는 것(Active·Unknown)은 어떤 수준·건강에서도 신호 0·우선순위 변화 0. 가짜 백엔드(신호는 가짜 세계에만).

use std::sync::Arc;

use stopcat_guard::fake::*;
use stopcat_guard::{Engine, GuardEventKind, GuardMemory, GuardPolicy, GuardUpdate};
use stopcat_model::*;

use crate::common::*;

fn engine(scene: &Scene, policy: GuardPolicy) -> (Engine<FakeGuardBackend>, Probe, FakeClock) {
    let clock = FakeClock::at(T0);
    let (s, r) = scene.build(T0);
    let be = FakeGuardBackend::scripted(vec![(s, r)], clock.clone());
    let probe = be.probe();
    (Engine::new(policy, be), probe, clock)
}

fn scan(e: &mut Engine<FakeGuardBackend>, clock: &FakeClock, step_ms: u64) -> GuardUpdate {
    let u = e.scan().expect("스캔 결과");
    clock.advance(step_ms);
    u
}

fn set_scene(e: &mut Engine<FakeGuardBackend>, sc: &Scene, now: u64) {
    let (s, r) = sc.build(now);
    e.backend_mut().script.clear();
    e.backend_mut().push_script(s, r);
}

fn levels() -> [GuardPolicy; 3] {
    [notify_only(), safe(), aggressive()]
}

fn usage(state: UsageState, reasons: Vec<UsageReason>) -> Usage {
    Usage {
        state,
        reasons,
        ..Usage::default()
    }
}

/// 쓰고 있는(Active·Unknown) 대상들. 주인 끝남·구역 unneeded·확실·나이 11분이라 사용 판정만 막는다.
fn in_use_scene(health: HealthLevel) -> (Scene, Vec<ProcRef>) {
    let mut sc = Scene::new();
    sc.health = health;
    let cases = [
        usage(
            UsageState::Active,
            vec![UsageReason::OwnerAlive, UsageReason::CpuActive],
        ),
        usage(UsageState::Active, vec![UsageReason::PeerOutsideSubtree]),
        usage(UsageState::Active, vec![UsageReason::CpuActive]),
        usage(
            UsageState::Unknown,
            vec![UsageReason::DiskUnknown, UsageReason::NoPeers],
        ),
        usage(UsageState::Unknown, vec![UsageReason::PeersUnknown]),
    ];
    let mut out = Vec::new();
    for (i, u) in cases.into_iter().enumerate() {
        let t = sc.leftover(
            301 + i as i32,
            Kind::DevServer,
            Confidence::Confirmed,
            OLD,
            Some(false),
        );
        sc.classified[i].usage = u;
        out.push(t);
    }
    (sc, out)
}

#[test]
fn in_use_and_unknown_get_no_signal_no_priority_change_in_any_level_and_health() {
    for health in [HealthLevel::Ok, HealthLevel::Watch, HealthLevel::Critical] {
        for policy in levels() {
            let (sc, targets) = in_use_scene(health);
            let (mut e, probe, clock) = engine(&sc, policy.clone());
            for (pid, rate) in [(301, 150.0), (303, 300.0), (304, 120.0)] {
                e.backend_mut().cpu_rate_pct.insert(pid, rate);
            }
            for i in 0..12 {
                let u = scan(&mut e, &clock, if i == 0 { 125_000 } else { 30_000 });
                assert!(u.status.pending.is_empty(), "{health:?} {:?}", policy.level);
                assert!(u.status.demoted.is_empty());
                assert_eq!(count(&u.new_events, GuardEventKind::AutoTerminated), 0);
                assert_eq!(count(&u.new_events, GuardEventKind::Demoted), 0);
            }
            assert_eq!(
                probe.log.calls(),
                0,
                "신호·우선순위 호출 0: {health:?} {:?}",
                policy.level
            );
            for t in &targets {
                assert!(probe.world.alive(*t));
                assert_eq!(probe.world.bg_of(t.pid), None);
            }
        }
    }
}

#[test]
fn decide_never_offers_in_use_or_demote_in_any_level_and_health() {
    for health in [HealthLevel::Ok, HealthLevel::Watch, HealthLevel::Critical] {
        for policy in levels() {
            let (sc, _) = in_use_scene(health);
            let mut m = observed_idle_mem(&sc, &policy, T0);
            for i in 0..4u64 {
                let now = T0 + i * 125_000;
                let (mut s, r) = sc.build(now);
                for p in &mut s.processes {
                    p.cpu_pct = Some(250.0);
                }
                stopcat_guard::observe(&mut m, &s, &r, None, &policy, now);
                let d = stopcat_guard::decide(&m, &s, &r, &policy, now);
                m.term_streak = d.next_term_streak.clone();
                assert!(d.terminate.is_empty() && d.demote.is_empty() && d.pending.is_empty());
            }
            assert!(
                m.idle_since.is_empty(),
                "Active·Unknown은 '안 씀' 기록 없음"
            );
        }
    }
}

#[test]
fn normal_health_means_no_auto_no_item_notification_no_pending() {
    for policy in levels() {
        let mut sc = Scene::new();
        sc.leftover(
            101,
            Kind::McpServer,
            Confidence::Confirmed,
            OLD,
            Some(false),
        );
        sc.leftover(102, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
        sc.leftover(103, Kind::DevServer, Confidence::Likely, OLD, Some(false));
        let young = T0 - 9 * 60_000;
        sc.leftover(
            104,
            Kind::McpServer,
            Confidence::Confirmed,
            young,
            Some(false),
        );
        let (mut e, probe, clock) = engine(&sc, policy.clone());
        for _ in 0..20 {
            let u = scan(&mut e, &clock, 30_000);
            assert!(u.status.pending.is_empty(), "{:?}", policy.level);
            assert!(!u.status.unstable && !u.status.circuit_open);
            assert_eq!(u.status.health, HealthLevel::Ok);
            assert!(u.new_events.is_empty(), "{:?}", kinds(&u.new_events));
        }
        assert!(probe.log.sent().is_empty(), "{:?}", policy.level);
        assert!(probe.notifications().is_empty(), "평소 항목 알림 0");
        assert_eq!(
            e.memory().idle_since.len(),
            4,
            "정상일 때도 '안 씀' 시작 시각은 유지"
        );
    }
}

#[test]
fn unstable_runs_only_unneeded_confirmed_idle_two_minutes_two_scans() {
    let mut sc = Scene::unstable();
    sc.health = HealthLevel::Critical;
    let ok = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let likely = sc.leftover(102, Kind::McpServer, Confidence::Likely, OLD, Some(false));
    let check = sc.leftover(
        103,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    sc.findings[2].section = Section::Check;
    let working = sc.leftover(104, Kind::McpServer, Confidence::Confirmed, OLD, Some(true));
    sc.findings[3].section = Section::Working;
    let manual = sc.leftover(105, Kind::LocalLlm, Confidence::Confirmed, OLD, Some(false));
    sc.findings[4].section = Section::Manual;
    let (mut e, probe, clock) = engine(&sc, safe());

    let u1 = scan(&mut e, &clock, 5000);
    assert!(
        probe.log.sent().is_empty(),
        "지킴이를 막 켰을 때 2분 동안 0건"
    );
    let waits: Vec<(ProcRef, PendingWait)> = u1
        .status
        .pending
        .iter()
        .map(|p| (p.target, p.wait))
        .collect();
    assert_eq!(waits, vec![(ok, PendingWait::IdleConfirming)]);
    clock.advance(safe().idle_confirm_ms - 10_000);
    scan(&mut e, &clock, 5000);
    assert!(probe.log.sent().is_empty(), "2분 전에는 0건");
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(
        probe.log.sent(),
        vec![(101, libc::SIGTERM)],
        "2분·2회 뒤 확실·unneeded만"
    );
    assert_eq!(count(&u.new_events, GuardEventKind::AutoTerminated), 1);
    for t in [likely, check, working, manual] {
        assert!(probe.world.alive(t));
    }
}

#[test]
fn idle_since_resets_when_used_again_and_survives_normal_health() {
    let mut sc = Scene::new();
    let t = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, probe, clock) = engine(&sc, safe());
    scan(&mut e, &clock, 100_000);
    assert_eq!(e.memory().idle_since.get(&t), Some(&T0));

    sc.classified[0].usage = usage(UsageState::Active, vec![UsageReason::PeerOutsideSubtree]);
    set_scene(&mut e, &sc, clock.now());
    scan(&mut e, &clock, 5000);
    assert!(
        e.memory().idle_since.is_empty(),
        "한 번이라도 쓰고 있으면 지운다"
    );

    sc.classified[0].usage = stopcat_guard::fake::fixture_usage(Some(false));
    set_scene(&mut e, &sc, clock.now());
    let restart = clock.now();
    scan(&mut e, &clock, 5000);
    assert_eq!(e.memory().idle_since.get(&t), Some(&restart));

    sc.health = HealthLevel::Watch;
    set_scene(&mut e, &sc, clock.now());
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(u.status.pending[0].wait, PendingWait::IdleConfirming);
    assert_eq!(
        u.status.pending[0].eta_ms,
        Some(safe().idle_confirm_ms - 5000)
    );
    assert!(probe.log.sent().is_empty());

    let mut gone = Scene::new();
    gone.health = HealthLevel::Watch;
    set_scene(&mut e, &gone, clock.now());
    scan(&mut e, &clock, 5000);
    assert!(e.memory().idle_since.is_empty(), "사라진 대상은 정리");
}

#[test]
fn idle_since_is_capped() {
    let policy = safe();
    let mut sc = Scene::new();
    let n = stopcat_guard::MAX_IDLE_TRACKED + 5;
    for i in 0..n {
        let p = proc_(10_000 + i as i32, 1, UID, OLD, "x");
        let r = pref(&p);
        sc.procs.push(p);
        sc.classified
            .push(classified(r, Kind::DevServer, "x", Some(false)));
    }
    let mut m = GuardMemory::new(policy.level);
    let (s, r) = sc.build(T0);
    stopcat_guard::observe(&mut m, &s, &r, None, &policy, T0);
    assert_eq!(m.idle_since.len(), stopcat_guard::MAX_IDLE_TRACKED);
}

#[test]
fn disk_delta_is_filled_so_real_analysis_can_reach_idle_after_two_scans() {
    let mut sc = Scene::new();
    let mut p = proc_(101, 1, UID, OLD, "srv");
    p.tcp = Some(TcpSummary::default());
    p.disk_read_bytes = Some(4096);
    p.disk_written_bytes = Some(8192);
    p.cpu_time_ns = Some(1_000_000);
    let t = pref(&p);
    sc.procs.push(p);
    let clock = FakeClock::at(T0);
    let (s, r) = sc.build(T0);
    let mut be = FakeGuardBackend::scripted(vec![(s, r)], clock.clone());
    be.use_real_analyze = true;
    let mut e = Engine::new(safe(), be);
    let u1 = scan(&mut e, &clock, 5000);
    let p1 = u1.snapshot.processes.iter().find(|p| p.pid == 101).unwrap();
    assert_eq!(p1.disk_io_delta_bytes, None, "첫 스캔은 비교할 값이 없다");
    let c1 = u1.report.classified.iter().find(|c| c.target == t).unwrap();
    assert_eq!(c1.usage.state, UsageState::Unknown);
    assert!(c1.usage.reasons.contains(&UsageReason::DiskUnknown));

    let u2 = scan(&mut e, &clock, 5000);
    let p2 = u2.snapshot.processes.iter().find(|p| p.pid == 101).unwrap();
    assert_eq!(p2.disk_io_delta_bytes, Some(0));
    let c2 = u2.report.classified.iter().find(|c| c.target == t).unwrap();
    assert!(
        c2.usage.reasons.contains(&UsageReason::DiskIdle),
        "{:?}",
        c2.usage
    );
    assert_eq!(c2.usage.state, UsageState::Idle, "{:?}", c2.usage);
    assert!(e.memory().idle_since.contains_key(&t));
}

fn two_targets(health: HealthLevel) -> (Scene, ProcRef, ProcRef) {
    let mut sc = Scene::unstable();
    sc.health = health;
    let small = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let big = sc.leftover(
        102,
        Kind::DevServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    sc.findings[1].reclaim_bytes = 900 * 1024 * 1024;
    (sc, small, big)
}

#[test]
fn watch_round_takes_largest_one_then_settles_sixty_seconds() {
    let (sc, small, big) = two_targets(HealthLevel::Watch);
    let (mut e, probe, clock) = engine(&sc, safe());
    scan(&mut e, &clock, safe().idle_confirm_ms);
    let u = scan(&mut e, &clock, 2000);
    assert_eq!(
        probe.log.sent(),
        vec![(big.pid, libc::SIGTERM)],
        "큰 것 1개"
    );
    let p: Vec<(ProcRef, PendingWait)> = u
        .status
        .pending
        .iter()
        .map(|p| (p.target, p.wait))
        .collect();
    assert_eq!(p, vec![(small, PendingWait::RoundLimit)]);
    let round_at = u.status.last_scan_at_unix_ms;
    assert_eq!(u.status.settle_until_unix_ms, Some(round_at + 60_000));

    let mut last = None;
    while clock.now() < round_at + 60_000 {
        let u = scan(&mut e, &clock, 2000);
        assert_eq!(probe.log.sent().len(), 1, "정착 중 0건");
        if !u.status.pending.is_empty() {
            assert_eq!(u.status.pending[0].wait, PendingWait::Settling);
        }
        last = Some(u);
    }
    assert!(last.is_some());
    scan(&mut e, &clock, 2000);
    assert_eq!(
        probe.log.sent().len(),
        2,
        "정착 60초 뒤 아직 불안정이면 다음 것"
    );
    assert_eq!(probe.log.sent()[1], (small.pid, libc::SIGTERM));
}

#[test]
fn critical_round_takes_all_within_quota() {
    let (sc, small, big) = two_targets(HealthLevel::Critical);
    let (mut e, probe, clock) = engine(&sc, safe());
    scan(&mut e, &clock, safe().idle_confirm_ms);
    scan(&mut e, &clock, 2000);
    assert_eq!(
        probe.log.sent(),
        vec![(big.pid, libc::SIGTERM), (small.pid, libc::SIGTERM)]
    );
}

#[test]
fn back_to_normal_stops_with_one_stable_event_and_no_more_actions() {
    let (mut sc, small, big) = two_targets(HealthLevel::Watch);
    let (mut e, probe, clock) = engine(&sc, safe());
    let u = scan(&mut e, &clock, safe().idle_confirm_ms);
    assert_eq!(count(&u.new_events, GuardEventKind::Unstable), 1);
    scan(&mut e, &clock, 2000);
    assert_eq!(probe.log.sent(), vec![(big.pid, libc::SIGTERM)]);

    sc.health = HealthLevel::Ok;
    set_scene(&mut e, &sc, clock.now());
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(count(&u.new_events, GuardEventKind::Stable), 1);
    assert!(u.status.pending.is_empty() && !u.status.unstable);
    assert_eq!(u.status.settle_until_unix_ms, None);
    let notes = probe.notifications().len();
    for _ in 0..30 {
        let u = scan(&mut e, &clock, 5000);
        assert_eq!(count(&u.new_events, GuardEventKind::Stable), 0, "한 번만");
    }
    assert_eq!(probe.log.sent().len(), 1, "정상 복귀 뒤 새 자동 조치 0");
    assert!(probe.world.alive(small));
    assert_eq!(probe.notifications().len(), notes, "정상 복귀는 알림 없음");
}

#[test]
fn unstable_notification_has_reclaim_summary_and_ten_minute_cooldown() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    let (mut e, probe, clock) = engine(&sc, notify_only());
    let totals = |sc: &mut Scene, e: &mut Engine<FakeGuardBackend>, h: HealthLevel| {
        sc.health = h;
        let (s, mut r) = sc.build(clock.now());
        r.totals.unneeded_bytes = 3 * 1024 * 1024 * 1024;
        r.totals.check_bytes = 7 * 1024 * 1024 * 1024;
        r.totals.manual_bytes = 22 * 1024 * 1024 * 1024;
        e.backend_mut().script.clear();
        e.backend_mut().push_script(s, r);
    };
    totals(&mut sc, &mut e, HealthLevel::Watch);
    let u = scan(&mut e, &clock, 60_000);
    assert_eq!(count(&u.new_events, GuardEventKind::Unstable), 1);
    let n = probe.notifications();
    assert_eq!(n.len(), 1);
    assert!(
        n[0].1.contains("불안정")
            && n[0].1.contains("3.0GB")
            && n[0].1.contains("+7.0GB")
            && n[0].1.contains("+22.0GB"),
        "{}",
        n[0].1
    );
    assert!(
        n[0].1.contains("화면에서 골라"),
        "보고만 수준 문장: {}",
        n[0].1
    );
    assert!(!n[0].1.contains("Emulator"), "항목 줄 없음");

    totals(&mut sc, &mut e, HealthLevel::Ok);
    scan(&mut e, &clock, 60_000);
    totals(&mut sc, &mut e, HealthLevel::Watch);
    let u = scan(&mut e, &clock, 60_000);
    assert_eq!(
        count(&u.new_events, GuardEventKind::Unstable),
        1,
        "이벤트는 남는다"
    );
    assert_eq!(probe.notifications().len(), 1, "10분 안 재전환은 알림 없음");

    totals(&mut sc, &mut e, HealthLevel::Ok);
    scan(&mut e, &clock, 600_000);
    totals(&mut sc, &mut e, HealthLevel::Critical);
    scan(&mut e, &clock, 5000);
    assert_eq!(probe.notifications().len(), 2, "10분 뒤에는 다시 알림");
    assert!(probe.notifications()[1].1.contains("건강 위험"));
}

#[test]
fn forced_health_makes_unstable_without_touching_report() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, probe, clock) = engine(&sc, safe());
    probe.set_forced_health(Some(HealthLevel::Watch));
    let u = scan(&mut e, &clock, safe().idle_confirm_ms);
    assert_eq!(
        u.report.health.level,
        HealthLevel::Ok,
        "리포트 건강은 진짜 값"
    );
    assert_eq!(u.status.health_forced, Some(HealthLevel::Watch));
    assert_eq!(u.status.health, HealthLevel::Watch);
    assert!(u.status.unstable);
    assert!(probe.notifications()[0].1.starts_with("[시험] "));
    scan(&mut e, &clock, 2000);
    assert_eq!(probe.log.sent(), vec![(101, libc::SIGTERM)]);

    probe.set_forced_health(None);
    let u = scan(&mut e, &clock, 2000);
    assert_eq!(count(&u.new_events, GuardEventKind::Stable), 1);
    assert_eq!(u.status.health_forced, None);
}

fn swap_scene(used: u64, now: u64, sc: &Scene) -> (Snapshot, Report) {
    let (mut s, r) = sc.build(now);
    s.memory.swap_used_bytes = used;
    (s, r)
}

#[test]
fn swap_growth_counts_only_after_min_span_inside_window() {
    const GIB: u64 = 1024 * 1024 * 1024;
    let policy = safe();
    let sc = Scene::new();
    let feed = |points: &[(u64, u64)]| {
        let mut m = GuardMemory::new(policy.level);
        let mut last = None;
        for &(at, used) in points {
            let (s, r) = swap_scene(used, at, &sc);
            stopcat_guard::observe(&mut m, &s, &r, None, &policy, at);
            last = Some(stopcat_guard::stability(&m, &r, &policy));
        }
        last.unwrap()
    };
    let st = feed(&[(T0, GIB), (T0 + 70_000, 2 * GIB)]);
    assert!(st.unstable);
    assert_eq!(st.reasons, vec![UnstableReason::SwapGrowing]);
    assert_eq!(st.swap_delta_bytes, Some(GIB as i64));
    let st = feed(&[(T0, GIB), (T0 + 30_000, 3 * GIB)]);
    assert!(
        !st.unstable && st.swap_delta_bytes.is_none(),
        "이력 60초 미만은 판단하지 않음"
    );
    let st = feed(&[
        (T0, GIB),
        (T0 + 200_000, 2 * GIB),
        (T0 + 600_000, 2 * GIB + 1),
    ]);
    assert!(!st.unstable, "5분 창 밖의 증가는 세지 않음: {st:?}");
    let st = feed(&[(T0, 3 * GIB), (T0 + 40_000, GIB), (T0 + 90_000, 2 * GIB)]);
    assert!(st.unstable, "창 안 최솟값 기준");
    let st = feed(&[(T0, GIB), (T0 + 70_000, 2 * GIB - 1)]);
    assert!(!st.unstable, "1GiB 미만");
}

#[test]
fn aggressive_config_reads_and_runs_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        r#"{"schema_version":1,"auto_level":"aggressive","first_run_done":true,"scan_interval_ms":null}"#,
    )
    .unwrap();
    let cfg = stopcat_guard::config::load(dir.path()).unwrap().unwrap();
    assert_eq!(cfg.auto_level, AutoLevel::Aggressive);
    let eff = stopcat_guard::config::effective_level(None, Some(&cfg));
    assert_eq!(
        (eff.level, eff.locked_by_env),
        (AutoLevel::Aggressive, false)
    );
    let eff = stopcat_guard::config::effective_level(Some("aggressive"), None);
    assert_eq!(eff.level, AutoLevel::Aggressive);

    for health in [HealthLevel::Ok, HealthLevel::Critical] {
        let mut sc = Scene::new();
        sc.health = health;
        sc.leftover(101, Kind::DevServer, Confidence::Likely, OLD, Some(false));
        let (mut e, probe, clock) = engine(&sc, GuardPolicy::for_level(eff.level));
        scan(&mut e, &clock, safe().idle_confirm_ms);
        scan(&mut e, &clock, 2000);
        let sent = probe.log.sent().len();
        match health {
            HealthLevel::Ok => assert_eq!(sent, 0, "적극 자동도 평소에는 0"),
            _ => assert_eq!(sent, 1, "불안정이면 가능성 높음까지"),
        }
    }
}

#[test]
fn circuit_s12_only_in_unstable_never_in_normal() {
    for health in [HealthLevel::Ok, HealthLevel::Critical] {
        let mut sc = Scene::new();
        sc.health = health;
        for pid in 101..=107 {
            sc.leftover(
                pid,
                Kind::McpServer,
                Confidence::Confirmed,
                OLD,
                Some(false),
            );
        }
        let (mut e, probe, clock) = engine(&sc, safe());
        scan(&mut e, &clock, safe().idle_confirm_ms);
        let u = scan(&mut e, &clock, 2000);
        assert!(probe.log.sent().is_empty(), "{health:?}: 0건 실행");
        let open = health != HealthLevel::Ok;
        assert_eq!(u.status.circuit_open, open, "{health:?}");
        assert_eq!(
            count(&u.new_events, GuardEventKind::CircuitOpen),
            usize::from(open)
        );
    }
}

#[test]
fn young_orphan_pending_only_when_unstable() {
    let make = |health: HealthLevel| {
        let mut sc = Scene::new();
        sc.health = health;
        let p = proc_(101, 1, UID, T0 - 9 * 60_000, "p101");
        let r = pref(&p);
        sc.procs.push(p);
        let mut c = classified(r, Kind::McpServer, "MCP", None);
        c.usage = usage(
            UsageState::Active,
            vec![UsageReason::Young, UsageReason::NoPeers],
        );
        sc.classified.push(c);
        let mut f = stopcat_guard::fake::finding(
            "orphan:101",
            FindingKind::Orphan,
            Confidence::Possible,
            vec![r],
            Suggestion::Review,
            0,
        );
        f.reason_codes = vec!["young".into()];
        sc.findings.push(f);
        sc
    };
    let (mut e, _probe, clock) = engine(&make(HealthLevel::Ok), safe());
    assert!(
        scan(&mut e, &clock, 5000).status.pending.is_empty(),
        "정상: young 보호, 표시 없음"
    );
    let (mut e, probe, clock) = engine(&make(HealthLevel::Watch), safe());
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(u.status.pending.len(), 1);
    assert_eq!(u.status.pending[0].wait, PendingWait::TooYoung);
    assert!(probe.log.sent().is_empty());

    let mut busy = make(HealthLevel::Watch);
    busy.classified[0]
        .usage
        .reasons
        .push(UsageReason::PeerOutsideSubtree);
    let (mut e, _probe, clock) = engine(&busy, safe());
    assert!(
        scan(&mut e, &clock, 5000).status.pending.is_empty(),
        "young 말고도 쓰고 있음 근거가 있으면 표시 안 함"
    );
}

#[test]
fn status_reports_swap_delta_and_arc_snapshot_is_shared() {
    let sc = Scene::new();
    let (mut e, _probe, clock) = engine(&sc, safe());
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(u.status.swap_delta_bytes, None);
    for _ in 0..13 {
        scan(&mut e, &clock, 5000);
    }
    let u = scan(&mut e, &clock, 5000);
    assert_eq!(u.status.swap_delta_bytes, Some(0));
    assert!(Arc::strong_count(&u.snapshot) >= 1);
}
