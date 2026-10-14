//! GUARD_2·GUARD_5 엔진(동기). 신호는 가짜 세계에만, 계획·실행은 진짜 vh_act 경로.

use std::sync::Arc;

use vh_act::{AuditEntry, AuditEvent, Policy, Selection, audit_log_path};
use vh_guard::fake::*;
use vh_guard::{AutoLevel, Engine, GuardCommand, GuardEventKind, GuardPolicy};
use vh_model::*;

use crate::common::*;

fn engine_for(scene: &Scene, policy: GuardPolicy) -> (Engine<FakeGuardBackend>, Probe, FakeClock) {
    let clock = FakeClock::at(T0);
    let (s, r) = scene.build(T0);
    let be = FakeGuardBackend::scripted(vec![(s, r)], clock.clone());
    let probe = be.probe();
    (Engine::new(policy, be), probe, clock)
}

fn scan(e: &mut Engine<FakeGuardBackend>, clock: &FakeClock) -> vh_guard::GuardUpdate {
    let u = e.scan().expect("스캔 결과");
    clock.advance(5000);
    u
}

fn audit(probe: &Probe) -> Vec<AuditEntry> {
    std::fs::read_to_string(audit_log_path(&probe.state_dir))
        .map(|t| {
            t.lines()
                .map(|l| serde_json::from_str(l).expect("감사 로그 줄"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn safe_auto_terminates_through_plan_execute_with_audit_event_and_notification() {
    let mut sc = Scene::new();
    let t = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, probe, clock) = engine_for(&sc, safe());
    let u1 = scan(&mut e, &clock);
    assert_eq!(u1.status.scan_seq, 1);
    assert_eq!(u1.status.pending.len(), 1);
    assert!(probe.log.sent().is_empty());

    let u2 = scan(&mut e, &clock);
    assert_eq!(probe.log.sent(), vec![(101, libc::SIGTERM)]);
    assert!(!probe.world.alive(t));
    assert_eq!(count(&u2.new_events, GuardEventKind::AutoTerminated), 1);
    let ev = u2
        .new_events
        .iter()
        .find(|e| e.kind == GuardEventKind::AutoTerminated)
        .unwrap();
    assert_eq!(ev.target, Some(t));
    assert_eq!(ev.reclaimed_bytes, 100 * 1024 * 1024);
    assert_eq!(ev.run_id.as_deref(), Some("guard-2"));
    assert_eq!(count(&u2.new_events, GuardEventKind::Notified), 1);
    assert_eq!(probe.notifications().len(), 1);
    assert!(probe.notifications()[0].1.contains("종료"));
    assert_eq!(u2.status.terminations_in_window, 1);
    assert!(u2.status.pending.is_empty());

    let log = audit(&probe);
    assert!(
        log.iter()
            .any(|a| a.event == AuditEvent::Term && a.subject_pid == 101)
    );
    assert!(
        log.iter()
            .any(|a| a.event == AuditEvent::Exited && a.run_id == "guard-2")
    );

    let u3 = scan(&mut e, &clock);
    assert!(
        u3.report.findings.is_empty(),
        "사라진 프로세스는 다음 스냅샷에 없다"
    );
    assert_eq!(probe.log.sent().len(), 1);
}

#[test]
fn every_signal_goes_through_execute_audit_matches_signaler() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    sc.leftover(
        102,
        Kind::DevServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let r = sc.plain(103, Kind::Watcher, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    e.backend_mut().cpu_rate_pct.insert(r.pid, 250.0);
    for _ in 0..5 {
        scan(&mut e, &clock);
    }
    let log = audit(&probe);
    let signals = log
        .iter()
        .filter(|a| {
            matches!(
                a.event,
                AuditEvent::Term
                    | AuditEvent::Kill
                    | AuditEvent::Cont
                    | AuditEvent::Demote
                    | AuditEvent::Undemote
            )
        })
        .count();
    assert_eq!(signals, probe.log.calls());
    assert_eq!(probe.log.demoted(), vec![103]);
    assert_eq!(probe.log.sent().len(), 2);
}

#[test]
fn protection_rules_refuse_even_when_decide_said_yes() {
    let mut sc = Scene::new();
    let t = sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    sc.procs.iter_mut().find(|p| p.pid == 101).unwrap().exe = Some("/System/Library/x".into());
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let u2 = scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty());
    let refused: Vec<_> = u2
        .new_events
        .iter()
        .filter(|e| e.kind == GuardEventKind::Refused)
        .collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].target, Some(t));
    assert!(refused[0].detail_ko.starts_with("R05"));
    assert_eq!(
        u2.status.terminations_in_window, 0,
        "거부된 것은 시도로 세지 않는다"
    );
    let u3 = scan(&mut e, &clock);
    assert_eq!(
        count(&u3.new_events, GuardEventKind::Refused),
        0,
        "같은 거부를 반복하지 않는다"
    );
    assert!(probe.log.sent().is_empty());
}

#[test]
fn rate_limit_trips_circuit_then_notify_only_until_reset() {
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
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let u2 = scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty(), "할당량을 넘는 스캔은 0건 실행");
    assert!(u2.status.circuit_open);
    assert_eq!(u2.status.circuit_opened_at_unix_ms, Some(T0 + 5000));
    assert_eq!(count(&u2.new_events, GuardEventKind::CircuitOpen), 1);
    assert_eq!(probe.notifications().len(), 1);
    assert!(probe.notifications()[0].1.contains("멈췄어요"));

    clock.advance(60_000);
    let u3 = scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty());
    assert_eq!(count(&u3.new_events, GuardEventKind::CircuitOpen), 0);
    assert_eq!(count(&u3.new_events, GuardEventKind::AutoTerminated), 0);

    let u = e.handle(GuardCommand::ResetCircuit).unwrap();
    assert!(!u.status.circuit_open);
    assert_eq!(count(&u.new_events, GuardEventKind::CircuitReset), 1);
    assert!(
        e.handle(GuardCommand::ResetCircuit)
            .unwrap()
            .new_events
            .is_empty()
    );

    sc.findings.truncate(3);
    sc.procs.truncate(4);
    sc.classified.truncate(3);
    let (s, r) = sc.build(clock.now());
    e.backend_mut().push_script(s, r);
    e.backend_mut().script.pop_front();
    scan(&mut e, &clock);
    scan(&mut e, &clock);
    assert_eq!(probe.log.sent().len(), 3, "3개(≤5)는 2회 확인 뒤 실행");
}

#[test]
fn pause_blocks_everything_and_resume_needs_fresh_confirmation() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let u = e.handle(GuardCommand::Pause).unwrap();
    assert!(u.status.paused);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Paused]);
    assert!(e.handle(GuardCommand::Pause).unwrap().new_events.is_empty());
    for _ in 0..3 {
        let u = scan(&mut e, &clock);
        assert!(u.status.pending.is_empty());
    }
    assert!(probe.log.sent().is_empty());
    let u = e.handle(GuardCommand::Resume).unwrap();
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Resumed]);
    scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty(), "재개 뒤 첫 스캔은 1/2");
    scan(&mut e, &clock);
    assert_eq!(probe.log.sent().len(), 1);
}

#[test]
fn set_level_changes_policy_and_env_lock_refuses() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let u = e
        .handle(GuardCommand::SetLevel(AutoLevel::NotifyOnly))
        .unwrap();
    assert_eq!(u.status.level, AutoLevel::NotifyOnly);
    assert_eq!(u.policy.level, AutoLevel::NotifyOnly);
    assert!(u.policy.auto_terminate_kinds.is_empty());
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::LevelChanged]);
    for _ in 0..3 {
        scan(&mut e, &clock);
    }
    assert!(probe.log.sent().is_empty());
    assert_eq!(
        probe.notifications().len(),
        1,
        "알림만 수준: 후보를 한 번 알림"
    );
    e.handle(GuardCommand::SetLevel(AutoLevel::Safe)).unwrap();
    scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty());
    scan(&mut e, &clock);
    assert_eq!(probe.log.sent().len(), 1);

    let (s, r) = sc.build(T0);
    let be = FakeGuardBackend::scripted(vec![(s, r)], FakeClock::at(T0));
    let mut locked = Engine::new(safe(), be).level_locked_by_env(true);
    locked.scan();
    let u = locked
        .handle(GuardCommand::SetLevel(AutoLevel::Aggressive))
        .unwrap();
    assert_eq!(u.status.level, AutoLevel::Safe);
    assert!(u.status.level_locked_by_env);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Refused]);
}

#[test]
fn set_scan_interval_updates_policy_and_next_scan() {
    let sc = Scene::new();
    let (mut e, _probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let u = e.handle(GuardCommand::SetScanInterval(30_000)).unwrap();
    assert_eq!(u.policy.scan_interval_ms, 30_000);
    assert!(u.new_events.is_empty());
    let u = scan(&mut e, &clock);
    assert_eq!(u.status.next_scan_at_unix_ms, clock.now() - 5000 + 30_000);
    let u = e.handle(GuardCommand::SetScanInterval(10)).unwrap();
    assert_eq!(u.policy.scan_interval_ms, 1000);
}

#[test]
fn demote_after_three_scans_undo_restores_and_events_dedupe() {
    let mut sc = Scene::new();
    let r = sc.plain(201, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    e.backend_mut().cpu_rate_pct.insert(201, 180.0);
    scan(&mut e, &clock);
    let u2 = scan(&mut e, &clock);
    assert_eq!(u2.status.pending.len(), 1);
    assert_eq!(u2.status.pending[0].step, Step::Demote);
    assert_eq!(u2.status.pending[0].seen_scans, 1, "첫 스캔은 cpu_pct 없음");
    scan(&mut e, &clock);
    let u4 = scan(&mut e, &clock);
    assert_eq!(probe.log.demoted(), vec![201]);
    assert_eq!(probe.world.bg_of(201), Some(libc::PRIO_DARWIN_BG));
    assert_eq!(count(&u4.new_events, GuardEventKind::Demoted), 1);
    assert_eq!(u4.status.demoted.len(), 1);
    assert_eq!(u4.status.demoted[0].target, r);
    assert!(u4.status.demoted[0].label_ko.contains("CPU"));
    let u5 = scan(&mut e, &clock);
    assert_eq!(count(&u5.new_events, GuardEventKind::Demoted), 0);
    assert_eq!(probe.log.demoted().len(), 1);

    let u = e.handle(GuardCommand::UndoDemote(r)).unwrap();
    assert_eq!(probe.log.undemoted(), vec![201]);
    assert_eq!(probe.world.bg_of(201), None);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Undemoted]);
    assert!(u.status.demoted.is_empty());
    let log = audit(&probe);
    assert!(log.iter().any(|a| a.event == AuditEvent::Demote && a.ok));
    assert!(
        log.iter()
            .any(|a| a.event == AuditEvent::Undemote && a.ok && a.run_id.starts_with("guard-undo"))
    );

    let u = e.handle(GuardCommand::UndoDemote(r)).unwrap();
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Refused]);
    assert_eq!(probe.log.undemoted().len(), 1);
}

#[test]
fn shutdown_restores_all_demoted_and_reports_vanished_without_signal() {
    let mut sc = Scene::new();
    let a = sc.plain(201, Kind::DevServer, OLD);
    let b = sc.plain(202, Kind::Watcher, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    e.backend_mut().cpu_rate_pct.insert(201, 150.0);
    e.backend_mut().cpu_rate_pct.insert(202, 150.0);
    for _ in 0..4 {
        scan(&mut e, &clock);
    }
    assert_eq!(probe.log.demoted(), vec![201, 202]);
    probe.world.with(|w| w.remove(202));
    let (report, events) = e.restore_all();
    assert_eq!(report.undemoted, vec![a, b]);
    assert!(report.failed.is_empty());
    assert_eq!(probe.log.undemoted(), vec![201], "사라진 것에는 신호 0");
    assert_eq!(count(&events, GuardEventKind::Undemoted), 2);
    assert!(e.status().demoted.is_empty());
}

#[test]
fn shutdown_failure_is_reported_with_errno() {
    let mut sc = Scene::new();
    let a = sc.plain(201, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    e.backend_mut().cpu_rate_pct.insert(201, 150.0);
    for _ in 0..4 {
        scan(&mut e, &clock);
    }
    assert_eq!(probe.log.demoted(), vec![201]);
    let failing = SyncSignaler {
        world: probe.world.clone(),
        log: probe.log.clone(),
        fail_with: Some(libc::EPERM),
    };
    e.backend_mut().signaler = Box::new(failing);
    let (report, events) = e.restore_all();
    assert_eq!(report.failed, vec![(a, libc::EPERM)]);
    assert!(report.undemoted.is_empty());
    assert_eq!(kinds(&events), vec![GuardEventKind::Refused]);
    assert_eq!(e.status().demoted.len(), 1, "실패한 것은 목록에 남는다");
}

#[test]
fn manual_run_plan_does_not_count_and_its_demote_is_restored_at_shutdown() {
    let mut sc = Scene::new();
    let t = sc.leftover(101, Kind::McpServer, Confidence::Likely, OLD, Some(false));
    let d = sc.plain(202, Kind::DevServer, OLD);
    sc.findings.push(finding(
        "run:202",
        FindingKind::HighCpu,
        Confidence::Possible,
        vec![d],
        Suggestion::Demote,
        0,
    ));
    let (mut e, probe, clock) = engine_for(&sc, safe());
    let u1 = scan(&mut e, &clock);
    let sel = Selection {
        finding_ids: vec!["orphan:101".into(), "run:202".into()],
        pids: Vec::new(),
        min_confidence: Confidence::Possible,
        direct: Vec::new(),
    };
    let pol = Policy {
        allow_demote: true,
        ..Policy::default()
    };
    let plan = vh_act::plan(&u1.snapshot, &u1.report, &sel, &pol);
    assert_eq!(plan.items.len(), 2, "{:?}", plan.refused);
    let u = e
        .handle(GuardCommand::RunPlan {
            request_id: 7,
            plan,
            snapshot: Arc::clone(&u1.snapshot),
        })
        .unwrap();
    let m = u.manual_result.expect("manual_result");
    assert_eq!(m.request_id, 7);
    assert_eq!(m.outcomes.len(), 2);
    assert_eq!(m.state_dir, probe.state_dir);
    assert!(!probe.world.alive(t));
    assert_eq!(probe.log.demoted(), vec![202]);
    assert_eq!(
        u.status.terminations_in_window, 0,
        "수동 실행은 속도 제한에 세지 않는다"
    );
    assert_eq!(u.status.demoted.len(), 1);
    assert_eq!(count(&u.new_events, GuardEventKind::Demoted), 1);
    assert_eq!(count(&u.new_events, GuardEventKind::AutoTerminated), 0);
    let (report, _) = e.restore_all();
    assert_eq!(report.undemoted, vec![d]);
    assert_eq!(probe.log.undemoted(), vec![202]);
}

#[test]
fn notifications_batch_per_scan_and_respect_30s() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    sc.leftover(102, Kind::LocalLlm, Confidence::Confirmed, OLD, Some(false));
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    assert_eq!(probe.notifications().len(), 1, "두 알림 후보 → 한 알림");
    let body = &probe.notifications()[0].1;
    assert!(
        body.contains("Emulator 101") && body.contains("LocalLlm 102"),
        "{body}"
    );
    for _ in 0..5 {
        scan(&mut e, &clock);
    }
    assert_eq!(
        probe.notifications().len(),
        1,
        "같은 (대상, 사유)는 다시 알리지 않는다"
    );

    sc.leftover(103, Kind::Tunnel, Confidence::Confirmed, OLD, Some(false));
    let (s, r) = sc.build(clock.now());
    e.backend_mut().script.clear();
    e.backend_mut().push_script(s, r);
    probe.world.with(|w| {
        w.insert(vh_act::LiveProc::alive(
            103,
            OLD,
            1,
            UID,
            Some("/opt/homebrew/bin/p103"),
        ));
    });
    let u = scan(&mut e, &clock);
    assert_eq!(probe.notifications().len(), 2);
    assert_eq!(count(&u.new_events, GuardEventKind::Notified), 1);
    assert!(probe.notifications()[1].1.contains("Tunnel 103"));
}

#[test]
fn notification_rate_limit_queues_and_merges() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    let (mut e, probe, clock) = engine_for(&sc, safe());
    e.scan();
    assert_eq!(probe.notifications().len(), 1);
    clock.advance(5000);
    sc.leftover(102, Kind::LocalLlm, Confidence::Confirmed, OLD, Some(false));
    let (s, r) = sc.build(clock.now());
    e.backend_mut().script.clear();
    e.backend_mut().push_script(s, r);
    probe.world.with(|w| {
        w.insert(vh_act::LiveProc::alive(
            102,
            OLD,
            1,
            UID,
            Some("/opt/homebrew/bin/p102"),
        ));
    });
    let u = e.scan().unwrap();
    assert_eq!(
        probe.notifications().len(),
        1,
        "30초 안에는 보내지 않고 모아 둔다"
    );
    assert_eq!(count(&u.new_events, GuardEventKind::Notified), 0);
    clock.advance(30_000);
    let u = e.scan().unwrap();
    assert_eq!(probe.notifications().len(), 2);
    assert!(probe.notifications()[1].1.contains("LocalLlm 102"));
    assert_eq!(count(&u.new_events, GuardEventKind::Notified), 1);
}

#[test]
fn collect_error_becomes_scan_error_and_keeps_last_snapshot() {
    let mut sc = Scene::new();
    sc.plain(101, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    probe.set_collect_error(Some("권한 없음"));
    let u = e.scan().expect("마지막 스냅샷으로 갱신");
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::ScanError]);
    assert_eq!(u.status.scan_error_streak, 1);
    assert_eq!(u.status.scan_seq, 1);
    assert_eq!(u.snapshot.processes.len(), 2);
    probe.set_collect_error(None);
    let u = scan(&mut e, &clock);
    assert_eq!(u.status.scan_error_streak, 0);
    assert_eq!(u.status.scan_seq, 2);
}

#[test]
fn first_collect_error_yields_no_update_then_recovers() {
    let sc = Scene::new();
    let (mut e, probe, _clock) = engine_for(&sc, safe());
    probe.set_collect_error(Some("x"));
    assert!(e.scan().is_none());
    probe.set_collect_error(None);
    let u = e.scan().unwrap();
    assert_eq!(
        kinds(&u.new_events),
        vec![GuardEventKind::ScanError],
        "모아 둔 이벤트를 첫 갱신에 붙인다"
    );
}

#[test]
fn cpu_pct_is_filled_from_previous_scan_and_analyze_gets_interval() {
    let mut sc = Scene::new();
    sc.plain(101, Kind::DevServer, OLD);
    let (mut e, _probe, clock) = engine_for(&sc, safe());
    e.backend_mut().cpu_rate_pct.insert(101, 40.0);
    let u1 = scan(&mut e, &clock);
    let p1 = u1.snapshot.processes.iter().find(|p| p.pid == 101).unwrap();
    assert_eq!(p1.cpu_pct, None);
    assert_eq!(u1.snapshot.cpu_sample_interval_ms, None);
    let u2 = scan(&mut e, &clock);
    let p2 = u2.snapshot.processes.iter().find(|p| p.pid == 101).unwrap();
    let pct = p2.cpu_pct.expect("두 번째 스캔부터 CPU%");
    assert!((pct - 40.0).abs() < 0.5, "{pct}");
    assert_eq!(u2.snapshot.cpu_sample_interval_ms, Some(5000));
}

#[test]
fn status_reflects_memory() {
    let mut sc = Scene::new();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (mut e, _probe, clock) = engine_for(&sc, safe());
    let u = scan(&mut e, &clock);
    assert_eq!(u.status.level, AutoLevel::Safe);
    assert!(!u.status.level_locked_by_env);
    assert!(!u.status.paused && !u.status.circuit_open);
    assert_eq!(u.status.last_scan_at_unix_ms, T0);
    assert_eq!(u.status.next_scan_at_unix_ms, T0 + 5000);
    assert_eq!(u.status.pending[0].kind, Kind::McpServer);
    assert_eq!(*u.policy, safe());
    assert!(u.manual_result.is_none());
}

fn demote_201(e: &mut Engine<FakeGuardBackend>, probe: &Probe, clock: &FakeClock) {
    e.backend_mut().cpu_rate_pct.insert(201, 180.0);
    for _ in 0..4 {
        scan(e, clock);
    }
    assert_eq!(probe.log.demoted(), vec![201]);
    assert_eq!(e.status().demoted.len(), 1);
}

#[test]
fn vanished_demoted_is_pruned_on_next_scan_once_without_signal() {
    let mut sc = Scene::new();
    sc.plain(201, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    demote_201(&mut e, &probe, &clock);
    probe.world.with(|w| w.remove(201));
    let u = scan(&mut e, &clock);
    assert_eq!(count(&u.new_events, GuardEventKind::Undemoted), 1);
    let ev = u
        .new_events
        .iter()
        .find(|x| x.kind == GuardEventKind::Undemoted)
        .unwrap();
    assert!(ev.detail_ko.contains("이미 끝난"), "{}", ev.detail_ko);
    assert!(u.status.demoted.is_empty());
    assert!(probe.log.undemoted().is_empty(), "사라진 것에는 신호 0");
    let u = scan(&mut e, &clock);
    assert_eq!(
        count(&u.new_events, GuardEventKind::Undemoted),
        0,
        "한 번만"
    );
    let (report, events) = e.restore_all();
    assert!(report.undemoted.is_empty() && report.failed.is_empty());
    assert!(events.is_empty());
}

#[test]
fn pid_reuse_of_demoted_counts_as_gone_without_signal() {
    let mut sc = Scene::new();
    sc.plain(201, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    demote_201(&mut e, &probe, &clock);
    probe.world.with(|w| {
        w.remove(201);
        w.insert(vh_act::LiveProc::alive(
            201,
            OLD + 1,
            1,
            UID,
            Some("/opt/homebrew/bin/p201"),
        ));
    });
    let mut sc2 = Scene::new();
    sc2.plain(201, Kind::DevServer, OLD + 1);
    let (s, r) = sc2.build(clock.now());
    e.backend_mut().script.clear();
    e.backend_mut().push_script(s, r);
    let u = scan(&mut e, &clock);
    assert_eq!(count(&u.new_events, GuardEventKind::Undemoted), 1);
    assert!(u.status.demoted.is_empty());
    assert!(probe.log.undemoted().is_empty(), "재사용된 PID에는 신호 0");
}

#[test]
fn gone_undemote_failure_is_not_retried_every_scan_but_at_shutdown() {
    let mut sc = Scene::new();
    let a = sc.plain(201, Kind::DevServer, OLD);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    demote_201(&mut e, &probe, &clock);
    e.backend_mut().signaler = Box::new(SyncSignaler {
        world: probe.world.clone(),
        log: probe.log.clone(),
        fail_with: Some(libc::EPERM),
    });
    let (s, r) = Scene::new().build(clock.now());
    e.backend_mut().script.clear();
    e.backend_mut().push_script(s, r);
    let u = scan(&mut e, &clock);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Refused]);
    assert_eq!(u.status.demoted.len(), 1, "실패한 것은 목록에 남는다");
    assert_eq!(probe.log.undemoted(), vec![201]);
    let u = scan(&mut e, &clock);
    assert!(u.new_events.is_empty(), "{:?}", kinds(&u.new_events));
    assert_eq!(
        probe.log.undemoted(),
        vec![201],
        "스캔마다 다시 시도하지 않는다"
    );
    let (report, _) = e.restore_all();
    assert_eq!(report.failed, vec![(a, libc::EPERM)]);
    assert_eq!(probe.log.undemoted(), vec![201, 201], "종료 때는 다시 시도");
}

#[test]
fn buffered_events_capped_keeping_latest() {
    let sc = Scene::new();
    let (mut e, probe, _clock) = engine_for(&sc, safe());
    for i in 0..150 {
        probe.set_collect_error(Some(&format!("x{i}")));
        assert!(e.scan().is_none());
    }
    probe.set_collect_error(None);
    let u = e.scan().unwrap();
    assert_eq!(
        count(&u.new_events, GuardEventKind::ScanError),
        vh_guard::engine::MAX_BUFFERED_EVENTS
    );
    assert!(
        u.new_events[0].detail_ko.ends_with("x50"),
        "{}",
        u.new_events[0].detail_ko
    );
    assert!(u.new_events[99].detail_ko.ends_with("x149"));
}

#[test]
fn policy_arc_is_shared_until_changed() {
    let sc = Scene::new();
    let (mut e, _probe, clock) = engine_for(&sc, safe());
    let u1 = scan(&mut e, &clock);
    let u2 = scan(&mut e, &clock);
    assert!(Arc::ptr_eq(&u1.policy, &u2.policy));
    let u3 = e.handle(GuardCommand::SetScanInterval(7000)).unwrap();
    assert!(!Arc::ptr_eq(&u2.policy, &u3.policy));
    assert_eq!(u3.policy.scan_interval_ms, 7000);
    assert_eq!(
        u2.policy.scan_interval_ms, 5000,
        "이미 보낸 갱신의 값은 그대로"
    );
    assert_eq!(e.policy().scan_interval_ms, 7000);
}

#[test]
fn notifications_distinguish_same_named_targets() {
    let mut sc = Scene::new();
    sc.leftover(101, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    sc.leftover(102, Kind::Emulator, Confidence::Confirmed, OLD, Some(false));
    for c in &mut sc.classified {
        c.label_ko = "MCP 서버: chrome-devtools".into();
    }
    sc.classified[0].project = Some("~/dev/alpha".into());
    let (mut e, probe, clock) = engine_for(&sc, safe());
    scan(&mut e, &clock);
    let body = &probe.notifications()[0].1;
    assert!(body.contains("MCP 서버: chrome-devtools (alpha)"), "{body}");
    assert!(
        body.contains("MCP 서버: chrome-devtools (pid 102)"),
        "{body}"
    );
}

#[test]
fn young_orphan_pending_shows_in_status_without_signal() {
    let mut sc = Scene::new();
    let p = proc_(101, 1, UID, T0 - 9 * 60_000, "p101");
    let r = pref(&p);
    sc.procs.push(p);
    sc.classified
        .push(classified(r, Kind::McpServer, "MCP 서버: x", None));
    let mut f = finding(
        "orphan:101",
        FindingKind::Orphan,
        Confidence::Possible,
        vec![r],
        Suggestion::Review,
        0,
    );
    f.reason_codes = vec!["young".into()];
    sc.findings.push(f);
    let (mut e, probe, clock) = engine_for(&sc, safe());
    let u = scan(&mut e, &clock);
    assert_eq!(u.status.pending.len(), 1);
    assert_eq!(u.status.pending[0].eta_ms, Some(60_000));
    scan(&mut e, &clock);
    assert!(probe.log.sent().is_empty(), "표시뿐, 신호 0");
}
