//! GUARD_5 스레드·손잡이. 기다림은 모두 채널 recv_timeout(상한 10초)로, 고정 sleep 없음.

use std::time::Duration;

use vh_act::PlanOrigin;
use vh_guard::fake::*;
use vh_guard::{AutoLevel, GuardCommand, GuardEventKind, GuardHandle, GuardUpdate, UpdateReceiver};
use vh_model::*;

use crate::common::*;

const WAIT: Duration = Duration::from_secs(10);

fn next(rx: &UpdateReceiver) -> GuardUpdate {
    rx.recv_timeout(WAIT).expect("10초 안에 GuardUpdate")
}

fn backend(scene: &Scene) -> (FakeGuardBackend, Probe, FakeClock) {
    let clock = FakeClock::at(T0);
    let (s, r) = scene.build(T0);
    let be = FakeGuardBackend::scripted(vec![(s, r)], clock.clone());
    let probe = be.probe();
    (be, probe, clock)
}

fn demoted_scene() -> (Scene, ProcRef) {
    let mut sc = Scene::unstable();
    let r = sc.plain(201, Kind::DevServer, OLD);
    (sc, r)
}

/// 첫 갱신을 받아 201을 화면 직접 낮추기(RunPlan, Pointed)로 낮춘다(W4: 자동 낮추기 없음).
fn drive_to_demote(h: &GuardHandle, rx: &UpdateReceiver, clock: &FakeClock) -> GuardUpdate {
    let first = next(rx);
    assert_eq!(first.status.scan_seq, 1);
    clock.advance(5000);
    let r = ProcRef {
        pid: 201,
        start_time_unix_ms: OLD,
    };
    let plan = demote_plan(&first, &[r]);
    h.run_plan_as(1, plan, first.snapshot.clone(), PlanOrigin::Pointed)
        .unwrap();
    let last = next(rx);
    assert_eq!(last.status.demoted.len(), 1, "{:?}", last.status);
    last
}

#[test]
fn spawn_sends_first_update_immediately() {
    let mut sc = Scene::unstable();
    sc.leftover(
        101,
        Kind::McpServer,
        Confidence::Confirmed,
        OLD,
        Some(false),
    );
    let (be, probe, _clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn(safe(), be);
    let u = next(&rx);
    assert_eq!(u.status.scan_seq, 1);
    assert_eq!(u.status.level, AutoLevel::Safe);
    assert_eq!(u.status.pending.len(), 1);
    assert_eq!(probe.collects(), 1);
    assert!(h.is_alive());
    let report = h.shutdown();
    assert!(report.undemoted.is_empty() && report.failed.is_empty());
}

#[test]
fn scan_now_triggers_scan_and_commands_return_status_updates() {
    let sc = Scene::unstable();
    let (be, probe, clock) = backend(&sc);
    let mut policy = safe();
    policy.scan_interval_ms = 600_000;
    let (h, rx) = GuardHandle::spawn(policy, be);
    assert_eq!(next(&rx).status.scan_seq, 1);
    clock.advance(1000);
    h.scan_now().unwrap();
    assert_eq!(next(&rx).status.scan_seq, 2);
    h.pause().unwrap();
    let u = next(&rx);
    assert!(u.status.paused);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Paused]);
    assert_eq!(u.status.scan_seq, 2, "명령 갱신은 스캔하지 않는다");
    assert_eq!(probe.collects(), 2);
    h.set_scan_interval(5000).unwrap();
    assert_eq!(next(&rx).policy.scan_interval_ms, 5000);
    drop(h);
}

#[test]
fn shutdown_restores_demoted_joins_and_then_send_fails() {
    let (sc, r) = demoted_scene();
    let (be, probe, clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn(safe(), be);
    drive_to_demote(&h, &rx, &clock);
    assert_eq!(probe.log.demoted(), vec![201]);
    let report = h.shutdown();
    assert_eq!(report.undemoted, vec![r]);
    assert!(report.failed.is_empty());
    assert_eq!(probe.log.undemoted(), vec![201]);
    assert_eq!(probe.world.bg_of(201), None);
    let last = rx.recv_timeout(WAIT).expect("종료 갱신");
    assert!(last.status.demoted.is_empty());
    assert_eq!(count(&last.new_events, GuardEventKind::Undemoted), 1);
    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "스레드가 끝나 더 오지 않는다"
    );
}

#[test]
fn drop_without_shutdown_still_restores() {
    let (sc, _r) = demoted_scene();
    let (be, probe, clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn(safe(), be);
    drive_to_demote(&h, &rx, &clock);
    drop(h);
    assert_eq!(probe.log.undemoted(), vec![201]);
    assert!(
        rx.recv_timeout(WAIT).is_ok(),
        "종료 갱신이 온 뒤 채널이 닫힌다"
    );
    assert!(rx.recv_timeout(WAIT).is_err());
}

#[test]
fn receiver_dropped_makes_thread_restore_and_exit() {
    let (sc, _r) = demoted_scene();
    let (be, probe, clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn(safe(), be);
    drive_to_demote(&h, &rx, &clock);
    drop(rx);
    h.scan_now().unwrap();
    let report = h.shutdown();
    assert_eq!(probe.log.undemoted(), vec![201]);
    assert_eq!(report.undemoted.len(), 1);
}

#[test]
fn scan_panic_becomes_scan_error_thread_survives_and_restores_on_shutdown() {
    let (sc, _r) = demoted_scene();
    let (be, probe, clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn(safe(), be);
    drive_to_demote(&h, &rx, &clock);
    probe.set_collect_panic(true);
    h.scan_now().unwrap();
    let u = next(&rx);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::ScanError]);
    assert!(u.new_events[0].detail_ko.contains("패닉"));
    assert_eq!(u.status.scan_error_streak, 1);
    assert!(h.is_alive());
    probe.set_collect_panic(false);
    h.scan_now().unwrap();
    assert_eq!(next(&rx).status.scan_error_streak, 0);
    let report = h.shutdown();
    assert_eq!(report.undemoted.len(), 1);
    assert_eq!(probe.log.undemoted(), vec![201]);
}

#[test]
fn spawn_with_env_lock_refuses_set_level() {
    let sc = Scene::unstable();
    let (be, _probe, _clock) = backend(&sc);
    let (h, rx) = GuardHandle::spawn_with(notify_only(), be, true);
    assert!(next(&rx).status.level_locked_by_env);
    h.set_level(AutoLevel::Safe).unwrap();
    let u = next(&rx);
    assert_eq!(u.status.level, AutoLevel::NotifyOnly);
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Refused]);
    h.send(GuardCommand::Shutdown).unwrap();
    let _ = h.shutdown();
}

#[test]
fn updates_not_received_are_merged_and_none_lost() {
    let sc = Scene::unstable();
    let (be, _probe, _clock) = backend(&sc);
    let mut policy = safe();
    policy.scan_interval_ms = 600_000;
    let (h, rx) = GuardHandle::spawn(policy, be);
    assert_eq!(next(&rx).status.scan_seq, 1);
    h.pause().unwrap();
    h.resume().unwrap();
    h.set_level(AutoLevel::NotifyOnly).unwrap();
    let _ = h.shutdown();
    let u = rx.try_recv().expect("합친 갱신 하나");
    assert_eq!(
        kinds(&u.new_events),
        vec![
            GuardEventKind::Paused,
            GuardEventKind::Resumed,
            GuardEventKind::LevelChanged
        ]
    );
    assert_eq!(u.status.level, AutoLevel::NotifyOnly);
    assert_eq!(
        rx.try_recv().unwrap_err(),
        std::sync::mpsc::TryRecvError::Disconnected
    );
}

#[test]
fn run_plan_result_is_kept_when_merged_with_later_updates() {
    let sc = Scene::unstable();
    let (be, _probe, _clock) = backend(&sc);
    let mut policy = safe();
    policy.scan_interval_ms = 600_000;
    let (h, rx) = GuardHandle::spawn(policy, be);
    let first = next(&rx);
    let plan = ActionPlan {
        created_at_unix_ms: T0,
        total_deadline_ms: 1000,
        items: Vec::new(),
        refused: Vec::new(),
    };
    h.run_plan(7, plan, first.snapshot.clone()).unwrap();
    h.pause().unwrap();
    let _ = h.shutdown();
    let u = rx.try_recv().expect("합친 갱신 하나");
    assert_eq!(u.manual_result.map(|m| m.request_id), Some(7));
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Paused]);
    assert!(rx.try_recv().is_err());
}
