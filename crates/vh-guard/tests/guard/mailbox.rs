//! W3 PM-1 갱신 우편함: 받지 않은 갱신은 하나로 합치고(메모리 상한), 이벤트·수동 결과는 잃지 않는다.

use std::path::PathBuf;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Barrier, Weak};
use std::time::Duration;

use vh_guard::fake::*;
use vh_guard::{Engine, GuardEvent, GuardEventKind, GuardUpdate, ManualRunResult, mailbox};
use vh_model::*;

use crate::common::*;

fn base() -> GuardUpdate {
    let sc = Scene::new();
    let clock = FakeClock::at(T0);
    let (s, r) = sc.build(T0);
    let be = FakeGuardBackend::scripted(vec![(s, r)], clock);
    Engine::new(safe(), be).scan().expect("첫 갱신")
}

fn ev(n: u64) -> GuardEvent {
    GuardEvent {
        at_unix_ms: T0 + n,
        kind: GuardEventKind::Notified,
        target: None,
        finding_id: None,
        run_id: None,
        label_ko: "지킴이".into(),
        detail_ko: format!("e{n}"),
        reclaimed_bytes: 0,
    }
}

fn upd(b: &GuardUpdate, seq: u64, events: Vec<GuardEvent>, manual: Option<u64>) -> GuardUpdate {
    let mut u = b.clone();
    u.snapshot = Arc::new((*b.snapshot).clone());
    u.status.scan_seq = seq;
    u.new_events = events;
    u.manual_result = manual.map(|request_id| ManualRunResult {
        request_id,
        outcomes: Vec::new(),
        state_dir: PathBuf::from("/tmp/x"),
    });
    u
}

fn details(u: &GuardUpdate) -> Vec<String> {
    u.new_events.iter().map(|e| e.detail_ko.clone()).collect()
}

#[test]
fn coalesces_and_concatenates_events_in_order() {
    let b = base();
    let (tx, rx) = mailbox();
    tx.send(upd(&b, 1, vec![ev(1)], None)).unwrap();
    tx.send(upd(&b, 2, vec![ev(2), ev(3)], None)).unwrap();
    tx.send(upd(&b, 3, Vec::new(), None)).unwrap();
    assert_eq!(rx.pending(), 1);
    let u = rx.try_recv().unwrap();
    assert_eq!(details(&u), vec!["e1", "e2", "e3"]);
    assert_eq!(u.status.scan_seq, 3, "상태는 가장 최근 것");
    assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
}

#[test]
fn sender_ahead_keeps_one_snapshot_and_every_event() {
    let b = base();
    let (tx, rx) = mailbox();
    let mut weaks: Vec<Weak<Snapshot>> = Vec::new();
    for i in 0..1000u64 {
        let u = upd(&b, i, vec![ev(i)], None);
        weaks.push(Arc::downgrade(&u.snapshot));
        tx.send(u).unwrap();
    }
    assert_eq!(rx.pending(), 1);
    let alive = weaks.iter().filter(|w| w.upgrade().is_some()).count();
    assert_eq!(alive, 1, "받지 않은 옛 스냅샷은 붙잡지 않는다");
    let u = rx.try_recv().unwrap();
    assert_eq!(u.new_events.len(), 1000);
    assert_eq!(
        details(&u),
        (0..1000).map(|i| format!("e{i}")).collect::<Vec<_>>()
    );
    assert_eq!(u.status.scan_seq, 999);
}

#[test]
fn manual_result_survives_coalescing() {
    let b = base();
    let (tx, rx) = mailbox();
    tx.send(upd(&b, 1, vec![ev(1)], Some(7))).unwrap();
    tx.send(upd(&b, 2, vec![ev(2)], None)).unwrap();
    tx.send(upd(&b, 3, vec![ev(3)], None)).unwrap();
    let u = rx.try_recv().unwrap();
    assert_eq!(u.manual_result.as_ref().map(|m| m.request_id), Some(7));
    assert_eq!(details(&u), vec!["e1", "e2", "e3"]);
    assert_eq!(u.status.scan_seq, 3);
}

#[test]
fn two_manual_results_are_both_delivered_in_order() {
    let b = base();
    let (tx, rx) = mailbox();
    tx.send(upd(&b, 1, vec![ev(1)], Some(1))).unwrap();
    tx.send(upd(&b, 2, vec![ev(2)], Some(2))).unwrap();
    tx.send(upd(&b, 3, vec![ev(3)], None)).unwrap();
    assert_eq!(rx.pending(), 2);
    let a = rx.try_recv().unwrap();
    let c = rx.try_recv().unwrap();
    assert_eq!(a.manual_result.as_ref().map(|m| m.request_id), Some(1));
    assert_eq!(details(&a), vec!["e1"]);
    assert_eq!(c.manual_result.as_ref().map(|m| m.request_id), Some(2));
    assert_eq!(details(&c), vec!["e2", "e3"]);
}

#[test]
fn disconnected_only_after_drain() {
    let b = base();
    let (tx, rx) = mailbox();
    tx.send(upd(&b, 1, vec![ev(1)], None)).unwrap();
    drop(tx);
    assert_eq!(rx.try_recv().unwrap().status.scan_seq, 1);
    assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Disconnected);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap_err(),
        RecvTimeoutError::Disconnected
    );
    assert!(rx.recv().is_err());
}

#[test]
fn iter_and_try_iter_match_std_receiver() {
    let b = base();
    let (tx, rx) = mailbox();
    tx.send(upd(&b, 1, Vec::new(), Some(1))).unwrap();
    tx.send(upd(&b, 2, Vec::new(), Some(2))).unwrap();
    assert_eq!(rx.try_iter().count(), 2);
    assert_eq!(rx.try_iter().count(), 0, "기다리지 않는다");
    tx.send(upd(&b, 3, Vec::new(), Some(3))).unwrap();
    tx.send(upd(&b, 4, Vec::new(), Some(4))).unwrap();
    drop(tx);
    let seqs: Vec<u64> = rx.iter().map(|u| u.status.scan_seq).collect();
    assert_eq!(seqs, vec![3, 4], "보내는 쪽이 끝나면 iter도 끝난다");
}

#[test]
fn send_fails_after_receiver_drop_and_queued_updates_are_freed() {
    let b = base();
    let (tx, rx) = mailbox();
    let u = upd(&b, 1, Vec::new(), None);
    let w = Arc::downgrade(&u.snapshot);
    tx.send(u).unwrap();
    drop(rx);
    assert!(w.upgrade().is_none(), "받는 쪽이 사라지면 큐도 비운다");
    let back = tx.send(upd(&b, 2, Vec::new(), None)).unwrap_err();
    assert_eq!(back.status.scan_seq, 2, "보내지 못한 갱신을 돌려받는다");
}

#[test]
fn recv_timeout_wakes_on_send_from_another_thread() {
    let b = base();
    let (tx, rx) = mailbox();
    let gate = Arc::new(Barrier::new(2));
    let g2 = Arc::clone(&gate);
    let u = upd(&b, 5, vec![ev(5)], None);
    let t = std::thread::spawn(move || {
        g2.wait();
        tx.send(u).unwrap();
        tx
    });
    gate.wait();
    let got = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("10초 안에 깨어남");
    assert_eq!(got.status.scan_seq, 5);
    let tx = t.join().unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_millis(10)).unwrap_err(),
        RecvTimeoutError::Timeout
    );
    drop(tx);
}
