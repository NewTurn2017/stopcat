use vh_lab::notify::NotifyRec;
use vh_lab::run::{ClsLite, FindingLite, KernelRec, ScanRec};
use vh_lab::signal::SignalCall;
use vh_lab::verdict::{self, Records, Verdict};
use vh_model::{
    AutoLevel, Confidence, FindingKind, GuardEvent, GuardEventKind, GuardStatus, Kind,
    PendingAction, ProcRef, Step, Suggestion,
};

const T0: u64 = 1_800_000_000_000;

fn r(pid: i32) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: T0,
    }
}

fn status(seq: u64, pending: Vec<PendingAction>, circuit: bool) -> GuardStatus {
    GuardStatus {
        level: AutoLevel::Safe,
        level_locked_by_env: true,
        paused: false,
        circuit_open: circuit,
        circuit_opened_at_unix_ms: None,
        terminations_in_window: 0,
        scan_seq: seq,
        scan_error_streak: 0,
        last_scan_at_unix_ms: 0,
        last_scan_ms: 40.0,
        next_scan_at_unix_ms: 0,
        demoted: vec![],
        pending,
    }
}

fn ev(kind: GuardEventKind, t: Option<ProcRef>, at: u64, detail: &str) -> GuardEvent {
    GuardEvent {
        at_unix_ms: at,
        kind,
        target: t,
        finding_id: None,
        run_id: None,
        label_ko: "MCP 서버: chrome-devtools".into(),
        detail_ko: detail.into(),
        reclaimed_bytes: 0,
    }
}

fn pend(t: ProcRef, seen: u32, step: Step) -> PendingAction {
    PendingAction {
        target: t,
        finding_id: "f".into(),
        kind: Kind::McpServer,
        label_ko: "x".into(),
        step,
        seen_scans: seen,
        needed_scans: 2,
        eta_ms: Some(5_000),
    }
}

fn scan(at: u64, seq: u64, pending: Vec<PendingAction>, events: Vec<GuardEvent>) -> ScanRec {
    ScanRec {
        recv_ms: at,
        taken_at_ms: at,
        status: status(seq, pending, false),
        events,
        findings: vec![],
        classified: vec![],
        procs: vec![],
        listeners: vec![],
        collection_errors: 0,
        timings_total_ms: 40.0,
    }
}

fn krec(t: ProcRef, at: u64, alive: bool) -> KernelRec {
    KernelRec {
        at_ms: at,
        r: t,
        alive,
        zombie: false,
        stopped: false,
        ppid: 1,
        pgid: 1,
        priority: Some(12),
        footprint_bytes: None,
        cpu_ns: None,
    }
}

fn terminated_at(age_ms: u64) -> Records {
    let t = r(10);
    let at = T0 + age_ms;
    Records {
        scans: vec![
            scan(at - 5_000, 1, vec![pend(t, 1, Step::Term)], vec![]),
            scan(
                at,
                2,
                vec![],
                vec![ev(GuardEventKind::AutoTerminated, Some(t), at, "")],
            ),
        ],
        kernel: vec![krec(t, at - 1_000, true), krec(t, at + 2_000, false)],
        signals: vec![SignalCall {
            at_ms: at,
            op: "send".into(),
            pid: 10,
            sig: Some(libc::SIGTERM),
            allowed: true,
            ok: true,
            errno: None,
        }],
        notes: vec![NotifyRec {
            at_ms: at + 100,
            title: "vh 지킴이".into(),
            body: "MCP 서버: chrome-devtools 종료(100MB 회수)".into(),
        }],
        audit: vec![serde_json::json!({"target": {"pid": 10}})],
        undemoted: vec![],
        markers: Default::default(),
    }
}

#[test]
fn auto_terminated_pass_and_too_early_fail() {
    let ok = verdict::auto_terminated("S1", &terminated_at(605_000), r(10), None);
    assert_eq!(ok.verdict, Verdict::Pass, "{:?}", ok.checks);
    let early = verdict::auto_terminated("S1", &terminated_at(540_000), r(10), None);
    assert_eq!(early.verdict, Verdict::Fail);
    assert!(!early.checks["age_ge_10m"]);
    let late = verdict::auto_terminated("S1", &terminated_at(700_000), r(10), None);
    assert!(!late.checks["age_within_window"]);
}

#[test]
fn missing_termination_blames_by_finding() {
    let t = r(10);
    let mut rec = Records {
        scans: vec![scan(T0 + 700_000, 1, vec![], vec![])],
        ..Default::default()
    };
    rec.scans[0].findings.push(FindingLite {
        id: "o".into(),
        kind: FindingKind::Orphan,
        confidence: Confidence::Confirmed,
        suggestion: Suggestion::Terminate {
            include_descendants: true,
        },
        targets: vec![t],
        short_ko: String::new(),
        reason_codes: vec!["owner_dead".into()],
    });
    let it = verdict::auto_terminated("S1", &rec, t, None);
    assert_eq!(
        (it.verdict, it.suspected_owner.as_str()),
        (Verdict::Fail, "GUARD")
    );
    rec.scans[0].findings[0].confidence = Confidence::Possible;
    let it = verdict::auto_terminated("S1", &rec, t, None);
    assert_eq!(it.suspected_owner, "CORE");
}

#[test]
fn circuit_pass_and_spread_inconclusive() {
    let ts: Vec<ProcRef> = (0..7).map(|i| r(100 + i)).collect();
    let mut rec = Records {
        scans: vec![scan(
            T0,
            1,
            vec![],
            vec![ev(
                GuardEventKind::CircuitOpen,
                None,
                T0,
                "자동 종료 후보 7개가 한꺼번에 나와",
            )],
        )],
        kernel: ts.iter().map(|t| krec(*t, T0 + 1, true)).collect(),
        notes: vec![NotifyRec {
            at_ms: T0,
            title: "t".into(),
            body: "자동 종료를 멈췄어요".into(),
        }],
        ..Default::default()
    };
    rec.scans[0].status.circuit_open = true;
    assert_eq!(verdict::circuit(&rec, &ts).verdict, Verdict::Pass);

    let mut spread: Vec<ProcRef> = ts.clone();
    spread[6].start_time_unix_ms += 9_000;
    rec.scans.push(scan(
        T0 + 5_000,
        2,
        vec![],
        vec![ev(
            GuardEventKind::AutoTerminated,
            Some(spread[0]),
            T0 + 5_000,
            "",
        )],
    ));
    assert_eq!(
        verdict::circuit(&rec, &spread).verdict,
        Verdict::Inconclusive
    );
    assert_eq!(verdict::circuit(&rec, &ts).verdict, Verdict::Fail);
}

#[test]
fn demote_without_sustained_cpu_is_inconclusive() {
    let t = r(10);
    let mut rec = Records {
        scans: (0..4)
            .map(|i| scan(T0 + i * 5_000, i, vec![], vec![]))
            .collect(),
        ..Default::default()
    };
    for s in &mut rec.scans {
        s.procs.push(vh_lab::run::ProcLite {
            r: t,
            ppid: 2,
            pgid: 2,
            name: "lab-spin".into(),
            status: vh_model::ProcStatus::Running,
            has_tty: false,
            footprint_bytes: None,
            cpu_pct: Some(95.0),
            argv_len: 0,
            argv_sha256: String::new(),
            argv: None,
        });
    }
    let it = verdict::demoted_and_restored(&rec, t, Some(12));
    assert_eq!(it.verdict, Verdict::Inconclusive);
}

#[test]
fn notify_only_requires_exactly_one_mention() {
    let t = r(10);
    let mut rec = Records {
        scans: vec![scan(T0, 1, vec![], vec![])],
        kernel: vec![krec(t, T0, true)],
        notes: vec![NotifyRec {
            at_ms: T0,
            title: "t".into(),
            body: "Android 에뮬레이터(qemu) 알림".into(),
        }],
        ..Default::default()
    };
    rec.scans[0].classified.push(ClsLite {
        target: t,
        kind: Kind::Emulator,
        signature_id: None,
        owner_alive: Some(false),
        owner_source: None,
        label_ko: "Android 에뮬레이터(qemu)".into(),
    });
    assert_eq!(verdict::notify_only(&rec, t).verdict, Verdict::Pass);
    rec.notes.push(rec.notes[0].clone());
    assert_eq!(verdict::notify_only(&rec, t).verdict, Verdict::Fail);
}

fn mcp(t: ProcRef, label: &str) -> ClsLite {
    ClsLite {
        target: t,
        kind: Kind::McpServer,
        signature_id: None,
        owner_alive: Some(true),
        owner_source: None,
        label_ko: label.into(),
    }
}

/// W3 3단계 S10 오탐: 같은 이름의 S1 종료 알림을 S10 알림으로 셌다. 표지(pid·프로젝트)가 있으면
/// 그 줄은 표지 주인 것이고, 표지 없이 이름만 같으면 다른 실험실 대상의 표지가 있는 줄은 세지 않는다.
#[test]
fn notification_lines_are_attributed_by_marker_not_by_shared_name() {
    let (s1, s10) = (r(10), r(11));
    let label = "MCP 서버: chrome-devtools";
    let mut rec = Records {
        scans: vec![scan(T0, 1, vec![], vec![])],
        kernel: vec![krec(s10, T0, true)],
        notes: vec![NotifyRec {
            at_ms: T0,
            title: "t".into(),
            body: format!("Android 에뮬레이터(qemu) 알림 · {label}(lab-s1) 종료(1MB 회수)"),
        }],
        ..Default::default()
    };
    rec.scans[0].classified = vec![mcp(s1, label), mcp(s10, label)];
    rec.markers.insert(s1, vec!["s1".into(), "lab-s1".into()]);
    rec.markers
        .insert(s10, vec!["s10".into(), "lab-s10".into()]);
    assert_eq!(rec.notes_about(s1, label, 0), 1);
    assert_eq!(rec.notes_about(s10, label, 0), 0);
    let it = verdict::never_touched("S10", "x", &rec, s10, Some(true));
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);

    rec.notes[0].body = format!("{label} 종료 (pid 11)");
    assert_eq!(rec.notes_about(s10, label, 0), 1);
    assert_eq!(rec.notes_about(s1, label, 0), 0);
    assert_eq!(
        verdict::never_touched("S10", "x", &rec, s10, Some(true)).verdict,
        Verdict::Fail
    );
}

#[test]
fn tokens_need_word_boundaries() {
    assert!(verdict::has_token("x(lab-s1) y", "lab-s1"));
    assert!(!verdict::has_token("lab-s10", "lab-s1"));
    assert!(!verdict::has_token("lab-s1", "s1"));
    assert!(verdict::has_token("pid 11 종료", "pid 11"));
    assert!(!verdict::has_token("pid 112", "pid 11"));
}
