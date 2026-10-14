use vh_lab::notify::NotifyRec;
use vh_lab::run::{ClsLite, FindingLite, KernelRec, ProcLite, ScanRec};
use vh_lab::signal::SignalCall;
use vh_lab::verdict::{Records, Verdict};
use vh_lab::verdict_w4::{self as w4, N4Input, N5Input};
use vh_model::{
    AutoLevel, Confidence, FindingKind, GuardEvent, GuardEventKind, GuardStatus, HealthLevel, Kind,
    ProcRef, ProcStatus, Section, Suggestion, Usage, UsageReason, UsageState,
};

const T0: u64 = 1_800_000_000_000;
const MIN: u64 = 60_000;

fn r(pid: i32) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: T0,
    }
}

fn status(forced: Option<HealthLevel>) -> GuardStatus {
    GuardStatus {
        level: AutoLevel::Safe,
        level_locked_by_env: true,
        paused: false,
        circuit_open: false,
        circuit_opened_at_unix_ms: None,
        terminations_in_window: 0,
        scan_seq: 0,
        scan_error_streak: 0,
        last_scan_at_unix_ms: 0,
        last_scan_ms: 40.0,
        next_scan_at_unix_ms: 0,
        demoted: vec![],
        pending: vec![],
        health: forced.unwrap_or(HealthLevel::Ok),
        health_forced: forced,
        unstable: forced.is_some(),
        unstable_reasons: Vec::new(),
        unstable_since_unix_ms: None,
        settle_until_unix_ms: None,
        swap_delta_bytes: None,
    }
}

fn scan(
    at: u64,
    t: ProcRef,
    sec: Option<Section>,
    reasons: &[UsageReason],
    forced: Option<HealthLevel>,
) -> ScanRec {
    let findings = sec
        .map(|s| FindingLite {
            id: "f".into(),
            kind: FindingKind::Orphan,
            confidence: Confidence::Confirmed,
            suggestion: Suggestion::Terminate {
                include_descendants: true,
            },
            targets: vec![t],
            short_ko: String::new(),
            reason_codes: vec![],
            section: s,
        })
        .into_iter()
        .collect();
    ScanRec {
        recv_ms: at,
        taken_at_ms: at,
        status: status(forced),
        events: vec![],
        findings,
        classified: vec![ClsLite {
            target: t,
            kind: Kind::DevServer,
            signature_id: None,
            owner_alive: Some(false),
            owner_source: None,
            label_ko: "개발 서버".into(),
            usage: Usage {
                state: UsageState::Active,
                reasons: reasons.to_vec(),
                ..Usage::default()
            },
        }],
        procs: vec![ProcLite {
            r: t,
            ppid: 1,
            pgid: 1,
            name: "node".into(),
            status: ProcStatus::Running,
            has_tty: false,
            footprint_bytes: None,
            cpu_pct: Some(150.0),
            argv_len: 0,
            argv_sha256: String::new(),
            argv: None,
            tcp: None,
            disk_io_delta_bytes: None,
        }],
        listeners: vec![],
        collection_errors: 0,
        timings_total_ms: 30.0,
        health_level: HealthLevel::Ok,
        totals_unneeded_bytes: 0,
        totals_check_bytes: 0,
        totals_manual_bytes: 0,
    }
}

fn scans(
    t: ProcRef,
    from: u64,
    to: u64,
    every: u64,
    sec: Section,
    reasons: &[UsageReason],
    forced: Option<HealthLevel>,
) -> Vec<ScanRec> {
    (0..)
        .map(|i| from + i * every)
        .take_while(|at| *at < to)
        .map(|at| scan(at, t, Some(sec), reasons, forced))
        .collect()
}

fn kernel(t: ProcRef, from: u64, to: u64, prio: i32, nice: i32) -> Vec<KernelRec> {
    (0..)
        .map(|i| from + i * 2_000)
        .take_while(|at| *at < to)
        .map(|at| KernelRec {
            at_ms: at,
            r: t,
            alive: true,
            zombie: false,
            stopped: false,
            ppid: 1,
            pgid: 1,
            priority: Some(prio),
            nice: Some(nice),
            footprint_bytes: None,
            cpu_ns: None,
        })
        .collect()
}

fn sig(pid: i32, at: u64, op: &str) -> SignalCall {
    SignalCall {
        at_ms: at,
        op: op.into(),
        pid,
        sig: (op == "send").then_some(libc::SIGTERM),
        allowed: true,
        ok: true,
        errno: None,
    }
}

fn ev(kind: GuardEventKind, t: ProcRef, at: u64) -> GuardEvent {
    GuardEvent {
        at_unix_ms: at,
        kind,
        target: Some(t),
        finding_id: None,
        run_id: None,
        label_ko: "개발 서버".into(),
        detail_ko: String::new(),
        reclaimed_bytes: 0,
    }
}

fn push_event(rec: &mut Records, e: GuardEvent) {
    let i = rec
        .scans
        .iter()
        .rposition(|s| s.taken_at_ms <= e.at_unix_ms)
        .unwrap_or(0);
    rec.scans[i].events.push(e);
}

const WORK: [UsageReason; 2] = [UsageReason::OwnerAlive, UsageReason::CpuActive];

fn n1_records() -> Records {
    let t = r(10);
    Records {
        scans: scans(t, T0, T0 + 5 * MIN, 5_000, Section::Working, &WORK, None),
        kernel: kernel(t, T0, T0 + 5 * MIN, 31, 0),
        ..Default::default()
    }
}

#[test]
fn n1_invariant_passes_untouched_and_fails_on_demote_or_priority_change() {
    let t = r(10);
    let rec = n1_records();
    let it = w4::invariant_untouched(
        "N1",
        "f-safe",
        &rec,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);
    assert_eq!(it.id, "N1/f-safe");

    let mut demoted = n1_records();
    demoted.signals.push(sig(10, T0 + MIN, "demote"));
    let it = w4::invariant_untouched(
        "N1",
        "n-safe",
        &demoted,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert_eq!(it.verdict, Verdict::Fail);
    assert!(!it.checks["no_signals_any_op"]);
    assert_eq!(it.suspected_owner, "GUARD");

    let mut slowed = n1_records();
    slowed.kernel[40].priority = Some(4);
    let it = w4::invariant_untouched(
        "N1",
        "n-safe",
        &slowed,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert!(!it.checks["priority_unchanged"]);
    let mut niced = n1_records();
    niced.kernel[40].nice = Some(10);
    let it = w4::invariant_untouched(
        "N1",
        "n-safe",
        &niced,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert!(!it.checks["nice_unchanged"]);
    assert_eq!(it.verdict, Verdict::Fail);
}

#[test]
fn n1_wrong_section_is_a_core_failure_not_a_signal() {
    let t = r(10);
    let mut rec = n1_records();
    for s in rec.scans.iter_mut() {
        s.findings[0].section = Section::Unneeded;
    }
    let it = w4::invariant_untouched(
        "N1",
        "n-notify",
        &rec,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert_eq!(it.verdict, Verdict::Fail);
    assert!(!it.checks["section_expected"]);
    assert_eq!(it.suspected_owner, "CORE");
}

#[test]
fn working_with_no_finding_counts_as_untouched_report() {
    let t = r(10);
    let mut rec = n1_records();
    for s in rec.scans.iter_mut() {
        s.findings.clear();
    }
    let it = w4::invariant_untouched(
        "N1",
        "n-notify",
        &rec,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Working],
        &WORK,
    );
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);
    let it = w4::invariant_untouched(
        "N2",
        "n-notify",
        &rec,
        t,
        (T0, T0 + 5 * MIN),
        &[Section::Check],
        &WORK,
    );
    assert!(!it.checks["section_expected"]);
}

fn report_only_records(signal: bool, unhealthy: bool) -> Records {
    let t = r(10);
    let mut rec = Records {
        scans: scans(
            t,
            T0 + 9 * MIN,
            T0 + 13 * MIN,
            5_000,
            Section::Unneeded,
            &[UsageReason::NoPeers],
            None,
        ),
        kernel: kernel(t, T0 + 9 * MIN, T0 + 13 * MIN + 1, 31, 0),
        ..Default::default()
    };
    if signal {
        rec.signals.push(sig(10, T0 + 11 * MIN, "send"));
    }
    if unhealthy {
        rec.scans[20].health_level = HealthLevel::Watch;
    }
    rec
}

#[test]
fn normal_side_is_inconclusive_only_when_real_mac_was_not_normal() {
    let t = r(10);
    let end = T0 + 13 * MIN;
    let after = T0 + 10 * MIN + 30_000;
    let ok = w4::report_only("S1", &report_only_records(false, false), t, after, end);
    assert_eq!(ok.verdict, Verdict::Pass, "{:?}", ok.checks);
    let fail = w4::report_only("S1", &report_only_records(true, false), t, after, end);
    assert_eq!(fail.verdict, Verdict::Fail);
    let inc = w4::report_only("S1", &report_only_records(true, true), t, after, end);
    assert_eq!(inc.verdict, Verdict::Inconclusive);
    assert_eq!(inc.observed["inconclusive_reason"], "real_mac_not_normal");
    let pass_anyway = w4::report_only("S1", &report_only_records(false, true), t, after, end);
    assert_eq!(pass_anyway.verdict, Verdict::Pass);
    assert_eq!(pass_anyway.observed["real_mac_not_normal_scans"], 1);
}

#[test]
fn forced_unstable_reported_by_guard_without_forcing_is_real_instability() {
    let t = r(10);
    let mut rec = report_only_records(true, false);
    rec.scans[20].status.unstable = true;
    let it = w4::report_only("S1", &rec, t, T0 + 10 * MIN + 30_000, T0 + 13 * MIN);
    assert_eq!(it.verdict, Verdict::Inconclusive);
}

fn n4_records(d: u64, term_at: Option<u64>) -> Records {
    let t = r(20);
    let watch = Some(HealthLevel::Watch);
    let mut s = scans(
        t,
        T0,
        d,
        2_000,
        Section::Check,
        &[UsageReason::PeerOutsideSubtree],
        watch,
    );
    s.extend(scans(
        t,
        d,
        d + 6 * MIN,
        2_000,
        Section::Unneeded,
        &[UsageReason::NoPeers],
        watch,
    ));
    let mut rec = Records {
        scans: s,
        kernel: kernel(t, T0, d + 6 * MIN, 31, 0),
        ..Default::default()
    };
    if let Some(at) = term_at {
        push_event(&mut rec, ev(GuardEventKind::AutoTerminated, t, at));
        rec.signals.push(sig(20, at, "send"));
    }
    rec
}

fn n4_in(d: u64, forced: bool, allowed: bool) -> N4Input {
    N4Input {
        server: r(20),
        disconnect_ms: Some(d),
        forced,
        term_allowed: allowed,
        end_ms: d + 6 * MIN,
    }
}

#[test]
fn n4_q6_window_floor_is_disconnect_plus_idle_confirm() {
    let d = T0 + 11 * MIN;
    let early = w4::n4(
        "f-safe",
        &n4_records(d, Some(d + 119_000)),
        &n4_in(d, true, true),
    );
    assert_eq!(early.verdict, Verdict::Fail);
    assert!(!early.checks["not_before_floor"]);
    assert!(!early.checks["no_signal_2m_after_disconnect"]);

    let on_time = w4::n4(
        "f-safe",
        &n4_records(d, Some(d + 125_000)),
        &n4_in(d, true, true),
    );
    assert_eq!(on_time.verdict, Verdict::Pass, "{:?}", on_time.checks);
    assert_eq!(on_time.observed["late"], false);

    let late = w4::n4(
        "f-safe",
        &n4_records(d, Some(d + 200_000)),
        &n4_in(d, true, true),
    );
    assert_eq!(late.verdict, Verdict::Pass, "늦음은 FAIL이 아니다");
    assert_eq!(late.observed["late"], true);

    let none = w4::n4("f-safe", &n4_records(d, None), &n4_in(d, true, true));
    assert!(!none.checks["auto_terminated_after_disconnect"]);
}

#[test]
fn n4_prior_round_moves_floor_by_settle_time() {
    let d = T0 + 11 * MIN;
    let mut rec = n4_records(d, Some(d + 125_000));
    push_event(
        &mut rec,
        ev(GuardEventKind::AutoTerminated, r(99), d + 100_000),
    );
    let it = w4::n4("f-aggressive", &rec, &n4_in(d, true, true));
    assert_eq!(it.observed["floor_ms"], d + 160_000);
    assert_eq!(it.verdict, Verdict::Fail);
}

#[test]
fn n4_signal_inside_two_minutes_fails_even_if_no_event() {
    let d = T0 + 11 * MIN;
    let mut rec = n4_records(d, None);
    rec.signals.push(sig(20, d + 60_000, "send"));
    let it = w4::n4("f-notify", &rec, &n4_in(d, true, false));
    assert!(!it.checks["no_signal_2m_after_disconnect"]);
    assert!(!it.checks["no_signals_whole_run"]);
    assert_eq!(it.verdict, Verdict::Fail);
}

#[test]
fn n4_normal_cell_wants_unneeded_after_disconnect_and_no_action() {
    let d = T0 + 11 * MIN;
    let mut rec = n4_records(d, None);
    for s in rec.scans.iter_mut() {
        s.status = status(None);
    }
    let it = w4::n4("n-safe", &rec, &n4_in(d, false, false));
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);
    let missing = w4::n4(
        "n-safe",
        &rec,
        &N4Input {
            disconnect_ms: None,
            ..n4_in(d, false, false)
        },
    );
    assert_eq!(missing.verdict, Verdict::Inconclusive);
}

fn n5_records(switch: u64, pre: Option<u64>, post: Option<u64>) -> Records {
    let (a, b) = (r(30), r(31));
    let mut s = scans(
        a,
        T0 + 3 * MIN,
        switch,
        2_000,
        Section::Unneeded,
        &[UsageReason::NoPeers],
        Some(HealthLevel::Watch),
    );
    s.extend(scans(
        a,
        switch + 1,
        switch + 5 * MIN,
        5_000,
        Section::Unneeded,
        &[UsageReason::NoPeers],
        None,
    ));
    let mut k = kernel(a, T0, switch + 5 * MIN, 31, 0);
    k.extend(kernel(b, T0, switch + 5 * MIN, 31, 0));
    let mut rec = Records {
        scans: s,
        kernel: k,
        ..Default::default()
    };
    if let Some(at) = pre {
        push_event(&mut rec, ev(GuardEventKind::AutoTerminated, a, at));
        rec.signals.push(sig(30, at, "send"));
        rec.signals.push(sig(30, at + 3_000, "send"));
    }
    if let Some(at) = post {
        push_event(&mut rec, ev(GuardEventKind::AutoTerminated, b, at));
        rec.signals.push(sig(31, at, "send"));
    }
    rec
}

fn n5_in(switch: u64, expect: bool) -> N5Input {
    N5Input {
        candidates: vec![r(30), r(31)],
        switch_ms: Some(switch),
        expect_pre_term: expect,
        end_ms: switch + 5 * MIN,
    }
}

#[test]
fn n5_stops_after_switch_to_normal() {
    let sw = T0 + 10 * MIN + 10_000;
    let mut ok = n5_records(sw, Some(sw - 1_000), None);
    ok.kernel.retain(|k| !(k.r == r(30) && k.at_ms > sw));
    let it = w4::n5("t-safe", &ok, &n5_in(sw, true));
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);

    let bad = n5_records(sw, Some(sw - 1_000), Some(sw + 90_000));
    let it = w4::n5("t-safe", &bad, &n5_in(sw, true));
    assert!(!it.checks["no_auto_terminate_after_switch"]);
    assert!(!it.checks["no_new_signals_after_switch"]);
    assert_eq!(it.verdict, Verdict::Fail);

    let notify_killed = n5_records(sw, Some(sw - 1_000), None);
    let it = w4::n5("t-notify", &notify_killed, &n5_in(sw, false));
    assert!(!it.checks["pre_switch_terminations_expected"]);
    assert!(!it.checks["no_signals_at_all"]);
}

#[test]
fn forced_termination_before_start_floor_fails() {
    let t = r(40);
    let watch = Some(HealthLevel::Watch);
    let start = T0 + 9 * MIN;
    let at = T0 + 10 * MIN + 2_000;
    let mut rec = Records {
        scans: scans(
            t,
            start,
            at + 10_000,
            2_000,
            Section::Unneeded,
            &[UsageReason::NoPeers],
            watch,
        ),
        kernel: vec![],
        notes: vec![NotifyRec {
            at_ms: start,
            title: "vh".into(),
            body: "[시험] 맥이 불안정해요(주의). 필요 없음 1MB".into(),
        }],
        audit: vec![serde_json::json!({"target": {"pid": 40}})],
        ..Default::default()
    };
    rec.kernel.extend(kernel(t, start, at, 31, 0));
    rec.kernel.push(KernelRec {
        alive: false,
        ..kernel(t, at + 2_000, at + 2_001, 31, 0)[0].clone()
    });
    rec.scans[10].status.pending.push(vh_model::PendingAction {
        target: t,
        finding_id: "f".into(),
        kind: Kind::McpServer,
        label_ko: "x".into(),
        step: vh_model::Step::Term,
        seen_scans: 1,
        needed_scans: 2,
        eta_ms: None,
        wait: vh_model::PendingWait::Confirming,
    });
    push_event(&mut rec, ev(GuardEventKind::AutoTerminated, t, at));
    rec.signals.push(sig(40, at, "send"));
    rec.notes.push(NotifyRec {
        at_ms: at + 10,
        title: "vh".into(),
        body: "개발 서버 종료(1MB 회수)".into(),
    });
    let it = w4::forced_auto_terminated("S1", &rec, t);
    assert!(it.checks["forced_health_applied"]);
    assert!(it.checks["unstable_notification"]);
    assert!(!it.checks["not_before_start_floor"], "{:?}", it.observed);
    assert_eq!(it.verdict, Verdict::Fail);

    rec.scans.iter_mut().for_each(|s| s.status = status(None));
    let it = w4::forced_auto_terminated("S1", &rec, t);
    assert!(!it.checks["forced_health_applied"]);
}

#[test]
fn s3_no_priority_change_and_undersped_spinner_is_inconclusive() {
    let t = r(50);
    let mut rec = Records {
        scans: scans(
            t,
            T0,
            T0 + 3 * MIN,
            5_000,
            Section::Check,
            &[UsageReason::CpuActive],
            None,
        ),
        kernel: kernel(t, T0, T0 + 3 * MIN, 12, 19),
        ..Default::default()
    };
    let it = w4::no_priority_change(&rec, t, false);
    assert_eq!(it.verdict, Verdict::Pass, "{:?}", it.checks);
    rec.signals.push(sig(50, T0 + MIN, "demote"));
    rec.kernel[30].priority = Some(4);
    let it = w4::no_priority_change(&rec, t, false);
    assert_eq!(it.verdict, Verdict::Fail);
    assert_eq!(it.suspected_owner, "GUARD");

    let mut slow = Records {
        scans: scans(t, T0, T0 + 3 * MIN, 5_000, Section::Check, &[], None),
        kernel: kernel(t, T0, T0 + 3 * MIN, 12, 19),
        ..Default::default()
    };
    for s in slow.scans.iter_mut() {
        s.procs[0].cpu_pct = Some(60.0);
    }
    let it = w4::no_priority_change(&slow, t, false);
    assert_eq!(it.verdict, Verdict::Inconclusive);
}
