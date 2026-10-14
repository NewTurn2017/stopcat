//! W4 판정(PM 판정 `ADJUDICATION-w4-expectations.md`·`ADJUDICATION-plan-review.md`·2단계 추가 절).
//! 정상 실행에서 '실기기가 정상이어야 성립하는' 기대는 [`health_gate`]로 INCONCLUSIVE를 가리고,
//! 쓰고 있는 것 불변식(신호 0, 우선순위 변화 0)은 건강과 무관하게 판정한다.

use serde_json::json;
use vh_model::{GuardEventKind, HealthLevel, ProcRef, Section, Step, UsageReason};

use crate::verdict::{self, Item, MIN_AGE_MS, Records, Verdict};

pub const IDLE_CONFIRM_MS: u64 = 120_000;
pub const SETTLE_MS: u64 = 60_000;
pub const UNSTABLE_SCAN_MS: u64 = 2_000;
pub const LADDER_MS: u64 = 20_000;
pub const FORCED: HealthLevel = HealthLevel::Watch;

fn finish(
    id: &str,
    expected: &str,
    checks: Vec<(&str, bool)>,
    observed: serde_json::Value,
) -> Item {
    let checks: std::collections::BTreeMap<String, bool> = checks
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let pass = checks.values().all(|v| *v);
    Item {
        id: id.to_string(),
        expected: expected.to_string(),
        observed,
        verdict: if pass { Verdict::Pass } else { Verdict::Fail },
        evidence: Vec::new(),
        suspected_owner: if pass { "none" } else { "GUARD" }.into(),
        severity: if pass { "low" } else { "high" }.into(),
        repro: String::new(),
        checks,
    }
}

impl Records {
    /// 스캔마다 `t`에 걸린 발견의 구역(없으면 빈 목록).
    pub fn sections_at(&self, t: ProcRef) -> Vec<(u64, Vec<Section>)> {
        self.scans
            .iter()
            .filter(|s| s.procs.iter().any(|p| p.r == t))
            .map(|s| {
                let v = s
                    .findings
                    .iter()
                    .filter(|f| f.targets.contains(&t))
                    .map(|f| f.section)
                    .collect();
                (s.taken_at_ms, v)
            })
            .collect()
    }

    pub fn reasons_at(&self, t: ProcRef) -> Vec<(u64, Vec<UsageReason>)> {
        self.scans
            .iter()
            .filter_map(|s| {
                s.classified
                    .iter()
                    .find(|c| c.target == t)
                    .map(|c| (s.taken_at_ms, c.usage.reasons.clone()))
            })
            .collect()
    }

    /// 첫 스캔은 CPU·디스크가 없어 Unknown이고 `idle_since`는 둘째 스캔부터 → 시작 뒤 첫 종료 하한.
    pub fn first_term_floor(&self) -> Option<u64> {
        self.scans.get(1).map(|s| s.taken_at_ms + IDLE_CONFIRM_MS)
    }

    /// 실기기가 정상이 아니었던 스캔(분석 건강 ≠ ok, 또는 강제값 없이 지킴이가 불안정으로 본 스캔).
    pub fn real_unstable_scans(&self, from: u64, to: u64) -> Vec<serde_json::Value> {
        self.scans
            .iter()
            .filter(|s| s.taken_at_ms >= from && s.taken_at_ms <= to)
            .filter(|s| {
                s.health_level != HealthLevel::Ok
                    || (s.status.unstable && s.status.health_forced.is_none())
            })
            .map(|s| json!({"at_ms": s.taken_at_ms, "health": s.health_level, "unstable": s.status.unstable, "reasons": s.status.unstable_reasons}))
            .collect()
    }

    /// `[from, to)` 커널 표본의 우선순위·nice가 처음 값과 모두 같은지.
    pub fn priority_steady(
        &self,
        t: ProcRef,
        from: u64,
        to: u64,
    ) -> (bool, bool, serde_json::Value) {
        let ks: Vec<_> = self
            .kernel
            .iter()
            .filter(|k| k.r == t && k.alive && k.at_ms >= from && k.at_ms < to)
            .collect();
        let p0 = ks.first().and_then(|k| k.priority);
        let n0 = ks.first().and_then(|k| k.nice);
        let p_ok = p0.is_some() && ks.iter().all(|k| k.priority == p0);
        let n_ok = n0.is_some() && ks.iter().all(|k| k.nice == n0);
        let pv: std::collections::BTreeSet<_> = ks.iter().filter_map(|k| k.priority).collect();
        let nv: std::collections::BTreeSet<_> = ks.iter().filter_map(|k| k.nice).collect();
        (
            p_ok,
            n_ok,
            json!({"samples": ks.len(), "priority_values": pv, "nice_values": nv}),
        )
    }

    pub fn signals_in(&self, pid: i32, from: u64, to: u64) -> usize {
        self.signals
            .iter()
            .filter(|c| c.pid == pid && c.at_ms >= from && c.at_ms < to)
            .count()
    }

    /// 강제 칸: `[from, to)` 스캔(첫 스캔 제외)이 모두 강제값과 불안정을 보였는지.
    pub fn forced_applied(&self, from: u64, to: u64) -> bool {
        let w: Vec<_> = self
            .scans
            .iter()
            .skip(1)
            .filter(|s| s.taken_at_ms >= from && s.taken_at_ms < to)
            .collect();
        !w.is_empty()
            && w.iter()
                .all(|s| s.status.health_forced == Some(FORCED) && s.status.unstable)
    }
}

/// 정상 실행 항목: 판정 구간에 실기기가 정상이 아닌 스캔이 있으면 INCONCLUSIVE(사유 기록).
pub fn health_gate(mut it: Item, r: &Records, from: u64, to: u64) -> Item {
    let bad = r.real_unstable_scans(from, to);
    it.observed["real_mac_not_normal_scans"] = json!(bad.len());
    if !bad.is_empty() {
        it.observed["real_mac_not_normal_first"] = bad[0].clone();
        if it.verdict != Verdict::Pass {
            it.verdict = Verdict::Inconclusive;
            it.suspected_owner = "none".into();
            it.severity = "low".into();
            it.observed["inconclusive_reason"] = json!("real_mac_not_normal");
        }
    }
    it
}

/// 구역 검사: 발견이 있으면 모두 허용 구역이어야 하고, 발견이 없으면 Working이 허용될 때만 통과
/// (발견 없음 = 보고에 안 나옴 = 건드리지 않음). 첫 두 스캔(Unknown 구간)은 뺀다.
pub fn sections_ok(
    r: &Records,
    t: ProcRef,
    from: u64,
    to: u64,
    allowed: &[Section],
) -> (bool, serde_json::Value) {
    let w: Vec<_> = r
        .sections_at(t)
        .into_iter()
        .skip(2)
        .filter(|(at, _)| *at >= from && *at < to)
        .collect();
    let ok = !w.is_empty()
        && w.iter().all(|(_, v)| {
            if v.is_empty() {
                allowed.contains(&Section::Working)
            } else {
                v.iter().all(|s| allowed.contains(s))
            }
        });
    let seen: std::collections::BTreeSet<String> =
        w.iter().map(|(_, v)| format!("{v:?}")).collect();
    (ok, json!({"scans": w.len(), "distinct": seen}))
}

fn reasons_seen(
    r: &Records,
    t: ProcRef,
    from: u64,
    to: u64,
    want: &[UsageReason],
) -> (bool, serde_json::Value) {
    let w: Vec<_> = r
        .reasons_at(t)
        .into_iter()
        .filter(|(at, _)| *at >= from && *at < to)
        .collect();
    let ok = w.iter().any(|(_, v)| want.iter().all(|x| v.contains(x)));
    let last = w.last().map(|(_, v)| v.clone());
    (ok, json!({"scans": w.len(), "last": last}))
}

/// N1·N2·N3(모든 칸)·S9·S10 등: 쓰고 있는 것 불변식. 건강과 무관.
pub fn invariant_untouched(
    id: &str,
    cell: &str,
    r: &Records,
    t: ProcRef,
    (from, to): (u64, u64),
    allowed: &[Section],
    want_reasons: &[UsageReason],
) -> Item {
    let (p_ok, n_ok, prio) = r.priority_steady(t, from, to);
    let (s_ok, sec) = sections_ok(r, t, from, to, allowed);
    let (re_ok, rea) = reasons_seen(r, t, from, to, want_reasons);
    let pend = r.pending_seen(t).len();
    let mut it = finish(
        id,
        "신호 0(demote 포함), 이벤트·대기 0, 우선순위·nice 변화 0, 기대 구역·근거",
        vec![
            ("no_signals_any_op", r.signals_in(t.pid, 0, u64::MAX) == 0),
            ("no_events_on_target", r.any_event_on(t) == 0),
            ("no_pending", pend == 0),
            ("priority_unchanged", p_ok),
            ("nice_unchanged", n_ok),
            ("section_expected", s_ok),
            ("reasons_expected", re_ok),
        ],
        json!({"cell": cell, "priority": prio, "sections": sec, "reasons": rea, "signals": r.signals_to(t.pid)}),
    );
    if it.verdict == Verdict::Fail
        && it.checks["no_signals_any_op"]
        && it.checks["no_events_on_target"]
        && it.checks["no_pending"]
    {
        it.suspected_owner = if p_ok && n_ok { "CORE" } else { "LAB" }.into();
        it.severity = "medium".into();
    }
    it.id = format!("{id}/{cell}");
    it
}

/// 정상 실행의 S1·S2·S11: 신호 0·대기 0·항목 알림 0, `after` 이후 구역 unneeded.
pub fn report_only(id: &str, r: &Records, t: ProcRef, after: u64, end: u64) -> Item {
    let label = r.last_kind(t).map(|k| k.2).unwrap_or_default();
    let (s_ok, sec) = sections_ok(r, t, after, end, &[Section::Unneeded]);
    let it = finish(
        id,
        "정상: 신호 0, 대기 0, 항목 알림 0, 구역 unneeded(지킴이 칸 '정리 추천'은 TUI가 그림), 생존",
        vec![
            ("no_signals", r.signals_to(t.pid) == 0),
            ("no_events_on_target", r.any_event_on(t) == 0),
            ("no_pending", r.pending_seen(t).is_empty()),
            ("item_notifications_zero", r.notes_about(t, &label, 0) == 0),
            ("section_unneeded", s_ok),
            ("alive_at_end", r.alive_at_end(t)),
        ],
        json!({"sections": sec, "label": label}),
    );
    health_gate(it, r, t.start_time_unix_ms, end)
}

/// 정상 S11: 10분 전 근거 young(구역 check), 10분 뒤 unneeded, 신호 0.
pub fn young_normal(r: &Records, t: ProcRef, end: u64) -> Item {
    let ten = t.start_time_unix_ms + MIN_AGE_MS;
    let (y_ok, y) = reasons_seen(r, t, 0, ten, &[UsageReason::Young]);
    let (c_ok, c) = sections_ok(r, t, 0, ten - 5_000, &[Section::Check]);
    let mut it = report_only("S11", r, t, ten + 30_000, end);
    it.expected = "정상: 신호 0, 10분 전 young 근거로 보호(구역 check), 10분 뒤 unneeded".into();
    it.checks.insert("young_before_10m".into(), y_ok);
    it.checks.insert("section_check_before_10m".into(), c_ok);
    it.observed["young"] = y;
    it.observed["before_10m"] = c;
    if it.verdict == Verdict::Pass && !(y_ok && c_ok) {
        it.verdict = Verdict::Fail;
        it.suspected_owner = "CORE".into();
        it.severity = "medium".into();
    }
    it
}

/// 강제 칸의 S1·S2·S11: W3 검사 + 강제 적용 + 불안정 알림 + 첫 종료 하한.
pub fn forced_auto_terminated(id: &str, r: &Records, t: ProcRef) -> Item {
    let mut it = verdict::auto_terminated(id, r, t, None);
    let at = r
        .events(GuardEventKind::AutoTerminated, t)
        .first()
        .map(|e| e.at_unix_ms);
    let floor = r.first_term_floor();
    let after_floor = match (at, floor) {
        (Some(a), Some(f)) => a >= f,
        _ => false,
    };
    let end = r.scans.last().map_or(0, |s| s.taken_at_ms + 1);
    let applied = r.forced_applied(0, end);
    let unstable_note = r.notes_with(crate::strings::UNSTABLE_NOTE) >= 1;
    it.checks.insert("forced_health_applied".into(), applied);
    it.checks
        .insert("unstable_notification".into(), unstable_note);
    it.checks
        .insert("not_before_start_floor".into(), after_floor);
    it.observed["start_floor_ms"] = json!(floor);
    if !(applied && unstable_note && after_floor) {
        it.verdict = Verdict::Fail;
        it.suspected_owner = "GUARD".into();
        it.severity = "high".into();
    }
    it.expected = format!("{} + 강제 적용·불안정 알림·시작 하한", it.expected);
    it
}

/// S3(정상·강제): 신호 0, 우선순위·nice 변화 0, 구역 check·근거 cpu_active.
pub fn no_priority_change(r: &Records, t: ProcRef, forced: bool) -> Item {
    let end = r.scans.last().map_or(0, |s| s.taken_at_ms + 1);
    let (p_ok, n_ok, prio) = r.priority_steady(t, 0, u64::MAX);
    let cpu: Vec<f32> = r
        .scans
        .iter()
        .filter_map(|s| s.procs.iter().find(|p| p.r == t).and_then(|p| p.cpu_pct))
        .collect();
    let (s_ok, sec) = sections_ok(r, t, 0, end, &[Section::Check]);
    let (re_ok, rea) = reasons_seen(r, t, 0, end, &[UsageReason::CpuActive]);
    let demote_pending = r.pending_seen(t).iter().any(|p| p.2 == Step::Demote);
    let mut checks = vec![
        ("no_signals_any_op", r.signals_to(t.pid) == 0),
        (
            "no_demoted_event",
            r.events(GuardEventKind::Demoted, t).is_empty(),
        ),
        ("no_demote_pending", !demote_pending),
        ("priority_unchanged", p_ok),
        ("nice_unchanged", n_ok),
        ("section_check", s_ok),
        ("reason_cpu_active", re_ok),
    ];
    if forced {
        checks.push(("forced_health_applied", r.forced_applied(0, end)));
    }
    let mut it = finish(
        "S3",
        "CPU ≥ 100% 연속: 신호 0, 우선순위·nice 변화 0, 구역 check, 근거 cpu_active",
        checks,
        json!({"cpu_pct_by_scan": cpu, "priority": prio, "sections": sec, "reasons": rea, "mode": if forced {"forced"} else {"normal"}}),
    );
    let spun = cpu.iter().skip(1).take(4).all(|c| *c >= 100.0);
    if it.verdict == Verdict::Fail && !spun && it.checks["no_signals_any_op"] && p_ok && n_ok {
        it.verdict = Verdict::Inconclusive;
        it.suspected_owner = "LAB".into();
        it.severity = "low".into();
    } else if it.verdict == Verdict::Fail && it.checks["no_signals_any_op"] && p_ok && n_ok {
        it.suspected_owner = "CORE".into();
        it.severity = "medium".into();
    }
    it
}

/// S8: 정상은 항목 알림 0·신호 0·구역 check, 강제는 신호 0·생존(알림 언급은 관찰값).
pub fn emulator(r: &Records, t: ProcRef, forced: bool) -> Item {
    let k = r.last_kind(t);
    let label = k.as_ref().map(|k| k.2.clone()).unwrap_or_default();
    let end = r.scans.last().map_or(0, |s| s.taken_at_ms + 1);
    let (s_ok, sec) = sections_ok(r, t, 0, end, &[Section::Check]);
    let mentions = r.notes_about(t, &label, 0);
    let mut checks = vec![
        (
            "kind_emulator",
            k.as_ref().map(|k| k.0) == Some(vh_model::Kind::Emulator),
        ),
        ("no_signals", r.signals_to(t.pid) == 0),
        (
            "no_auto_terminate",
            r.events(GuardEventKind::AutoTerminated, t).is_empty(),
        ),
        ("alive_at_end", r.alive_at_end(t)),
        ("section_check", s_ok),
    ];
    if !forced {
        checks.push(("item_notifications_zero", mentions == 0));
    }
    let it = finish(
        "S8",
        if forced {
            "강제: 신호 0, 생존, 구역 check(불안정 알림 언급은 관찰값)"
        } else {
            "정상: 항목 알림 0, 신호 0, 구역 check"
        },
        checks,
        json!({"label": label, "notification_mentions": mentions, "sections": sec}),
    );
    if forced {
        it
    } else {
        health_gate(it, r, t.start_time_unix_ms, end)
    }
}

/// 정상 S12: 0건 실행, 차단기 안 열림, 7개 생존, 구역 unneeded.
pub fn no_circuit(r: &Records, targets: &[ProcRef]) -> Item {
    let end = r.scans.last().map_or(0, |s| s.taken_at_ms + 1);
    let ten = targets
        .iter()
        .map(|t| t.start_time_unix_ms)
        .max()
        .unwrap_or(0)
        + MIN_AGE_MS
        + 30_000;
    let unneeded = targets
        .iter()
        .all(|t| sections_ok(r, *t, ten, end, &[Section::Unneeded]).0);
    let it = finish(
        "S12",
        "정상: 0건 실행, CircuitOpen 0, circuit_open 끝까지 false, 7개 생존, 구역 unneeded",
        vec![
            (
                "zero_auto_terminated",
                r.events_kind(GuardEventKind::AutoTerminated).is_empty(),
            ),
            (
                "zero_term_signals",
                r.signals.iter().all(|c| c.op != "send"),
            ),
            (
                "circuit_never_opened",
                r.events_kind(GuardEventKind::CircuitOpen).is_empty(),
            ),
            (
                "status_never_circuit_open",
                r.scans.iter().all(|s| !s.status.circuit_open),
            ),
            ("all_alive", targets.iter().all(|t| r.alive_at_end(*t))),
            ("section_unneeded_after_10m", unneeded),
        ],
        json!({"targets": targets.len()}),
    );
    health_gate(it, r, 0, end)
}

/// 강제 S12: W3 circuit 판정 + 강제 적용.
pub fn forced_circuit(r: &Records, targets: &[ProcRef]) -> Item {
    let mut it = verdict::circuit(r, targets);
    let end = r.scans.last().map_or(0, |s| s.taken_at_ms + 1);
    let applied = r.forced_applied(0, end);
    it.checks.insert("forced_health_applied".into(), applied);
    if !applied && it.verdict == Verdict::Pass {
        it.verdict = Verdict::Fail;
        it.suspected_owner = "GUARD".into();
        it.severity = "high".into();
    }
    it
}

pub struct N4Input {
    pub server: ProcRef,
    pub disconnect_ms: Option<u64>,
    pub forced: bool,
    /// 이 칸에서 자동 종료가 허용되는지(안전·적극 강제 칸).
    pub term_allowed: bool,
    pub end_ms: u64,
}

/// N4: 끊기 전 0, 끊긴 직후 2분 신호 0, 정상은 끝까지 0·구역 unneeded, 강제(허용 칸)는 하한 뒤 종료.
pub fn n4(cell: &str, r: &Records, i: &N4Input) -> Item {
    let s = i.server;
    let Some(d) = i.disconnect_ms else {
        let mut it = finish(
            "N4",
            "클라이언트 끊김을 관찰해야 판정",
            vec![("disconnect_observed", false)],
            json!({"cell": cell}),
        );
        it.verdict = Verdict::Inconclusive;
        it.suspected_owner = "LAB".into();
        it.id = format!("N4/{cell}");
        return it;
    };
    let pend_before = r.pending_seen(s).iter().filter(|p| p.0 < d).count();
    let ev_before = r
        .scans
        .iter()
        .flat_map(|x| x.events.iter())
        .filter(|e| e.target == Some(s) && e.at_unix_ms < d)
        .count();
    let (c_ok, c) = sections_ok(r, s, 0, d, &[Section::Check]);
    let (p_ok, p) = reasons_seen(r, s, 0, d, &[UsageReason::PeerOutsideSubtree]);
    let mut checks = vec![
        (
            "no_action_before_disconnect",
            r.signals_in(s.pid, 0, d) == 0 && pend_before == 0 && ev_before == 0,
        ),
        (
            "no_signal_2m_after_disconnect",
            r.signals_in(s.pid, d, d + IDLE_CONFIRM_MS) == 0,
        ),
        ("section_check_while_connected", c_ok),
        ("reason_peer_outside_subtree", p_ok),
    ];
    let term = r
        .events(GuardEventKind::AutoTerminated, s)
        .first()
        .map(|e| e.at_unix_ms);
    let prior_round = r
        .events_kind(GuardEventKind::AutoTerminated)
        .iter()
        .filter(|e| e.target != Some(s) && e.at_unix_ms < term.unwrap_or(u64::MAX))
        .map(|e| e.at_unix_ms)
        .max();
    let mut floor = d + IDLE_CONFIRM_MS;
    if let Some(pr) = prior_round {
        floor = floor.max(pr + SETTLE_MS);
    }
    if let Some(f) = r.first_term_floor() {
        floor = floor.max(f);
    }
    let late_after = floor + 2 * UNSTABLE_SCAN_MS + LADDER_MS;
    let mut obs = json!({"cell": cell, "disconnect_ms": d, "floor_ms": floor, "late_after_ms": late_after, "terminated_at_ms": term, "before_disconnect": c, "peer_reason": p});
    if i.term_allowed {
        checks.push(("auto_terminated_after_disconnect", term.is_some()));
        checks.push(("not_before_floor", term.is_some_and(|t| t >= floor)));
        let pend: Vec<_> = r.pending_seen(s).into_iter().filter(|x| x.0 >= d).collect();
        obs["pending_after_disconnect"] = json!(pend);
        obs["late"] = json!(term.is_some_and(|t| t > late_after));
        if term.is_some_and(|t| t > late_after) {
            obs["late_reason_ko"] =
                json!("하한 + 2스캔 + 정리 사다리(20초) 뒤 종료: FAIL 아님, 기록만");
        }
    } else {
        checks.push(("no_signals_whole_run", r.signals_to(s.pid) == 0));
        checks.push(("no_auto_terminate", term.is_none()));
        if !i.forced {
            let (u_ok, u) = sections_ok(r, s, d + 30_000, i.end_ms, &[Section::Unneeded]);
            checks.push(("section_unneeded_after_disconnect", u_ok));
            obs["after_disconnect"] = u;
        }
    }
    if i.forced {
        checks.push(("forced_health_applied", r.forced_applied(0, i.end_ms)));
    }
    let mut it = finish(
        "N4",
        "끊기 전 신호·대기 0(check, peer_outside_subtree), 끊긴 직후 2분 신호 0. 정상: 끝까지 0·unneeded. 강제 허용 칸: max(끊김+120초, 직전 회차+60초, 시작 하한) 뒤에만 종료",
        checks,
        obs,
    );
    it.id = format!("N4/{cell}");
    if !i.forced {
        it = health_gate(it, r, d, i.end_ms);
    }
    it
}

pub struct N5Input {
    pub candidates: Vec<ProcRef>,
    pub switch_ms: Option<u64>,
    pub expect_pre_term: bool,
    pub end_ms: u64,
}

/// N5: 전환 전(강제) 안전·적극은 첫 후보 정리, 전환 뒤 새 자동 조치 0. 전환이 걸친 스캔은 기록만.
pub fn n5(cell: &str, r: &Records, i: &N5Input) -> Item {
    let Some(sw) = i.switch_ms else {
        let mut it = finish(
            "N5",
            "전환이 있어야 판정",
            vec![("switched", false)],
            json!({"cell": cell}),
        );
        it.verdict = Verdict::Inconclusive;
        it.suspected_owner = "LAB".into();
        it.id = format!("N5/{cell}");
        return it;
    };
    let terms: Vec<(ProcRef, u64)> = i
        .candidates
        .iter()
        .flat_map(|c| {
            r.events(GuardEventKind::AutoTerminated, *c)
                .into_iter()
                .map(move |e| (*c, e.at_unix_ms))
        })
        .collect();
    let pre: Vec<_> = terms.iter().filter(|(_, at)| *at <= sw).collect();
    let post: Vec<_> = terms.iter().filter(|(_, at)| *at > sw).collect();
    let pre_targets: Vec<ProcRef> = pre.iter().map(|(t, _)| *t).collect();
    let post_signals = r
        .signals
        .iter()
        .filter(|c| c.at_ms > sw && !pre_targets.iter().any(|t| t.pid == c.pid))
        .filter(|c| i.candidates.iter().any(|t| t.pid == c.pid))
        .count();
    let post_scan_from = r
        .scans
        .iter()
        .find(|s| s.taken_at_ms > sw)
        .map_or(u64::MAX, |s| s.taken_at_ms);
    let post_pending = r
        .scans
        .iter()
        .filter(|s| s.taken_at_ms > post_scan_from)
        .map(|s| s.status.pending.len())
        .sum::<usize>();
    let post_forced = r
        .scans
        .iter()
        .filter(|s| s.taken_at_ms > post_scan_from)
        .any(|s| s.status.health_forced.is_some());
    let remaining_alive = i
        .candidates
        .iter()
        .filter(|c| !pre_targets.contains(c))
        .all(|c| r.alive_at_end(*c));
    let floor_ok = match (pre.first(), r.first_term_floor()) {
        (Some((_, at)), Some(f)) => *at >= f,
        (None, _) => true,
        (Some(_), None) => false,
    };
    let mut checks = vec![
        ("forced_before_switch", r.forced_applied(0, sw)),
        (
            "pre_switch_terminations_expected",
            if i.expect_pre_term {
                !pre.is_empty()
            } else {
                pre.is_empty()
            },
        ),
        ("not_before_start_floor", floor_ok),
        ("no_auto_terminate_after_switch", post.is_empty()),
        ("no_new_signals_after_switch", post_signals == 0),
        ("no_pending_after_switch", post_pending == 0),
        ("forced_cleared_after_switch", !post_forced),
        ("remaining_alive", remaining_alive),
    ];
    if !i.expect_pre_term {
        checks.push((
            "no_signals_at_all",
            r.signals
                .iter()
                .all(|c| !i.candidates.iter().any(|t| t.pid == c.pid)),
        ));
    }
    let stable_events = r.events_kind(GuardEventKind::Stable).len();
    let it = finish(
        "N5",
        "강제 → 정상 전환: 전환 전 안전·적극은 첫 후보 정리(알림만 0), 전환 뒤 새 자동 조치·신호·대기 0, 남은 후보 생존",
        checks,
        json!({"cell": cell, "switch_ms": sw, "pre": pre, "post": post, "post_signals": post_signals, "stable_events": stable_events}),
    );
    let mut it = health_gate(it, r, sw, i.end_ms);
    it.id = format!("N5/{cell}");
    it
}
