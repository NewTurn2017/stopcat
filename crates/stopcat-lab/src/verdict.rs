//! 기록(스캔·커널·신호·알림·감사)에서 시나리오 판정을 계산한다. 순수 함수라 합성 기록으로 시험한다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stopcat_model::{
    Confidence, FindingKind, GuardEvent, GuardEventKind, Kind, ProcRef, Step, Suggestion,
};

use crate::notify::NotifyRec;
use crate::run::{KernelRec, ScanRec};
use crate::signal::SignalCall;

pub const MIN_AGE_MS: u64 = 600_000;
pub const TERM_WINDOW_MS: u64 = 3 * 5_000 + 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub expected: String,
    pub observed: serde_json::Value,
    pub verdict: Verdict,
    pub evidence: Vec<String>,
    pub suspected_owner: String,
    pub severity: String,
    pub repro: String,
    #[serde(default)]
    pub checks: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Records {
    pub scans: Vec<ScanRec>,
    pub kernel: Vec<KernelRec>,
    pub signals: Vec<SignalCall>,
    pub notes: Vec<NotifyRec>,
    pub audit: Vec<serde_json::Value>,
    pub undemoted: Vec<ProcRef>,
    /// 실험실 대상마다 알림 줄에서 그 대상을 가리키는 표지(pid, 프로젝트 폴더·package 이름).
    pub markers: BTreeMap<ProcRef, Vec<String>>,
}

/// `needle`이 앞뒤로 글자·숫자·`-`·`_`가 붙지 않은 채 나오는지("s1"이 "s10"·"lab-s1"에 걸리지 않게).
pub fn has_token(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let word = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + needle.len()..].chars().next();
        !before.is_some_and(word) && !after.is_some_and(word)
    })
}

impl Records {
    pub fn events(&self, kind: GuardEventKind, t: ProcRef) -> Vec<&GuardEvent> {
        self.scans
            .iter()
            .flat_map(|s| s.events.iter())
            .filter(|e| e.kind == kind && e.target == Some(t))
            .collect()
    }

    pub fn events_kind(&self, kind: GuardEventKind) -> Vec<&GuardEvent> {
        self.scans
            .iter()
            .flat_map(|s| s.events.iter())
            .filter(|e| e.kind == kind)
            .collect()
    }

    pub fn any_event_on(&self, t: ProcRef) -> usize {
        self.scans
            .iter()
            .flat_map(|s| s.events.iter())
            .filter(|e| e.target == Some(t))
            .count()
    }

    pub fn pending_seen(&self, t: ProcRef) -> Vec<(u64, u32, Step)> {
        self.scans
            .iter()
            .flat_map(|s| {
                s.status
                    .pending
                    .iter()
                    .filter(move |p| p.target == t)
                    .map(move |p| (s.taken_at_ms, p.seen_scans, p.step))
            })
            .collect()
    }

    pub fn last_finding(&self, t: ProcRef) -> Option<(FindingKind, Confidence, Suggestion)> {
        self.scans.iter().rev().find_map(|s| {
            s.findings
                .iter()
                .find(|f| f.targets.contains(&t))
                .map(|f| (f.kind, f.confidence, f.suggestion.clone()))
        })
    }

    pub fn finding_of_kind(&self, t: ProcRef, k: FindingKind) -> Option<(Confidence, Suggestion)> {
        self.scans.iter().rev().find_map(|s| {
            s.findings
                .iter()
                .find(|f| f.kind == k && f.targets.contains(&t))
                .map(|f| (f.confidence, f.suggestion.clone()))
        })
    }

    pub fn last_kind(&self, t: ProcRef) -> Option<(Kind, Option<bool>, String)> {
        self.scans.iter().rev().find_map(|s| {
            s.classified
                .iter()
                .find(|c| c.target == t)
                .map(|c| (c.kind, c.owner_alive, c.label_ko.clone()))
        })
    }

    pub fn signals_to(&self, pid: i32) -> usize {
        self.signals.iter().filter(|c| c.pid == pid).count()
    }

    pub fn alive_at_end(&self, t: ProcRef) -> bool {
        self.kernel
            .iter()
            .rev()
            .find(|k| k.r == t)
            .is_some_and(|k| k.alive || k.zombie)
    }

    pub fn gone_after(&self, t: ProcRef, at: u64) -> Option<u64> {
        self.kernel
            .iter()
            .filter(|k| k.r == t && k.at_ms >= at && !k.alive)
            .map(|k| k.at_ms)
            .next()
    }

    pub fn audit_mentions(&self, pid: i32) -> bool {
        self.audit
            .iter()
            .any(|a| serde_json::to_string(a).is_ok_and(|s| s.contains(&format!("\"pid\":{pid}"))))
    }

    pub fn notes_with(&self, needle: &str) -> usize {
        self.notes
            .iter()
            .filter(|n| n.body.contains(needle))
            .count()
    }

    fn marks(&self, t: ProcRef) -> Vec<String> {
        let mut m = vec![format!("pid {}", t.pid)];
        m.extend(self.markers.get(&t).cloned().unwrap_or_default());
        m
    }

    /// 알림 한 줄(본문은 " · "로 묶인 줄들)이 `t`에 대한 것인지. `t`의 표지가 있으면 그렇다.
    /// 표지가 없으면 라벨이 같고 다른 실험실 대상의 표지가 없을 때만 `t`로 본다
    /// (같은 이름 여러 개를 이름만으로 세지 않는다 — W3 S10 오탐).
    pub fn line_about(&self, line: &str, t: ProcRef, label: &str) -> bool {
        if self.marks(t).iter().any(|m| has_token(line, m)) {
            return true;
        }
        if label.is_empty() || !line.contains(label) {
            return false;
        }
        !self
            .markers
            .keys()
            .filter(|o| **o != t)
            .any(|o| self.marks(*o).iter().any(|m| has_token(line, m)))
    }

    /// `since_ms` 이후 알림 중 `t`에 대한 줄의 수.
    pub fn notes_about(&self, t: ProcRef, label: &str, since_ms: u64) -> usize {
        self.notes
            .iter()
            .filter(|n| n.at_ms >= since_ms)
            .flat_map(|n| n.body.split(" · "))
            .filter(|l| self.line_about(l, t, label))
            .count()
    }

    pub fn untouched(&self, t: ProcRef) -> bool {
        self.any_event_on(t) == 0 && self.pending_seen(t).is_empty() && self.signals_to(t.pid) == 0
    }
}

fn item(
    id: &str,
    expected: &str,
    checks: BTreeMap<String, bool>,
    observed: serde_json::Value,
) -> Item {
    let verdict = if checks.values().all(|v| *v) {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    Item {
        id: id.to_string(),
        expected: expected.to_string(),
        observed,
        verdict,
        evidence: Vec::new(),
        suspected_owner: "none".into(),
        severity: "low".into(),
        repro: String::new(),
        checks,
    }
}

fn chk(pairs: &[(&str, bool)]) -> BTreeMap<String, bool> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn owner_for_missing_termination(
    f: Option<&(FindingKind, Confidence, Suggestion)>,
) -> &'static str {
    match f {
        Some((_, Confidence::Confirmed, Suggestion::Terminate { .. })) => "GUARD",
        _ => "CORE",
    }
}

/// S1·S2·S11: 10분 지나고 연속 2회 뒤 자동 종료, 감사 로그·알림 기록.
pub fn auto_terminated(id: &str, r: &Records, t: ProcRef, label_hint: Option<&str>) -> Item {
    let ev = r
        .events(GuardEventKind::AutoTerminated, t)
        .first()
        .copied()
        .cloned();
    let finding = r.last_finding(t);
    let pend = r.pending_seen(t);
    let expected = "나이 ≥ 10분 첫 스캔에서 대기 1/2 → 다음 스캔 종료(AutoTerminated), 감사 로그 Term, 알림 기록";
    let Some(ev) = ev else {
        let mut it = item(
            id,
            expected,
            chk(&[("auto_terminated_event", false)]),
            serde_json::json!({
                "auto_terminated": false,
                "last_finding": finding,
                "pending_seen": pend,
                "alive_at_end": r.alive_at_end(t),
            }),
        );
        it.suspected_owner = owner_for_missing_termination(finding.as_ref()).into();
        it.severity = "high".into();
        return it;
    };
    let age = ev.at_unix_ms.saturating_sub(t.start_time_unix_ms);
    let gone = r.gone_after(t, ev.at_unix_ms);
    let label = label_hint.unwrap_or(ev.label_ko.as_str()).to_string();
    let noted = r.notes_about(t, &label, ev.at_unix_ms) > 0;
    let checks = chk(&[
        ("age_ge_10m", age >= MIN_AGE_MS),
        ("age_within_window", age <= MIN_AGE_MS + TERM_WINDOW_MS),
        (
            "pending_1_of_2_seen_before",
            pend.iter().any(|(_, s, _)| *s == 1),
        ),
        (
            "gone_within_10s",
            gone.is_some_and(|g| g <= ev.at_unix_ms + 10_000),
        ),
        ("audit_logged", r.audit_mentions(t.pid)),
        ("notification_recorded", noted),
        (
            "only_term_signals_to_target",
            r.signals
                .iter()
                .filter(|c| c.pid == t.pid)
                .all(|c| c.op == "send"),
        ),
    ]);
    let mut it = item(
        id,
        expected,
        checks,
        serde_json::json!({
            "age_ms_at_auto_terminated": age,
            "pending_seen": pend,
            "gone_at_ms": gone,
            "label": label,
        }),
    );
    if it.verdict == Verdict::Fail {
        it.suspected_owner = "GUARD".into();
        it.severity = "medium".into();
    }
    it
}

/// S11 추가: S1이 끝나는 스캔에서 9분째 고아가 '자동 예정'(대기)으로 보이는지.
pub fn young_pending_visible(r: &Records, young: ProcRef, at_ms: u64) -> (bool, serde_json::Value) {
    let scan = r
        .scans
        .iter()
        .find(|s| s.taken_at_ms >= at_ms.saturating_sub(6_000));
    let p = scan.and_then(|s| s.status.pending.iter().find(|p| p.target == young).cloned());
    let f = r.last_finding(young);
    (
        p.is_some(),
        serde_json::json!({"pending_at_s1_termination": p, "finding_before_10m": r.scans.iter().find_map(|s| {
            let age = s.taken_at_ms.saturating_sub(young.start_time_unix_ms);
            (age < MIN_AGE_MS && age > MIN_AGE_MS - 120_000)
                .then(|| s.findings.iter().find(|f| f.targets.contains(&young)).map(|f| (f.kind, f.confidence)))
                .flatten()
        }), "last_finding": f}),
    )
}

/// S3: 3회 연속 CPU ≥ 100 뒤 Demote(우선순위 4 실측), 종료 때 되돌림(실측).
pub fn demoted_and_restored(r: &Records, t: ProcRef, base: Option<i32>) -> Item {
    let ev = r
        .events(GuardEventKind::Demoted, t)
        .first()
        .copied()
        .cloned();
    let pend = r.pending_seen(t);
    let cpu: Vec<f32> = r
        .scans
        .iter()
        .filter_map(|s| s.procs.iter().find(|p| p.r == t).and_then(|p| p.cpu_pct))
        .collect();
    let prio_4_after = ev.as_ref().is_some_and(|e| {
        r.kernel.iter().any(|k| {
            k.r == t
                && k.at_ms >= e.at_unix_ms
                && k.at_ms <= e.at_unix_ms + 5_000
                && k.priority == Some(4)
        })
    });
    let last_prio = r
        .kernel
        .iter()
        .rev()
        .find(|k| k.r == t && k.alive)
        .and_then(|k| k.priority);
    let checks = chk(&[
        (
            "pending_demote_1_and_2",
            pend.iter().any(|x| x.1 == 1) && pend.iter().any(|x| x.1 == 2),
        ),
        ("demoted_event", ev.is_some()),
        ("priority_4_within_5s", prio_4_after),
        ("undemoted_at_shutdown", r.undemoted.contains(&t)),
        ("priority_restored", base.is_some() && last_prio == base),
        (
            "no_auto_terminate",
            r.events(GuardEventKind::AutoTerminated, t).is_empty(),
        ),
    ]);
    let mut it = item(
        "S3",
        "CPU ≥ 100% 연속 3회 → Demoted, 우선순위 기준 → 4, shutdown 뒤 기준값으로 복귀, 자동 종료 없음",
        checks,
        serde_json::json!({"cpu_pct_by_scan": cpu, "priority_base": base, "priority_last": last_prio, "pending_seen": pend}),
    );
    if it.verdict == Verdict::Fail {
        let under = cpu.iter().take(4).any(|c| *c < 100.0);
        if ev.is_none() && under {
            it.verdict = Verdict::Inconclusive;
        } else {
            it.suspected_owner = "GUARD".into();
            it.severity = "high".into();
        }
    }
    it
}

/// S4: 자동 조치 없음, 계속 분류에 보임, footprint 증가가 보임.
pub fn memory_grower(r: &Records, t: ProcRef) -> Item {
    let fps: Vec<(u64, u64)> = r
        .scans
        .iter()
        .filter_map(|s| {
            s.procs
                .iter()
                .find(|p| p.r == t)
                .and_then(|p| p.footprint_bytes.map(|f| (s.taken_at_ms, f)))
        })
        .collect();
    let first = fps.first().copied();
    let at8 = first.and_then(|(t0, _)| fps.iter().find(|(at, _)| *at >= t0 + 480_000).copied());
    let grew = match (first, at8) {
        (Some((_, a)), Some((_, b))) => b.saturating_sub(a),
        _ => 0,
    };
    let kmatch = at8.is_some_and(|(at, f)| {
        r.kernel
            .iter()
            .filter(|k| k.r == t && k.at_ms.abs_diff(at) <= 5_000)
            .filter_map(|k| k.footprint_bytes)
            .any(|kf| (kf as f64 - f as f64).abs() <= kf as f64 * 0.10)
    });
    let in_findings = r.last_finding(t).is_some();
    let checks = chk(&[
        (
            "classified_every_scan",
            r.scans
                .iter()
                .filter(|s| s.taken_at_ms > t.start_time_unix_ms)
                .all(|s| s.classified.iter().any(|c| c.target == t)),
        ),
        ("no_action", r.untouched(t)),
        ("footprint_grew_ge_300mb_by_8min", grew >= 300 * 1024 * 1024),
        ("footprint_matches_kernel_10pct", kmatch),
    ]);
    item(
        "S4",
        "자동 종료 없음, 목록(Report.classified)에 계속 보임, footprint 증가(8분에 ≥ 300MB)",
        checks,
        serde_json::json!({
            "footprint_grew_bytes_8min": grew,
            "in_findings_list": in_findings,
            "improvement_candidate_ko": "메모리가 계속 늘어나는 프로세스를 4GB(HeavyProcess) 전에는 알려 주지 않는다(PM 판정 Q5)",
        }),
    )
}

/// S5: 좀비 → RestartParent 제안, 자동 조치 없음.
pub fn zombie(r: &Records, parent: ProcRef, z: ProcRef) -> Item {
    let f = r.finding_of_kind(z, FindingKind::Zombie);
    let ok_sugg = matches!(&f, Some((_, Suggestion::RestartParent { parent: p })) if *p == parent);
    let checks = chk(&[
        ("zombie_finding_restart_parent", ok_sugg),
        ("parent_untouched", r.untouched(parent)),
        ("zombie_untouched", r.untouched(z)),
        (
            "zombie_until_end",
            r.kernel
                .iter()
                .rev()
                .find(|k| k.r == z)
                .is_some_and(|k| k.zombie),
        ),
    ]);
    item(
        "S5",
        "자동 조치 없음, Zombie 발견 + RestartParent{부모}",
        checks,
        serde_json::json!({"finding": f}),
    )
}

pub fn stopped(r: &Records, t: ProcRef) -> Item {
    let f = r.finding_of_kind(t, FindingKind::Stopped);
    let checks = chk(&[
        (
            "stopped_finding_resume",
            matches!(f, Some((_, Suggestion::Resume))),
        ),
        (
            "stopped_until_end",
            r.kernel
                .iter()
                .rev()
                .find(|k| k.r == t)
                .is_some_and(|k| k.stopped),
        ),
        ("untouched", r.untouched(t)),
    ]);
    item(
        "S6",
        "자동 종료 없음, Stopped 발견(Resume)",
        checks,
        serde_json::json!({"finding": f}),
    )
}

pub fn duplicate(r: &Records, first: ProcRef, second: ProcRef) -> Item {
    let f = r.finding_of_kind(first, FindingKind::Duplicate);
    let checks = chk(&[
        ("duplicate_finding_on_older", f.is_some()),
        (
            "both_alive",
            r.alive_at_end(first) && r.alive_at_end(second),
        ),
        ("untouched", r.untouched(first) && r.untouched(second)),
    ]);
    item(
        "S7",
        "자동 종료 없음, Duplicate 발견",
        checks,
        serde_json::json!({"finding": f}),
    )
}

pub fn notify_only(r: &Records, t: ProcRef) -> Item {
    let label = r.last_kind(t).map(|k| k.2).unwrap_or_default();
    let kind = r.last_kind(t).map(|k| k.0);
    let n = r.notes_about(t, &label, 0);
    let checks = chk(&[
        ("kind_emulator", kind == Some(Kind::Emulator)),
        (
            "no_auto_terminate",
            r.events(GuardEventKind::AutoTerminated, t).is_empty() && r.signals_to(t.pid) == 0,
        ),
        ("notified_exactly_once", n == 1),
        ("alive_at_end", r.alive_at_end(t)),
    ]);
    let mut it = item(
        "S8",
        "자동 종료 없음, 알림만(라벨이 알림에 정확히 1번)",
        checks,
        serde_json::json!({"kind": kind, "label": label, "notification_mentions": n, "last_finding": r.last_finding(t)}),
    );
    if it.verdict == Verdict::Fail {
        it.suspected_owner = if kind == Some(Kind::Emulator) {
            "GUARD"
        } else {
            "CORE"
        }
        .into();
        it.severity = "high".into();
    }
    it
}

pub fn never_touched(
    id: &str,
    expected: &str,
    r: &Records,
    t: ProcRef,
    owner_alive: Option<bool>,
) -> Item {
    let k = r.last_kind(t);
    let label = k.as_ref().map(|k| k.2.clone()).unwrap_or_default();
    let mut pairs = vec![
        ("untouched", r.untouched(t)),
        ("alive_at_end", r.alive_at_end(t)),
        ("not_in_notifications", r.notes_about(t, &label, 0) == 0),
    ];
    if let Some(want) = owner_alive {
        pairs.push((
            "owner_alive_matches",
            k.as_ref().and_then(|k| k.1) == Some(want),
        ));
    }
    let mut it = item(
        id,
        expected,
        chk(&pairs),
        serde_json::json!({"kind": k.as_ref().map(|k| k.0), "owner_alive": k.as_ref().and_then(|k| k.1), "last_finding": r.last_finding(t), "label": label, "notification_lines_about_target": r.notes_about(t, &label, 0), "notification_lines_with_label": r.notes_with(&label)}),
    );
    if it.verdict == Verdict::Fail {
        it.suspected_owner = "GUARD".into();
        it.severity = "high".into();
    }
    it
}

/// 차단기 detail에 들어 있는 할당량 표기(W4 문구에는 후보 수가 없다).
pub const CIRCUIT_QUOTA_KO: &str = "10분에 5개 제한";

/// S12: 한꺼번에 7개 → 그 스캔 0건 실행 + 차단기 + 알림.
/// '7개 동시 자격'은 문구가 아니라 all_alive·zero_auto_terminated·circuit_open_once를 함께 보아 판정한다.
pub fn circuit(r: &Records, targets: &[ProcRef]) -> Item {
    let auto = r.events_kind(GuardEventKind::AutoTerminated).len();
    let opens = r.events_kind(GuardEventKind::CircuitOpen);
    let sends = r.signals.iter().filter(|c| c.op == "send").count();
    let checks = chk(&[
        ("zero_auto_terminated", auto == 0),
        ("zero_term_signals", sends == 0),
        ("circuit_open_once", opens.len() == 1),
        (
            "circuit_detail_quota",
            opens.iter().any(|e| e.detail_ko.contains(CIRCUIT_QUOTA_KO)),
        ),
        (
            "status_circuit_open",
            r.scans.iter().any(|s| s.status.circuit_open),
        ),
        (
            "notification_recorded",
            r.notes_with(crate::strings::CIRCUIT_NOTE) >= 1,
        ),
        ("all_alive", targets.iter().all(|t| r.alive_at_end(*t))),
    ]);
    let starts: Vec<u64> = targets.iter().map(|t| t.start_time_unix_ms).collect();
    let spread = starts.iter().max().unwrap_or(&0) - starts.iter().min().unwrap_or(&0);
    let mut it = item(
        "S12",
        "7개가 같은 스캔에서 자격 → 0건 실행 + CircuitOpen 1번 + 알림, 7개 생존",
        checks,
        serde_json::json!({"auto_terminated": auto, "circuit_open_events": opens.len(), "start_spread_ms": spread}),
    );
    if it.verdict == Verdict::Fail {
        if auto > 0 && spread >= 5_000 {
            it.verdict = Verdict::Inconclusive;
        } else {
            it.suspected_owner = "GUARD".into();
            it.severity = "high".into();
        }
    }
    it
}
