//! 순수 판정: 신호·IO·시계 호출 없음. 2,000 프로세스에서 ≤ 5ms.
//!
//! 수준과 무관한 바닥(R01~R17)은 여기가 아니라 `vh_act::plan`/`execute`가 다시 적용한다.
//! 여기의 자기·조상·보호 Kind 제외는 화면에 "자동 예정"으로 보이지 않게 하는 선필터다.

use std::collections::{HashMap, HashSet};

use vh_model::{
    Classified, Confidence, ExeOrigin, Finding, FindingKind, GuardPolicy, Kind, PendingAction,
    PendingWait, Proc, ProcRef, ProcStatus, Report, Snapshot, Step, Suggestion, exe_origin,
};

use crate::cpu::next_scan_interval_ms;
use crate::memory::{CpuStreak, GuardMemory, Streak};

/// vh-act `PROTECTED_KINDS`와 같은 집합(R08). 어느 수준에서도 자동 종료·Demote하지 않는다.
pub const PROTECTED_KINDS: [Kind; 4] = [
    Kind::AgentCli,
    Kind::GuiApp,
    Kind::VirtualMachine,
    Kind::Database,
];

/// 제외 사유(테스트·화면 디버그·알림 중복 방지 키).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    Paused,
    LevelNotifyOnly,
    ConfidenceBelow,
    SuggestionNotTerminate,
    KindNotAuto,
    KindProtected,
    KindNotifyOnly,
    OwnerAlive,
    TooYoung,
    NotPersisted,
    NotInSnapshot,
    SelfOrAncestor,
    CircuitOpen,
    QuotaExceeded,
    CpuNotSustained,
    RunawayNoDemote,
    AlreadyDemoted,
    RefusedBefore,
}

/// 이번 스캔에 실행할 조치 하나.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub target: ProcRef,
    pub finding_id: String,
    pub kind: Kind,
    pub label_ko: String,
    /// Term(사다리) 또는 Demote.
    pub step: Step,
    pub include_descendants: bool,
    pub reclaim_bytes: u64,
    pub confidence: Confidence,
    pub cpu_pct: Option<f32>,
}

/// 알림 후보.
#[derive(Debug, Clone, PartialEq)]
pub struct NotifyItem {
    pub target: ProcRef,
    pub finding_id: String,
    pub label_ko: String,
    pub reason: SkipReason,
    pub reclaim_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Skip {
    pub target: ProcRef,
    pub finding_id: Option<String>,
    pub reason: SkipReason,
}

/// 판정 결과.
#[derive(Debug, Clone, PartialEq)]
pub struct Decisions {
    /// 실행 순서대로.
    pub terminate: Vec<Candidate>,
    pub demote: Vec<Candidate>,
    /// 후보 수가 남은 할당량을 넘었다: 이번 스캔은 0건 실행하고 차단기를 연다.
    pub trip_circuit: bool,
    pub pending: Vec<PendingAction>,
    pub notify: Vec<NotifyItem>,
    pub skipped: Vec<Skip>,
    /// 이번 스캔을 반영한 다음 기억(엔진이 그대로 저장한다).
    pub next_term_streak: HashMap<ProcRef, Streak>,
    pub next_cpu_streak: HashMap<ProcRef, CpuStreak>,
    pub next_scan_interval_ms: u32,
}

struct Index<'a> {
    procs: HashMap<ProcRef, &'a Proc>,
    cls: HashMap<ProcRef, &'a Classified>,
    runaway_ids: HashMap<ProcRef, &'a str>,
    self_and_ancestors: HashSet<i32>,
}

impl<'a> Index<'a> {
    fn new(s: &'a Snapshot, r: &'a Report) -> Self {
        let mut ppid: HashMap<i32, i32> = HashMap::with_capacity(s.processes.len());
        let mut procs = HashMap::with_capacity(s.processes.len());
        for p in &s.processes {
            ppid.insert(p.pid, p.ppid);
            procs.insert(pref(p), p);
        }
        let mut self_and_ancestors = HashSet::from([s.self_pid]);
        let mut cur = ppid.get(&s.self_pid).copied();
        while let Some(p) = cur {
            if p <= 0 || !self_and_ancestors.insert(p) || self_and_ancestors.len() > 64 {
                break;
            }
            cur = ppid.get(&p).copied();
        }
        let cls = r.classified.iter().map(|c| (c.target, c)).collect();
        let runaway_ids = r
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::HighCpu)
            .flat_map(|f| f.targets.iter().map(move |t| (*t, f.id.as_str())))
            .collect();
        Index {
            procs,
            cls,
            runaway_ids,
            self_and_ancestors,
        }
    }

    fn kind(&self, t: ProcRef) -> Kind {
        self.cls.get(&t).map(|c| c.kind).unwrap_or(Kind::Other)
    }

    fn label(&self, t: ProcRef) -> String {
        match self.cls.get(&t) {
            Some(c) => c.label_ko.clone(),
            None => self
                .procs
                .get(&t)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| format!("pid {}", t.pid)),
        }
    }
}

fn pref(p: &Proc) -> ProcRef {
    ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

/// 이번 스캔에 할 일을 정한다. `skipped`에 제외 사유를 모두 채운다(테스트·실험실 그림자 판정용).
pub fn decide(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    policy: &GuardPolicy,
    now_ms: u64,
) -> Decisions {
    decide_impl(prev, snapshot, report, policy, now_ms, true)
}

/// [`decide`]와 같은 판정이되 `skipped`를 만들지 않는다(엔진이 쓰는 제품 경로, 스캔당 할당 감소).
pub fn decide_lean(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    policy: &GuardPolicy,
    now_ms: u64,
) -> Decisions {
    decide_impl(prev, snapshot, report, policy, now_ms, false)
}

fn decide_impl(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    policy: &GuardPolicy,
    now_ms: u64,
    record_skips: bool,
) -> Decisions {
    let interval = next_scan_interval_ms(policy, snapshot.memory.pressure_level);
    let mut d = Decisions {
        terminate: Vec::new(),
        demote: Vec::new(),
        trip_circuit: false,
        pending: Vec::new(),
        notify: Vec::new(),
        skipped: Vec::new(),
        next_term_streak: HashMap::new(),
        next_cpu_streak: HashMap::new(),
        next_scan_interval_ms: interval,
    };
    if prev.paused {
        return d;
    }
    let idx = Index::new(snapshot, report);
    let mut terminate = Vec::new();
    decide_terminations(
        prev,
        snapshot,
        report,
        policy,
        now_ms,
        &idx,
        &mut d,
        &mut terminate,
        record_skips,
    );
    apply_quota(
        prev,
        policy,
        now_ms,
        snapshot.memory.pressure_level,
        terminate,
        &mut d,
    );
    decide_demotes(prev, snapshot, policy, &idx, &mut d, record_skips);
    d
}

#[allow(clippy::too_many_arguments)]
fn decide_terminations(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    policy: &GuardPolicy,
    now_ms: u64,
    idx: &Index<'_>,
    d: &mut Decisions,
    out: &mut Vec<Candidate>,
    record_skips: bool,
) {
    let level_notify_only = policy.auto_terminate_kinds.is_empty();
    let mut skip = |t: ProcRef, fid: &str, reason: SkipReason| {
        if !record_skips {
            return;
        }
        d.skipped.push(Skip {
            target: t,
            finding_id: Some(fid.to_string()),
            reason,
        });
    };
    for f in &report.findings {
        let Suggestion::Terminate {
            include_descendants,
        } = f.suggestion
        else {
            for &t in &f.targets {
                match young_orphan_pending(prev, f, t, idx, policy, now_ms) {
                    Some(p) => {
                        skip(t, &f.id, SkipReason::TooYoung);
                        d.pending.push(p);
                    }
                    None => skip(t, &f.id, SkipReason::SuggestionNotTerminate),
                }
            }
            continue;
        };
        for &t in &f.targets {
            let Some(proc_) = idx.procs.get(&t).filter(|p| p.status != ProcStatus::Zombie) else {
                skip(t, &f.id, SkipReason::NotInSnapshot);
                continue;
            };
            if idx.self_and_ancestors.contains(&t.pid) {
                skip(t, &f.id, SkipReason::SelfOrAncestor);
                continue;
            }
            let kind = idx.kind(t);
            if PROTECTED_KINDS.contains(&kind) {
                skip(t, &f.id, SkipReason::KindProtected);
                continue;
            }
            if !f.confidence.meets(policy.min_confidence) {
                skip(t, &f.id, SkipReason::ConfidenceBelow);
                continue;
            }
            let label_ko = idx.label(t);
            if policy.notify_only_kinds.contains(&kind) {
                d.notify.push(NotifyItem {
                    target: t,
                    finding_id: f.id.clone(),
                    label_ko,
                    reason: SkipReason::KindNotifyOnly,
                    reclaim_bytes: f.reclaim_bytes,
                });
                continue;
            }
            if !policy.auto_terminate_kinds.contains(&kind) {
                if level_notify_only {
                    d.notify.push(NotifyItem {
                        target: t,
                        finding_id: f.id.clone(),
                        label_ko,
                        reason: SkipReason::LevelNotifyOnly,
                        reclaim_bytes: f.reclaim_bytes,
                    });
                } else {
                    skip(t, &f.id, SkipReason::KindNotAuto);
                }
                continue;
            }
            if idx.cls.get(&t).is_some_and(|c| c.owner_alive == Some(true)) {
                skip(t, &f.id, SkipReason::OwnerAlive);
                continue;
            }
            if prev.refused.contains(&t) {
                skip(t, &f.id, SkipReason::RefusedBefore);
                continue;
            }
            let age = now_ms.saturating_sub(proc_.start_time_unix_ms);
            if age < policy.min_process_age_ms {
                skip(t, &f.id, SkipReason::TooYoung);
                d.pending.push(PendingAction {
                    target: t,
                    finding_id: f.id.clone(),
                    kind,
                    label_ko,
                    step: Step::Term,
                    seen_scans: 0,
                    needed_scans: policy.persistence_scans,
                    eta_ms: Some(policy.min_process_age_ms - age),
                    wait: PendingWait::Confirming,
                });
                continue;
            }
            if d.next_term_streak.contains_key(&t) {
                continue;
            }
            let seen = match prev.term_streak.get(&t) {
                Some(s) if s.finding_kind == f.kind => s.seen + 1,
                _ => 1,
            };
            let first_seen = prev
                .term_streak
                .get(&t)
                .filter(|s| s.finding_kind == f.kind)
                .map(|s| s.first_seen_at_unix_ms)
                .unwrap_or(now_ms);
            d.next_term_streak.insert(
                t,
                Streak {
                    finding_id: f.id.clone(),
                    finding_kind: f.kind,
                    confidence: f.confidence,
                    include_descendants,
                    seen,
                    first_seen_at_unix_ms: first_seen,
                },
            );
            if seen < policy.persistence_scans {
                skip(t, &f.id, SkipReason::NotPersisted);
                d.pending.push(PendingAction {
                    target: t,
                    finding_id: f.id.clone(),
                    kind,
                    label_ko,
                    step: Step::Term,
                    seen_scans: seen,
                    needed_scans: policy.persistence_scans,
                    eta_ms: Some(
                        u64::from(policy.persistence_scans - seen)
                            * u64::from(d.next_scan_interval_ms),
                    ),
                    wait: PendingWait::Confirming,
                });
                continue;
            }
            out.push(Candidate {
                target: t,
                finding_id: f.id.clone(),
                kind,
                label_ko,
                step: Step::Term,
                include_descendants,
                reclaim_bytes: f.reclaim_bytes,
                confidence: f.confidence,
                cpu_pct: proc_.cpu_pct,
            });
        }
    }
    let _ = snapshot;
}

/// 나이만 모자라 아직 Terminate 제안이 아닌 고아를 화면의 '자동 예정'으로만 보여 준다(실행 없음).
/// vh-analyze는 나이 미달 고아에 `young`만 남기고 다른 근거를 적지 않으므로, 나이가 차면 Confirmed가 될
/// 근거(stdio 종류 또는 주인 종료)와 강등 요인(터미널·실행 파일 미상)을 분류 결과와 스냅샷에서 다시 본다.
fn young_orphan_pending(
    prev: &GuardMemory,
    f: &Finding,
    t: ProcRef,
    idx: &Index<'_>,
    policy: &GuardPolicy,
    now_ms: u64,
) -> Option<PendingAction> {
    if !matches!(f.kind, FindingKind::Orphan | FindingKind::LogicalOrphan)
        || !f.reason_codes.iter().any(|r| r == "young")
    {
        return None;
    }
    let p = idx
        .procs
        .get(&t)
        .filter(|p| p.status != ProcStatus::Zombie)?;
    let age = now_ms.saturating_sub(p.start_time_unix_ms);
    if age >= policy.min_process_age_ms
        || idx.self_and_ancestors.contains(&t.pid)
        || prev.refused.contains(&t)
    {
        return None;
    }
    let c = idx.cls.get(&t)?;
    let kind = c.kind;
    if PROTECTED_KINDS.contains(&kind)
        || policy.notify_only_kinds.contains(&kind)
        || !policy.auto_terminate_kinds.contains(&kind)
        || c.owner_alive == Some(true)
    {
        return None;
    }
    let sig = c.signature_id.as_deref().unwrap_or("");
    let stdio = matches!(kind, Kind::McpServer | Kind::LanguageServer)
        || matches!(sig, "w_esbuild_service" | "agent_claude_bg");
    let owner_dead = c.owner_alive == Some(false);
    if sig == "agent_claude_daemon" || !(stdio || owner_dead) {
        return None;
    }
    let mut would_be = Confidence::Confirmed;
    if p.has_tty {
        would_be = Confidence::Likely;
    }
    if exe_origin(p.exe.as_deref()) == ExeOrigin::Unknown {
        would_be = Confidence::Possible;
    }
    if !would_be.meets(policy.min_confidence) {
        return None;
    }
    Some(PendingAction {
        target: t,
        finding_id: f.id.clone(),
        kind,
        label_ko: idx.label(t),
        step: Step::Term,
        seen_scans: 0,
        needed_scans: policy.persistence_scans,
        eta_ms: Some(policy.min_process_age_ms - age),
        wait: PendingWait::Confirming,
    })
}

fn apply_quota(
    prev: &GuardMemory,
    policy: &GuardPolicy,
    now_ms: u64,
    pressure_level: u32,
    mut cands: Vec<Candidate>,
    d: &mut Decisions,
) {
    if cands.is_empty() {
        return;
    }
    if policy.pressure_largest_first && pressure_level >= 4 {
        cands.sort_by_key(|a| std::cmp::Reverse(a.reclaim_bytes));
    }
    let to_notify = |cands: Vec<Candidate>, reason: SkipReason, d: &mut Decisions| {
        for c in cands {
            d.notify.push(NotifyItem {
                target: c.target,
                finding_id: c.finding_id,
                label_ko: c.label_ko,
                reason,
                reclaim_bytes: c.reclaim_bytes,
            });
        }
    };
    if prev.circuit_open {
        to_notify(cands, SkipReason::CircuitOpen, d);
        return;
    }
    let used = prev.terminations_in_window(now_ms, policy.rate_window_ms);
    let quota = policy.max_auto_terminations.saturating_sub(used) as usize;
    if cands.len() > quota {
        d.trip_circuit = true;
        to_notify(cands, SkipReason::QuotaExceeded, d);
        return;
    }
    d.terminate = cands;
}

fn decide_demotes(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    policy: &GuardPolicy,
    idx: &Index<'_>,
    d: &mut Decisions,
    record_skips: bool,
) {
    if !policy.auto_demote {
        return;
    }
    let max_per_scan = policy.max_auto_terminations as usize;
    for p in &snapshot.processes {
        let Some(pct) = p.cpu_pct else { continue };
        let t = pref(p);
        if p.uid != snapshot.self_uid
            || matches!(p.status, ProcStatus::Zombie | ProcStatus::Stopped)
            || idx.self_and_ancestors.contains(&p.pid)
        {
            continue;
        }
        let kind = idx.kind(t);
        if kind == Kind::System || exe_origin(p.exe.as_deref()) == ExeOrigin::System {
            continue;
        }
        if pct < policy.runaway_cpu_pct {
            continue;
        }
        let seen = prev.cpu_streak.get(&t).map(|s| s.seen).unwrap_or(0) + 1;
        d.next_cpu_streak.insert(
            t,
            CpuStreak {
                seen,
                last_pct: pct,
            },
        );
        let finding_id = idx
            .runaway_ids
            .get(&t)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("guard-runaway:{}:{}", t.pid, t.start_time_unix_ms));
        let label_ko = idx.label(t);
        let no_demote_kind = PROTECTED_KINDS.contains(&kind)
            || policy.notify_only_kinds.contains(&kind)
            || kind == Kind::AppHelper;
        if no_demote_kind {
            if seen >= policy.runaway_sustained_scans {
                d.notify.push(NotifyItem {
                    target: t,
                    finding_id,
                    label_ko,
                    reason: SkipReason::RunawayNoDemote,
                    reclaim_bytes: 0,
                });
            }
            continue;
        }
        if prev.demoted.contains_key(&t) {
            if record_skips {
                d.skipped.push(Skip {
                    target: t,
                    finding_id: Some(finding_id),
                    reason: SkipReason::AlreadyDemoted,
                });
            }
            continue;
        }
        if prev.refused.contains(&t) {
            if record_skips {
                d.skipped.push(Skip {
                    target: t,
                    finding_id: Some(finding_id),
                    reason: SkipReason::RefusedBefore,
                });
            }
            continue;
        }
        if seen < policy.runaway_sustained_scans {
            if record_skips {
                d.skipped.push(Skip {
                    target: t,
                    finding_id: Some(finding_id.clone()),
                    reason: SkipReason::CpuNotSustained,
                });
            }
            d.pending.push(PendingAction {
                target: t,
                finding_id,
                kind,
                label_ko,
                step: Step::Demote,
                seen_scans: seen,
                needed_scans: policy.runaway_sustained_scans,
                eta_ms: Some(
                    u64::from(policy.runaway_sustained_scans - seen)
                        * u64::from(d.next_scan_interval_ms),
                ),
                wait: PendingWait::Confirming,
            });
            continue;
        }
        if d.demote.len() >= max_per_scan {
            continue;
        }
        d.demote.push(Candidate {
            target: t,
            finding_id,
            kind,
            label_ko: format!("{label_ko} CPU {pct:.0}%"),
            step: Step::Demote,
            include_descendants: false,
            reclaim_bytes: 0,
            confidence: Confidence::Confirmed,
            cpu_pct: Some(pct),
        });
    }
}
