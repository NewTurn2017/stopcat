//! 순수 판정: 신호·IO·시계 호출 없음. 2,000 프로세스에서 ≤ 5ms.
//!
//! W4: 자동 조치는 맥이 불안정할 때만, 구역 unneeded·쓰고 있지 않음·지킴이가 본 '안 씀' 2분·나이 10분·
//! 불안정 중 2번 연속·종류·신뢰도·상한·차단기·정착 시간을 모두 통과한 것만 한다. 우선순위 자동 낮추기는 없다.
//! 수준과 무관한 바닥(R01~R19)은 여기가 아니라 `vh_act::plan`/`execute`가 다시 적용한다.

use std::collections::{HashMap, HashSet};

use vh_model::{
    Classified, Confidence, ExeOrigin, Finding, FindingKind, GuardPolicy, HealthLevel, Kind,
    PendingAction, PendingWait, Proc, ProcRef, ProcStatus, Report, Section, Snapshot, Step,
    Suggestion, Usage, UsageReason, exe_origin,
};

use crate::cpu::next_scan_interval_ms;
use crate::memory::{GuardMemory, Streak};
use crate::stability::{Stability, stability};

/// vh-act `PROTECTED_KINDS`와 같은 집합(R08). 어느 수준에서도 자동 종료하지 않는다.
pub const PROTECTED_KINDS: [Kind; 4] = [
    Kind::AgentCli,
    Kind::GuiApp,
    Kind::VirtualMachine,
    Kind::Database,
];

/// 제외 사유(테스트·실험실 그림자 판정용).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    Paused,
    /// 맥이 안정(정상)이라 자동 조치하지 않는다.
    NotUnstable,
    /// 구역이 unneeded가 아니다.
    SectionNotUnneeded,
    LevelNotifyOnly,
    ConfidenceBelow,
    SuggestionNotTerminate,
    KindNotAuto,
    KindProtected,
    KindNotifyOnly,
    /// `Usage::in_use()`(Unknown 포함) 또는 분류 없음.
    InUse,
    OwnerAlive,
    TooYoung,
    /// 지킴이가 본 '안 씀'이 `idle_confirm_ms`에 못 미침.
    IdleNotConfirmed,
    NotPersisted,
    NotInSnapshot,
    SelfOrAncestor,
    CircuitOpen,
    QuotaExceeded,
    /// 직전 회차 뒤 정착 시간 중.
    Settling,
    /// 주의 단계 회차 한도(큰 것부터 `max_per_round_watch`개).
    RoundLimit,
    RefusedBefore,
}

/// 이번 스캔에 실행할 조치 하나.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub target: ProcRef,
    pub finding_id: String,
    pub kind: Kind,
    pub label_ko: String,
    /// 언제나 Term(사다리).
    pub step: Step,
    pub include_descendants: bool,
    pub reclaim_bytes: u64,
    pub confidence: Confidence,
    pub cpu_pct: Option<f32>,
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
    /// 실행 순서대로(큰 것부터).
    pub terminate: Vec<Candidate>,
    /// W4부터 자동 우선순위 낮추기가 없어 언제나 비어 있다(실험실 그림자 판정의 불변식 확인용으로 남김).
    pub demote: Vec<Candidate>,
    /// 후보 수가 남은 할당량을 넘었다: 이번 스캔은 0건 실행하고 차단기를 연다.
    pub trip_circuit: bool,
    /// 불안정일 때만 채운다.
    pub pending: Vec<PendingAction>,
    pub skipped: Vec<Skip>,
    /// 이번 스캔을 반영한 다음 연속 기억(엔진이 그대로 저장한다). 안정이면 비어 있다.
    pub next_term_streak: HashMap<ProcRef, Streak>,
    pub next_scan_interval_ms: u32,
    /// 이번 스캔의 안정 판단.
    pub stability: Stability,
}

struct Index<'a> {
    procs: HashMap<ProcRef, &'a Proc>,
    cls: HashMap<ProcRef, &'a Classified>,
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
        Index {
            procs,
            cls,
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

    /// 분류가 없으면 쓰고 있음(닫힌 쪽).
    fn in_use(&self, t: ProcRef) -> bool {
        self.cls.get(&t).is_none_or(|c| c.usage.in_use())
    }
}

fn pref(p: &Proc) -> ProcRef {
    ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

/// 이번 스캔에 할 일을 정한다. `skipped`에 제외 사유를 모두 채운다(테스트·실험실 그림자 판정용).
/// `prev`에는 이번 스캔의 [`crate::stability::observe`]가 반영되어 있어야 한다.
pub fn decide(
    prev: &GuardMemory,
    snapshot: &Snapshot,
    report: &Report,
    policy: &GuardPolicy,
    now_ms: u64,
) -> Decisions {
    decide_impl(prev, snapshot, report, policy, now_ms, true)
}

/// [`decide`]와 같은 판정이되 `skipped`를 만들지 않는다(엔진이 쓰는 제품 경로).
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
    let stab = stability(prev, report, policy);
    let mut d = Decisions {
        terminate: Vec::new(),
        demote: Vec::new(),
        trip_circuit: false,
        pending: Vec::new(),
        skipped: Vec::new(),
        next_term_streak: HashMap::new(),
        next_scan_interval_ms: next_scan_interval_ms(policy, stab.unstable),
        stability: stab,
    };
    if prev.paused {
        return d;
    }
    if !d.stability.unstable {
        if record_skips {
            for f in &report.findings {
                for &t in &f.targets {
                    d.skipped.push(Skip {
                        target: t,
                        finding_id: Some(f.id.clone()),
                        reason: SkipReason::NotUnstable,
                    });
                }
            }
        }
        return d;
    }
    let idx = Index::new(snapshot, report);
    let mut cands = Vec::new();
    decide_terminations(
        prev,
        report,
        policy,
        now_ms,
        &idx,
        &mut d,
        &mut cands,
        record_skips,
    );
    let health = d.stability.health;
    apply_limits(prev, policy, now_ms, health, cands, &mut d, record_skips);
    d
}

#[allow(clippy::too_many_arguments)]
fn decide_terminations(
    prev: &GuardMemory,
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
        if f.section != Section::Unneeded {
            for &t in &f.targets {
                skip(t, &f.id, SkipReason::SectionNotUnneeded);
            }
            continue;
        }
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
            if policy.notify_only_kinds.contains(&kind) {
                skip(t, &f.id, SkipReason::KindNotifyOnly);
                continue;
            }
            if !policy.auto_terminate_kinds.contains(&kind) {
                let reason = if level_notify_only {
                    SkipReason::LevelNotifyOnly
                } else {
                    SkipReason::KindNotAuto
                };
                skip(t, &f.id, reason);
                continue;
            }
            if idx.in_use(t) {
                skip(t, &f.id, SkipReason::InUse);
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
            let label_ko = idx.label(t);
            let age = now_ms.saturating_sub(proc_.start_time_unix_ms);
            if age < policy.min_process_age_ms {
                skip(t, &f.id, SkipReason::TooYoung);
                d.pending.push(pending(
                    t,
                    f,
                    kind,
                    label_ko,
                    0,
                    policy,
                    PendingWait::TooYoung,
                    Some(policy.min_process_age_ms - age),
                ));
                continue;
            }
            if d.next_term_streak.contains_key(&t) {
                continue;
            }
            let same = prev
                .term_streak
                .get(&t)
                .filter(|s| s.finding_kind == f.kind);
            let seen = same.map(|s| s.seen + 1).unwrap_or(1);
            let first_seen = same.map(|s| s.first_seen_at_unix_ms).unwrap_or(now_ms);
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
            let idle_for = prev
                .idle_since
                .get(&t)
                .map(|&since| now_ms.saturating_sub(since));
            if idle_for.is_none_or(|ms| ms < policy.idle_confirm_ms) {
                skip(t, &f.id, SkipReason::IdleNotConfirmed);
                let eta = policy.idle_confirm_ms - idle_for.unwrap_or(0);
                d.pending.push(pending(
                    t,
                    f,
                    kind,
                    label_ko,
                    seen,
                    policy,
                    PendingWait::IdleConfirming,
                    Some(eta),
                ));
                continue;
            }
            if seen < policy.persistence_scans {
                skip(t, &f.id, SkipReason::NotPersisted);
                let eta =
                    u64::from(policy.persistence_scans - seen) * u64::from(d.next_scan_interval_ms);
                d.pending.push(pending(
                    t,
                    f,
                    kind,
                    label_ko,
                    seen,
                    policy,
                    PendingWait::Confirming,
                    Some(eta),
                ));
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
}

#[allow(clippy::too_many_arguments)]
fn pending(
    t: ProcRef,
    f: &Finding,
    kind: Kind,
    label_ko: String,
    seen: u32,
    policy: &GuardPolicy,
    wait: PendingWait,
    eta_ms: Option<u64>,
) -> PendingAction {
    PendingAction {
        target: t,
        finding_id: f.id.clone(),
        kind,
        label_ko,
        step: Step::Term,
        seen_scans: seen,
        needed_scans: policy.persistence_scans,
        eta_ms,
        wait,
    }
}

/// '쓰고 있음' 근거가 `young` 하나뿐인지(나이만 차면 안 씀이 될 대상).
fn only_young(u: &Usage) -> bool {
    u.reasons.contains(&UsageReason::Young)
        && !u.reasons.iter().any(|r| {
            matches!(
                r,
                UsageReason::OwnerAlive
                    | UsageReason::UserOwned
                    | UsageReason::HasTty
                    | UsageReason::PeerOutsideSubtree
                    | UsageReason::PeerExternal
                    | UsageReason::PeerUnresolved
                    | UsageReason::CpuActive
                    | UsageReason::DiskActive
                    | UsageReason::CpuUnknown
                    | UsageReason::DiskUnknown
                    | UsageReason::PeersUnknown
            )
        })
}

/// 나이만 모자라 아직 Terminate 제안이 아닌 고아를 '자동 예정'(too_young)으로만 보여 준다(불안정일 때만, 실행 없음).
/// 쓰고 있음 근거가 `young` 하나뿐이어야 하고, 나이가 차면 Confirmed가 될 근거(stdio 종류 또는 주인 종료)와
/// 강등 요인(터미널·실행 파일 미상)을 분류 결과와 스냅샷에서 다시 본다.
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
        || !only_young(&c.usage)
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
        wait: PendingWait::TooYoung,
    })
}

/// 큰 것부터 정렬 → 차단기 → 할당량(넘으면 0건 + 차단기) → 정착 시간 → 주의 단계 회차 한도.
fn apply_limits(
    prev: &GuardMemory,
    policy: &GuardPolicy,
    now_ms: u64,
    health: HealthLevel,
    mut cands: Vec<Candidate>,
    d: &mut Decisions,
    record_skips: bool,
) {
    if cands.is_empty() {
        return;
    }
    cands.sort_by_key(|a| std::cmp::Reverse(a.reclaim_bytes));
    let skip_all = |cands: &[Candidate], reason: SkipReason, d: &mut Decisions| {
        if record_skips {
            for c in cands {
                d.skipped.push(Skip {
                    target: c.target,
                    finding_id: Some(c.finding_id.clone()),
                    reason,
                });
            }
        }
    };
    if prev.circuit_open {
        skip_all(&cands, SkipReason::CircuitOpen, d);
        return;
    }
    let used = prev.terminations_in_window(now_ms, policy.rate_window_ms);
    let quota = policy.max_auto_terminations.saturating_sub(used) as usize;
    if cands.len() > quota {
        d.trip_circuit = true;
        skip_all(&cands, SkipReason::QuotaExceeded, d);
        return;
    }
    let settle_until = prev
        .last_round_at_unix_ms
        .map(|t| t.saturating_add(policy.settle_ms));
    if let Some(until) = settle_until.filter(|&u| now_ms < u) {
        skip_all(&cands, SkipReason::Settling, d);
        for c in cands {
            d.pending.push(from_candidate(
                c,
                policy,
                PendingWait::Settling,
                Some(until - now_ms),
            ));
        }
        return;
    }
    let per_round = if health == HealthLevel::Critical {
        cands.len()
    } else {
        (policy.max_per_round_watch as usize).max(1)
    };
    if cands.len() > per_round {
        let rest = cands.split_off(per_round);
        skip_all(&rest, SkipReason::RoundLimit, d);
        for c in rest {
            d.pending.push(from_candidate(
                c,
                policy,
                PendingWait::RoundLimit,
                Some(policy.settle_ms),
            ));
        }
    }
    d.terminate = cands;
}

fn from_candidate(
    c: Candidate,
    policy: &GuardPolicy,
    wait: PendingWait,
    eta_ms: Option<u64>,
) -> PendingAction {
    PendingAction {
        target: c.target,
        finding_id: c.finding_id,
        kind: c.kind,
        label_ko: c.label_ko,
        step: Step::Term,
        seen_scans: policy.persistence_scans,
        needed_scans: policy.persistence_scans,
        eta_ms,
        wait,
    }
}
