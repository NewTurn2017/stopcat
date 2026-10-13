//! 1겹 격리: 지킴이 백엔드를 감싸 스냅샷을 실험실 것만 남기고, 계획·실행 직전에 다시 확인한다.
//! 대조군(shadow)은 걸러지기 전 전체 스냅샷으로 같은 판정을 순수하게 돌려 "새면 무엇이 됐을지"를 개수로만 남긴다.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use vh_act::{Policy, PriorityTarget, Selection};
use vh_guard::{GuardBackend, GuardMemory};
use vh_model::{
    ActionOutcome, ActionPlan, FindingKind, GuardPolicy, Proc, ProcRef, Report, Snapshot,
};

use crate::spec::TAG;

pub fn pref(p: &Proc) -> ProcRef {
    ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabScope {
    pub tag: String,
    pub refs: BTreeSet<ProcRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ScopeStats {
    pub total: usize,
    pub kept: usize,
    pub dropped: usize,
    pub kept_registered: usize,
    pub unregistered_tagged: usize,
    pub registry_missing: usize,
    pub kept_refs: Vec<ProcRef>,
}

impl LabScope {
    pub fn admits(&self, p: &Proc) -> bool {
        p.env.get(TAG).is_some_and(|t| *t == self.tag) || self.refs.contains(&pref(p))
    }

    pub fn retain(&self, s: &mut Snapshot) -> ScopeStats {
        let total = s.processes.len();
        s.processes.retain(|p| self.admits(p));
        let kept: BTreeSet<ProcRef> = s.processes.iter().map(pref).collect();
        let kept_pids: BTreeSet<i32> = kept.iter().map(|r| r.pid).collect();
        s.listeners.retain(|l| {
            kept.contains(&ProcRef {
                pid: l.pid,
                start_time_unix_ms: l.start_time_unix_ms,
            })
        });
        s.launchd_job_pids.retain(|p| kept_pids.contains(p));
        s.launchd_job_labels.retain(|p, _| kept_pids.contains(p));
        let cwds: BTreeSet<&str> = s
            .processes
            .iter()
            .filter_map(|p| p.cwd.as_deref())
            .collect();
        s.project_roots.retain(|k, _| cwds.contains(k.as_str()));
        s.collection_errors
            .retain(|e| e.pid.is_none_or(|p| kept_pids.contains(&p)));
        let kept_registered = kept.iter().filter(|r| self.refs.contains(r)).count();
        ScopeStats {
            total,
            kept: kept.len(),
            dropped: total - kept.len(),
            kept_registered,
            unregistered_tagged: kept.len() - kept_registered,
            registry_missing: self.refs.iter().filter(|r| !kept.contains(r)).count(),
            kept_refs: kept.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ShadowRec {
    pub full_procs: usize,
    pub outside_orphan_findings: usize,
    pub outside_terminate_candidates: usize,
    pub outside_demote_candidates: usize,
    pub outside_pending: usize,
    pub watched_in_terminate: Vec<ProcRef>,
    pub watched_in_demote: Vec<ProcRef>,
    pub watched_in_pending: Vec<ProcRef>,
}

/// 대조군: 전체 스냅샷 + 별도 기억으로 `decide`만(신호·실행 없음). 개수와 감시 대상(미끼) ProcRef만 남긴다.
pub struct Shadow {
    pub policy: GuardPolicy,
    pub mem: GuardMemory,
    pub watch: BTreeSet<ProcRef>,
}

impl Shadow {
    pub fn new(policy: GuardPolicy, watch: BTreeSet<ProcRef>) -> Self {
        Shadow {
            mem: GuardMemory::new(policy.level),
            policy,
            watch,
        }
    }

    pub fn observe(&mut self, full: &mut Snapshot, scope: &LabScope) -> ShadowRec {
        vh_guard::fill_cpu_pct(full, &self.mem);
        let report = vh_analyze::analyze(full);
        let d = vh_guard::decide(
            &self.mem,
            full,
            &report,
            &self.policy,
            full.taken_at_unix_ms,
        );
        self.mem.term_streak = d.next_term_streak.clone();
        self.mem.cpu_streak = d.next_cpu_streak.clone();
        vh_guard::cpu::remember(&mut self.mem, full);
        let inside: BTreeSet<ProcRef> = full
            .processes
            .iter()
            .filter(|p| scope.admits(p))
            .map(pref)
            .collect();
        let outside = |r: &ProcRef| !inside.contains(r);
        let watched = |rs: Vec<ProcRef>| -> Vec<ProcRef> {
            rs.into_iter().filter(|r| self.watch.contains(r)).collect()
        };
        ShadowRec {
            full_procs: full.processes.len(),
            outside_orphan_findings: report
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.kind,
                        FindingKind::Orphan
                            | FindingKind::LogicalOrphan
                            | FindingKind::HeadlessBrowserLeftover
                    )
                })
                .flat_map(|f| f.targets.iter())
                .filter(|t| outside(t))
                .count(),
            outside_terminate_candidates: d.terminate.iter().filter(|c| outside(&c.target)).count(),
            outside_demote_candidates: d.demote.iter().filter(|c| outside(&c.target)).count(),
            outside_pending: d.pending.iter().filter(|p| outside(&p.target)).count(),
            watched_in_terminate: watched(d.terminate.iter().map(|c| c.target).collect()),
            watched_in_demote: watched(d.demote.iter().map(|c| c.target).collect()),
            watched_in_pending: watched(d.pending.iter().map(|p| p.target).collect()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanFilterRec {
    pub at_ms: u64,
    pub stats: ScopeStats,
    pub shadow: Option<ShadowRec>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Violation {
    pub at_ms: u64,
    pub stage: String,
    pub target: ProcRef,
}

#[derive(Debug, Default)]
pub struct ScopeLog {
    pub scans: Vec<ScanFilterRec>,
    pub violations: Vec<Violation>,
}

pub struct ScopedBackend<B: GuardBackend> {
    inner: B,
    scope: LabScope,
    admitted: BTreeSet<ProcRef>,
    log: Arc<Mutex<ScopeLog>>,
    shadow: Option<Shadow>,
}

impl<B: GuardBackend> ScopedBackend<B> {
    pub fn new(inner: B, scope: LabScope, shadow: Option<Shadow>) -> (Self, Arc<Mutex<ScopeLog>>) {
        let log = Arc::new(Mutex::new(ScopeLog::default()));
        let admitted = scope.refs.clone();
        (
            ScopedBackend {
                inner,
                scope,
                admitted,
                log: log.clone(),
                shadow,
            },
            log,
        )
    }

    pub fn inner(&self) -> &B {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }

    fn check_plan(&mut self, mut plan: ActionPlan, stage: &str) -> ActionPlan {
        let now = self.inner.now_unix_ms();
        let admitted = &self.admitted;
        let mut bad = Vec::new();
        plan.items.retain(|it| {
            let ok = admitted.contains(&it.target);
            if !ok {
                bad.push(it.target);
            }
            ok
        });
        plan.refused.retain(|rf| {
            let ok = admitted.contains(&rf.target);
            if !ok {
                bad.push(rf.target);
            }
            ok
        });
        if !bad.is_empty()
            && let Ok(mut l) = self.log.lock()
        {
            for t in bad {
                l.violations.push(Violation {
                    at_ms: now,
                    stage: stage.to_string(),
                    target: t,
                });
            }
        }
        plan
    }
}

impl<B: GuardBackend> GuardBackend for ScopedBackend<B> {
    fn collect(&mut self) -> Result<Snapshot, String> {
        let mut s = self.inner.collect()?;
        let shadow = self.shadow.as_mut().map(|sh| {
            let mut full = s.clone();
            sh.observe(&mut full, &self.scope)
        });
        let stats = self.scope.retain(&mut s);
        self.admitted.extend(stats.kept_refs.iter().copied());
        if let Ok(mut l) = self.log.lock() {
            l.scans.push(ScanFilterRec {
                at_ms: s.taken_at_unix_ms,
                stats,
                shadow,
            });
        }
        Ok(s)
    }

    fn analyze(&mut self, s: &Snapshot) -> Report {
        self.inner.analyze(s)
    }

    fn plan(&mut self, s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
        let p = self.inner.plan(s, r, sel, policy);
        self.check_plan(p, "plan")
    }

    fn plan_priority(
        &mut self,
        s: &Snapshot,
        r: Option<&Report>,
        targets: &[PriorityTarget],
        policy: &Policy,
    ) -> ActionPlan {
        let p = self.inner.plan_priority(s, r, targets, policy);
        self.check_plan(p, "plan_priority")
    }

    fn execute(&mut self, plan: &ActionPlan, s: &Snapshot, run_id: &str) -> Vec<ActionOutcome> {
        let checked = self.check_plan(plan.clone(), "execute");
        if checked.items.is_empty() {
            return Vec::new();
        }
        self.inner.execute(&checked, s, run_id)
    }

    fn notify(&mut self, title: &str, body: &str) -> Result<(), String> {
        self.inner.notify(title, body)
    }

    fn now_unix_ms(&self) -> u64 {
        self.inner.now_unix_ms()
    }

    fn state_dir(&self) -> &Path {
        self.inner.state_dir()
    }
}
