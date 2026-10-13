//! plan: Report·Selection·Policy → ActionPlan. 신호 0회.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use vh_model::{
    ActionPlan, Kind, PlannedAction, Proc, ProcRef, ProcStatus, Refusal, Report, Snapshot, Step,
    Suggestion,
};

use crate::protect::{check, refusal};
use crate::rule::*;
use crate::{Policy, ProtectCtx, Selection};

const MAX_ANCESTORS: usize = 64;
const MAX_SUBTREE: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Act {
    Terminate { include_descendants: bool },
    Demote,
    Resume,
}

struct Candidate {
    finding_id: String,
    target: ProcRef,
    act: Act,
    reason_ko: String,
}

pub(crate) struct SnapIndex<'s> {
    by_pid: HashMap<i32, &'s Proc>,
    kids: HashMap<i32, Vec<&'s Proc>>,
}

impl<'s> SnapIndex<'s> {
    pub(crate) fn new(s: &'s Snapshot) -> Self {
        let mut by_pid = HashMap::new();
        let mut kids: HashMap<i32, Vec<&Proc>> = HashMap::new();
        for p in &s.processes {
            by_pid.insert(p.pid, p);
            if p.ppid != p.pid {
                kids.entry(p.ppid).or_default().push(p);
            }
        }
        SnapIndex { by_pid, kids }
    }

    /// pid와 start_time이 모두 맞는 스냅샷 프로세스.
    pub(crate) fn get(&self, r: ProcRef) -> Option<&'s Proc> {
        self.by_pid
            .get(&r.pid)
            .copied()
            .filter(|p| p.start_time_unix_ms == r.start_time_unix_ms)
    }

    pub(crate) fn children(&self, pid: i32) -> &[&'s Proc] {
        self.kids.get(&pid).map(Vec::as_slice).unwrap_or(&[])
    }

    /// 대상 제외 스냅샷 자손(BFS).
    pub(crate) fn subtree(&self, root: i32) -> Vec<&'s Proc> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::from([root]);
        let mut q = VecDeque::from([root]);
        while let Some(pid) = q.pop_front() {
            for &c in self.children(pid) {
                if out.len() >= MAX_SUBTREE {
                    return out;
                }
                if seen.insert(c.pid) {
                    out.push(c);
                    q.push_back(c.pid);
                }
            }
        }
        out
    }

    /// 스냅샷 기준 `pid`의 조상 체인(ppid → … , 최대 64단).
    pub(crate) fn ancestors(&self, pid: i32) -> Vec<i32> {
        let mut out = Vec::new();
        let mut cur = self.by_pid.get(&pid).map(|p| p.ppid);
        while let Some(p) = cur {
            if p <= 0 || out.len() >= MAX_ANCESTORS || out.contains(&p) {
                break;
            }
            out.push(p);
            cur = self.by_pid.get(&p).map(|x| x.ppid);
        }
        out
    }
}

fn pref(p: &Proc) -> ProcRef {
    ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn not_actionable_reason(s: &Suggestion) -> &'static str {
    match s {
        Suggestion::HandoffThenRestart => {
            "에이전트 세션입니다. 핸드오프를 저장한 뒤 직접 재시작하세요(자동 조치 대상 아님)"
        }
        Suggestion::RestartParent { .. } => {
            "부모 프로세스를 재시작해야 정리됩니다(자동 조치 대상 아님)"
        }
        Suggestion::Review => {
            "검토가 필요한 발견입니다. `vh fix --only <pid>`로 직접 지목하면 정리합니다"
        }
        _ => "이 발견은 자동 조치 대상이 아닙니다",
    }
}

pub(crate) fn plan(s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
    let idx = SnapIndex::new(s);
    let kinds: HashMap<ProcRef, Kind> = r.classified.iter().map(|c| (c.target, c.kind)).collect();
    let self_ancestors = idx.ancestors(s.self_pid);

    let mut refused: Vec<Refusal> = Vec::new();
    let mut refuse = |rf: Refusal| {
        if !refused
            .iter()
            .any(|x| x.target == rf.target && x.rule == rf.rule)
        {
            refused.push(rf);
        }
    };

    let mut cands: Vec<Candidate> = Vec::new();
    if !sel.direct.is_empty() {
        for d in &sel.direct {
            cands.push(Candidate {
                finding_id: format!("direct:{}:{}", d.target.pid, d.target.start_time_unix_ms),
                target: d.target,
                act: Act::Terminate {
                    include_descendants: d.include_descendants,
                },
                reason_ko: "사용자가 직접 지정".to_string(),
            });
        }
    } else {
        let explicit = !sel.finding_ids.is_empty() || !sel.pids.is_empty();
        let pointed = !sel.pids.is_empty();
        for f in &r.findings {
            if !sel.finding_ids.is_empty() && !sel.finding_ids.contains(&f.id) {
                continue;
            }
            let targets: Vec<ProcRef> = f
                .targets
                .iter()
                .copied()
                .filter(|t| sel.pids.is_empty() || sel.pids.contains(&t.pid))
                .collect();
            if targets.is_empty() || !f.confidence.meets(sel.min_confidence) {
                continue;
            }
            let act = match &f.suggestion {
                Suggestion::Terminate {
                    include_descendants,
                } => Act::Terminate {
                    include_descendants: policy.include_descendants.unwrap_or(*include_descendants),
                },
                Suggestion::Review if pointed => Act::Terminate {
                    include_descendants: policy.include_descendants.unwrap_or(false),
                },
                Suggestion::Demote if policy.allow_demote => Act::Demote,
                Suggestion::Demote => {
                    if explicit {
                        for t in &targets {
                            refuse(refusal(
                                *t,
                                R12_DEMOTE_DISABLED,
                                "우선순위 낮추기는 --demote를 줘야 실행합니다",
                            ));
                        }
                    }
                    continue;
                }
                Suggestion::Resume => Act::Resume,
                other @ (Suggestion::None
                | Suggestion::RestartParent { .. }
                | Suggestion::HandoffThenRestart
                | Suggestion::Review) => {
                    if explicit {
                        for t in &targets {
                            refuse(refusal(
                                *t,
                                R11_SUGGESTION_NOT_ACTIONABLE,
                                not_actionable_reason(other),
                            ));
                        }
                    }
                    continue;
                }
            };
            for t in targets {
                cands.push(Candidate {
                    finding_id: f.id.clone(),
                    target: t,
                    act,
                    reason_ko: f.title_ko.clone(),
                });
            }
        }
    }

    let mut items: Vec<PlannedAction> = Vec::new();
    let mut covered: BTreeMap<ProcRef, BTreeSet<ProcRef>> = BTreeMap::new();
    for c in cands {
        if items.iter().any(|i| i.target == c.target) {
            continue;
        }
        let Some(snap) = idx.get(c.target) else {
            refuse(refusal(
                c.target,
                R14_START_TIME_MISMATCH,
                "스냅샷에서 이 프로세스를 찾지 못했습니다(이미 끝났거나 PID가 재사용됨). 건드리지 않습니다",
            ));
            continue;
        };
        let subtree = idx.subtree(c.target.pid);
        let subtree_kinds: Vec<(ProcRef, Kind)> = subtree
            .iter()
            .filter_map(|p| kinds.get(&pref(p)).map(|k| (pref(p), *k)))
            .collect();
        let ctx = ProtectCtx {
            target: c.target,
            live: None,
            snap: Some(snap),
            kind: kinds.get(&c.target).copied(),
            self_pid: s.self_pid,
            self_uid: s.self_uid,
            self_ancestors: &self_ancestors,
            subtree_kinds: &subtree_kinds,
        };
        if let Some(rf) = check(&ctx) {
            refuse(rf);
            continue;
        }
        let (steps, include, reclaim) = match c.act {
            Act::Terminate {
                include_descendants,
            } => {
                let mut steps = Vec::new();
                if snap.status == ProcStatus::Stopped {
                    steps.push(Step::Cont);
                }
                steps.extend([Step::Term, Step::Kill]);
                let mut bytes = snap.footprint_bytes.unwrap_or(0);
                if include_descendants {
                    bytes += subtree
                        .iter()
                        .map(|p| p.footprint_bytes.unwrap_or(0))
                        .sum::<u64>();
                    covered.insert(c.target, subtree.iter().map(|p| pref(p)).collect());
                }
                (steps, include_descendants, bytes)
            }
            Act::Demote => (vec![Step::Demote], false, 0),
            Act::Resume => (vec![Step::Cont], false, 0),
        };
        items.push(PlannedAction {
            finding_id: c.finding_id,
            target: c.target,
            include_descendants: include,
            descendant_count: if include { subtree.len() as u32 } else { 0 },
            steps,
            grace_ms: policy.grace_ms,
            reason_ko: c.reason_ko,
            est_reclaim_bytes: reclaim,
        });
    }

    items.retain(|i| {
        !covered
            .iter()
            .any(|(owner, set)| *owner != i.target && set.contains(&i.target))
    });
    items.truncate(policy.max_actions);

    ActionPlan {
        created_at_unix_ms: now_ms(),
        total_deadline_ms: policy.total_deadline_ms,
        items,
        refused,
    }
}
