#![allow(dead_code)]

use vh_guard::fake::*;
use vh_guard::{AutoLevel, GuardEvent, GuardEventKind, GuardPolicy};
use vh_model::*;

pub const SELF_PID: i32 = 4_000_000;
pub const UID: u32 = 501;
/// 시계 시작(2026-10-13 쯤의 unix ms).
pub const T0: u64 = 1_792_000_000_000;
/// 11분 전에 시작한 프로세스(나이 조건 통과).
pub const OLD: u64 = T0 - 11 * 60_000;

pub fn safe() -> GuardPolicy {
    GuardPolicy::for_level(AutoLevel::Safe)
}

pub fn aggressive() -> GuardPolicy {
    GuardPolicy::for_level(AutoLevel::Aggressive)
}

pub fn notify_only() -> GuardPolicy {
    GuardPolicy::for_level(AutoLevel::NotifyOnly)
}

pub fn term(include_descendants: bool) -> Suggestion {
    Suggestion::Terminate {
        include_descendants,
    }
}

/// 한 프로세스짜리 장면: (스냅샷, 리포트). Finding 하나, Classified 하나.
pub struct Scene {
    pub procs: Vec<Proc>,
    pub classified: Vec<Classified>,
    pub findings: Vec<Finding>,
}

impl Scene {
    pub fn new() -> Self {
        Scene {
            procs: vec![proc_(SELF_PID, 1, UID, OLD, "vh")],
            classified: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// 자동 종료 후보 하나를 넣는다. 돌려주는 값은 ProcRef.
    pub fn leftover(
        &mut self,
        pid: i32,
        kind: Kind,
        confidence: Confidence,
        start: u64,
        owner_alive: Option<bool>,
    ) -> ProcRef {
        let p = proc_(pid, 1, UID, start, &format!("p{pid}"));
        let r = pref(&p);
        self.procs.push(p);
        self.classified
            .push(classified(r, kind, &format!("{kind:?} {pid}"), owner_alive));
        self.findings.push(finding(
            &format!("orphan:{pid}"),
            FindingKind::LogicalOrphan,
            confidence,
            vec![r],
            term(false),
            100 * 1024 * 1024,
        ));
        r
    }

    /// Finding 없이 프로세스만(폭주 테스트용).
    pub fn plain(&mut self, pid: i32, kind: Kind, start: u64) -> ProcRef {
        let p = proc_(pid, 1, UID, start, &format!("p{pid}"));
        let r = pref(&p);
        self.procs.push(p);
        self.classified
            .push(classified(r, kind, &format!("{kind:?} {pid}"), None));
        r
    }

    pub fn build(&self, now: u64) -> (Snapshot, Report) {
        (
            snapshot(SELF_PID, UID, now, self.procs.clone()),
            report(now, self.classified.clone(), self.findings.clone()),
        )
    }

    pub fn build_pressure(&self, now: u64, pressure: u32) -> (Snapshot, Report) {
        let (mut s, r) = self.build(now);
        s.memory.pressure_level = pressure;
        (s, r)
    }
}

impl Default for Scene {
    fn default() -> Self {
        Self::new()
    }
}

pub fn kinds(events: &[GuardEvent]) -> Vec<GuardEventKind> {
    events.iter().map(|e| e.kind).collect()
}

pub fn count(events: &[GuardEvent], k: GuardEventKind) -> usize {
    events.iter().filter(|e| e.kind == k).count()
}
