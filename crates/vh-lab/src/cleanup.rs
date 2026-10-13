//! 실험실 자체 신호(SIGSTOP·정리)는 여기서만 나간다. 대상은 허용된 ProcRef뿐이고, 보내기 직전 시작 시각을
//! 다시 확인한다. killpg는 그룹 구성원 전부가 허용 목록에 있을 때만 쓰고, 아니면 pid별로 내려간다.

use std::collections::BTreeSet;

use serde::Serialize;
use vh_act::Liveness;
use vh_model::ProcRef;

use crate::kernel::LabKernel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReapCall {
    pub at_ms: u64,
    pub op: String,
    pub target: i32,
    pub sig: i32,
    pub ok: bool,
    pub note: String,
}

pub struct LabReaper<'k> {
    k: &'k dyn LabKernel,
    allowed: BTreeSet<ProcRef>,
    pub calls: Vec<ReapCall>,
}

impl<'k> LabReaper<'k> {
    pub fn new(k: &'k dyn LabKernel, allowed: BTreeSet<ProcRef>) -> Self {
        LabReaper {
            k,
            allowed,
            calls: Vec::new(),
        }
    }

    fn push(&mut self, op: &str, target: i32, sig: i32, ok: bool, note: &str) {
        self.calls.push(ReapCall {
            at_ms: self.k.now_ms(),
            op: op.to_string(),
            target,
            sig,
            ok,
            note: note.to_string(),
        });
    }

    pub fn is_alive(&self, r: ProcRef) -> bool {
        let live = self.k.probe(r.pid);
        live.liveness == Liveness::Alive && live.start_time_unix_ms == r.start_time_unix_ms
    }

    /// 허용된 ProcRef에만, 시작 시각이 같을 때만 보낸다.
    pub fn signal(&mut self, r: ProcRef, sig: i32) -> bool {
        if !self.allowed.contains(&r) {
            self.push("refused", r.pid, sig, false, "허용 목록 밖");
            return false;
        }
        let live = self.k.probe(r.pid);
        if live.liveness == Liveness::Gone {
            return false;
        }
        if live.start_time_unix_ms != r.start_time_unix_ms {
            self.push("refused", r.pid, sig, false, "시작 시각 다름(pid 재사용)");
            return false;
        }
        let ok = self.k.kill(r.pid, sig).is_ok();
        self.push("kill", r.pid, sig, ok, "");
        ok
    }

    /// 그룹 구성원 전부가 허용 목록 안이면 killpg, 아니면 허용된 구성원에게만 pid별로.
    pub fn killpg_checked(&mut self, pgid: i32, sig: i32) -> bool {
        let members = self.k.pgrp_members(pgid);
        if members.is_empty() {
            return false;
        }
        let refs: Vec<ProcRef> = members
            .iter()
            .map(|&(pid, st)| ProcRef {
                pid,
                start_time_unix_ms: st,
            })
            .collect();
        if refs.iter().all(|r| self.allowed.contains(r)) {
            let ok = self.k.killpg(pgid, sig).is_ok();
            self.push("killpg", pgid, sig, ok, &format!("구성원 {}개", refs.len()));
            return ok;
        }
        let outside = refs.iter().filter(|r| !self.allowed.contains(r)).count();
        self.push(
            "refused",
            pgid,
            sig,
            false,
            &format!("killpg 거부: 허용 밖 구성원 {outside}개 → pid별"),
        );
        let mut any = false;
        let allowed: Vec<ProcRef> = refs
            .into_iter()
            .filter(|r| self.allowed.contains(r))
            .collect();
        for r in allowed {
            any |= self.signal(r, sig);
        }
        any
    }

    pub fn alive_of(&self, refs: &BTreeSet<ProcRef>) -> Vec<ProcRef> {
        refs.iter().copied().filter(|r| self.is_alive(*r)).collect()
    }
}
