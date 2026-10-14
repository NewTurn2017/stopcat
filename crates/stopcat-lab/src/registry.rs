//! 실험실 등록부: 실험실이 띄운 프로세스의 ProcRef(pid + 시작 시각). 범위 필터·잠금·정리의 근거.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use stopcat_act::Liveness;
use stopcat_model::ProcRef;

use crate::kernel::LabKernel;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub r: ProcRef,
    pub sub: String,
    pub scenario: String,
    pub role: String,
    pub name: String,
    pub decoy: bool,
    pub parent: Option<ProcRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRegistry {
    pub run_id: String,
    pub anchor: ProcRef,
    pub started_at_ms: u64,
    pub uid: u32,
    #[serde(with = "members_as_list")]
    pub members: BTreeMap<ProcRef, Member>,
    pub frozen_subs: BTreeSet<String>,
    pub dead_pids: Vec<i32>,
}

impl LabRegistry {
    pub fn new(run_id: &str, anchor: ProcRef, started_at_ms: u64, uid: u32) -> Self {
        LabRegistry {
            run_id: run_id.to_string(),
            anchor,
            started_at_ms,
            uid,
            members: BTreeMap::new(),
            frozen_subs: BTreeSet::new(),
            dead_pids: Vec::new(),
        }
    }

    pub fn tag_prefix(&self) -> String {
        format!("lab-{}", self.run_id)
    }

    pub fn tag(&self, sub: &str) -> String {
        format!("lab-{}-{sub}", self.run_id)
    }

    /// 커널에서 시작 시각을 읽어 등록한다. 자기 uid, 실행 시작 뒤 시작, anchor 프로세스 그룹
    /// (좀비는 부모가 맞을 때)만 받는다. 얼린 하위 실행에는 더 넣지 못한다.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        k: &dyn LabKernel,
        pid: i32,
        sub: &str,
        scenario: &str,
        role: &str,
        name: &str,
        decoy: bool,
        parent: Option<ProcRef>,
    ) -> Result<ProcRef, String> {
        if self.frozen_subs.contains(sub) {
            return Err(format!("하위 실행 {sub}는 이미 얼림"));
        }
        if pid <= 1 {
            return Err(format!("pid {pid} 거부"));
        }
        let live = k.probe(pid);
        if live.liveness == Liveness::Gone {
            return Err(format!("pid {pid} 없음"));
        }
        if live.uid != self.uid {
            return Err(format!("pid {pid} uid {} ≠ {}", live.uid, self.uid));
        }
        if live.start_time_unix_ms + 1000 < self.started_at_ms {
            return Err(format!("pid {pid}는 실행 시작 전에 시작"));
        }
        let ok_group = if live.liveness == Liveness::Zombie {
            parent.is_some_and(|p| p.pid == live.ppid)
        } else {
            live.pgid == self.anchor.pid
        };
        if !ok_group {
            return Err(format!(
                "pid {pid} 프로세스 그룹 {} ≠ anchor {}",
                live.pgid, self.anchor.pid
            ));
        }
        let r = ProcRef {
            pid,
            start_time_unix_ms: live.start_time_unix_ms,
        };
        if self.members.contains_key(&r) {
            return Err(format!("pid {pid}는 이미 등록됨"));
        }
        self.members.insert(
            r,
            Member {
                r,
                sub: sub.to_string(),
                scenario: scenario.to_string(),
                role: role.to_string(),
                name: name.to_string(),
                decoy,
                parent,
            },
        );
        Ok(r)
    }

    pub fn freeze(&mut self, sub: &str) {
        self.frozen_subs.insert(sub.to_string());
    }

    /// 범위에 넣는 ProcRef(미끼 제외).
    pub fn scope_refs(&self, sub: &str) -> BTreeSet<ProcRef> {
        self.members
            .values()
            .filter(|m| m.sub == sub && !m.decoy)
            .map(|m| m.r)
            .collect()
    }

    /// 잠금 signaler에 줄 pid(미끼 제외).
    pub fn lock_pids(&self, sub: &str) -> BTreeSet<i32> {
        self.scope_refs(sub).into_iter().map(|r| r.pid).collect()
    }

    pub fn decoys(&self) -> BTreeSet<ProcRef> {
        self.members
            .values()
            .filter(|m| m.decoy)
            .map(|m| m.r)
            .collect()
    }

    /// 정리할 때 신호를 보낼 수 있는 전부(미끼·anchor 포함).
    pub fn all_refs(&self) -> BTreeSet<ProcRef> {
        let mut s: BTreeSet<ProcRef> = self.members.keys().copied().collect();
        s.insert(self.anchor);
        s
    }

    pub fn by_scenario(&self, scenario: &str) -> Vec<ProcRef> {
        self.members
            .values()
            .filter(|m| m.scenario == scenario)
            .map(|m| m.r)
            .collect()
    }

    pub fn contains(&self, r: &ProcRef) -> bool {
        self.members.contains_key(r) || *r == self.anchor
    }
}

mod members_as_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use stopcat_model::ProcRef;

    use super::Member;

    pub fn serialize<S: Serializer>(
        m: &BTreeMap<ProcRef, Member>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        m.values().collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<ProcRef, Member>, D::Error> {
        let v = Vec::<Member>::deserialize(d)?;
        Ok(v.into_iter().map(|m| (m.r, m)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_serializes_to_json() {
        let a = ProcRef {
            pid: 5,
            start_time_unix_ms: 9,
        };
        let mut r = LabRegistry::new("T", a, 0, 501);
        r.members.insert(
            a,
            Member {
                r: a,
                sub: "A".into(),
                scenario: "s".into(),
                role: "idle".into(),
                name: "node".into(),
                decoy: false,
                parent: None,
            },
        );
        let j = serde_json::to_string(&r).expect("직렬화");
        let back: LabRegistry = serde_json::from_str(&j).expect("역직렬화");
        assert_eq!(back.members, r.members);
    }
}
