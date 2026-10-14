//! 지킴이 칸: 수준 하나 × 건강 모드 하나. 범위는 등록부 하위 실행 여러 개의 합집합(공유 프로세스 지원),
//! 태그는 칸 이름(어떤 프로세스도 갖지 않음)이라 등록된 ProcRef만 범위에 들어간다.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use serde_json::json;
use vh_model::{AutoLevel, GuardPolicy, HealthLevel, ProcRef};

use crate::lab::Lab;
use crate::run::{GuardRun, KernelRec};
use crate::scope::{ForcedHealth, LabScope};
use crate::util::now_ms;
use crate::verdict::Records;

pub struct Cell {
    pub name: String,
    pub level: AutoLevel,
    pub forced_at_start: Option<HealthLevel>,
    pub subs: Vec<String>,
    pub guard: Option<GuardRun>,
    pub forced: ForcedHealth,
    pub refs: BTreeSet<ProcRef>,
    pub started_ms: Option<u64>,
    pub done: bool,
}

pub fn level_name(l: AutoLevel) -> &'static str {
    match l {
        AutoLevel::NotifyOnly => "notify",
        AutoLevel::Safe => "safe",
        AutoLevel::Aggressive => "aggressive",
    }
}

impl Cell {
    pub fn new(name: &str, level: AutoLevel, forced: Option<HealthLevel>, subs: &[&str]) -> Cell {
        Cell {
            name: name.to_string(),
            level,
            forced_at_start: forced,
            subs: subs.iter().map(|s| s.to_string()).collect(),
            guard: None,
            forced: ForcedHealth::default(),
            refs: BTreeSet::new(),
            started_ms: None,
            done: false,
        }
    }

    pub fn is_forced(&self) -> bool {
        self.forced_at_start.is_some()
    }

    /// 범위 하위 실행을 모두 얼린 뒤 부른다(잠금 pid 목록이 고정돼야 한다).
    pub fn start(&mut self, lab: &mut Lab, out: &Path) -> io::Result<()> {
        for s in &self.subs {
            lab.registry.freeze(s);
        }
        self.refs = self
            .subs
            .iter()
            .flat_map(|s| lab.registry.scope_refs(s))
            .collect();
        let lock: BTreeSet<i32> = self.refs.iter().map(|r| r.pid).collect();
        let at = now_ms();
        self.forced = ForcedHealth::new(self.forced_at_start, at);
        let scope = LabScope {
            tag: lab.tag(&self.name),
            refs: self.refs.clone(),
        };
        self.guard = Some(GuardRun::start_with(
            &out.join(&self.name),
            &self.name,
            scope,
            lock,
            lab.registry.decoys(),
            GuardPolicy::for_level(self.level),
            self.forced.clone(),
        )?);
        self.started_ms = Some(at);
        Ok(())
    }

    pub fn pump(&mut self) {
        if let Some(g) = self.guard.as_mut()
            && !self.done
        {
            g.pump();
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(g) = self.guard.as_mut()
            && !self.done
        {
            g.shutdown();
            g.write()?;
        }
        self.done = true;
        Ok(())
    }

    pub fn records(
        &self,
        kernel: &[KernelRec],
        markers: &BTreeMap<ProcRef, Vec<String>>,
    ) -> Option<Records> {
        let g = self.guard.as_ref()?;
        Some(Records {
            scans: g.scans.clone(),
            kernel: kernel.to_vec(),
            signals: g.signal_calls(),
            notes: g.notifications(),
            audit: g.audit_lines(),
            undemoted: g
                .shutdown
                .as_ref()
                .map(|x| x.undemoted.clone())
                .unwrap_or_default(),
            markers: markers.clone(),
        })
    }

    /// 격리 불변식(칸마다).
    pub fn isolation(&self) -> (bool, serde_json::Value) {
        let Some(g) = &self.guard else {
            return (false, json!({"started": false}));
        };
        let inv = g.isolation_check(&self.refs);
        (
            inv.holds(false),
            json!({"cell": self.name, "level": level_name(self.level), "forced_at_start": self.forced_at_start, "invariants": inv, "scan_seq_gaps": g.seq_gaps, "forced": self.forced.state()}),
        )
    }
}

/// 실험실 폴더 이름 → 알림 줄 귀속 표지(폴더 이름, package.json 이름 `lab-<폴더>`).
pub fn dir_markers(m: &mut BTreeMap<ProcRef, Vec<String>>, r: ProcRef, dir: &str) {
    m.insert(r, vec![dir.to_string(), format!("lab-{dir}")]);
}
