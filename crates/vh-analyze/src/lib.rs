//! vh-analyze: 스냅샷 분석과 도감 (ANALYZE 소유).
//!
//! `Snapshot`만 읽는 순수 함수다. 파일 시스템·프로세스·네트워크에 접근하지 않는다.

mod ctx;
mod explain;
mod features;
mod findings;
mod fmt;
mod groups;
mod health;
mod ports;
mod sections;
mod signatures;
#[cfg(feature = "synth")]
pub mod synth;
mod usage;

use std::collections::BTreeSet;

use vh_model::{
    Classified, Confidence, Explanation, Finding, Report, SCHEMA_VERSION, Section, Snapshot,
    Suggestion, Totals,
};

use crate::ctx::Ctx;
use crate::findings::{Ports, kind_order};

/// 스냅샷을 분석해 화면·조치에 쓸 Report를 만든다.
pub fn analyze(s: &Snapshot) -> Report {
    let c = Ctx::new(s);
    let groups = groups::groups(&c);
    let ports = Ports::new(&c);
    let mut findings = findings::process_findings(&c, &ports);
    let (listeners, port_findings) = ports::listeners(&c);
    findings.extend(port_findings);
    let (health, health_findings) = health::health(&c, &groups);
    findings.extend(health_findings);
    for f in &mut findings {
        sections::assign(&c, f);
    }
    findings.sort_by(|a, b| {
        kind_order(a.kind)
            .cmp(&kind_order(b.kind))
            .then_with(|| b.confidence.rank().cmp(&a.confidence.rank()))
            .then_with(|| b.reclaim_bytes.cmp(&a.reclaim_bytes))
            .then_with(|| a.id.cmp(&b.id))
    });

    let reclaim_set = |f: &Finding| -> BTreeSet<usize> {
        let mut set = BTreeSet::new();
        for t in &f.targets {
            let Some(&i) = c.idx.get(&t.pid) else {
                continue;
            };
            if c.pref(i) != *t {
                continue;
            }
            set.insert(i);
            if f.descendant_count > 0 {
                set.extend(c.descendants(i));
            }
        }
        set
    };
    let mut confirmed = BTreeSet::new();
    let mut likely = BTreeSet::new();
    let mut unneeded = BTreeSet::new();
    let mut check = BTreeSet::new();
    let mut manual = BTreeSet::new();
    for f in &findings {
        if f.reclaim_bytes > 0 {
            match f.section {
                Section::Unneeded => unneeded.extend(reclaim_set(f)),
                Section::Check => check.extend(reclaim_set(f)),
                Section::Manual => manual.extend(reclaim_set(f)),
                Section::Working | Section::Info => {}
            }
        }
        let Suggestion::Terminate {
            include_descendants,
        } = f.suggestion
        else {
            continue;
        };
        let set = match f.confidence {
            Confidence::Confirmed => &mut confirmed,
            Confidence::Likely => &mut likely,
            Confidence::Possible => continue,
        };
        for t in &f.targets {
            let Some(&i) = c.idx.get(&t.pid) else {
                continue;
            };
            if c.pref(i) != *t {
                continue;
            }
            set.insert(i);
            if include_descendants {
                set.extend(c.descendants(i));
            }
        }
    }
    let fp = |set: &mut dyn Iterator<Item = &usize>| -> u64 { set.map(|&i| c.footprint(i)).sum() };
    let totals = Totals {
        reclaimable_confirmed_bytes: fp(&mut confirmed.iter()),
        reclaimable_likely_bytes: fp(&mut likely.difference(&confirmed)),
        unneeded_bytes: fp(&mut unneeded.iter()),
        check_bytes: fp(&mut check.difference(&unneeded)),
        manual_bytes: fp(&mut manual
            .iter()
            .filter(|i| !unneeded.contains(i) && !check.contains(i))),
    };

    let mut order: Vec<usize> = (0..c.procs.len()).collect();
    order.sort_by_key(|&i| (c.procs[i].pid, c.procs[i].start_time_unix_ms));
    let classified = order
        .into_iter()
        .map(|i| {
            let o = &c.owner[i];
            Classified {
                target: c.pref(i),
                kind: c.cls[i].kind,
                label_ko: c.cls[i].label.clone(),
                signature_id: Some(c.cls[i].sig.to_string()),
                project: c.project[i].clone(),
                owner_session: o.session,
                owner_pid: o.pid,
                owner_source: o.source.map(str::to_string),
                owner_label_ko: o.label.clone(),
                owner_alive: o.alive,
                usage: c.usage[i].clone(),
            }
        })
        .collect();

    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: s.taken_at_unix_ms,
        health,
        classified,
        groups,
        findings,
        listeners,
        totals,
    }
}

/// `vh why <pid>`: 계보·종류·주인·관련 발견·한국어 요약. 스냅샷에 없는 pid면 `None`.
pub fn explain_pid(s: &Snapshot, r: &Report, pid: i32) -> Option<Explanation> {
    explain::explain(s, r, pid)
}

/// `vh why :<port>`: 그 포트에서 대기 중인 프로세스마다 설명 하나(pid 순). 없으면 빈 Vec.
pub fn explain_port(s: &Snapshot, r: &Report, port: u16) -> Vec<Explanation> {
    explain::explain_port(s, r, port)
}
