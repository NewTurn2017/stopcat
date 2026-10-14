#![allow(dead_code)]

use std::collections::BTreeSet;

use vh_analyze::analyze;
use vh_model::{
    Classified, Finding, FindingKind, Kind, ProcStatus, Report, Section, Snapshot, Suggestion,
    UsageState,
};

pub fn raw(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub fn parse(json: &str) -> Snapshot {
    serde_json::from_str(json).expect("fixture는 계약 모양 Snapshot이어야 한다")
}

pub fn load(name: &str) -> Snapshot {
    parse(&raw(name))
}

pub fn run(name: &str) -> (Snapshot, Report) {
    let s = load(name);
    let r = analyze(&s);
    check_invariants(&s, &r);
    (s, r)
}

pub fn class(r: &Report, pid: i32) -> &Classified {
    r.classified
        .iter()
        .find(|c| c.target.pid == pid)
        .unwrap_or_else(|| panic!("pid {pid} 분류 없음"))
}

pub fn of_kind(r: &Report, kind: FindingKind) -> Vec<&Finding> {
    r.findings.iter().filter(|f| f.kind == kind).collect()
}

pub fn one(r: &Report, kind: FindingKind, pid: i32) -> &Finding {
    let v: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.kind == kind && f.targets.iter().any(|t| t.pid == pid))
        .collect();
    assert_eq!(v.len(), 1, "{kind:?} pid {pid}: {:#?}", r.findings);
    v[0]
}

pub fn terminate(include_descendants: bool) -> Suggestion {
    Suggestion::Terminate {
        include_descendants,
    }
}

pub fn has_reason(f: &Finding, code: &str) -> bool {
    f.reason_codes.iter().any(|c| c == code)
}

pub fn none_targets(r: &Report, pid: i32) {
    let hits: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.targets.iter().any(|t| t.pid == pid))
        .collect();
    assert!(
        hits.is_empty(),
        "pid {pid}에 finding이 없어야 함: {hits:#?}"
    );
}

pub fn check_invariants(s: &Snapshot, r: &Report) {
    assert_eq!(r.classified.len(), s.processes.len());
    let ids: BTreeSet<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids.len(), r.findings.len(), "finding id 중복");
    for f in &r.findings {
        if let Suggestion::Terminate { .. } = f.suggestion {
            for t in &f.targets {
                let c = r
                    .classified
                    .iter()
                    .find(|c| c.target == *t)
                    .expect("대상은 분류돼 있어야 함");
                assert!(
                    !matches!(
                        c.kind,
                        Kind::AgentCli | Kind::System | Kind::AppHelper | Kind::GuiApp
                    ),
                    "정리 제안 대상이 보호 종류: {c:?}"
                );
            }
        }
        if f.kind == FindingKind::HeavyAgentSession {
            assert_eq!(f.suggestion, Suggestion::HandoffThenRestart);
        }
        if f.suggestion == Suggestion::Review {
            assert!(
                f.detail_ko.contains("사람이"),
                "Review는 사람이 판단할 일임을 적어야 함: {}",
                f.detail_ko
            );
        }
        assert!(!f.short_ko.is_empty() && !f.title_ko.is_empty());
        // W4: Terminate는 unneeded에만, unneeded 대상은 모두 Idle, 낮추기 제안 없음.
        if let Suggestion::Terminate { .. } = f.suggestion {
            assert_eq!(
                f.section,
                Section::Unneeded,
                "Terminate는 unneeded에만: {f:#?}"
            );
        }
        if f.section == Section::Unneeded {
            for t in &f.targets {
                let c = r.classified.iter().find(|c| c.target == *t).unwrap();
                assert_eq!(
                    c.usage.state,
                    UsageState::Idle,
                    "unneeded 대상은 Idle: {c:?}"
                );
            }
        }
        assert_ne!(
            f.suggestion,
            Suggestion::Demote,
            "W4 분석은 낮추기 제안을 만들지 않음"
        );
        if matches!(
            f.kind,
            FindingKind::MemoryPressure
                | FindingKind::LimitNearing
                | FindingKind::ExposedListener
                | FindingKind::KnownPortConflict
        ) {
            assert_eq!(f.section, Section::Info);
        }
    }
    let own_total: u64 = s
        .processes
        .iter()
        .filter(|p| p.uid == s.self_uid && p.status != ProcStatus::Zombie)
        .map(|p| p.footprint_bytes.unwrap_or(0))
        .sum();
    let t = &r.totals;
    assert!(
        t.unneeded_bytes + t.check_bytes + t.manual_bytes <= own_total,
        "구역 확보량 합 ≤ 전체: {t:?}"
    );
    let again = analyze(s);
    assert_eq!(&again, r, "같은 입력은 같은 Report");
    let mut groups = 0usize;
    for g in &r.groups {
        groups += g.members.len();
    }
    assert_eq!(
        groups,
        s.processes.len(),
        "모든 프로세스는 묶음에 정확히 한 번"
    );
}
