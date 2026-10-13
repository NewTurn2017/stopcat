#![cfg(feature = "synth")]

mod common;

use vh_analyze::analyze;
use vh_analyze::synth::synth_snapshot;
use vh_model::{FindingKind, Kind};

#[test]
fn synth_2000_properties() {
    let s = synth_snapshot(2000, 7);
    assert_eq!(s.processes.len(), 2000);
    assert_eq!(s, synth_snapshot(2000, 7), "같은 seed는 같은 스냅샷");
    let r = analyze(&s);
    common::check_invariants(&s, &r);

    let mcp = r
        .classified
        .iter()
        .filter(|c| c.kind == Kind::McpServer)
        .count();
    assert!(mcp >= 30, "MCP 서버 {mcp}개");
    let dup_mcp = r.findings.iter().filter(|f| {
        f.kind == FindingKind::Duplicate
            && f.targets.iter().any(|t| {
                r.classified
                    .iter()
                    .any(|c| c.target == *t && c.kind == Kind::McpServer)
            })
    });
    assert_eq!(dup_mcp.count(), 0, "세션마다 한 세트인 MCP는 중복이 아님");

    let zombies: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::Zombie)
        .collect();
    assert_eq!(zombies.len(), 1);
    assert_eq!(zombies[0].targets.len(), 20);
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == FindingKind::HeadlessBrowserLeftover)
    );
    assert!(r.findings.iter().any(|f| f.kind == FindingKind::Orphan));

    let total: u64 = s.processes.iter().filter_map(|p| p.footprint_bytes).sum();
    assert!(r.totals.reclaimable_confirmed_bytes + r.totals.reclaimable_likely_bytes <= total);
}
