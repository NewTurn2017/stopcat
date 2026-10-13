mod common;

use common::*;
use vh_analyze::{explain_pid, explain_port};
use vh_model::Kind;

#[test]
fn explain_codex_app_server() {
    let (s, r) = run("codex_app_server_logical_orphan");
    let e = explain_pid(&s, &r, 4101).expect("있는 pid");
    let pids: Vec<i32> = e.chain.iter().map(|n| n.target.pid).collect();
    assert_eq!(pids, [4101, 4000, 300, 1]);
    assert_eq!(e.kind, Kind::AgentHelper);
    assert_eq!(e.project.as_deref(), Some("~/dev/shop"));
    let owner = e.owner_ko.as_deref().unwrap();
    assert!(owner.contains("3301") && owner.contains("종료"), "{owner}");
    assert_eq!(e.finding_ids.len(), 1);
    assert!(e.finding_ids[0].starts_with("logical_orphan:4101:"));
    assert!(e.summary_ko.contains("29개"), "{}", e.summary_ko);
}

#[test]
fn explain_appium_port() {
    let (s, r) = run("appium_orphan_exposed");
    let v = explain_port(&s, &r, 4723);
    assert_eq!(v.len(), 1);
    let e = &v[0];
    assert_eq!(e.target.pid, 800);
    assert_eq!(e.listeners.len(), 1);
    assert_eq!(e.finding_ids.len(), 2);
    assert_eq!(e.chain.last().map(|n| n.target.pid), Some(1));
}

#[test]
fn explain_controlcenter_port() {
    let (s, r) = run("controlcenter_5000");
    let v = explain_port(&s, &r, 5000);
    assert_eq!(v.len(), 1, "IPv4·IPv6 두 소켓이어도 프로세스는 하나");
    let e = &v[0];
    assert_eq!(e.kind, Kind::System);
    assert_eq!(e.listeners.len(), 3);
    assert!(
        e.finding_ids
            .iter()
            .any(|id| id == "known_port_conflict:5000")
    );
}

#[test]
fn explain_missing_targets() {
    let (s, r) = run("pressure_1_normal");
    assert!(explain_pid(&s, &r, 424242).is_none());
    assert!(explain_port(&s, &r, 1).is_empty());
}
