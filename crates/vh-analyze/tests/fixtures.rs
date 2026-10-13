mod common;

use common::*;
use vh_analyze::{analyze, explain_pid};
use vh_model::{Confidence, FindingKind, HealthLevel, Kind, Suggestion};

const MIB: u64 = 1024 * 1024;

#[test]
fn codex_app_server_logical_orphan() {
    let (_, r) = run("codex_app_server_logical_orphan");
    let c = class(&r, 4101);
    assert_eq!(c.kind, Kind::AgentHelper);
    assert_eq!(c.signature_id.as_deref(), Some("agent_codex_app_server"));
    assert_eq!(c.owner_alive, Some(false));
    assert_eq!(c.owner_pid, Some(3301));
    assert_eq!(c.owner_source.as_deref(), Some("env:CLAUDE_PID"));
    assert_eq!(class(&r, 4103).kind, Kind::AgentHelper);

    let f = one(&r, FindingKind::LogicalOrphan, 4101);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.suggestion, terminate(true));
    for code in [
        "owner_dead",
        "owner_from_env_claude_pid",
        "parent_alive",
        "age_ge_10m",
    ] {
        assert!(has_reason(f, code), "{code}: {:?}", f.reason_codes);
    }
    assert_eq!(f.descendant_count, 29);
    assert_eq!(f.reclaim_bytes, (60 + 40 + 300 + 27 * 24) * MIB);
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
    assert_eq!(r.totals.reclaimable_confirmed_bytes, f.reclaim_bytes);
}

#[test]
fn apple_xpc_not_orphan() {
    let (_, r) = run("apple_xpc_not_orphan");
    assert_eq!(class(&r, 500).kind, Kind::System);
    assert_eq!(class(&r, 501).kind, Kind::System);
    assert_eq!(class(&r, 502).kind, Kind::AppHelper);
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}

#[test]
fn launchagent_service_not_orphan() {
    let (_, r) = run("launchagent_service_not_orphan");
    assert!(of_kind(&r, FindingKind::Orphan).is_empty());
    let f = one(&r, FindingKind::ExposedListener, 5101);
    assert_eq!(f.confidence, Confidence::Possible);
    assert_eq!(f.suggestion, Suggestion::Review);
    assert!(has_reason(f, "launchd_service"));
    assert!(f.detail_ko.contains("com.demo.stt"));
    assert!(f.id.ends_with(":8004"));
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn orbstack_helper_not_orphan() {
    let (_, r) = run("orbstack_helper_not_orphan");
    assert_eq!(class(&r, 600).kind, Kind::VirtualMachine);
    assert_eq!(class(&r, 590).kind, Kind::GuiApp);
    assert!(of_kind(&r, FindingKind::Orphan).is_empty());
    let h = one(&r, FindingKind::HeavyProcess, 600);
    assert_eq!(h.suggestion, Suggestion::Review);
    assert!(has_reason(h, "vm_expected_large"));
    let e = one(&r, FindingKind::ExposedListener, 600);
    assert_eq!(e.confidence, Confidence::Confirmed);
    let view = r
        .listeners
        .iter()
        .find(|v| v.listener.port == 6333)
        .unwrap();
    assert!(view.exposure_ko.as_deref().unwrap().contains("Qdrant"));
}

#[test]
fn homebrew_python_devserver_is_not_apphelper() {
    let (_, r) = run("homebrew_python_devserver");
    let uv = class(&r, 700);
    assert_eq!(uv.kind, Kind::DevServer);
    assert_eq!(uv.signature_id.as_deref(), Some("dev_uvicorn"));
    let xp = class(&r, 710);
    assert_eq!(xp.kind, Kind::DevServer);
    assert_eq!(xp.signature_id.as_deref(), Some("dev_http_server"));
    let f = one(&r, FindingKind::Orphan, 700);
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.suggestion, terminate(true));
    assert!(has_reason(f, "dev_kind") && has_reason(f, "age_ge_1h"));
    none_targets(&r, 710);
}

#[test]
fn appium_orphan_and_exposed() {
    let (_, r) = run("appium_orphan_exposed");
    assert_eq!(class(&r, 800).kind, Kind::TestTool);
    let o = one(&r, FindingKind::Orphan, 800);
    assert_eq!(o.confidence, Confidence::Likely);
    assert_eq!(o.suggestion, terminate(true));
    assert!(has_reason(o, "leftover_kind") && has_reason(o, "age_ge_1h"));
    assert!(o.short_ko.contains(":4723"));
    let e = one(&r, FindingKind::ExposedListener, 800);
    assert_eq!(e.confidence, Confidence::Confirmed);
    assert_eq!(e.suggestion, Suggestion::Review);
}

#[test]
fn headless_chrome_leftover() {
    let (_, r) = run("headless_chrome_leftover");
    for pid in 900..=904 {
        assert_eq!(class(&r, pid).kind, Kind::HeadlessBrowser, "pid {pid}");
    }
    let f = one(&r, FindingKind::HeadlessBrowserLeftover, 900);
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.suggestion, terminate(true));
    assert_eq!(f.descendant_count, 4);
    assert_eq!(f.reclaim_bytes, (400 + 4 * 150) * MIB);
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn zombies_restart_parent() {
    let (_, r) = run("zombies_unreaped");
    let z = of_kind(&r, FindingKind::Zombie);
    assert_eq!(z.len(), 1, "{z:#?}");
    let f = z[0];
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.targets.len(), 20);
    assert_eq!(f.reclaim_bytes, 0);
    match &f.suggestion {
        Suggestion::RestartParent { parent } => assert_eq!(parent.pid, 8000),
        other => panic!("{other:?}"),
    }
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn duplicate_in_same_session() {
    let (_, r) = run("duplicate_same_session");
    let d = of_kind(&r, FindingKind::Duplicate);
    assert_eq!(d.len(), 2, "{d:#?}");
    let mcp = one(&r, FindingKind::Duplicate, 5010);
    assert_eq!(mcp.confidence, Confidence::Likely);
    assert_eq!(mcp.suggestion, terminate(true));
    assert!(has_reason(mcp, "same_owner_session"));
    assert_eq!(mcp.targets.len(), 1);
    let next = one(&r, FindingKind::Duplicate, 5020);
    assert_eq!(next.targets.len(), 1);
    assert!(!has_reason(next, "same_owner_session"));
    none_targets(&r, 5011);
    none_targets(&r, 5021);
}

#[test]
fn mcp_across_sessions_not_duplicate() {
    let (_, r) = run("mcp_across_sessions_not_duplicate");
    for base in [5000, 6000] {
        for pid in base + 1..=base + 3 {
            let c = class(&r, pid);
            assert_eq!(c.kind, Kind::McpServer, "pid {pid}");
            assert_eq!(c.signature_id.as_deref(), Some("mcp_chrome_devtools"));
            assert_eq!(c.owner_session.map(|o| o.pid), Some(base));
        }
    }
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}

#[test]
fn omo_heavy_session_handoff() {
    let (_, r) = run("omo_heavy_session");
    assert_eq!(class(&r, 7000).kind, Kind::AgentCli);
    let h = one(&r, FindingKind::HeavyAgentSession, 7000);
    assert_eq!(h.confidence, Confidence::Confirmed);
    assert_eq!(h.suggestion, Suggestion::HandoffThenRestart);
    assert!(has_reason(h, "session_root_ge_8g"));
    assert!(of_kind(&r, FindingKind::HeavyProcess).is_empty());
    let o = one(&r, FindingKind::Orphan, 7100);
    assert_eq!(o.confidence, Confidence::Possible);
    assert_eq!(o.suggestion, Suggestion::Review);
    assert!(has_reason(o, "agent_cli_never_terminated"));
    let session = r
        .groups
        .iter()
        .find(|g| g.id.starts_with("session:7000:"))
        .unwrap();
    assert!(session.title.contains("shop"), "{}", session.title);
    assert_eq!(r.totals.reclaimable_confirmed_bytes, 0);
    assert_eq!(r.totals.reclaimable_likely_bytes, 0);
}

#[test]
fn controlcenter_airplay_5000() {
    let (_, r) = run("controlcenter_5000");
    let k = of_kind(&r, FindingKind::KnownPortConflict);
    let ports: Vec<&str> = k.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ports,
        ["known_port_conflict:5000", "known_port_conflict:7000"]
    );
    for f in &k {
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.suggestion, Suggestion::None);
    }
    assert!(of_kind(&r, FindingKind::ExposedListener).is_empty());
    let v = r
        .listeners
        .iter()
        .find(|v| v.listener.port == 5000)
        .unwrap();
    assert!(v.exposure_ko.as_deref().unwrap().contains("AirPlay"));
    let flask = r
        .listeners
        .iter()
        .find(|v| v.listener.port == 5001)
        .unwrap();
    assert_eq!(flask.kind, Kind::DevServer);
    assert_eq!(flask.exposure_ko, None);
}

#[test]
fn pressure_1_normal() {
    let (_, r) = run("pressure_1_normal");
    assert_eq!(r.health.level, HealthLevel::Ok);
    for part in [
        "메모리 정상",
        "압력 1",
        "압축 41GB",
        "스왑 1.6/2GB",
        "부하 5.8/18코어",
    ] {
        assert!(
            r.health.headline_ko.contains(part),
            "{part}: {}",
            r.health.headline_ko
        );
    }
    assert!(of_kind(&r, FindingKind::MemoryPressure).is_empty());
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}

#[test]
fn pressure_2_warn() {
    let (_, r) = run("pressure_2_warn");
    assert_eq!(r.health.level, HealthLevel::Watch);
    let f = of_kind(&r, FindingKind::MemoryPressure);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].confidence, Confidence::Confirmed);
    assert!(has_reason(f[0], "pressure_warn"));
}

#[test]
fn pressure_4_critical() {
    let (_, r) = run("pressure_4_critical");
    assert_eq!(r.health.level, HealthLevel::Critical);
    let f = of_kind(&r, FindingKind::MemoryPressure);
    assert_eq!(f.len(), 1);
    assert!(has_reason(f[0], "pressure_critical"));
}

#[test]
fn limits_nearing() {
    let (_, r) = run("limits_nearing");
    assert_eq!(r.health.level, HealthLevel::Watch);
    let f = of_kind(&r, FindingKind::LimitNearing);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].id, "limit_nearing:maxprocperuid");
    assert!(has_reason(f[0], "procs_ge_80pct_maxprocperuid"));
    assert!(!has_reason(f[0], "ge_95pct"));
}

#[test]
fn agent_tmp_cwd_test_server() {
    let (_, r) = run("agent_tmp_cwd_test_server");
    let f = one(&r, FindingKind::Orphan, 1800);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.suggestion, terminate(true));
    for code in ["agent_tmp_cwd", "tmp_session_gone", "age_ge_10m"] {
        assert!(has_reason(f, code), "{code}: {:?}", f.reason_codes);
    }
    assert_eq!(class(&r, 1910).owner_alive, Some(true));
    none_targets(&r, 1910);
}

#[test]
fn claude_daemon_transient() {
    let (_, r) = run("claude_daemon_transient");
    assert_eq!(class(&r, 1300).kind, Kind::AgentHelper);
    assert_eq!(
        class(&r, 1300).signature_id.as_deref(),
        Some("agent_claude_daemon")
    );
    assert_eq!(class(&r, 1301).kind, Kind::AgentHelper);
    assert_eq!(class(&r, 1302).kind, Kind::AgentHelper);
    let f = one(&r, FindingKind::Orphan, 1300);
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.suggestion, terminate(true));
    assert!(has_reason(f, "transient_origin") && has_reason(f, "spawner_dead"));
    assert_eq!(f.descendant_count, 2);
    assert_eq!(f.reclaim_bytes, 818 * MIB);
    assert_eq!(r.totals.reclaimable_likely_bytes, 818 * MIB);
}

#[test]
fn stopped_devserver() {
    let (_, r) = run("stopped_devserver");
    let a = one(&r, FindingKind::Stopped, 1400);
    assert_eq!(a.confidence, Confidence::Confirmed);
    assert_eq!(a.suggestion, Suggestion::Resume);
    let b = one(&r, FindingKind::Stopped, 1410);
    assert_eq!(b.suggestion, terminate(true));
    assert!(has_reason(b, "ppid_launchd"));
    assert!(of_kind(&r, FindingKind::Orphan).is_empty());
}

#[test]
fn runaway_cpu() {
    let (_, r) = run("runaway_cpu");
    let f = of_kind(&r, FindingKind::Runaway);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0].targets[0].pid, 1500);
    assert_eq!(f[0].confidence, Confidence::Possible);
    assert_eq!(f[0].suggestion, Suggestion::Demote);
}

#[test]
fn owner_pid_reused() {
    let (_, r) = run("owner_pid_reused");
    let f = one(&r, FindingKind::LogicalOrphan, 1600);
    assert_eq!(f.confidence, Confidence::Confirmed);
    for code in [
        "owner_pid_reused",
        "owner_from_env_claude_pid",
        "parent_alive",
    ] {
        assert!(has_reason(f, code), "{code}: {:?}", f.reason_codes);
    }
    assert_eq!(class(&r, 1600).owner_session, None);
    assert_eq!(class(&r, 1600).owner_pid, Some(7000));
}

#[test]
fn secrets_in_argv_never_reach_report() {
    let secret = ["sk", "-", "demo", &"A".repeat(24)].concat();
    let secret2 = ["gh", "p_", &"B".repeat(30)].concat();
    let url = ["postgres://", "u", ":", "p", "@", "db.local/app"].concat();
    let json = raw("secrets_in_argv")
        .replace("__FAKE_SECRET_1__", &secret)
        .replace("__FAKE_SECRET_2__", &secret2)
        .replace("__FAKE_URL__", &url);
    let s = parse(&json);
    assert!(s.processes.iter().any(|p| p.argv.contains(&secret)));
    let r = analyze(&s);
    check_invariants(&s, &r);
    assert!(!of_kind(&r, FindingKind::Orphan).is_empty());
    let mut out = serde_json::to_string(&r).unwrap();
    if let Some(e) = explain_pid(&s, &r, 1700) {
        out.push_str(&serde_json::to_string(&e).unwrap());
    }
    for needle in [secret.as_str(), secret2.as_str(), "u:p@"] {
        assert!(!out.contains(needle), "Report에 원문이 나옴: {needle}");
    }
}

#[test]
fn env_unreadable_is_not_guessed_dead() {
    let (_, r) = run("env_unreadable_no_guess");
    let c = class(&r, 1950);
    assert_eq!(c.owner_session, None);
    assert_eq!(c.owner_alive, None);
    none_targets(&r, 1950);
}

#[test]
fn omo_py_kernels_not_duplicate() {
    let (_, r) = run("omo_py_kernels_not_duplicate");
    for pid in [7001, 7201] {
        let c = class(&r, pid);
        assert_eq!(c.kind, Kind::AgentHelper);
        assert_eq!(c.signature_id.as_deref(), Some("agent_omo_py_kernel"));
        assert_eq!(c.owner_alive, Some(true));
    }
    assert!(
        of_kind(&r, FindingKind::Duplicate).is_empty(),
        "{:#?}",
        r.findings
    );
}

#[test]
fn daemons_by_design_not_orphan() {
    let (_, r) = run("daemons_by_design_not_orphan");
    assert_eq!(
        class(&r, 3600).signature_id.as_deref(),
        Some("agent_omo_lsp_daemon")
    );
    assert_eq!(
        class(&r, 3610).signature_id.as_deref(),
        Some("android_adb_server")
    );
    assert_eq!(class(&r, 3620).signature_id.as_deref(), Some("ls_biome"));
    assert!(
        of_kind(&r, FindingKind::Orphan).is_empty(),
        "{:#?}",
        r.findings
    );
    assert!(of_kind(&r, FindingKind::HeadlessBrowserLeftover).is_empty());
    assert!(of_kind(&r, FindingKind::LogicalOrphan).is_empty());
    let h = one(&r, FindingKind::HeavyProcess, 3600);
    assert_eq!(h.suggestion, Suggestion::Review);
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn codex_broker_orphan() {
    let (_, r) = run("codex_broker_orphan");
    assert_eq!(class(&r, 4500).kind, Kind::AgentHelper);
    assert_eq!(
        class(&r, 4500).signature_id.as_deref(),
        Some("agent_codex_broker")
    );
    let f = one(&r, FindingKind::Orphan, 4500);
    assert_eq!(f.confidence, Confidence::Confirmed);
    assert_eq!(f.suggestion, terminate(true));
    assert!(has_reason(f, "owner_dead") && has_reason(f, "owner_from_env_claude_pid"));
    assert_eq!(f.descendant_count, 2);
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn claude_daemon_env_owner_covers_subtree() {
    let (_, r) = run("claude_daemon_env_owner");
    let f = one(&r, FindingKind::Orphan, 1300);
    assert_eq!(f.confidence, Confidence::Likely);
    assert_eq!(f.suggestion, terminate(true));
    assert!(has_reason(f, "transient_origin") && has_reason(f, "spawner_dead"));
    assert!(has_reason(f, "owner_from_env_cmux_claude_pid"));
    assert_eq!(f.descendant_count, 5);
    assert!(
        of_kind(&r, FindingKind::LogicalOrphan).is_empty(),
        "{:#?}",
        r.findings
    );
    assert_eq!(r.findings.len(), 1, "{:#?}", r.findings);
}

#[test]
fn pyright_workers_not_duplicate() {
    let (_, r) = run("pyright_workers_not_duplicate");
    for pid in [3701, 3711, 3721] {
        assert_eq!(class(&r, pid).kind, Kind::LanguageServer, "pid {pid}");
        assert_eq!(class(&r, pid).signature_id.as_deref(), Some("ls_pyright"));
    }
    assert!(r.findings.is_empty(), "{:#?}", r.findings);
}
