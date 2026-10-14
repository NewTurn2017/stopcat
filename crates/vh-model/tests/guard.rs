//! W2 지킴이 계약: serde 이름·왕복, `for_level` 표, `from_env_value`, `VhConfig::default`.

use std::collections::HashSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use vh_model::*;

const LEVELS: [AutoLevel; 3] = [
    AutoLevel::NotifyOnly,
    AutoLevel::Safe,
    AutoLevel::Aggressive,
];

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let json = serde_json::to_string(value).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&back, value);
}

fn j<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialize")
}

fn pref(pid: i32) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: 1_790_000_000_000 + pid as u64,
    }
}

fn pending(pid: i32, step: Step, eta_ms: Option<u64>) -> PendingAction {
    PendingAction {
        target: pref(pid),
        finding_id: format!("orphan:{pid}"),
        kind: Kind::McpServer,
        label_ko: "MCP 서버: demo-mcp".to_string(),
        step,
        seen_scans: 1,
        needed_scans: 2,
        eta_ms,
        wait: PendingWait::Confirming,
    }
}

#[test]
fn auto_level_serde_names() {
    assert_eq!(j(&AutoLevel::NotifyOnly), "\"notify_only\"");
    assert_eq!(j(&AutoLevel::Safe), "\"safe\"");
    assert_eq!(j(&AutoLevel::Aggressive), "\"aggressive\"");
    for l in LEVELS {
        roundtrip(&l);
    }
    assert!(serde_json::from_str::<AutoLevel>("\"Safe\"").is_err());
    assert!(serde_json::from_str::<AutoLevel>("\"notify\"").is_err());
}

#[test]
fn from_env_value_parses_and_rejects() {
    assert_eq!(
        AutoLevel::from_env_value("notify"),
        Some(AutoLevel::NotifyOnly)
    );
    assert_eq!(
        AutoLevel::from_env_value("notify_only"),
        Some(AutoLevel::NotifyOnly)
    );
    assert_eq!(AutoLevel::from_env_value("SAFE"), Some(AutoLevel::Safe));
    assert_eq!(
        AutoLevel::from_env_value("aggressive"),
        Some(AutoLevel::Aggressive)
    );
    assert_eq!(
        AutoLevel::from_env_value("Notify"),
        Some(AutoLevel::NotifyOnly)
    );
    for bad in [
        "",
        "auto",
        "off",
        "safe-ish",
        "aggresive",
        "1",
        "notify only",
    ] {
        assert_eq!(AutoLevel::from_env_value(bad), None, "{bad:?}");
    }
}

#[test]
fn step_undemote_serde() {
    assert_eq!(j(&Step::Undemote), "\"undemote\"");
    assert_eq!(j(&Step::Cont), "\"cont\"");
    assert_eq!(j(&Step::Term), "\"term\"");
    assert_eq!(j(&Step::Kill), "\"kill\"");
    assert_eq!(j(&Step::Demote), "\"demote\"");
    roundtrip(&Step::Undemote);
}

#[test]
fn guard_event_kind_serde_names() {
    let table = [
        (GuardEventKind::AutoTerminated, "auto_terminated"),
        (GuardEventKind::Demoted, "demoted"),
        (GuardEventKind::Undemoted, "undemoted"),
        (GuardEventKind::Notified, "notified"),
        (GuardEventKind::Skipped, "skipped"),
        (GuardEventKind::Refused, "refused"),
        (GuardEventKind::CircuitOpen, "circuit_open"),
        (GuardEventKind::CircuitReset, "circuit_reset"),
        (GuardEventKind::Paused, "paused"),
        (GuardEventKind::Resumed, "resumed"),
        (GuardEventKind::LevelChanged, "level_changed"),
        (GuardEventKind::ScanError, "scan_error"),
        (GuardEventKind::Unstable, "unstable"),
        (GuardEventKind::Stable, "stable"),
    ];
    for (k, name) in table {
        assert_eq!(j(&k), format!("\"{name}\""));
        roundtrip(&k);
    }
}

#[test]
fn for_level_common_defaults() {
    for l in LEVELS {
        let p = GuardPolicy::for_level(l);
        assert_eq!(p.level, l);
        assert_eq!(p.scan_interval_ms, 5_000);
        assert_eq!(p.pressure_scan_interval_ms, 2_000);
        assert_eq!(p.persistence_scans, 2);
        assert_eq!(p.min_process_age_ms, 600_000);
        assert_eq!(p.runaway_cpu_pct, 100.0);
        assert_eq!(p.runaway_sustained_scans, 3);
        assert_eq!(p.max_auto_terminations, 5);
        assert_eq!(p.rate_window_ms, 600_000);
        assert_eq!(p.grace_ms, 3_000);
        assert_eq!(p.notify_min_interval_ms, 30_000);
        assert_eq!(p.swap_growth_bytes, 1_073_741_824);
        assert_eq!(p.swap_window_ms, 300_000);
        assert_eq!(p.swap_min_span_ms, 60_000);
        assert_eq!(p.settle_ms, 60_000);
        assert_eq!(p.max_per_round_watch, 1);
        assert_eq!(p.unstable_notify_cooldown_ms, 600_000);
        assert_eq!(p.idle_confirm_ms, 120_000);
    }
}

#[test]
fn for_level_flags() {
    let n = GuardPolicy::for_level(AutoLevel::NotifyOnly);
    assert_eq!(
        (n.min_confidence, n.auto_demote, n.pressure_largest_first),
        (Confidence::Confirmed, false, false)
    );
    let s = GuardPolicy::for_level(AutoLevel::Safe);
    assert_eq!(
        (s.min_confidence, s.auto_demote, s.pressure_largest_first),
        (Confidence::Confirmed, true, false)
    );
    let a = GuardPolicy::for_level(AutoLevel::Aggressive);
    assert_eq!(
        (a.min_confidence, a.auto_demote, a.pressure_largest_first),
        (Confidence::Likely, true, true)
    );
}

#[test]
fn safe_kinds_match_user_decision() {
    let s = GuardPolicy::for_level(AutoLevel::Safe);
    assert_eq!(
        s.auto_terminate_kinds,
        vec![
            Kind::McpServer,
            Kind::DevServer,
            Kind::LanguageServer,
            Kind::Watcher,
            Kind::HeadlessBrowser,
            Kind::AgentHelper,
        ]
    );
    assert_eq!(
        s.notify_only_kinds,
        vec![
            Kind::Emulator,
            Kind::VirtualMachine,
            Kind::Database,
            Kind::LocalLlm,
            Kind::Tunnel,
        ]
    );
}

#[test]
fn notify_only_level_kinds() {
    let n = GuardPolicy::for_level(AutoLevel::NotifyOnly);
    assert!(n.auto_terminate_kinds.is_empty());
    assert_eq!(
        n.notify_only_kinds,
        GuardPolicy::for_level(AutoLevel::Safe).notify_only_kinds
    );
}

#[test]
fn aggressive_kinds() {
    let a = GuardPolicy::for_level(AutoLevel::Aggressive);
    assert_eq!(
        a.auto_terminate_kinds,
        vec![
            Kind::McpServer,
            Kind::DevServer,
            Kind::LanguageServer,
            Kind::Watcher,
            Kind::HeadlessBrowser,
            Kind::AgentHelper,
            Kind::BuildTool,
            Kind::TestTool,
            Kind::DevRuntime,
            Kind::Emulator,
            Kind::LocalLlm,
            Kind::Tunnel,
        ]
    );
    assert_eq!(
        a.notify_only_kinds,
        vec![Kind::VirtualMachine, Kind::Database]
    );
}

#[test]
fn forbidden_kinds_in_no_list() {
    let forbidden = [
        Kind::System,
        Kind::AppHelper,
        Kind::GuiApp,
        Kind::AgentCli,
        Kind::Other,
    ];
    let never_auto = [Kind::VirtualMachine, Kind::Database];
    for l in LEVELS {
        let p = GuardPolicy::for_level(l);
        for k in forbidden {
            assert!(!p.auto_terminate_kinds.contains(&k), "{l:?} auto {k:?}");
            assert!(!p.notify_only_kinds.contains(&k), "{l:?} notify {k:?}");
        }
        for k in never_auto {
            assert!(!p.auto_terminate_kinds.contains(&k), "{l:?} auto {k:?}");
        }
    }
}

#[test]
fn kind_lists_disjoint_and_unique() {
    for l in LEVELS {
        let p = GuardPolicy::for_level(l);
        let auto: HashSet<Kind> = p.auto_terminate_kinds.iter().copied().collect();
        let notify: HashSet<Kind> = p.notify_only_kinds.iter().copied().collect();
        assert_eq!(auto.len(), p.auto_terminate_kinds.len(), "{l:?} auto dup");
        assert_eq!(notify.len(), p.notify_only_kinds.len(), "{l:?} notify dup");
        assert!(auto.is_disjoint(&notify), "{l:?} overlap");
    }
}

#[test]
fn guard_policy_roundtrip_and_shape() {
    for l in LEVELS {
        roundtrip(&GuardPolicy::for_level(l));
    }
    let v = serde_json::to_value(GuardPolicy::for_level(AutoLevel::Safe)).unwrap();
    assert_eq!(v["level"], "safe");
    assert_eq!(v["min_confidence"], "confirmed");
    assert_eq!(v["auto_terminate_kinds"][0], "mcp_server");
    assert_eq!(v["notify_only_kinds"][4], "tunnel");
    assert_eq!(v.as_object().unwrap().len(), 23);
}

#[test]
fn guard_event_roundtrip() {
    let full = GuardEvent {
        at_unix_ms: 1_790_000_123_000,
        kind: GuardEventKind::AutoTerminated,
        target: Some(pref(4321)),
        finding_id: Some("orphan:4321".to_string()),
        run_id: Some("run-1790000123000-1".to_string()),
        label_ko: "MCP 서버: demo-mcp".to_string(),
        detail_ko: "주인 세션이 끝난 지 12분, 두 번 연속 확인".to_string(),
        reclaimed_bytes: 52_428_800,
    };
    roundtrip(&full);
    let empty = GuardEvent {
        at_unix_ms: 1_790_000_124_000,
        kind: GuardEventKind::Paused,
        target: None,
        finding_id: None,
        run_id: None,
        label_ko: "지킴이".to_string(),
        detail_ko: "일시정지".to_string(),
        reclaimed_bytes: 0,
    };
    roundtrip(&empty);
    let v = serde_json::to_value(&empty).unwrap();
    assert!(v["target"].is_null() && v["run_id"].is_null());
    assert_eq!(v["kind"], "paused");
}

#[test]
fn pending_action_roundtrip() {
    roundtrip(&pending(10, Step::Term, Some(5_000)));
    roundtrip(&pending(11, Step::Demote, None));
    let v = serde_json::to_value(pending(12, Step::Demote, None)).unwrap();
    assert_eq!(v["kind"], "mcp_server");
    assert_eq!(v["step"], "demote");
    assert!(v["eta_ms"].is_null());
}

#[test]
fn guard_status_roundtrip() {
    let status = GuardStatus {
        level: AutoLevel::Safe,
        level_locked_by_env: true,
        paused: false,
        circuit_open: true,
        circuit_opened_at_unix_ms: Some(1_790_000_200_000),
        terminations_in_window: 5,
        scan_seq: 42,
        scan_error_streak: 1,
        last_scan_at_unix_ms: 1_790_000_210_000,
        last_scan_ms: 41.5,
        next_scan_at_unix_ms: 1_790_000_215_000,
        demoted: vec![
            DemotedProc {
                target: pref(20),
                label_ko: "개발 서버: demo-vite".to_string(),
                at_unix_ms: 1_790_000_100_000,
            },
            DemotedProc {
                target: pref(21),
                label_ko: "빌드 도구: demo-cargo".to_string(),
                at_unix_ms: 1_790_000_101_000,
            },
        ],
        pending: vec![pending(30, Step::Term, Some(5_000))],
        health: HealthLevel::Ok,
        health_forced: None,
        unstable: false,
        unstable_reasons: Vec::new(),
        unstable_since_unix_ms: None,
        settle_until_unix_ms: None,
        swap_delta_bytes: None,
    };
    roundtrip(&status);
    let quiet = GuardStatus {
        level: AutoLevel::NotifyOnly,
        level_locked_by_env: false,
        paused: true,
        circuit_open: false,
        circuit_opened_at_unix_ms: None,
        terminations_in_window: 0,
        scan_seq: 0,
        scan_error_streak: 0,
        last_scan_at_unix_ms: 0,
        last_scan_ms: 0.0,
        next_scan_at_unix_ms: 0,
        demoted: vec![],
        pending: vec![],
        health: HealthLevel::Ok,
        health_forced: None,
        unstable: false,
        unstable_reasons: Vec::new(),
        unstable_since_unix_ms: None,
        settle_until_unix_ms: None,
        swap_delta_bytes: None,
    };
    roundtrip(&quiet);
    assert_eq!(
        serde_json::to_value(&quiet).unwrap()["level"],
        "notify_only"
    );
}

#[test]
fn vh_config_default_and_shape() {
    let d = VhConfig::default();
    assert_eq!(
        d,
        VhConfig {
            schema_version: 1,
            auto_level: AutoLevel::Safe,
            first_run_done: false,
            scan_interval_ms: None,
        }
    );
    assert_eq!(
        serde_json::to_value(&d).unwrap(),
        serde_json::json!({
            "schema_version": 1,
            "auto_level": "safe",
            "first_run_done": false,
            "scan_interval_ms": null
        })
    );
    roundtrip(&d);
    roundtrip(&VhConfig {
        schema_version: 1,
        auto_level: AutoLevel::NotifyOnly,
        first_run_done: true,
        scan_interval_ms: Some(10_000),
    });
}

#[test]
fn guard_w4_enum_names_and_pending_wait() {
    let reasons = [
        (UnstableReason::HealthWatch, "health_watch"),
        (UnstableReason::HealthCritical, "health_critical"),
        (UnstableReason::SwapGrowing, "swap_growing"),
    ];
    for (r, name) in reasons {
        assert_eq!(j(&r), format!("\"{name}\""));
        roundtrip(&r);
    }
    let waits = [
        (PendingWait::TooYoung, "too_young"),
        (PendingWait::IdleConfirming, "idle_confirming"),
        (PendingWait::Confirming, "confirming"),
        (PendingWait::Settling, "settling"),
        (PendingWait::RoundLimit, "round_limit"),
    ];
    for (w, name) in waits {
        assert_eq!(j(&w), format!("\"{name}\""));
        roundtrip(&w);
    }
    let v = serde_json::to_value(pending(13, Step::Term, None)).unwrap();
    assert_eq!(v["wait"], "confirming");
}
