//! serde 왕복과 계약상의 JSON 모양. 이름·경로는 합성 값이다.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use vh_model::*;

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let json = serde_json::to_string(value).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&back, value);
}

fn pref(pid: i32) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: 1_790_000_000_000 + pid as u64,
    }
}

fn proc_(pid: i32, ppid: i32) -> Proc {
    let mut env = BTreeMap::new();
    env.insert("CLAUDE_PID".to_string(), "4242".to_string());
    Proc {
        pid,
        ppid,
        pgid: pid,
        uid: 501,
        start_time_unix_ms: pref(pid).start_time_unix_ms,
        name: "node".to_string(),
        exe: Some("/opt/homebrew/bin/node".to_string()),
        argv: vec!["node".to_string(), "server.js".to_string()],
        argv_readable: true,
        env,
        env_readable: true,
        cwd: Some("/Users/demo/dev/shop".to_string()),
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(123_456_789),
        rss_bytes: Some(98_765_432),
        cpu_time_ns: Some(5_000_000_000),
        cpu_pct: Some(12.5),
        threads: Some(11),
        nice: Some(0),
        translated: false,
        tcp: None,
        disk_read_bytes: None,
        disk_written_bytes: None,
        disk_io_delta_bytes: None,
    }
}

fn listener(pid: i32) -> Listener {
    Listener {
        pid,
        start_time_unix_ms: pref(pid).start_time_unix_ms,
        family: Family::V6,
        local_addr: "::".to_string(),
        port: 4723,
        all_interfaces: true,
        loopback: false,
        dual_stack: true,
    }
}

#[test]
fn roundtrip_snapshot() {
    let mut labels = BTreeMap::new();
    labels.insert(300, "com.demo.stt".to_string());
    let mut roots = BTreeMap::new();
    roots.insert(
        "/Users/demo/dev/shop/web".to_string(),
        "/Users/demo/dev/shop".to_string(),
    );
    let mut zombie = proc_(102, 100);
    zombie.status = ProcStatus::Zombie;
    zombie.footprint_bytes = None;
    zombie.cpu_pct = None;
    let s = Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: 1_791_000_000_000,
        host: HostInfo {
            model: "Mac17,6".to_string(),
            os_version: "27.0.1".to_string(),
            arch: "arm64".to_string(),
            ncpu: 18,
            perf_cores: Some(6),
            eff_cores: Some(12),
            mem_total_bytes: 137_438_953_472,
            boot_time_unix_ms: 1_791_267_584_115,
            loadavg: [4.46, 6.05, 6.39],
            home_dir: "/Users/demo".to_string(),
        },
        memory: MemoryInfo {
            pressure_level: 1,
            page_size: 16384,
            free_bytes: 1,
            active_bytes: 2,
            inactive_bytes: 3,
            speculative_bytes: 4,
            wired_bytes: 5,
            compressor_bytes: 44_845_678_592,
            compressed_logical_bytes: 71_963_361_280,
            purgeable_bytes: 6,
            swap_total_bytes: 2_147_483_648,
            swap_used_bytes: 1_704_656_896,
            swapins: 3470,
            swapouts: 107_124,
        },
        limits: LimitsInfo {
            maxproc: 16000,
            maxprocperuid: 10666,
            maxfiles: 491_520,
            maxfilesperproc: 245_760,
            num_files: 23195,
            user_proc_count: 1565,
            total_proc_count: 1816,
        },
        processes: vec![proc_(100, 1), proc_(101, 100), zombie],
        listeners: vec![
            listener(100),
            Listener {
                family: Family::V4,
                local_addr: "127.0.0.1".to_string(),
                all_interfaces: false,
                loopback: true,
                dual_stack: false,
                ..listener(101)
            },
        ],
        launchd_job_pids: vec![300],
        launchd_job_labels: labels,
        project_roots: roots,
        self_pid: 999,
        self_uid: 501,
        cpu_sample_interval_ms: Some(250),
        collection_errors: vec![CollectionError {
            pid: None,
            stage: "procargs".to_string(),
            errno: Some(1),
            message: "남의 사용자 프로세스 251개: 권한 없음(정상)".to_string(),
        }],
        timings_ms: Timings {
            list_ms: 1.25,
            procs_ms: 80.5,
            sockets_ms: 10.0,
            system_ms: 0.75,
            launchd_ms: 20.0,
            roots_ms: 2.5,
            cpu_wait_ms: 250.0,
            total_ms: 365.0,
        },
    };
    roundtrip(&s);
}

fn all_suggestions() -> Vec<Suggestion> {
    vec![
        Suggestion::None,
        Suggestion::Terminate {
            include_descendants: true,
        },
        Suggestion::Demote,
        Suggestion::Resume,
        Suggestion::RestartParent { parent: pref(1) },
        Suggestion::HandoffThenRestart,
        Suggestion::Review,
    ]
}

#[test]
fn roundtrip_report() {
    let findings = all_suggestions()
        .into_iter()
        .enumerate()
        .map(|(i, suggestion)| Finding {
            id: format!("orphan:{i}:1"),
            kind: FindingKind::LogicalOrphan,
            confidence: Confidence::Likely,
            targets: vec![pref(100 + i as i32)],
            title_ko: "고아".to_string(),
            short_ko: "appium :4723".to_string(),
            detail_ko: "띄운 Claude 세션 종료됨".to_string(),
            reason_codes: vec!["owner_dead".to_string()],
            reclaim_bytes: 1_000_000_000,
            descendant_count: 29,
            suggestion,
            section: Section::Check,
        })
        .collect();
    let report = Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: 1,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: "메모리 정상".to_string(),
            reasons_ko: vec![],
        },
        classified: vec![Classified {
            target: pref(100),
            kind: Kind::AgentHelper,
            label_ko: "codex app-server".to_string(),
            signature_id: Some("codex_app_server".to_string()),
            project: Some("~/dev/shop".to_string()),
            owner_session: None,
            owner_pid: Some(4242),
            owner_source: Some("env:CLAUDE_PID".to_string()),
            owner_label_ko: Some("Claude 세션".to_string()),
            owner_alive: Some(false),
            usage: Usage::default(),
        }],
        groups: vec![Group {
            id: "project:~/dev/shop".to_string(),
            kind: GroupKind::Project,
            title: "shop".to_string(),
            root: Some("/Users/demo/dev/shop".to_string()),
            members: vec![pref(100), pref(101)],
            footprint_bytes: 2_000_000,
            cpu_pct: Some(3.5),
        }],
        findings,
        listeners: vec![ListenerView {
            listener: listener(100),
            kind: Kind::TestTool,
            label_ko: "appium".to_string(),
            project: None,
            exposure_ko: Some("같은 네트워크의 다른 기기에서 접속 가능".to_string()),
        }],
        totals: Totals {
            reclaimable_confirmed_bytes: 1,
            reclaimable_likely_bytes: 2,
            unneeded_bytes: 0,
            check_bytes: 0,
            manual_bytes: 0,
        },
    };
    roundtrip(&report);
    roundtrip(&Explanation {
        target: pref(100),
        chain: vec![ChainNode {
            target: pref(1),
            name: "launchd".to_string(),
            label_ko: "시스템".to_string(),
        }],
        kind: Kind::Other,
        label_ko: "기타".to_string(),
        project: None,
        owner_ko: None,
        finding_ids: vec!["orphan:0:1".to_string()],
        listeners: vec![listener(100)],
        summary_ko: "요약".to_string(),
    });
}

#[test]
fn roundtrip_action_types() {
    let action = PlannedAction {
        finding_id: "direct:100:1".to_string(),
        target: pref(100),
        include_descendants: true,
        descendant_count: 2,
        steps: vec![Step::Cont, Step::Term, Step::Kill],
        grace_ms: 3000,
        reason_ko: "고아".to_string(),
        est_reclaim_bytes: 10,
    };
    roundtrip(&ActionPlan {
        created_at_unix_ms: 1,
        total_deadline_ms: 30_000,
        items: vec![action.clone()],
        refused: vec![Refusal {
            target: pref(2),
            rule: "R04".to_string(),
            reason_ko: "남의 사용자".to_string(),
        }],
    });
    for final_state in [
        FinalState::Exited,
        FinalState::StillAlive,
        FinalState::Skipped,
        FinalState::Refused,
        FinalState::Vanished,
        FinalState::Reused,
    ] {
        roundtrip(&ActionOutcome {
            action: action.clone(),
            steps: vec![StepResult {
                step: Step::Demote,
                pid: 100,
                at_unix_ms: 2,
                ok: false,
                errno: Some(3),
            }],
            final_state,
            note_ko: "메모".to_string(),
        });
    }
    let mut env = BTreeMap::new();
    env.insert("VH_TAG".to_string(), "demo".to_string());
    roundtrip(&ReviveRecord {
        target: pref(100),
        exe: Some("/opt/homebrew/bin/node".to_string()),
        argv: vec!["node".to_string()],
        cwd: None,
        env,
        recorded_at_unix_ms: 3,
    });
}

#[test]
fn enum_snake_case_names() {
    let j = |v: &dyn erased::Ser| v.json();
    assert_eq!(j(&ProcStatus::Zombie), "\"zombie\"");
    assert_eq!(j(&Kind::McpServer), "\"mcp_server\"");
    assert_eq!(j(&Kind::AgentHelper), "\"agent_helper\"");
    assert_eq!(j(&FindingKind::LogicalOrphan), "\"logical_orphan\"");
    assert_eq!(
        j(&FindingKind::HeadlessBrowserLeftover),
        "\"headless_browser_leftover\""
    );
    assert_eq!(j(&Family::V6), "\"v6\"");
    assert_eq!(j(&FinalState::StillAlive), "\"still_alive\"");
    assert_eq!(j(&ExeOrigin::DevToolBundle), "\"dev_tool_bundle\"");
    assert_eq!(j(&HealthLevel::Critical), "\"critical\"");
    assert_eq!(j(&GroupKind::AgentSession), "\"agent_session\"");
    assert_eq!(j(&Step::Demote), "\"demote\"");
    assert_eq!(j(&Confidence::Possible), "\"possible\"");
}

mod erased {
    pub trait Ser {
        fn json(&self) -> String;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> String {
            serde_json::to_string(self).expect("serialize")
        }
    }
}

#[test]
fn suggestion_internal_tag() {
    let v = serde_json::to_value(Suggestion::Terminate {
        include_descendants: true,
    })
    .unwrap();
    assert_eq!(
        v,
        serde_json::json!({"type": "terminate", "include_descendants": true})
    );
    let v = serde_json::to_value(Suggestion::None).unwrap();
    assert_eq!(v, serde_json::json!({"type": "none"}));
    let v = serde_json::to_value(Suggestion::RestartParent { parent: pref(7) }).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"type": "restart_parent", "parent": {"pid": 7, "start_time_unix_ms": 1_790_000_000_007u64}})
    );
    let v = serde_json::to_value(Suggestion::HandoffThenRestart).unwrap();
    assert_eq!(v, serde_json::json!({"type": "handoff_then_restart"}));
    for s in all_suggestions() {
        roundtrip(&s);
    }
}

#[test]
fn confidence_rank_and_meets() {
    assert_eq!(Confidence::Confirmed.rank(), 3);
    assert_eq!(Confidence::Likely.rank(), 2);
    assert_eq!(Confidence::Possible.rank(), 1);
    assert!(Confidence::Confirmed.meets(Confidence::Likely));
    assert!(Confidence::Likely.meets(Confidence::Likely));
    assert!(!Confidence::Possible.meets(Confidence::Likely));
    assert!(!Confidence::Likely.meets(Confidence::Confirmed));
}

#[test]
fn schema_and_allowlist_constants() {
    assert_eq!(SCHEMA_VERSION, 2);
    assert_eq!(ENV_ALLOWLIST.len(), 20);
    assert!(ENV_ALLOWLIST.contains(&"SENPI_PY_KERNEL_PARENT_PID"));
    assert_eq!(REDACTED, "<가림>");
}

fn js<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialize")
}

#[test]
fn serde_names_w4() {
    assert_eq!(SCHEMA_VERSION, 2);
    assert_eq!(js(&FindingKind::HighCpu), "\"high_cpu\"");
    let sections = [
        (Section::Unneeded, "unneeded"),
        (Section::Check, "check"),
        (Section::Working, "working"),
        (Section::Manual, "manual"),
        (Section::Info, "info"),
    ];
    for (s, name) in sections {
        assert_eq!(js(&s), format!("\"{name}\""));
        roundtrip(&s);
    }
    assert_eq!(js(&UsageState::Unknown), "\"unknown\"");
    assert_eq!(js(&OwnerState::User), "\"user\"");
    assert_eq!(
        js(&UsageReason::PeerOutsideSubtree),
        "\"peer_outside_subtree\""
    );
    assert_eq!(js(&UsageReason::LifetimeCpuLow), "\"lifetime_cpu_low\"");
    let usage = Usage {
        state: UsageState::Active,
        owner: OwnerState::Ended,
        reasons: vec![UsageReason::CpuActive, UsageReason::NoPeers],
        subtree_procs: 3,
        subtree_cpu_pct: Some(2.5),
        subtree_disk_delta_bytes: Some(4096),
        outside_peer_count: 1,
    };
    roundtrip(&usage);
    let v = serde_json::to_value(&usage).unwrap();
    assert_eq!(v["reasons"][0], "cpu_active");
    assert_eq!(v.as_object().unwrap().len(), 7);
    let tcp = TcpSummary {
        established: 3,
        loopback: 2,
        external: 1,
        unresolved: 0,
        peer_pids: vec![101, 102],
        peer_pids_truncated: false,
    };
    roundtrip(&tcp);
    let tv = serde_json::to_value(&tcp).unwrap();
    assert_eq!(tv.as_object().unwrap().len(), 6);
    assert_eq!(MAX_PEER_PIDS, 64);
    let mut p = proc_(100, 1);
    p.tcp = Some(tcp);
    p.disk_read_bytes = Some(1);
    p.disk_written_bytes = Some(2);
    p.disk_io_delta_bytes = Some(3);
    roundtrip(&p);
}

#[test]
fn v1_proc_json_still_parses() {
    let mut v = serde_json::to_value(proc_(100, 1)).unwrap();
    let o = v.as_object_mut().unwrap();
    for k in [
        "tcp",
        "disk_read_bytes",
        "disk_written_bytes",
        "disk_io_delta_bytes",
    ] {
        assert!(o.remove(k).is_some(), "{k}");
    }
    let back: Proc = serde_json::from_value(v).expect("v1 Proc JSON");
    assert_eq!(back.tcp, None);
    assert_eq!(back.disk_read_bytes, None);
    assert_eq!(back.disk_written_bytes, None);
    assert_eq!(back.disk_io_delta_bytes, None);
}

fn usage_with(state: UsageState) -> Usage {
    Usage {
        state,
        ..Usage::default()
    }
}

#[test]
fn in_use_active_is_true() {
    assert!(usage_with(UsageState::Active).in_use());
}

#[test]
fn in_use_unknown_is_true() {
    assert!(usage_with(UsageState::Unknown).in_use());
    assert!(Usage::default().in_use());
}

#[test]
fn in_use_idle_is_false() {
    assert!(!usage_with(UsageState::Idle).in_use());
}
