//! W4 사용 판정·구역·확보량 테스트(합성 이름·경로만).

mod common;

use std::collections::BTreeMap;

use common::*;
use vh_analyze::analyze;
use vh_model::{
    Confidence, FindingKind, Kind, OwnerState, Proc, ProcStatus, Report, Section, Snapshot,
    Suggestion, TcpSummary, UsageReason, UsageState,
};

const NOW: u64 = 1_791_900_000_000;
const UID: u32 = 501;
const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
/// 살아 있는 Claude 세션(zsh 310 밑).
const SESSION: i32 = 5000;
/// 끝난 세션 pid(스냅샷에 없음).
const DEAD: i32 = 4242;
const NODE: &str = "/Users/demo/.local/share/fnm/node-versions/v24.0.0/installation/bin/node";

fn proc_(pid: i32, ppid: i32, exe: &str, argv: &[&str], age: u64) -> Proc {
    Proc {
        pid,
        ppid,
        pgid: pid,
        uid: UID,
        start_time_unix_ms: NOW - age,
        name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
        exe: Some(exe.to_string()),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        argv_readable: true,
        env: BTreeMap::new(),
        env_readable: true,
        cwd: Some("/Users/demo/dev/shop".to_string()),
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(100 * MIB),
        rss_bytes: Some(100 * MIB),
        cpu_time_ns: Some(0),
        cpu_pct: Some(0.0),
        threads: Some(4),
        nice: Some(0),
        translated: false,
        tcp: Some(TcpSummary::default()),
        disk_read_bytes: Some(0),
        disk_written_bytes: Some(0),
        disk_io_delta_bytes: Some(0),
    }
}

fn owned_by(mut p: Proc, owner: i32) -> Proc {
    p.env.insert("CLAUDE_PID".into(), owner.to_string());
    p
}

fn peers(mut p: Proc, pids: &[i32]) -> Proc {
    let t = p.tcp.get_or_insert_with(TcpSummary::default);
    t.established += pids.len() as u32;
    t.loopback += pids.len() as u32;
    t.peer_pids = pids.to_vec();
    p
}

fn cpu(mut p: Proc, pct: f32) -> Proc {
    p.cpu_pct = Some(pct);
    p
}

/// 주인 끝난 MCP(stdio) 고아.
fn mcp_orphan(pid: i32) -> Proc {
    owned_by(
        proc_(
            pid,
            1,
            NODE,
            &[
                NODE,
                "/Users/demo/.npm/_npx/aa11/node_modules/.bin/demo-mcp",
                "mcp",
            ],
            2 * HOUR,
        ),
        DEAD,
    )
}

/// 주인 끝난 개발 서버 고아.
fn dev_orphan(pid: i32) -> Proc {
    owned_by(
        proc_(
            pid,
            1,
            NODE,
            &[
                NODE,
                "/Users/demo/dev/shop/node_modules/.bin/next",
                "dev",
                "--port",
                "3000",
            ],
            2 * HOUR,
        ),
        DEAD,
    )
}

fn session() -> Proc {
    proc_(
        SESSION,
        310,
        "/Users/demo/.local/share/claude/versions/2.1.0",
        &["claude"],
        6 * HOUR,
    )
}

fn world(extra: Vec<Proc>) -> Snapshot {
    let mut s = load("pressure_1_normal");
    s.processes.push(session());
    s.processes.extend(extra);
    s
}

fn report(s: &Snapshot) -> Report {
    let r = analyze(s);
    check_invariants(s, &r);
    r
}

fn usage(r: &Report, pid: i32) -> &vh_model::Usage {
    &class(r, pid).usage
}

fn has(r: &Report, pid: i32, code: UsageReason) -> bool {
    usage(r, pid).reasons.contains(&code)
}

fn finding_for(r: &Report, kind: FindingKind, pid: i32) -> &vh_model::Finding {
    one(r, kind, pid)
}

#[test]
fn child_cpu_makes_parent_active() {
    let s = world(vec![
        dev_orphan(800),
        cpu(proc_(801, 800, NODE, &[NODE, "worker.js"], HOUR), 3.0),
    ]);
    let r = report(&s);
    let u = usage(&r, 800);
    assert_eq!(u.subtree_cpu_pct, Some(3.0));
    assert_eq!(u.subtree_procs, 2);
    assert_eq!(u.state, UsageState::Active);
    assert!(u.reasons.contains(&UsageReason::CpuActive));
    let f = finding_for(&r, FindingKind::Orphan, 800);
    assert_eq!(f.section, Section::Check);
    assert_eq!(f.suggestion, Suggestion::Review);
    assert!(has_reason(f, "usage_not_idle"));
}

#[test]
fn loopback_inside_subtree_not_counted() {
    let s = world(vec![
        peers(dev_orphan(800), &[801]),
        peers(proc_(801, 800, NODE, &[NODE, "worker.js"], HOUR), &[800]),
    ]);
    let r = report(&s);
    assert!(has(&r, 800, UsageReason::NoPeers));
    assert_eq!(usage(&r, 800).state, UsageState::Idle);
    assert_eq!(usage(&r, 800).outside_peer_count, 0);
    assert!(has(&r, 801, UsageReason::PeerOutsideSubtree));
    let f = finding_for(&r, FindingKind::Orphan, 800);
    assert_eq!(f.section, Section::Unneeded);
    assert!(matches!(f.suggestion, Suggestion::Terminate { .. }));
}

#[test]
fn browser_to_orphan_server_is_active() {
    let chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    let s = world(vec![
        peers(proc_(400, 1, chrome, &[chrome], 5 * HOUR), &[800]),
        peers(dev_orphan(800), &[400]),
    ]);
    let r = report(&s);
    assert_eq!(class(&r, 400).kind, Kind::GuiApp);
    let u = usage(&r, 800);
    assert_eq!(u.state, UsageState::Active);
    assert_eq!(u.outside_peer_count, 1);
    assert!(u.reasons.contains(&UsageReason::PeerOutsideSubtree));
    let f = finding_for(&r, FindingKind::Orphan, 800);
    assert_eq!(f.section, Section::Check);
    assert_eq!(f.suggestion, Suggestion::Review);
}

#[test]
fn adb_peer_is_infra() {
    let adb = "/Users/demo/Library/Android/sdk/platform-tools/adb";
    let s = world(vec![
        peers(
            proc_(
                450,
                1,
                adb,
                &["adb", "-L", "tcp:5037", "fork-server", "server"],
                5 * HOUR,
            ),
            &[800],
        ),
        peers(dev_orphan(800), &[450]),
    ]);
    let r = report(&s);
    assert_eq!(
        class(&r, 450).signature_id.as_deref(),
        Some("android_adb_server")
    );
    assert!(has(&r, 800, UsageReason::NoPeers));
    assert!(has(&r, 800, UsageReason::InfraPeersOnly));
    assert_eq!(usage(&r, 800).state, UsageState::Idle);
    assert_eq!(
        finding_for(&r, FindingKind::Orphan, 800).section,
        Section::Unneeded
    );
}

#[test]
fn external_and_unresolved_are_active() {
    let mut ext = dev_orphan(800);
    ext.tcp = Some(TcpSummary {
        established: 1,
        external: 1,
        ..TcpSummary::default()
    });
    let mut unres = mcp_orphan(810);
    unres.tcp = Some(TcpSummary {
        established: 1,
        loopback: 1,
        unresolved: 1,
        ..TcpSummary::default()
    });
    let r = report(&world(vec![ext, unres]));
    assert!(has(&r, 800, UsageReason::PeerExternal));
    assert!(has(&r, 810, UsageReason::PeerUnresolved));
    for pid in [800, 810] {
        assert_eq!(usage(&r, pid).state, UsageState::Active, "{pid}");
        assert_eq!(
            finding_for(&r, FindingKind::Orphan, pid).section,
            Section::Check
        );
    }
}

#[test]
fn unknown_without_cpu_or_tcp() {
    let mut no_interval = world(vec![dev_orphan(800)]);
    no_interval.cpu_sample_interval_ms = None;
    let mut no_tcp = dev_orphan(800);
    no_tcp.tcp = None;
    let mut no_disk = dev_orphan(800);
    no_disk.disk_io_delta_bytes = None;
    let mut short = world(vec![dev_orphan(800)]);
    short.cpu_sample_interval_ms = Some(150);
    for (name, s, code) in [
        ("interval", no_interval, UsageReason::CpuUnknown),
        ("tcp", world(vec![no_tcp]), UsageReason::PeersUnknown),
        ("disk", world(vec![no_disk]), UsageReason::DiskUnknown),
        ("short", short, UsageReason::CpuUnknown),
    ] {
        let r = report(&s);
        let u = usage(&r, 800);
        assert_eq!(u.state, UsageState::Unknown, "{name}");
        assert!(u.reasons.contains(&code), "{name}: {:?}", u.reasons);
        assert!(u.in_use(), "{name}");
        let f = finding_for(&r, FindingKind::Orphan, 800);
        assert_eq!(f.section, Section::Check, "{name}");
        assert_eq!(f.suggestion, Suggestion::Review, "{name}");
    }
}

#[test]
fn thresholds_cpu_and_disk_boundaries() {
    let r = report(&world(vec![
        cpu(dev_orphan(800), 0.49),
        cpu(mcp_orphan(810), 0.5),
    ]));
    assert!(has(&r, 800, UsageReason::CpuIdle));
    assert!(has(&r, 810, UsageReason::CpuActive));
    // 간격 250ms에서 초당 1MiB = 262,144바이트.
    let mut below = dev_orphan(800);
    below.disk_io_delta_bytes = Some(262_143);
    let mut at = mcp_orphan(810);
    at.disk_io_delta_bytes = Some(262_144);
    let r = report(&world(vec![below, at]));
    assert!(has(&r, 800, UsageReason::DiskIdle));
    assert!(has(&r, 810, UsageReason::DiskActive));
    assert_eq!(usage(&r, 800).state, UsageState::Idle);
    assert_eq!(usage(&r, 810).state, UsageState::Active);
}

#[test]
fn young_root_only() {
    let mut young = dev_orphan(800);
    young.start_time_unix_ms = NOW - 9 * MIN;
    let old = dev_orphan(820);
    let kid = proc_(821, 820, NODE, &[NODE, "worker.js"], MIN);
    let r = report(&world(vec![young, old, kid]));
    assert!(has(&r, 800, UsageReason::Young));
    assert_eq!(usage(&r, 800).state, UsageState::Active);
    assert!(!has(&r, 820, UsageReason::Young));
    assert_eq!(usage(&r, 820).state, UsageState::Idle);
}

#[test]
fn lifetime_low_does_not_change_state() {
    let mut busy_before = dev_orphan(800);
    busy_before.cpu_time_ns = Some(30 * MIN * 1_000_000);
    let lazy = mcp_orphan(810);
    let r = report(&world(vec![busy_before, lazy]));
    assert!(!has(&r, 800, UsageReason::LifetimeCpuLow));
    assert_eq!(usage(&r, 800).state, UsageState::Idle);
    assert!(has(&r, 810, UsageReason::LifetimeCpuLow));
    assert_eq!(usage(&r, 810).state, UsageState::Idle);
}

#[test]
fn owner_state_mapping() {
    let alive = proc_(
        5010,
        SESSION,
        NODE,
        &[
            NODE,
            "/Users/demo/.npm/_npx/aa11/node_modules/.bin/demo-mcp",
            "mcp",
        ],
        HOUR,
    );
    let lone = proc_(830, 1, "/Users/demo/bin/mystery", &["mystery"], 2 * HOUR);
    let r = report(&world(vec![alive, dev_orphan(800), lone]));
    assert_eq!(usage(&r, 300).owner, OwnerState::User);
    assert_eq!(usage(&r, 310).owner, OwnerState::User);
    assert_eq!(usage(&r, SESSION).owner, OwnerState::User);
    assert_eq!(usage(&r, 5010).owner, OwnerState::Alive);
    assert!(has(&r, 5010, UsageReason::OwnerAlive));
    assert_eq!(usage(&r, 800).owner, OwnerState::Ended);
    assert_eq!(usage(&r, 830).owner, OwnerState::Unknown);
}

#[test]
fn section_table_four_cells() {
    let alive_idle = owned_by(mcp_orphan(810), SESSION);
    let alive_busy = cpu(owned_by(mcp_orphan(811), SESSION), 5.0);
    let ended_idle = mcp_orphan(812);
    let ended_busy = cpu(mcp_orphan(813), 5.0);
    let r = report(&world(vec![alive_idle, alive_busy, ended_idle, ended_busy]));
    let sec = |pid| finding_for(&r, FindingKind::Orphan, pid).section;
    assert_eq!(sec(810), Section::Check);
    assert_eq!(sec(811), Section::Working);
    assert_eq!(sec(812), Section::Unneeded);
    assert_eq!(sec(813), Section::Check);
}

#[test]
fn possible_and_service_kinds_never_unneeded() {
    let qemu = "/Users/demo/Library/Android/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64";
    let emu = owned_by(
        proc_(900, 1, qemu, &[qemu, "-avd", "Pixel_9"], 2 * HOUR),
        DEAD,
    );
    let mystery = proc_(830, 1, "/Users/demo/bin/mystery", &["mystery"], 2 * HOUR);
    let r = report(&world(vec![emu, mystery]));
    assert_eq!(class(&r, 900).kind, Kind::Emulator);
    assert_eq!(usage(&r, 900).state, UsageState::Idle);
    let e = finding_for(&r, FindingKind::Orphan, 900);
    assert_eq!(e.section, Section::Check);
    assert_eq!(e.suggestion, Suggestion::Review);
    assert!(has_reason(e, "kind_report_only"));
    let m = finding_for(&r, FindingKind::Orphan, 830);
    assert_eq!(m.confidence, Confidence::Possible);
    assert_eq!(m.section, Section::Check);
}

#[test]
fn terminate_only_in_unneeded() {
    let r = report(&world(vec![cpu(mcp_orphan(810), 2.0), mcp_orphan(811)]));
    let busy = finding_for(&r, FindingKind::Orphan, 810);
    assert_eq!(busy.confidence, Confidence::Confirmed);
    assert_eq!(busy.suggestion, Suggestion::Review);
    assert!(busy.detail_ko.contains("사람이") && busy.detail_ko.contains("CPU"));
    let idle = finding_for(&r, FindingKind::Orphan, 811);
    assert!(matches!(idle.suggestion, Suggestion::Terminate { .. }));
    for f in &r.findings {
        if matches!(f.suggestion, Suggestion::Terminate { .. }) {
            assert_eq!(f.section, Section::Unneeded, "{f:#?}");
        }
    }
}

#[test]
fn high_cpu_never_demotes() {
    let cmux = "/Applications/cmux.app/Contents/MacOS/cmux";
    let app = cpu(proc_(420, 1, cmux, &[cmux], 3 * HOUR), 103.0);
    let lost = cpu(mcp_orphan(810), 150.0);
    let r = report(&world(vec![app, lost]));
    let a = finding_for(&r, FindingKind::HighCpu, 420);
    assert_eq!(
        (a.section, &a.suggestion),
        (Section::Working, &Suggestion::None)
    );
    let l = finding_for(&r, FindingKind::HighCpu, 810);
    assert_eq!(
        (l.section, &l.suggestion),
        (Section::Check, &Suggestion::Review)
    );
    assert!(
        r.findings
            .iter()
            .all(|f| f.suggestion != Suggestion::Demote)
    );
    assert!(r.findings.iter().all(|f| !f.title_ko.contains("폭주")));
}

#[test]
fn zone_totals_dedup_and_precedence() {
    let mut llm = proc_(
        950,
        1,
        "/opt/homebrew/bin/python3.12",
        &["python3.12", "-m", "mlx_lm.server", "--port", "8080"],
        5 * HOUR,
    );
    llm.footprint_bytes = Some(5 * GIB);
    let r = report(&world(vec![mcp_orphan(810), llm]));
    assert_eq!(class(&r, 950).kind, Kind::LocalLlm);
    assert_eq!(
        finding_for(&r, FindingKind::Orphan, 950).section,
        Section::Check
    );
    assert_eq!(
        finding_for(&r, FindingKind::HeavyProcess, 950).section,
        Section::Manual
    );
    assert_eq!(r.totals.unneeded_bytes, 100 * MIB);
    assert_eq!(r.totals.check_bytes, 5 * GIB);
    assert_eq!(r.totals.manual_bytes, 0, "check에 센 것은 manual에서 뺀다");
}

#[test]
fn manual_detail_has_method_sentence() {
    let r = report(&world(vec![]));
    assert!(r.findings.iter().all(|f| f.section != Section::Manual));
    let (_, z) = run("zombies_unreaped");
    let zf = &of_kind(&z, FindingKind::Zombie)[0];
    assert_eq!(zf.section, Section::Manual);
    assert!(zf.detail_ko.contains("다시 시작하면 사라져요"));
    let (_, h) = run("omo_heavy_session");
    let hf = &of_kind(&h, FindingKind::HeavyAgentSession)[0];
    assert_eq!(hf.section, Section::Manual);
    assert!(hf.detail_ko.contains("새로 시작하면 약"));
    assert!(hf.detail_ko.contains("되찾아요"));
    assert!(h.totals.manual_bytes > 0);
}

/// N1~N4(PM 판정 표의 새 시나리오)를 합성으로.
#[test]
fn w4_in_use_scenarios() {
    let client = |pid, peer| {
        peers(
            proc_(pid, SESSION, NODE, &[NODE, "client.js"], HOUR),
            &[peer],
        )
    };
    let n1 = cpu(owned_by(mcp_orphan(810), SESSION), 100.0);
    let n2 = peers(dev_orphan(820), &[821]);
    let n3 = cpu(
        proc_(830, 1, "/Users/demo/bin/lab-spin", &["lab-spin"], 2 * HOUR),
        100.0,
    );
    let n3 = owned_by(n3, DEAD);
    let n4 = dev_orphan(840);
    let r = report(&world(vec![n1, n2, client(821, 820), n3, n4]));
    let u1 = usage(&r, 810);
    assert!(
        u1.reasons.contains(&UsageReason::OwnerAlive)
            && u1.reasons.contains(&UsageReason::CpuActive)
    );
    assert_eq!(
        finding_for(&r, FindingKind::Orphan, 810).section,
        Section::Working
    );
    assert_eq!(
        finding_for(&r, FindingKind::HighCpu, 810).section,
        Section::Working
    );
    assert!(has(&r, 820, UsageReason::PeerOutsideSubtree));
    assert_eq!(
        finding_for(&r, FindingKind::Orphan, 820).section,
        Section::Check
    );
    assert!(has(&r, 830, UsageReason::CpuActive));
    for f in r
        .findings
        .iter()
        .filter(|f| f.targets.iter().any(|t| t.pid == 830))
    {
        assert_eq!(f.section, Section::Check, "{f:#?}");
    }
    assert_eq!(
        finding_for(&r, FindingKind::Orphan, 840).section,
        Section::Unneeded
    );
}

/// inputs/CORE.md 실기기 표의 각 행을 합성으로(이름은 합성).
#[test]
fn w4_real_table() {
    // 에이전트 백엔드 중계(주인 끝남, CPU 0, 연결 0) → unneeded
    let (_, r) = run("codex_broker_orphan");
    assert_eq!(
        one(&r, FindingKind::Orphan, 4500).section,
        Section::Unneeded
    );
    // 예비 세션(3일 23시간, 0.07%) → unneeded
    let spare = cpu(
        owned_by(
            proc_(
                1302,
                1,
                "/Users/demo/.local/share/claude/versions/2.1.0",
                &["claude bg-spare --bg-spare /tmp/cc-daemon-501/x/spare.sock"],
                95 * HOUR,
            ),
            DEAD,
        ),
        0.07,
    );
    // python serve 높은 포트(주인 끝남, 0%, 연결 0) → unneeded
    let py = "/opt/homebrew/bin/python3.12";
    let serve = owned_by(
        proc_(710, 1, py, &[py, "-m", "http.server", "18788"], 3 * HOUR),
        DEAD,
    );
    // 에뮬레이터 qemu(주인 끝남, 2.8%, adb 연결) → check
    let qemu = "/Users/demo/Library/Android/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64";
    let adb = "/Users/demo/Library/Android/sdk/platform-tools/adb";
    let emu = peers(
        cpu(
            owned_by(
                proc_(900, 1, qemu, &[qemu, "-avd", "Pixel_9"], 5 * HOUR),
                DEAD,
            ),
            2.8,
        ),
        &[450],
    );
    let adbd = peers(
        proc_(
            450,
            1,
            adb,
            &["adb", "-L", "tcp:5037", "fork-server", "server"],
            6 * HOUR,
        ),
        &[900],
    );
    // Appium(주인 살아 있음, 0%, 연결 0) → check
    let appium = owned_by(
        proc_(
            960,
            1,
            NODE,
            &[
                NODE,
                "/Users/demo/.npm/_npx/bb22/node_modules/appium/build/lib/main.js",
            ],
            2 * HOUR,
        ),
        SESSION,
    );
    // GUI 앱 103% → working
    let cmux = "/Applications/cmux.app/Contents/MacOS/cmux";
    let app = cpu(proc_(420, 1, cmux, &[cmux], 3 * HOUR), 103.0);
    // 가상 머신 12GB → manual
    let orb = "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper";
    let mut vm = proc_(970, 1, orb, &[orb, "vmgr"], 9 * HOUR);
    vm.footprint_bytes = Some(12 * GIB);
    let r = report(&world(vec![spare, serve, emu, adbd, appium, app, vm]));
    assert_eq!(
        one(&r, FindingKind::Orphan, 1302).section,
        Section::Unneeded
    );
    assert_eq!(one(&r, FindingKind::Orphan, 710).section, Section::Unneeded);
    assert_eq!(one(&r, FindingKind::Orphan, 900).section, Section::Check);
    assert!(has(&r, 900, UsageReason::CpuActive));
    assert_eq!(one(&r, FindingKind::Orphan, 960).section, Section::Check);
    assert_eq!(usage(&r, 960).state, UsageState::Idle);
    assert_eq!(one(&r, FindingKind::HighCpu, 420).section, Section::Working);
    assert_eq!(class(&r, 970).kind, Kind::VirtualMachine);
    assert_eq!(
        one(&r, FindingKind::HeavyProcess, 970).section,
        Section::Manual
    );
    // 경계: 에이전트 백그라운드 데몬 1.0% → check(CORE 선택)
    let mut s = load("claude_daemon_transient");
    for p in &mut s.processes {
        if p.pid == 1300 {
            p.cpu_pct = Some(1.0);
        }
    }
    let r = report(&s);
    assert!(has(&r, 1300, UsageReason::CpuActive));
    assert_eq!(one(&r, FindingKind::Orphan, 1300).section, Section::Check);
    // 세션 22GB·좀비 → manual
    let (_, h) = run("omo_heavy_session");
    assert_eq!(
        one(&h, FindingKind::HeavyAgentSession, 7000).section,
        Section::Manual
    );
    let (_, z) = run("zombies_unreaped");
    assert_eq!(of_kind(&z, FindingKind::Zombie)[0].section, Section::Manual);
}

#[test]
fn v1_snapshot_is_unknown() {
    let mut v: serde_json::Value =
        serde_json::from_str(&raw("codex_app_server_logical_orphan")).unwrap();
    for p in v["processes"].as_array_mut().unwrap() {
        let o = p.as_object_mut().unwrap();
        for k in [
            "tcp",
            "disk_read_bytes",
            "disk_written_bytes",
            "disk_io_delta_bytes",
        ] {
            o.remove(k);
        }
        o.insert("cpu_pct".into(), serde_json::Value::Null);
    }
    let s: Snapshot = serde_json::from_value(v).unwrap();
    let r = report(&s);
    assert!(
        r.classified
            .iter()
            .all(|c| c.usage.state != UsageState::Idle)
    );
    assert!(r.findings.iter().all(|f| f.section != Section::Unneeded));
    assert!(
        r.findings
            .iter()
            .all(|f| !matches!(f.suggestion, Suggestion::Terminate { .. }))
    );
    assert_eq!(r.totals.unneeded_bytes, 0);
}
