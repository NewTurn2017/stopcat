//! 합성 Snapshot·Report(경로는 /Users/demo/…)와 가짜 신호기 백엔드.
#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use vh_act::{ExecEnv, FakeProber, FakeSignaler, FakeWorld, LiveProc};
use vh_cli::app::{self, Backend, Io};
use vh_cli::flow::Executed;
use vh_model::*;
use vh_sample::CollectOptions;

pub const T0: u64 = 1_760_000_000_000;
pub const MIN: u64 = 60_000;
pub const HOUR: u64 = 60 * MIN;
pub const DAY: u64 = 24 * HOUR;
pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
pub const SELF_PID: i32 = 90000;
pub const UID: u32 = 501;

pub fn r(pid: i32, s: &Snapshot) -> ProcRef {
    let p = s
        .processes
        .iter()
        .find(|p| p.pid == pid)
        .expect("pid in fixture");
    ProcRef {
        pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

fn proc_(pid: i32, ppid: i32, name: &str, exe: &str, fp: u64, age: u64) -> Proc {
    Proc {
        pid,
        ppid,
        pgid: pid,
        uid: UID,
        start_time_unix_ms: T0 - age,
        name: name.to_string(),
        exe: Some(exe.to_string()),
        argv: vec![exe.to_string()],
        argv_readable: true,
        env: BTreeMap::new(),
        env_readable: true,
        cwd: None,
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(fp),
        rss_bytes: Some(fp / 2),
        cpu_time_ns: Some(1_000_000),
        cpu_pct: Some(0.5),
        threads: Some(4),
        nice: Some(0),
        translated: false,
    }
}

fn with_cwd(mut p: Proc, cwd: &str) -> Proc {
    p.cwd = Some(cwd.to_string());
    p
}

fn lst(pid: i32, start: u64, family: Family, addr: &str, port: u16) -> Listener {
    let all = addr == "0.0.0.0" || addr == "::";
    Listener {
        pid,
        start_time_unix_ms: start,
        family,
        local_addr: addr.to_string(),
        port,
        all_interfaces: all,
        loopback: addr == "127.0.0.1" || addr == "::1",
        dual_stack: false,
    }
}

pub fn snapshot() -> Snapshot {
    let node = "/Users/demo/.local/share/fnm/node-versions/v22/installation/bin/node";
    let mut launchd = proc_(1, 0, "launchd", "/sbin/launchd", 20 * MIB, 9 * DAY);
    launchd.uid = 0;
    let mut zombie = proc_(
        8101,
        8100,
        "aside-daemon",
        "/Users/demo/.local/bin/aside-daemon",
        0,
        2 * DAY,
    );
    zombie.status = ProcStatus::Zombie;
    zombie.footprint_bytes = None;
    let processes = vec![
        launchd,
        proc_(89999, 1, "zsh", "/bin/zsh", 4 * MIB, DAY),
        proc_(
            SELF_PID,
            89999,
            "vh",
            "/Users/demo/dev/vibe-health/target/release/vh",
            8 * MIB,
            0,
        ),
        proc_(2000, 1, "zsh", "/bin/zsh", 4 * MIB, 5 * DAY),
        with_cwd(
            proc_(
                2001,
                2000,
                "bun",
                "/Users/demo/.bun/bin/bun",
                22 * GIB,
                5 * DAY,
            ),
            "/Users/demo/dev/warmtalent-ai",
        ),
        proc_(51230, 1, "node", node, 84 * MIB, 3 * DAY + 2 * HOUR),
        with_cwd(
            proc_(
                51234,
                51230,
                "codex",
                "/Users/demo/.local/bin/codex",
                120 * MIB,
                3 * DAY + 2 * HOUR,
            ),
            "/Users/demo/dev/warmtalent-ai",
        ),
        proc_(
            40001,
            1,
            "qemu-system-aarch64",
            "/Users/demo/Library/Android/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64",
            7 * GIB + GIB / 2,
            3 * DAY,
        ),
        with_cwd(
            proc_(40112, 1, "node", node, 412 * MIB, 2 * DAY + 5 * HOUR),
            "/Users/demo/dev/shop-app",
        ),
        proc_(
            40200,
            1,
            "Google Chrome for Testing",
            "/Users/demo/Library/Caches/ms-playwright/chromium-1/chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            380 * MIB,
            7 * HOUR,
        ),
        with_cwd(
            proc_(
                6333,
                1,
                "qdrant",
                "/opt/homebrew/bin/qdrant",
                600 * MIB,
                6 * DAY,
            ),
            "/Users/demo/dev/rag",
        ),
        proc_(
            700,
            1,
            "ControlCenter",
            "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter",
            90 * MIB,
            9 * DAY,
        ),
        with_cwd(
            proc_(3000, 2000, "node", node, 300 * MIB, 2 * HOUR),
            "/Users/demo/dev/shop",
        ),
        with_cwd(
            proc_(61822, 1, "node", node, 96 * MIB, DAY + 3 * HOUR),
            "/private/tmp/claude-501/abc/scratchpad/srv",
        ),
        proc_(61830, 61822, "node", node, 24 * MIB, DAY + 3 * HOUR),
        proc_(61831, 61822, "node", node, 24 * MIB, DAY + 3 * HOUR),
        proc_(
            8100,
            1,
            "aside-daemon",
            "/Users/demo/.local/bin/aside-daemon",
            30 * MIB,
            2 * DAY,
        ),
        zombie,
    ];
    let start = |pid: i32| {
        processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.start_time_unix_ms)
            .unwrap()
    };
    let listeners = vec![
        lst(3000, start(3000), Family::V4, "127.0.0.1", 3000),
        lst(40112, start(40112), Family::V4, "0.0.0.0", 4723),
        lst(40112, start(40112), Family::V6, "::", 4723),
        lst(700, start(700), Family::V6, "::", 5000),
        lst(6333, start(6333), Family::V4, "0.0.0.0", 6333),
        lst(700, start(700), Family::V6, "::", 7000),
        lst(61822, start(61822), Family::V4, "127.0.0.1", 18788),
    ];
    Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: T0,
        host: HostInfo {
            model: "Mac17,6".into(),
            os_version: "27.0.1".into(),
            arch: "arm64".into(),
            ncpu: 18,
            perf_cores: Some(6),
            eff_cores: Some(12),
            mem_total_bytes: 128 * GIB,
            boot_time_unix_ms: T0 - 9 * DAY,
            loadavg: [5.8, 5.1, 4.9],
            home_dir: "/Users/demo".into(),
        },
        memory: MemoryInfo {
            pressure_level: 1,
            page_size: 16384,
            free_bytes: 2 * GIB,
            active_bytes: 40 * GIB,
            inactive_bytes: 30 * GIB,
            speculative_bytes: GIB,
            wired_bytes: 8 * GIB,
            compressor_bytes: 41 * GIB,
            compressed_logical_bytes: 90 * GIB,
            purgeable_bytes: GIB,
            swap_total_bytes: 2 * GIB,
            swap_used_bytes: 1600 * MIB,
            swapins: 10,
            swapouts: 20,
        },
        limits: LimitsInfo {
            maxproc: 8000,
            maxprocperuid: 5333,
            maxfiles: 245_760,
            maxfilesperproc: 122_880,
            num_files: 30_000,
            user_proc_count: 1580,
            total_proc_count: 1800,
        },
        processes,
        listeners,
        launchd_job_pids: vec![],
        launchd_job_labels: BTreeMap::new(),
        project_roots: BTreeMap::new(),
        self_pid: SELF_PID,
        self_uid: UID,
        cpu_sample_interval_ms: Some(250),
        collection_errors: vec![],
        timings_ms: Timings {
            list_ms: 3.0,
            procs_ms: 40.0,
            sockets_ms: 10.0,
            system_ms: 1.0,
            launchd_ms: 8.0,
            roots_ms: 2.0,
            cpu_wait_ms: 250.0,
            total_ms: 314.0,
        },
    }
}

fn cls(s: &Snapshot, pid: i32, kind: Kind, label: &str, project: Option<&str>) -> Classified {
    Classified {
        target: r(pid, s),
        kind,
        label_ko: label.to_string(),
        signature_id: None,
        project: project.map(str::to_string),
        owner_session: None,
        owner_pid: None,
        owner_source: None,
        owner_label_ko: None,
        owner_alive: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    s: &Snapshot,
    kind: FindingKind,
    conf: Confidence,
    pid: i32,
    title: &str,
    short: &str,
    detail: &str,
    reclaim: u64,
    desc: u32,
    suggestion: Suggestion,
) -> Finding {
    let t = r(pid, s);
    Finding {
        id: format!("{kind:?}:{}:{}", t.pid, t.start_time_unix_ms).to_lowercase(),
        kind,
        confidence: conf,
        targets: vec![t],
        title_ko: title.to_string(),
        short_ko: short.to_string(),
        detail_ko: detail.to_string(),
        reason_codes: vec![],
        reclaim_bytes: reclaim,
        descendant_count: desc,
        suggestion,
    }
}

fn view(
    s: &Snapshot,
    i: usize,
    kind: Kind,
    label: &str,
    project: Option<&str>,
    exposure: Option<&str>,
) -> ListenerView {
    ListenerView {
        listener: s.listeners[i].clone(),
        kind,
        label_ko: label.to_string(),
        project: project.map(str::to_string),
        exposure_ko: exposure.map(str::to_string),
    }
}

pub const EXPOSED: &str = "같은 와이파이의 다른 기기에서도 접속할 수 있어요";

/// 실측 사례 모양의 정상 리포트(주의 항목 있음).
pub fn report(s: &Snapshot) -> Report {
    use Confidence::*;
    use FindingKind::*;
    let term = |d: bool| Suggestion::Terminate {
        include_descendants: d,
    };
    let findings = vec![
        finding(
            s,
            HeavyAgentSession,
            Confirmed,
            2001,
            "omo 세션(bun) 22GB, 5일째, warmtalent-ai",
            "omo 세션 22GB",
            "",
            0,
            0,
            Suggestion::HandoffThenRestart,
        ),
        finding(
            s,
            LogicalOrphan,
            Confirmed,
            51234,
            "codex app-server — 띄운 Claude 세션 종료됨, 자식 29개 1.0GB",
            "codex app-server",
            "띄운 Claude 세션이 이미 끝났어요",
            GIB,
            29,
            term(true),
        ),
        finding(
            s,
            Orphan,
            Likely,
            40001,
            "Android 에뮬레이터가 혼자 남음",
            "Android 에뮬레이터 7.5GB",
            "띄운 창이 닫혀 혼자 남았어요 · 3일째",
            7 * GIB + GIB / 2,
            0,
            term(false),
        ),
        finding(
            s,
            Orphan,
            Likely,
            40112,
            "appium이 혼자 남음",
            "appium :4723",
            "띄운 창이 닫혔는데 남아 있어요",
            412 * MIB,
            0,
            term(false),
        ),
        finding(
            s,
            HeadlessBrowserLeftover,
            Likely,
            40200,
            "테스트 브라우저가 남음",
            "headless Chrome 7시간",
            "테스트용 브라우저가 7시간째 남아 있어요",
            380 * MIB,
            0,
            term(false),
        ),
        finding(
            s,
            ExposedListener,
            Confirmed,
            6333,
            "Qdrant가 모든 네트워크에 열려 있음",
            "Qdrant 0.0.0.0:6333",
            "",
            0,
            0,
            Suggestion::Review,
        ),
        finding(
            s,
            ExposedListener,
            Confirmed,
            40112,
            "이 맥 밖에서도 접속할 수 있어요",
            "appium *:4723",
            "",
            0,
            0,
            Suggestion::None,
        ),
        finding(
            s,
            KnownPortConflict,
            Confirmed,
            700,
            "AirPlay 수신이 5000·7000을 씀",
            "AirPlay :5000·:7000",
            "",
            0,
            0,
            Suggestion::None,
        ),
        finding(
            s,
            Zombie,
            Confirmed,
            8101,
            "aside-daemon 좀비 20개",
            "aside 좀비 20개",
            "",
            0,
            0,
            Suggestion::RestartParent { parent: r(8100, s) },
        ),
        finding(
            s,
            Orphan,
            Possible,
            61822,
            "테스트 서버가 혼자 남음",
            "테스트 서버 :18788",
            "다른 Claude 세션의 임시 폴더에서 떠 있어요",
            96 * MIB,
            0,
            Suggestion::Review,
        ),
    ];
    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: T0,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: "메모리 정상 — 압력 1 · 압축 41GB · 스왑 1.6/2GB · 부하 5.8/18코어".into(),
            reasons_ko: vec![],
        },
        classified: vec![
            cls(
                s,
                2001,
                Kind::AgentCli,
                "omo 세션(bun)",
                Some("/Users/demo/dev/warmtalent-ai"),
            ),
            cls(s, 51230, Kind::DevRuntime, "npm exec", None),
            cls(
                s,
                51234,
                Kind::AgentHelper,
                "codex app-server",
                Some("/Users/demo/dev/warmtalent-ai"),
            ),
            cls(s, 40001, Kind::Emulator, "Android 에뮬레이터 (qemu)", None),
            cls(
                s,
                40112,
                Kind::TestTool,
                "appium (앱 테스트)",
                Some("/Users/demo/dev/shop-app"),
            ),
            cls(
                s,
                40200,
                Kind::HeadlessBrowser,
                "headless Chrome (Chrome for Testing)",
                None,
            ),
            cls(
                s,
                6333,
                Kind::Database,
                "Qdrant 데이터베이스",
                Some("/Users/demo/dev/rag"),
            ),
            cls(s, 700, Kind::System, "AirPlay 수신 (제어 센터)", None),
            cls(
                s,
                3000,
                Kind::DevServer,
                "Next.js 개발 서버",
                Some("/Users/demo/dev/shop"),
            ),
            cls(s, 61822, Kind::DevServer, "테스트 서버 (node)", None),
        ],
        groups: vec![],
        findings,
        listeners: vec![
            view(
                s,
                0,
                Kind::DevServer,
                "Next.js 개발 서버",
                Some("/Users/demo/dev/shop"),
                None,
            ),
            view(
                s,
                1,
                Kind::TestTool,
                "appium (앱 테스트)",
                Some("/Users/demo/dev/shop-app"),
                Some(EXPOSED),
            ),
            view(
                s,
                2,
                Kind::TestTool,
                "appium (앱 테스트)",
                Some("/Users/demo/dev/shop-app"),
                Some(EXPOSED),
            ),
            view(
                s,
                3,
                Kind::System,
                "AirPlay 수신 (제어 센터)",
                None,
                Some("Flask 기본 포트와 겹쳐요. 내 앱은 다른 포트(예: 5050)를 쓰세요"),
            ),
            view(
                s,
                4,
                Kind::Database,
                "Qdrant 데이터베이스",
                Some("/Users/demo/dev/rag"),
                Some(EXPOSED),
            ),
            view(s, 5, Kind::System, "AirPlay 수신 (제어 센터)", None, None),
            view(s, 6, Kind::DevServer, "테스트 서버 (node)", None, None),
        ],
        totals: Totals {
            reclaimable_confirmed_bytes: GIB,
            reclaimable_likely_bytes: 7 * GIB + GIB / 2 + 412 * MIB + 380 * MIB,
        },
    }
}

pub fn report_empty() -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: T0,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: "메모리 정상 — 압력 1 · 압축 3.2GB · 스왑 없음 · 부하 2.1/18코어".into(),
            reasons_ko: vec![],
        },
        classified: vec![],
        groups: vec![],
        findings: vec![],
        listeners: vec![],
        totals: Totals {
            reclaimable_confirmed_bytes: 0,
            reclaimable_likely_bytes: 0,
        },
    }
}

pub fn report_crisis(s: &Snapshot) -> Report {
    let mut rep = report(s);
    rep.health = Health {
        level: HealthLevel::Critical,
        headline_ko: "메모리 위험 — 압력 4 · 압축 58GB · 스왑 14.2/16GB · 부하 31.5/18코어".into(),
        reasons_ko: vec!["스왑을 많이 쓰고 있어요. 앱이 멈추거나 아주 느려질 수 있어요.".into()],
    };
    for (i, pid) in [3000, 51230, 61822].into_iter().enumerate() {
        rep.findings.insert(
            1 + i,
            finding(
                s,
                FindingKind::HeavyProcess,
                Confidence::Confirmed,
                pid,
                &format!("tsserver {}번째 3.0GB — 워크트리마다 하나씩", i + 1),
                "tsserver",
                "",
                0,
                0,
                Suggestion::Review,
            ),
        );
    }
    rep
}

pub fn explanations(s: &Snapshot, rep: &Report) -> (Explanation, Explanation) {
    let fid = |pid: i32, kind: FindingKind| {
        rep.findings
            .iter()
            .find(|f| f.kind == kind && f.targets[0].pid == pid)
            .unwrap()
            .id
            .clone()
    };
    let node = |pid: i32, name: &str, label: &str| ChainNode {
        target: r(pid, s),
        name: name.into(),
        label_ko: label.into(),
    };
    let launchd = node(1, "launchd", "macOS 시스템");
    let by_pid = Explanation {
        target: r(51234, s),
        chain: vec![
            node(51234, "codex", "codex app-server"),
            node(51230, "node", "npm exec"),
            launchd.clone(),
        ],
        kind: Kind::AgentHelper,
        label_ko: "AI 코딩 도구 서버".into(),
        project: Some("/Users/demo/dev/warmtalent-ai".into()),
        owner_ko: Some("Claude 세션(pid 33298)이 띄웠고 그 세션은 이미 종료됐어요".into()),
        finding_ids: vec![fid(51234, FindingKind::LogicalOrphan)],
        listeners: vec![],
        summary_ko: "Claude 세션이 끝난 뒤 남은 codex 서버예요. vh fix 로 정리할 수 있어요.".into(),
    };
    let by_port = Explanation {
        target: r(40112, s),
        chain: vec![node(40112, "node", "appium"), launchd],
        kind: Kind::TestTool,
        label_ko: "appium (모바일 앱 테스트 도구)".into(),
        project: Some("/Users/demo/dev/shop-app".into()),
        owner_ko: Some("띄운 터미널이 닫혀 시스템(launchd)이 맡고 있어요".into()),
        finding_ids: vec![
            fid(40112, FindingKind::Orphan),
            fid(40112, FindingKind::ExposedListener),
        ],
        listeners: vec![s.listeners[1].clone(), s.listeners[2].clone()],
        summary_ko: "테스트가 끝난 뒤 남은 appium이에요. 같은 와이파이의 다른 기기에서도 접속할 수 있으니, 쓰지 않으면 vh kill :4723 으로 끄세요.".into(),
    };
    (by_pid, by_port)
}

/// 합성 데이터 백엔드. 계획은 진짜 `vh_act::plan`, 실행은 가짜 세계(`FakeProber`·`FakeSignaler`).
pub struct Synth {
    pub snap: Snapshot,
    pub report: Report,
    pub exps: Vec<Explanation>,
    pub exec_calls: Cell<u32>,
    pub sent: RefCell<Vec<(i32, i32)>>,
    pub fail_exec: bool,
    pub state: tempfile::TempDir,
}

impl Synth {
    pub fn new() -> Self {
        let snap = snapshot();
        let report = report(&snap);
        let (a, b) = explanations(&snap, &report);
        Synth {
            snap,
            report,
            exps: vec![a, b],
            exec_calls: Cell::new(0),
            sent: RefCell::new(vec![]),
            fail_exec: false,
            state: tempfile::tempdir().expect("tempdir"),
        }
    }
}

impl Backend for Synth {
    fn collect(&self, _opts: &CollectOptions) -> Snapshot {
        self.snap.clone()
    }

    fn analyze(&self, _s: &Snapshot) -> Report {
        self.report.clone()
    }

    fn explain_pid(&self, _s: &Snapshot, _r: &Report, pid: i32) -> Option<Explanation> {
        self.exps.iter().find(|e| e.target.pid == pid).cloned()
    }

    fn explain_port(&self, _s: &Snapshot, _r: &Report, port: u16) -> Vec<Explanation> {
        self.exps
            .iter()
            .filter(|e| e.listeners.iter().any(|l| l.port == port))
            .cloned()
            .collect()
    }

    fn execute(&self, plan: &ActionPlan, s: &Snapshot) -> anyhow::Result<Executed> {
        self.exec_calls.set(self.exec_calls.get() + 1);
        if self.fail_exec {
            anyhow::bail!("상태 폴더를 준비하지 못했어요: 권한 없음");
        }
        let mut world = FakeWorld::default();
        for p in s
            .processes
            .iter()
            .filter(|p| p.status != ProcStatus::Zombie)
        {
            world.insert(LiveProc::alive(
                p.pid,
                p.start_time_unix_ms,
                p.ppid,
                p.uid,
                p.exe.as_deref(),
            ));
        }
        let world = world.shared();
        let mut prober = FakeProber::with_world(world.clone(), s.self_pid, s.self_uid);
        prober.ancestors = vec![89999, 1];
        prober.clock_ms.set(T0);
        let signaler = FakeSignaler::with_world(world);
        let env = ExecEnv {
            signaler: &signaler,
            prober: &prober,
            state_dir: self.state.path().to_path_buf(),
            snapshot: s,
            run_id: "test-run".into(),
        };
        let outcomes = vh_act::execute(plan, &env);
        self.sent
            .borrow_mut()
            .extend(signaler.sent.borrow().iter().copied());
        Ok(Executed {
            outcomes,
            state_dir: self.state.path().to_path_buf(),
        })
    }
}

pub struct Ran {
    pub code: i32,
    pub out: String,
    pub err: String,
}

/// `vh <args>`를 합성 백엔드로 실행. `tty`면 stdin·stdout·stderr 모두 터미널로 본다(색은 끔).
pub fn run(be: &Synth, args: &[&str], tty: bool, input: &str) -> Ran {
    let mut argv = vec!["vh".to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
    let code = {
        let mut io = Io {
            out: &mut out,
            err: &mut err,
            input: &mut inp,
            stdin_tty: tty,
            stdout_tty: tty,
            stderr_tty: tty,
            no_color_env: true,
        };
        app::run(&argv, &mut io, be)
    };
    Ran {
        code,
        out: String::from_utf8(out).expect("utf8"),
        err: String::from_utf8(err).expect("utf8"),
    }
}

pub fn lines(s: &str) -> Vec<&str> {
    s.lines().collect()
}
