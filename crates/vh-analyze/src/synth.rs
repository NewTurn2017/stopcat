//! 합성 스냅샷 생성기(feature `synth`, 테스트·벤치 전용). 이름·경로는 모두 합성이고 결과는 seed로 결정된다.

use std::collections::BTreeMap;

use vh_model::{
    Family, HostInfo, LimitsInfo, Listener, MemoryInfo, Proc, ProcStatus, SCHEMA_VERSION, Snapshot,
    Timings,
};

const HOME_DIR: &str = "/Users/demo/";
const NODE: &str = "/Users/demo/.local/share/fnm/node-versions/v24.0.0/installation/bin/node";
const T: u64 = 1_791_900_000_000;
const MIB: u64 = 1024 * 1024;
const HOUR: u64 = 3_600_000;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

struct B {
    rng: Lcg,
    procs: Vec<Proc>,
    listeners: Vec<Listener>,
    jobs: Vec<i32>,
    next_pid: i32,
}

impl B {
    fn add(&mut self, ppid: i32, exe: &str, argv: &[&str], cwd: Option<&str>, uid: u32) -> i32 {
        let pid = self.next_pid;
        self.next_pid += 1;
        let age = HOUR / 2 + self.rng.below(72) * HOUR;
        let parent_start = self
            .procs
            .iter()
            .rev()
            .find(|p| p.pid == ppid)
            .map_or(0, |p| p.start_time_unix_ms);
        let start = (T - age).max(parent_start + 1000);
        let fp = (5 + self.rng.below(400)) * MIB;
        let cpu = (self.rng.below(50) == 0).then(|| 100.0 + self.rng.below(100) as f32);
        self.procs.push(Proc {
            pid,
            ppid,
            pgid: pid,
            uid,
            start_time_unix_ms: start,
            name: exe
                .rsplit('/')
                .next()
                .unwrap_or(exe)
                .chars()
                .take(32)
                .collect(),
            exe: Some(exe.to_string()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            argv_readable: uid == 501,
            env: BTreeMap::new(),
            env_readable: uid == 501,
            cwd: cwd.map(str::to_string),
            status: ProcStatus::Sleeping,
            has_tty: false,
            footprint_bytes: Some(fp),
            rss_bytes: Some(fp / 2),
            cpu_time_ns: Some(1_000_000),
            cpu_pct: Some(cpu.unwrap_or(self.rng.below(20) as f32)),
            threads: Some(4),
            nice: Some(0),
            translated: false,
            tcp: Some(vh_model::TcpSummary::default()),
            disk_read_bytes: Some(0),
            disk_written_bytes: Some(0),
            disk_io_delta_bytes: Some(0),
        });
        pid
    }

    fn listen(&mut self, pid: i32, port: u16, all: bool) {
        let start = self
            .procs
            .iter()
            .find(|p| p.pid == pid)
            .map_or(0, |p| p.start_time_unix_ms);
        self.listeners.push(Listener {
            pid,
            start_time_unix_ms: start,
            family: Family::V4,
            local_addr: if all { "0.0.0.0" } else { "127.0.0.1" }.to_string(),
            port,
            all_interfaces: all,
            loopback: !all,
            dual_stack: false,
        });
    }
}

/// `n`개 프로세스(대략 실측 비율: 시스템 45%, 앱 25%, 에이전트 세션 6개, 개발 서버, 고아, 좀비)를 만든다.
pub fn synth_snapshot(n: usize, seed: u64) -> Snapshot {
    let mut b = B {
        rng: Lcg(seed ^ 0x9e37_79b9_7f4a_7c15),
        procs: Vec::with_capacity(n),
        listeners: Vec::new(),
        jobs: Vec::new(),
        next_pid: 100,
    };
    b.procs.push(Proc {
        pid: 1,
        ppid: 0,
        pgid: 1,
        uid: 0,
        start_time_unix_ms: T - 240 * HOUR,
        name: "launchd".into(),
        exe: Some("/sbin/launchd".into()),
        argv: vec!["/sbin/launchd".into()],
        argv_readable: false,
        env: BTreeMap::new(),
        env_readable: false,
        cwd: None,
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(20 * MIB),
        rss_bytes: Some(10 * MIB),
        cpu_time_ns: None,
        cpu_pct: None,
        threads: Some(4),
        nice: None,
        translated: false,
        tcp: Some(vh_model::TcpSummary::default()),
        disk_read_bytes: Some(0),
        disk_written_bytes: Some(0),
        disk_io_delta_bytes: Some(0),
    });
    let projects: Vec<String> = (0..50).map(|k| format!("{HOME_DIR}dev/p{k}")).collect();
    let mut roots = BTreeMap::new();
    for p in &projects {
        roots.insert(p.clone(), p.clone());
    }

    for k in 0..n * 45 / 100 {
        let (exe, uid) = if k % 2 == 0 {
            (format!("/usr/libexec/demosvc{k}"), 0)
        } else {
            (
                format!(
                    "/System/Library/PrivateFrameworks/D{k}.framework/XPCServices/S.xpc/Contents/MacOS/S"
                ),
                501,
            )
        };
        b.add(1, &exe, &[&exe], None, uid);
    }
    for a in 0..20 {
        let main = format!("/Applications/App{a}.app/Contents/MacOS/App{a}");
        let pid = b.add(1, &main, &[&main], None, 501);
        b.jobs.push(pid);
        let helper = format!(
            "/Applications/App{a}.app/Contents/Frameworks/App{a} Helper.app/Contents/MacOS/App{a} Helper"
        );
        for _ in 0..(n * 25 / 100 / 20).saturating_sub(1) {
            b.add(pid, &helper, &[&helper, "--type=renderer"], None, 501);
        }
    }
    let term = b.add(
        1,
        "/Applications/Term.app/Contents/MacOS/Term",
        &["Term"],
        None,
        501,
    );
    let shells: Vec<i32> = (0..10)
        .map(|k| b.add(term, "/bin/zsh", &["-zsh"], Some(&projects[k]), 501))
        .collect();

    for s in 0..6 {
        let cwd = projects[s].clone();
        let root = if s % 2 == 0 {
            b.add(
                shells[s],
                &format!("{HOME_DIR}.local/share/claude/versions/2.1.0"),
                &["claude"],
                Some(&cwd),
                501,
            )
        } else {
            b.add(
                shells[s],
                &format!("{HOME_DIR}.bun/bin/bun"),
                &[
                    "bun",
                    &format!(
                        "{HOME_DIR}.bun/install/global/node_modules/@demo/senpi/dist/bundle/cli.js"
                    ),
                ],
                Some(&cwd),
                501,
            )
        };
        let npm = b.add(
            root,
            NODE,
            &["npm exec chrome-devtools-mcp@1.9.0"],
            Some(&cwd),
            501,
        );
        let srv = b.add(npm, NODE, &["chrome-devtools-mcp"], Some(&cwd), 501);
        let flag = format!("--parent-pid={srv}");
        b.add(
            srv,
            NODE,
            &["node", &format!("{HOME_DIR}.npm/_npx/600081e5/node_modules/chrome-devtools-mcp/build/src/telemetry/watchdog/main.js"), &flag],
            Some(&cwd),
            501,
        );
        b.add(
            root,
            NODE,
            &[
                "node",
                &format!("{HOME_DIR}.npm/_npx/aa11/node_modules/.bin/xcodebuildmcp"),
                "mcp",
            ],
            Some(&cwd),
            501,
        );
        b.add(
            root,
            NODE,
            &[
                "node",
                &format!("{HOME_DIR}.npm/_npx/bb22/node_modules/.bin/convex"),
                "mcp",
                "start",
            ],
            Some(&cwd),
            501,
        );
        b.add(
            root,
            NODE,
            &[
                "node",
                &format!("{cwd}/node_modules/typescript/lib/tsserver.js"),
            ],
            Some(&cwd),
            501,
        );
        let kids = 10 + b.rng.below(30) as usize;
        for w in 0..kids {
            b.add(
                root,
                NODE,
                &["node", &format!("{cwd}/task-{w}.js")],
                Some(&cwd),
                501,
            );
        }
    }

    for d in 0..40 {
        let cwd = projects[d % projects.len()].clone();
        let shell = shells[d % shells.len()];
        let port = 3000 + d as u16;
        let ps = port.to_string();
        let pid = b.add(
            shell,
            NODE,
            &[
                "node",
                &format!("{cwd}/node_modules/.bin/next"),
                "dev",
                "--port",
                &ps,
            ],
            Some(&cwd),
            501,
        );
        b.listen(pid, port, d < 10);
    }
    for k in 0..12 {
        let cwd = projects[10 + k].clone();
        b.add(
            shells[k % shells.len()],
            NODE,
            &[
                "node",
                &format!("{cwd}/node_modules/typescript/lib/tsserver.js"),
            ],
            Some(&cwd),
            501,
        );
    }
    for k in 0..120 {
        let cwd = projects[20 + k % 30].clone();
        if k < 60 {
            let exe = format!("{HOME_DIR}dev/svc{k}/.venv/bin/python3");
            let pid = b.add(1, &exe, &["python3", "server.py"], Some(&cwd), 501);
            b.jobs.push(pid);
            b.listen(pid, 8000 + k as u16, k < 5);
        } else if k % 3 == 0 {
            let pid = b.add(
                1,
                NODE,
                &[
                    "node",
                    &format!("{HOME_DIR}.npm/_npx/0a/node_modules/.bin/appium"),
                    "--port",
                    &format!("{}", 4700 + k),
                ],
                Some(HOME_DIR),
                501,
            );
            b.listen(pid, 4700 + k as u16, false);
        } else if k % 3 == 1 {
            let exe = format!(
                "{HOME_DIR}.agent-browser/browsers/c{k}/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
            );
            b.add(1, &exe, &[&exe], None, 501);
        } else {
            b.add(
                1,
                NODE,
                &["node", &format!("{cwd}/server.js")],
                Some(&cwd),
                501,
            );
        }
    }
    let daemon = b.add(
        1,
        &format!("{HOME_DIR}.local/bin/demo-daemon"),
        &["demo-daemon"],
        None,
        501,
    );
    b.jobs.push(daemon);
    for _ in 0..20 {
        let z = b.add(daemon, "", &[], None, 501);
        if let Some(p) = b.procs.iter_mut().find(|p| p.pid == z) {
            p.status = ProcStatus::Zombie;
            p.exe = None;
            p.footprint_bytes = None;
        }
    }
    for k in 0..3 {
        let cwd = projects[k].clone();
        let z = b.add(
            shells[k],
            NODE,
            &["node", &format!("{cwd}/node_modules/.bin/vite")],
            Some(&cwd),
            501,
        );
        if let Some(p) = b.procs.iter_mut().find(|p| p.pid == z) {
            p.status = ProcStatus::Stopped;
        }
    }
    let mut k = 0usize;
    while b.procs.len() < n {
        let cwd = projects[k % projects.len()].clone();
        b.add(
            shells[k % shells.len()],
            NODE,
            &["node", &format!("{cwd}/worker-{k}.js")],
            Some(&cwd),
            501,
        );
        k += 1;
    }
    b.procs.truncate(n);
    let user = b.procs.iter().filter(|p| p.uid == 501).count() as u32;
    b.procs.sort_by_key(|p| p.pid);

    Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: T,
        host: HostInfo {
            model: "Mac17,6".into(),
            os_version: "27.0.1".into(),
            arch: "arm64".into(),
            ncpu: 18,
            perf_cores: Some(6),
            eff_cores: Some(12),
            mem_total_bytes: 128 * 1024 * MIB,
            boot_time_unix_ms: T - 300 * HOUR,
            loadavg: [5.8, 4.0, 3.5],
            home_dir: HOME_DIR.into(),
        },
        memory: MemoryInfo {
            pressure_level: 1,
            page_size: 16384,
            free_bytes: 2048 * MIB,
            active_bytes: 40 * 1024 * MIB,
            inactive_bytes: 30 * 1024 * MIB,
            speculative_bytes: 1024 * MIB,
            wired_bytes: 8 * 1024 * MIB,
            compressor_bytes: 41 * 1024 * MIB,
            compressed_logical_bytes: 120 * 1024 * MIB,
            purgeable_bytes: 512 * MIB,
            swap_total_bytes: 2048 * MIB,
            swap_used_bytes: 1600 * MIB,
            swapins: 100,
            swapouts: 200,
        },
        limits: LimitsInfo {
            maxproc: 4000,
            maxprocperuid: 2666,
            maxfiles: 245_760,
            maxfilesperproc: 122_880,
            num_files: 30_000,
            user_proc_count: user,
            total_proc_count: n as u32,
        },
        processes: b.procs,
        listeners: b.listeners,
        launchd_job_labels: b
            .jobs
            .iter()
            .map(|&p| (p, format!("com.demo.job{p}")))
            .collect(),
        launchd_job_pids: b.jobs,
        project_roots: roots,
        self_pid: 99_999,
        self_uid: 501,
        cpu_sample_interval_ms: Some(250),
        collection_errors: Vec::new(),
        timings_ms: Timings {
            list_ms: 0.0,
            procs_ms: 0.0,
            sockets_ms: 0.0,
            system_ms: 0.0,
            launchd_ms: 0.0,
            roots_ms: 0.0,
            cpu_wait_ms: 0.0,
            total_ms: 0.0,
        },
    }
}
