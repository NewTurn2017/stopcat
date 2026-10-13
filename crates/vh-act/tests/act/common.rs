//! 테스트 공용: 합성 스냅샷·리포트, 자기 자식 하네스, 허용 pid만 통과시키는 signaler.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use vh_act::{
    AuditEntry, FakeWorld, LiveProc, Liveness, Prober, RealProber, RealSignaler, Signaler,
    audit_log_path,
};
use vh_model::*;

pub const SELF_PID: i32 = 500;
pub const SELF_UID: u32 = 501;

pub fn pref(pid: i32, start: u64) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: start,
    }
}

pub fn proc_(pid: i32, ppid: i32, uid: u32, start: u64, exe: Option<&str>) -> Proc {
    Proc {
        pid,
        ppid,
        pgid: pid,
        uid,
        start_time_unix_ms: start,
        name: exe
            .and_then(|e| e.rsplit('/').next())
            .unwrap_or("x")
            .to_string(),
        exe: exe.map(str::to_string),
        argv: exe.map(|e| vec![e.to_string()]).unwrap_or_default(),
        argv_readable: true,
        env: BTreeMap::new(),
        env_readable: true,
        cwd: Some("/Users/demo/dev/shop".to_string()),
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(1_000_000),
        rss_bytes: None,
        cpu_time_ns: None,
        cpu_pct: None,
        threads: None,
        nice: None,
        translated: false,
    }
}

pub fn snapshot(self_pid: i32, self_uid: u32, processes: Vec<Proc>) -> Snapshot {
    Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: 1_000_000,
        host: HostInfo {
            model: "Mac".into(),
            os_version: "26.0".into(),
            arch: "arm64".into(),
            ncpu: 8,
            perf_cores: None,
            eff_cores: None,
            mem_total_bytes: 0,
            boot_time_unix_ms: 0,
            loadavg: [0.0; 3],
            home_dir: "/Users/demo".into(),
        },
        memory: MemoryInfo {
            pressure_level: 1,
            page_size: 16384,
            free_bytes: 0,
            active_bytes: 0,
            inactive_bytes: 0,
            speculative_bytes: 0,
            wired_bytes: 0,
            compressor_bytes: 0,
            compressed_logical_bytes: 0,
            purgeable_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            swapins: 0,
            swapouts: 0,
        },
        limits: LimitsInfo {
            maxproc: 0,
            maxprocperuid: 0,
            maxfiles: 0,
            maxfilesperproc: 0,
            num_files: 0,
            user_proc_count: 0,
            total_proc_count: 0,
        },
        processes,
        listeners: Vec::new(),
        launchd_job_pids: Vec::new(),
        launchd_job_labels: BTreeMap::new(),
        project_roots: BTreeMap::new(),
        self_pid,
        self_uid,
        cpu_sample_interval_ms: None,
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

pub fn classified(target: ProcRef, kind: Kind) -> Classified {
    Classified {
        target,
        kind,
        label_ko: "합성".into(),
        signature_id: None,
        project: None,
        owner_session: None,
        owner_pid: None,
        owner_source: None,
        owner_label_ko: None,
        owner_alive: None,
    }
}

pub fn finding(
    id: &str,
    confidence: Confidence,
    targets: Vec<ProcRef>,
    suggestion: Suggestion,
) -> Finding {
    Finding {
        id: id.into(),
        kind: FindingKind::Orphan,
        confidence,
        targets,
        title_ko: format!("합성 발견 {id}"),
        short_ko: id.into(),
        detail_ko: String::new(),
        reason_codes: Vec::new(),
        reclaim_bytes: 0,
        descendant_count: 0,
        suggestion,
    }
}

pub fn report(classified: Vec<Classified>, findings: Vec<Finding>) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: 1_000_000,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: String::new(),
            reasons_ko: Vec::new(),
        },
        classified,
        groups: Vec::new(),
        findings,
        listeners: Vec::new(),
        totals: Totals {
            reclaimable_confirmed_bytes: 0,
            reclaimable_likely_bytes: 0,
        },
    }
}

/// 스냅샷 프로세스를 그대로 살아 있는 가짜 세계로 옮긴다.
pub fn world_from(s: &Snapshot) -> FakeWorld {
    let mut w = FakeWorld::default();
    for p in &s.processes {
        let mut live =
            LiveProc::alive(p.pid, p.start_time_unix_ms, p.ppid, p.uid, p.exe.as_deref());
        live.stopped = p.status == ProcStatus::Stopped;
        if p.status == ProcStatus::Zombie {
            live.liveness = Liveness::Zombie;
        }
        w.insert(live);
    }
    w
}

/// 진짜 signaler 앞에서 허용 pid(이 테스트가 띄운 자식과 그 자손)만 통과시킨다.
#[derive(Default)]
pub struct GuardedSignaler {
    pub allowed: RefCell<BTreeSet<i32>>,
    pub sent: RefCell<Vec<(i32, i32)>>,
    pub demoted: RefCell<Vec<i32>>,
    pub violations: RefCell<Vec<i32>>,
}

impl GuardedSignaler {
    pub fn allowing(pids: impl IntoIterator<Item = i32>) -> Self {
        let g = GuardedSignaler::default();
        g.allowed.borrow_mut().extend(pids);
        g
    }

    fn permit(&self, pid: i32) -> bool {
        let ok = self.allowed.borrow().contains(&pid);
        if !ok {
            self.violations.borrow_mut().push(pid);
        }
        ok
    }
}

impl Signaler for GuardedSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        self.sent.borrow_mut().push((pid, sig));
        if !self.permit(pid) {
            return Err(libc::EPERM);
        }
        RealSignaler.send(pid, sig)
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        self.demoted.borrow_mut().push(pid);
        if !self.permit(pid) {
            return Err(libc::EPERM);
        }
        RealSignaler.demote(pid)
    }
}

/// 이 테스트가 띄운 자식. Drop에서 start_time이 같을 때만 SIGKILL 뒤 회수한다(패닉해도 남지 않게).
pub struct OwnedChild {
    pub child: Child,
    pub r: ProcRef,
    pub extra: Vec<ProcRef>,
    pub argv: Vec<String>,
    lines: Receiver<String>,
}

impl OwnedChild {
    pub fn spawn(argv: &[&str]) -> OwnedChild {
        let mut child = Command::new(argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("자식 실행");
        let pid = child.id() as i32;
        let start = RealProber.probe(pid).start_time_unix_ms;
        let out = child.stdout.take().expect("stdout");
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        OwnedChild {
            child,
            r: pref(pid, start),
            extra: Vec::new(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            lines: rx,
        }
    }

    pub fn pid(&self) -> i32 {
        self.r.pid
    }

    /// stdout 한 줄을 기다린다(최대 10초).
    pub fn line(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .expect("자식이 10초 안에 한 줄을 내지 않음")
    }

    /// 지금 자손(커널 열거)을 extra에 기록하고 돌려준다.
    pub fn record_descendants(&mut self) -> Vec<ProcRef> {
        let mut q = vec![self.pid()];
        while let Some(p) = q.pop() {
            for c in RealProber.children(p) {
                let live = RealProber.probe(c);
                if live.liveness == Liveness::Alive {
                    self.extra.push(pref(c, live.start_time_unix_ms));
                    q.push(c);
                }
            }
        }
        self.extra.clone()
    }

    /// 테스트가 직접 끝내고 회수한다(이미 끝난 대상 시나리오).
    pub fn kill_and_reap(&mut self) {
        // SAFETY: 방금 띄운 자기 자식이다.
        unsafe { libc::kill(self.pid(), libc::SIGKILL) };
        self.child.wait().expect("자식 회수");
    }

    pub fn all_pids(&self) -> Vec<i32> {
        self.extra
            .iter()
            .map(|r| r.pid)
            .chain([self.pid()])
            .collect()
    }

    /// 스냅샷에 넣을 Proc(실제 커널 값 + 이 하네스가 아는 argv).
    pub fn proc_of(&self, r: ProcRef, argv: Vec<String>) -> Proc {
        let live = RealProber.probe(r.pid);
        let mut p = proc_(
            r.pid,
            live.ppid,
            live.uid,
            r.start_time_unix_ms,
            live.exe.as_deref(),
        );
        p.pgid = live.pgid;
        p.argv = argv;
        p.status = if live.stopped {
            ProcStatus::Stopped
        } else {
            ProcStatus::Sleeping
        };
        p
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        for r in self.extra.iter().chain([&self.r]) {
            let live = RealProber.probe(r.pid);
            if live.liveness == Liveness::Alive && live.start_time_unix_ms == r.start_time_unix_ms {
                // SAFETY: 이 테스트가 띄운 자식(또는 그 자손)이고 start_time이 같음을 방금 확인했다.
                unsafe { libc::kill(r.pid, libc::SIGKILL) };
            }
        }
        let _ = self.child.wait();
    }
}

/// 대상 task의 기본 우선순위(`proc_pidinfo(PROC_PIDTASKINFO).pti_priority`). DARWIN_BG면 4(MAXPRI_THROTTLE).
pub fn task_priority(pid: i32) -> Option<i32> {
    // SAFETY: proc_taskinfo는 정수 필드뿐인 C 구조체라 0으로 채워도 유효하다.
    let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: ti는 size 바이트 쓰기 가능한 읽기 전용 조회.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut ti as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    (n == size).then_some(ti.pti_priority)
}

/// 실제 커널에서 종료(없음·좀비·재사용)인지.
pub fn is_gone(r: ProcRef) -> bool {
    let live = RealProber.probe(r.pid);
    live.liveness != Liveness::Alive || live.start_time_unix_ms != r.start_time_unix_ms
}

pub fn self_snapshot(processes: Vec<Proc>) -> Snapshot {
    snapshot(RealProber.self_pid(), RealProber.self_uid(), processes)
}

pub fn read_audit(dir: &Path) -> Vec<AuditEntry> {
    match std::fs::read_to_string(audit_log_path(dir)) {
        Ok(s) => s
            .lines()
            .map(|l| serde_json::from_str(l).expect("감사 로그 한 줄 파싱"))
            .collect(),
        Err(_) => Vec::new(),
    }
}
