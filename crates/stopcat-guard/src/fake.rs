//! 테스트용 가짜(커널 호출 0회). 전부 `Send`(Arc<Mutex<…>>)라 스레드 테스트에도 쓴다.
//! 계획·실행은 진짜 `stopcat_act::plan`/`plan_priority`/`execute`를 가짜 prober·signaler로 부른다 →
//! 보호 규칙·신호 직전 확인이 실제로 돈다.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use stopcat_act::{
    ExecEnv, FakeWorld, LiveProc, Liveness, Policy, PriorityTarget, Prober, Selection, Signaler,
};
use stopcat_model::{
    ActionOutcome, ActionPlan, Classified, Confidence, Finding, FindingKind, HealthLevel, Kind,
    OwnerState, Proc, ProcRef, ProcStatus, Report, Section, Snapshot, Suggestion, Usage,
    UsageReason, UsageState,
};

use crate::backend::GuardBackend;
use crate::snap::{bare_report, bare_snapshot};

/// 가짜 시계(밀리초).
#[derive(Debug, Clone, Default)]
pub struct FakeClock(pub Arc<AtomicU64>);

impl FakeClock {
    pub fn at(ms: u64) -> Self {
        FakeClock(Arc::new(AtomicU64::new(ms)))
    }

    pub fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

/// stopcat-act `FakeWorld`를 스레드에서도 쓸 수 있게 감싼 것.
#[derive(Debug, Clone, Default)]
pub struct SyncWorld(pub Arc<Mutex<FakeWorld>>);

impl SyncWorld {
    pub fn new(world: FakeWorld) -> Self {
        SyncWorld(Arc::new(Mutex::new(world)))
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut FakeWorld) -> T) -> T {
        let mut w = self.0.lock().expect("가짜 세계 잠금");
        f(&mut w)
    }

    pub fn alive(&self, r: ProcRef) -> bool {
        self.with(|w| {
            w.procs.get(&r.pid).is_some_and(|p| {
                p.liveness == Liveness::Alive && p.start_time_unix_ms == r.start_time_unix_ms
            })
        })
    }

    pub fn bg_of(&self, pid: i32) -> Option<i32> {
        self.with(|w| w.bg.get(&pid).copied())
    }
}

/// 스냅샷의 프로세스를 가짜 세계에 넣는다(uid·ppid·start_time·exe 그대로).
pub fn world_from_snapshot(s: &Snapshot) -> FakeWorld {
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

/// 가짜 세계를 읽는 prober(Send). `sleep_ms`는 시계만 전진.
#[derive(Debug, Clone)]
pub struct SyncProber {
    pub world: SyncWorld,
    pub self_pid: i32,
    pub self_uid: u32,
    pub ancestors: Vec<i32>,
    pub clock: FakeClock,
}

impl Prober for SyncProber {
    fn probe(&self, pid: i32) -> LiveProc {
        self.world.with(|w| {
            w.procs
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| LiveProc::gone(pid))
        })
    }

    fn children(&self, pid: i32) -> Vec<i32> {
        self.world.with(|w| {
            w.children
                .get(&pid)
                .map(|kids| {
                    kids.iter()
                        .copied()
                        .filter(|k| w.procs.contains_key(k))
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    fn self_pid(&self) -> i32 {
        self.self_pid
    }

    fn self_uid(&self) -> u32 {
        self.self_uid
    }

    fn ancestors_of_self(&self) -> Vec<i32> {
        self.ancestors.clone()
    }

    fn get_bg(&self, pid: i32) -> Result<i32, i32> {
        self.world.with(|w| {
            if !w.procs.contains_key(&pid) {
                return Err(libc::ESRCH);
            }
            Ok(w.bg.get(&pid).copied().unwrap_or(0))
        })
    }

    fn now_unix_ms(&self) -> u64 {
        self.clock.now()
    }

    fn sleep_ms(&self, ms: u64) {
        self.clock.advance(ms);
    }
}

/// 신호 기록(스레드 밖에서 읽는다).
#[derive(Debug, Clone, Default)]
pub struct SignalLog {
    pub sent: Arc<Mutex<Vec<(i32, i32)>>>,
    pub demoted: Arc<Mutex<Vec<i32>>>,
    pub undemoted: Arc<Mutex<Vec<i32>>>,
}

impl SignalLog {
    pub fn sent(&self) -> Vec<(i32, i32)> {
        self.sent.lock().unwrap().clone()
    }

    pub fn demoted(&self) -> Vec<i32> {
        self.demoted.lock().unwrap().clone()
    }

    pub fn undemoted(&self) -> Vec<i32> {
        self.undemoted.lock().unwrap().clone()
    }

    pub fn calls(&self) -> usize {
        self.sent().len() + self.demoted().len() + self.undemoted().len()
    }
}

/// 가짜 세계에 신호 효과를 반영하는 signaler(Send).
#[derive(Debug, Clone)]
pub struct SyncSignaler {
    pub world: SyncWorld,
    pub log: SignalLog,
    pub fail_with: Option<i32>,
}

impl Signaler for SyncSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        self.log.sent.lock().unwrap().push((pid, sig));
        if let Some(e) = self.fail_with {
            return Err(e);
        }
        self.world.with(|w| {
            if !w.procs.contains_key(&pid) {
                return Err(libc::ESRCH);
            }
            match sig {
                libc::SIGCONT => {
                    if let Some(p) = w.procs.get_mut(&pid) {
                        p.stopped = false;
                    }
                }
                libc::SIGTERM => {
                    for kid in w.spawn_on_term.remove(&pid).unwrap_or_default() {
                        w.insert(kid);
                    }
                    if !w.ignore_term.contains(&pid) {
                        w.remove(pid);
                    }
                }
                libc::SIGKILL => w.remove(pid),
                _ => return Err(libc::EINVAL),
            }
            Ok(())
        })
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        self.log.demoted.lock().unwrap().push(pid);
        if let Some(e) = self.fail_with {
            return Err(e);
        }
        self.world.with(|w| {
            if !w.procs.contains_key(&pid) {
                return Err(libc::ESRCH);
            }
            w.bg.insert(pid, libc::PRIO_DARWIN_BG);
            Ok(())
        })
    }

    fn undemote(&self, pid: i32) -> Result<(), i32> {
        self.log.undemoted.lock().unwrap().push(pid);
        if let Some(e) = self.fail_with {
            return Err(e);
        }
        self.world.with(|w| {
            if !w.procs.contains_key(&pid) {
                return Err(libc::ESRCH);
            }
            w.bg.remove(&pid);
            Ok(())
        })
    }
}

/// 스레드 밖에서 보는 창(백엔드를 엔진에 넘기기 전에 복제해 둔다).
#[derive(Clone)]
pub struct Probe {
    pub clock: FakeClock,
    pub world: SyncWorld,
    pub log: SignalLog,
    pub notifications: Arc<Mutex<Vec<(String, String)>>>,
    pub executed: Arc<Mutex<Vec<ActionOutcome>>>,
    pub collect_error: Arc<Mutex<Option<String>>>,
    pub collect_panic: Arc<Mutex<bool>>,
    pub collects: Arc<AtomicU64>,
    pub state_dir: PathBuf,
    /// `GuardBackend::forced_health`가 돌려주는 값(스캔 사이에 바꿀 수 있다).
    pub forced_health: Arc<Mutex<Option<HealthLevel>>>,
}

impl Probe {
    pub fn notifications(&self) -> Vec<(String, String)> {
        self.notifications.lock().unwrap().clone()
    }

    pub fn executed(&self) -> Vec<ActionOutcome> {
        self.executed.lock().unwrap().clone()
    }

    pub fn collects(&self) -> u64 {
        self.collects.load(Ordering::SeqCst)
    }

    pub fn set_collect_error(&self, e: Option<&str>) {
        *self.collect_error.lock().unwrap() = e.map(str::to_string);
    }

    pub fn set_collect_panic(&self, on: bool) {
        *self.collect_panic.lock().unwrap() = on;
    }

    pub fn set_forced_health(&self, h: Option<HealthLevel>) {
        *self.forced_health.lock().unwrap() = h;
    }
}

/// 가짜 백엔드. 대본(스냅샷·리포트 쌍)을 차례로 내고, 마지막 것은 반복한다.
/// 수집 때 가짜 세계에서 사라진 프로세스는 스냅샷에서도 뺀다. `cpu_rate_pct`가 있는 pid는
/// 시계 기준으로 `cpu_time_ns`를 채운다(연속 스캔 CPU% 검증용).
pub struct FakeGuardBackend {
    pub script: VecDeque<(Snapshot, Report)>,
    pub cpu_rate_pct: HashMap<i32, f32>,
    pub self_pid: i32,
    pub self_uid: u32,
    pub ancestors: Vec<i32>,
    pub prober: Box<dyn Prober + Send>,
    pub signaler: Box<dyn Signaler + Send>,
    pub use_real_analyze: bool,
    probe: Probe,
    _dir: tempfile::TempDir,
}

impl FakeGuardBackend {
    /// 대본으로 만든다. 첫 스냅샷의 프로세스로 가짜 세계를 채운다.
    pub fn scripted(script: Vec<(Snapshot, Report)>, clock: FakeClock) -> Self {
        let first = script.first().map(|(s, _)| s.clone());
        let (self_pid, self_uid) = first
            .as_ref()
            .map(|s| (s.self_pid, s.self_uid))
            .unwrap_or((4_000_000, 501));
        let world = SyncWorld::new(first.as_ref().map(world_from_snapshot).unwrap_or_default());
        let log = SignalLog::default();
        let dir = tempfile::tempdir().expect("임시 상태 폴더");
        let probe = Probe {
            clock: clock.clone(),
            world: world.clone(),
            log: log.clone(),
            notifications: Arc::default(),
            executed: Arc::default(),
            collect_error: Arc::default(),
            collect_panic: Arc::new(Mutex::new(false)),
            collects: Arc::default(),
            state_dir: dir.path().to_path_buf(),
            forced_health: Arc::default(),
        };
        let prober = SyncProber {
            world: world.clone(),
            self_pid,
            self_uid,
            ancestors: Vec::new(),
            clock,
        };
        let signaler = SyncSignaler {
            world,
            log,
            fail_with: None,
        };
        FakeGuardBackend {
            script: script.into_iter().collect(),
            cpu_rate_pct: HashMap::new(),
            self_pid,
            self_uid,
            ancestors: Vec::new(),
            prober: Box::new(prober),
            signaler: Box::new(signaler),
            use_real_analyze: false,
            probe,
            _dir: dir,
        }
    }

    /// 진짜 커널(RealProber)과 주입한 signaler로 실행하는 변형(자기 자식 실제 신호 테스트용).
    /// 대본 스냅샷은 그대로 쓰되 가짜 세계 필터는 적용하지 않는다.
    pub fn with_kernel(
        mut self,
        prober: Box<dyn Prober + Send>,
        signaler: Box<dyn Signaler + Send>,
    ) -> Self {
        self.prober = prober;
        self.signaler = signaler;
        self.use_real_analyze = false;
        self.probe.world = SyncWorld::new(FakeWorld::default());
        self
    }

    pub fn probe(&self) -> Probe {
        self.probe.clone()
    }

    pub fn push_script(&mut self, s: Snapshot, r: Report) {
        self.script.push_back((s, r));
    }

    fn filter_by_world(&self, s: &mut Snapshot, r: &mut Report) {
        let world = &self.probe.world;
        let any = world.with(|w| !w.procs.is_empty());
        if !any {
            return;
        }
        s.processes.retain(|p| {
            world.alive(ProcRef {
                pid: p.pid,
                start_time_unix_ms: p.start_time_unix_ms,
            })
        });
        let alive: Vec<ProcRef> = s.processes.iter().map(pref).collect();
        r.classified.retain(|c| alive.contains(&c.target));
        for f in &mut r.findings {
            f.targets.retain(|t| alive.contains(t));
        }
        r.findings.retain(|f| !f.targets.is_empty());
    }
}

impl GuardBackend for FakeGuardBackend {
    fn collect(&mut self) -> Result<Snapshot, String> {
        self.probe.collects.fetch_add(1, Ordering::SeqCst);
        if *self.probe.collect_panic.lock().unwrap() {
            panic!("가짜 수집 패닉(테스트)");
        }
        if let Some(e) = self.probe.collect_error.lock().unwrap().clone() {
            return Err(e);
        }
        let (mut s, mut r) = if self.script.len() > 1 {
            self.script.pop_front().expect("대본")
        } else {
            self.script.front().cloned().unwrap_or_else(|| {
                let now = self.probe.clock.now();
                (
                    bare_snapshot(self.self_pid, self.self_uid, now),
                    bare_report(now, Vec::new()),
                )
            })
        };
        let now = self.probe.clock.now();
        s.taken_at_unix_ms = now;
        self.filter_by_world(&mut s, &mut r);
        for p in &mut s.processes {
            if let Some(rate) = self.cpu_rate_pct.get(&p.pid) {
                let alive_ms = now.saturating_sub(p.start_time_unix_ms) as f64;
                p.cpu_time_ns = Some((alive_ms * 1_000_000.0 * f64::from(*rate) / 100.0) as u64);
            }
        }
        if self.script.len() <= 1 {
            self.script.clear();
            self.script.push_back((s.clone(), r));
            return Ok(s);
        }
        Ok(s)
    }

    fn analyze(&mut self, s: &Snapshot) -> Report {
        if self.use_real_analyze {
            return stopcat_analyze::analyze(s);
        }
        self.script
            .front()
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| bare_report(s.taken_at_unix_ms, Vec::new()))
    }

    fn plan(&mut self, s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
        stopcat_act::plan(s, r, sel, policy)
    }

    fn plan_priority(
        &mut self,
        s: &Snapshot,
        r: Option<&Report>,
        targets: &[PriorityTarget],
        policy: &Policy,
    ) -> ActionPlan {
        stopcat_act::plan_priority(s, r, targets, policy)
    }

    fn execute(&mut self, plan: &ActionPlan, s: &Snapshot, run_id: &str) -> Vec<ActionOutcome> {
        let env = ExecEnv {
            signaler: &*self.signaler,
            prober: &*self.prober,
            state_dir: self.probe.state_dir.clone(),
            snapshot: s,
            run_id: run_id.to_string(),
        };
        let out = stopcat_act::execute(plan, &env);
        self.probe.executed.lock().unwrap().extend(out.clone());
        out
    }

    fn notify(&mut self, title: &str, body: &str) -> Result<(), String> {
        self.probe
            .notifications
            .lock()
            .unwrap()
            .push((title.to_string(), body.to_string()));
        Ok(())
    }

    fn now_unix_ms(&self) -> u64 {
        self.probe.clock.now()
    }

    fn state_dir(&self) -> &Path {
        &self.probe.state_dir
    }

    fn forced_health(&self) -> Option<HealthLevel> {
        *self.probe.forced_health.lock().unwrap()
    }
}

pub fn pref(p: &Proc) -> ProcRef {
    ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    }
}

/// 합성 프로세스(자기 uid, exe는 사용자 경로).
pub fn proc_(pid: i32, ppid: i32, uid: u32, start_time_unix_ms: u64, name: &str) -> Proc {
    Proc {
        pid,
        ppid,
        pgid: pid,
        uid,
        start_time_unix_ms,
        name: name.to_string(),
        exe: Some(format!("/opt/homebrew/bin/{name}")),
        argv: vec![name.to_string()],
        argv_readable: true,
        env: BTreeMap::new(),
        env_readable: true,
        cwd: None,
        status: ProcStatus::Sleeping,
        has_tty: false,
        footprint_bytes: Some(100 * 1024 * 1024),
        rss_bytes: Some(100 * 1024 * 1024),
        cpu_time_ns: Some(0),
        cpu_pct: None,
        threads: Some(1),
        nice: Some(0),
        translated: false,
        tcp: None,
        disk_read_bytes: None,
        disk_written_bytes: None,
        disk_io_delta_bytes: None,
    }
}

pub fn snapshot(self_pid: i32, self_uid: u32, now: u64, processes: Vec<Proc>) -> Snapshot {
    let mut s = bare_snapshot(self_pid, self_uid, now);
    s.processes = processes;
    s
}

pub fn classified(
    target: ProcRef,
    kind: Kind,
    label: &str,
    owner_alive: Option<bool>,
) -> Classified {
    Classified {
        target,
        kind,
        label_ko: label.to_string(),
        signature_id: None,
        project: None,
        owner_session: None,
        owner_pid: None,
        owner_source: None,
        owner_label_ko: None,
        owner_alive,
        usage: fixture_usage(owner_alive),
    }
}

/// 합성 분류의 사용 판정: 연결·CPU·디스크 없음(Idle). stopcat-analyze처럼 주인 생존은 Idle을 바꾸지 않고
/// 근거(`owner_alive`)와 주인 상태로만 남는다(구역은 working·check가 되는 쪽).
pub fn fixture_usage(owner_alive: Option<bool>) -> Usage {
    let (owner, mut reasons) = match owner_alive {
        Some(true) => (OwnerState::Alive, vec![UsageReason::OwnerAlive]),
        Some(false) => (OwnerState::Ended, Vec::new()),
        None => (OwnerState::Unknown, Vec::new()),
    };
    reasons.extend([
        UsageReason::NoPeers,
        UsageReason::CpuIdle,
        UsageReason::DiskIdle,
    ]);
    Usage {
        state: UsageState::Idle,
        owner,
        reasons,
        ..Usage::default()
    }
}

pub fn finding(
    id: &str,
    kind: FindingKind,
    confidence: Confidence,
    targets: Vec<ProcRef>,
    suggestion: Suggestion,
    reclaim_bytes: u64,
) -> Finding {
    Finding {
        id: id.to_string(),
        kind,
        confidence,
        targets,
        title_ko: id.to_string(),
        short_ko: id.to_string(),
        detail_ko: String::new(),
        reason_codes: Vec::new(),
        reclaim_bytes,
        descendant_count: 0,
        suggestion,
        section: Section::Check,
    }
}

pub fn report(now: u64, classified: Vec<Classified>, findings: Vec<Finding>) -> Report {
    let mut r = bare_report(now, classified);
    r.findings = findings;
    r
}
