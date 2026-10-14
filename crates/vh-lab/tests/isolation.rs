use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vh_act::{Policy, PriorityTarget, Selection, Signaler};
use vh_guard::fake::{FakeClock, FakeGuardBackend, SyncSignaler, proc_, snapshot};
use vh_guard::{Engine, GuardBackend, GuardUpdate};
use vh_lab::scope::{ForcedHealth, LabScope, ScopedBackend};
use vh_lab::signal::RecordingSignaler;
use vh_model::{
    ActionOutcome, ActionPlan, AutoLevel, CollectionError, Family, GuardPolicy, HealthLevel,
    Listener, PlannedAction, Proc, ProcRef, Report, Snapshot, Step,
};

const SELF_PID: i32 = 4_000_000;
const UID: u32 = 501;
const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;
const TAG: &str = "lab-T-I";
/// 5초씩 감는 가짜 시계에서 둘째 스캔 + idle_confirm 120초 + 연속 2회를 넘기는 스캔 수.
const SCANS_PAST_IDLE_CONFIRM: usize = 40;

const FOREIGN_ORPHAN: i32 = 5001;
const FOREIGN_SPIN: i32 = 5002;
const LAB_ORPHAN: i32 = 6001;
const LAB_SPIN: i32 = 6002;

fn mcp(pid: i32, owner: i32, tag: Option<&str>) -> Proc {
    let mut p = proc_(pid, 1, UID, NOW - 2 * HOUR, "node");
    p.argv = vec![
        "node".into(),
        format!("/w/p{pid}/node_modules/chrome-devtools-mcp/build/src/index.js"),
    ];
    p.cwd = Some(format!("/w/p{pid}"));
    p.env.insert("CLAUDE_PID".into(), owner.to_string());
    if let Some(t) = tag {
        p.env.insert("VH_TAG".into(), t.into());
    }
    p.tcp = Some(Default::default());
    p.disk_read_bytes = Some(0);
    p.disk_written_bytes = Some(0);
    p
}

fn spinner(pid: i32, tag: Option<&str>) -> Proc {
    let mut p = proc_(pid, 900, UID, NOW - HOUR, "lab-spin");
    if let Some(t) = tag {
        p.env.insert("VH_TAG".into(), t.into());
    }
    p
}

fn world() -> Snapshot {
    snapshot(
        SELF_PID,
        UID,
        NOW,
        vec![
            mcp(FOREIGN_ORPHAN, 7777, None),
            spinner(FOREIGN_SPIN, None),
            mcp(LAB_ORPHAN, 7778, Some(TAG)),
            spinner(LAB_SPIN, Some(TAG)),
        ],
    )
}

fn backend(clock: &FakeClock) -> FakeGuardBackend {
    let s = world();
    let r = vh_analyze::analyze(&s);
    let mut b = FakeGuardBackend::scripted(vec![(s, r)], clock.clone());
    b.use_real_analyze = true;
    b.cpu_rate_pct.insert(FOREIGN_SPIN, 300.0);
    b.cpu_rate_pct.insert(LAB_SPIN, 300.0);
    b
}

fn scan_n<B: GuardBackend>(e: &mut Engine<B>, clock: &FakeClock, n: usize) -> Vec<GuardUpdate> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend(e.scan());
        clock.advance(5_000);
    }
    out
}

fn targets_in(updates: &[GuardUpdate]) -> BTreeSet<i32> {
    let mut s = BTreeSet::new();
    for u in updates {
        s.extend(u.new_events.iter().filter_map(|e| e.target).map(|t| t.pid));
        s.extend(u.status.pending.iter().map(|p| p.target.pid));
        s.extend(u.status.demoted.iter().map(|d| d.target.pid));
        s.extend(u.snapshot.processes.iter().map(|p| p.pid));
    }
    s
}

#[test]
fn t_iso_1_control_reaches_foreign_scoped_does_not() {
    let clock = FakeClock::at(NOW);
    let b = backend(&clock);
    let probe = b.probe();
    probe.set_forced_health(Some(HealthLevel::Watch));
    let mut e = Engine::new(GuardPolicy::for_level(AutoLevel::Safe), b);
    let _ = scan_n(&mut e, &clock, SCANS_PAST_IDLE_CONFIRM);
    let sent = probe.log.sent();
    assert!(
        sent.iter()
            .any(|&(p, s)| p == FOREIGN_ORPHAN && s == libc::SIGTERM),
        "대조군: 범위 없이는(강제 불안정) 남의 고아에 TERM이 나가야 한다(테스트가 실패할 수 있음을 보임): {sent:?}"
    );
    assert!(
        probe.log.demoted().is_empty(),
        "W4: 자동 우선순위 낮추기 없음"
    );

    let clock = FakeClock::at(NOW);
    let mut b = backend(&clock);
    let probe = b.probe();
    let (rec, calls) = RecordingSignaler::new(
        Box::new(SyncSignaler {
            world: probe.world.clone(),
            log: probe.log.clone(),
            fail_with: None,
        }),
        BTreeSet::from([LAB_ORPHAN, LAB_SPIN]),
    );
    b.signaler = Box::new(rec);
    let scope = LabScope {
        tag: TAG.into(),
        refs: BTreeSet::new(),
    };
    let (scoped, log) = ScopedBackend::new(b, scope, None);
    let scoped = scoped.with_forced(ForcedHealth::new(Some(HealthLevel::Watch), NOW));
    let mut e = Engine::new(GuardPolicy::for_level(AutoLevel::Safe), scoped);
    let ups = scan_n(&mut e, &clock, SCANS_PAST_IDLE_CONFIRM);
    let (shutdown, _) = e.restore_all();

    let seen = targets_in(&ups);
    assert!(
        !seen.contains(&FOREIGN_ORPHAN) && !seen.contains(&FOREIGN_SPIN),
        "{seen:?}"
    );
    let sent = probe.log.sent();
    assert!(sent.iter().all(|&(p, _)| p == LAB_ORPHAN), "{sent:?}");
    assert!(
        sent.iter()
            .any(|&(p, s)| p == LAB_ORPHAN && s == libc::SIGTERM)
    );
    assert!(
        probe.log.demoted().is_empty(),
        "W4: 실험실 폭주도 자동으로 낮추지 않음"
    );
    assert!(shutdown.undemoted.is_empty());
    let calls = calls.lock().unwrap();
    assert!(!calls.is_empty() && calls.iter().all(|c| c.allowed));
    assert!(calls.iter().all(|c| c.pid == LAB_ORPHAN && c.op == "send"));
    let log = log.lock().unwrap();
    assert!(log.violations.is_empty());
    assert!(
        log.scans
            .iter()
            .all(|s| s.stats.dropped == 2 || s.stats.total < 4)
    );
}

#[derive(Default, Clone)]
struct CountingSignaler(Arc<Mutex<Vec<(String, i32)>>>);

impl Signaler for CountingSignaler {
    fn send(&self, pid: i32, _sig: i32) -> Result<(), i32> {
        self.0.lock().unwrap().push(("send".into(), pid));
        Ok(())
    }
    fn demote(&self, pid: i32) -> Result<(), i32> {
        self.0.lock().unwrap().push(("demote".into(), pid));
        Ok(())
    }
    fn undemote(&self, pid: i32) -> Result<(), i32> {
        self.0.lock().unwrap().push(("undemote".into(), pid));
        Ok(())
    }
}

#[test]
fn t_iso_2_lock_blocks_unlisted_pid_and_records() {
    let inner = CountingSignaler::default();
    let (rec, log) = RecordingSignaler::new(Box::new(inner.clone()), BTreeSet::from([10]));
    assert_eq!(rec.send(11, libc::SIGTERM), Err(libc::EPERM));
    assert_eq!(rec.demote(11), Err(libc::EPERM));
    assert_eq!(rec.undemote(11), Err(libc::EPERM));
    assert!(inner.0.lock().unwrap().is_empty());
    assert_eq!(rec.send(10, libc::SIGTERM), Ok(()));
    assert_eq!(rec.undemote(10), Ok(()));
    assert_eq!(
        *inner.0.lock().unwrap(),
        vec![("send".to_string(), 10), ("undemote".to_string(), 10)]
    );
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 5);
    assert_eq!(log.iter().filter(|c| !c.allowed).count(), 3);
    assert!(
        log.iter()
            .filter(|c| !c.allowed)
            .all(|c| c.errno == Some(libc::EPERM))
    );
}

fn listener(pid: i32, st: u64) -> Listener {
    Listener {
        pid,
        start_time_unix_ms: st,
        family: Family::V4,
        local_addr: "127.0.0.1".into(),
        port: 4000,
        all_interfaces: false,
        loopback: true,
        dual_stack: false,
    }
}

#[test]
fn t_iso_3_pid_reuse_and_side_tables() {
    let registered = ProcRef {
        pid: 10,
        start_time_unix_ms: 1000,
    };
    let mut reg = proc_(10, 1, UID, 1000, "node");
    reg.cwd = Some("/w/a".into());
    let mut reused = proc_(11, 1, UID, 2000, "node");
    reused.pid = 10;
    reused.cwd = Some("/w/b".into());
    let other = proc_(12, 1, UID, 1000, "node");
    let mut s = snapshot(SELF_PID, UID, NOW, vec![reg, reused, other]);
    s.listeners = vec![listener(10, 1000), listener(10, 2000), listener(12, 1000)];
    s.launchd_job_pids = vec![10, 12];
    s.project_roots = BTreeMap::from([
        ("/w/a".to_string(), "/w/a".to_string()),
        ("/w/b".to_string(), "/w/b".to_string()),
    ]);
    s.collection_errors = vec![
        CollectionError {
            pid: Some(12),
            stage: "argv".into(),
            errno: Some(1),
            message: "x".into(),
        },
        CollectionError {
            pid: None,
            stage: "argv".into(),
            errno: None,
            message: "요약".into(),
        },
    ];
    let scope = LabScope {
        tag: TAG.into(),
        refs: BTreeSet::from([registered]),
    };
    let st = scope.retain(&mut s);
    assert_eq!(st.kept_refs, vec![registered]);
    assert_eq!(st.dropped, 2);
    assert_eq!(s.listeners.len(), 1);
    assert_eq!(s.listeners[0].start_time_unix_ms, 1000);
    assert_eq!(s.launchd_job_pids, vec![10]);
    assert_eq!(s.project_roots.keys().collect::<Vec<_>>(), vec!["/w/a"]);
    assert_eq!(s.collection_errors.len(), 1);
    assert!(s.collection_errors[0].pid.is_none());
}

#[test]
fn t_iso_4_tag_must_match_exactly() {
    let mk = |pid: i32, tag: Option<&str>, uid: u32| {
        let mut p = proc_(pid, 1, uid, 1000, "node");
        if let Some(t) = tag {
            p.env.insert("VH_TAG".into(), t.into());
        }
        p
    };
    let mut s = snapshot(
        SELF_PID,
        UID,
        NOW,
        vec![
            mk(1, Some(TAG), UID),
            mk(2, Some("lab-T-I2"), UID),
            mk(3, Some("lab-T"), UID),
            mk(4, Some("lab-X-I"), UID),
            mk(5, None, UID),
            mk(6, None, 0),
        ],
    );
    let scope = LabScope {
        tag: TAG.into(),
        refs: BTreeSet::new(),
    };
    let st = scope.retain(&mut s);
    assert_eq!(
        s.processes.iter().map(|p| p.pid).collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(st.unregistered_tagged, 1);
    assert_eq!(st.kept_registered, 0);
}

struct StubBackend {
    plan: ActionPlan,
    executed: Arc<Mutex<usize>>,
    dir: PathBuf,
}

impl GuardBackend for StubBackend {
    fn collect(&mut self) -> Result<Snapshot, String> {
        Ok(snapshot(SELF_PID, UID, NOW, vec![]))
    }
    fn analyze(&mut self, s: &Snapshot) -> Report {
        vh_analyze::analyze(s)
    }
    fn plan(&mut self, _: &Snapshot, _: &Report, _: &Selection, _: &Policy) -> ActionPlan {
        self.plan.clone()
    }
    fn plan_priority(
        &mut self,
        _: &Snapshot,
        _: Option<&Report>,
        _: &[PriorityTarget],
        _: &Policy,
    ) -> ActionPlan {
        self.plan.clone()
    }
    fn execute(&mut self, plan: &ActionPlan, _: &Snapshot, _: &str) -> Vec<ActionOutcome> {
        *self.executed.lock().unwrap() += plan.items.len();
        Vec::new()
    }
    fn notify(&mut self, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn now_unix_ms(&self) -> u64 {
        NOW
    }
    fn state_dir(&self) -> &Path {
        &self.dir
    }
}

#[test]
fn scoped_backend_drops_out_of_scope_plan_items_as_violations() {
    let foreign = ProcRef {
        pid: 77,
        start_time_unix_ms: 1,
    };
    let lab = ProcRef {
        pid: 88,
        start_time_unix_ms: 1,
    };
    let item = |t: ProcRef| PlannedAction {
        finding_id: "f".into(),
        target: t,
        include_descendants: false,
        descendant_count: 0,
        steps: vec![Step::Term],
        grace_ms: 0,
        reason_ko: String::new(),
        est_reclaim_bytes: 0,
    };
    let plan = ActionPlan {
        created_at_unix_ms: NOW,
        total_deadline_ms: 1000,
        items: vec![item(foreign), item(lab)],
        refused: vec![],
    };
    let executed = Arc::new(Mutex::new(0));
    let stub = StubBackend {
        plan: plan.clone(),
        executed: executed.clone(),
        dir: std::env::temp_dir(),
    };
    let scope = LabScope {
        tag: TAG.into(),
        refs: BTreeSet::from([lab]),
    };
    let (mut b, log) = ScopedBackend::new(stub, scope, None);
    let s = snapshot(SELF_PID, UID, NOW, vec![]);
    let r = vh_analyze::analyze(&s);
    let p = b.plan(&s, &r, &Selection::default(), &Policy::default());
    assert_eq!(
        p.items.iter().map(|i| i.target).collect::<Vec<_>>(),
        vec![lab]
    );
    let _ = b.execute(&plan, &s, "t");
    assert_eq!(*executed.lock().unwrap(), 1);
    let only_foreign = ActionPlan {
        items: vec![item(foreign)],
        ..plan
    };
    let _ = b.execute(&only_foreign, &s, "t");
    assert_eq!(*executed.lock().unwrap(), 1);
    let v = &log.lock().unwrap().violations;
    assert_eq!(v.len(), 3);
    assert!(v.iter().all(|x| x.target == foreign));
}

#[test]
fn forced_health_is_per_cell_switchable_and_reaches_the_engine() {
    let clock = FakeClock::at(NOW);
    let scope = LabScope {
        tag: TAG.into(),
        refs: BTreeSet::new(),
    };
    let fa = ForcedHealth::new(Some(HealthLevel::Watch), NOW);
    let fb = ForcedHealth::default();
    let (a, _) = ScopedBackend::new(backend(&clock), scope.clone(), None);
    let a = a.with_forced(fa.clone());
    let (b, _) = ScopedBackend::new(backend(&clock), scope, None);
    let b = b.with_forced(fb.clone());
    assert_eq!(GuardBackend::forced_health(&a), Some(HealthLevel::Watch));
    assert_eq!(GuardBackend::forced_health(&b), None);

    let mut e = Engine::new(GuardPolicy::for_level(AutoLevel::Safe), a);
    let ups = scan_n(&mut e, &clock, 2);
    assert!(
        ups.iter()
            .all(|u| u.status.health_forced == Some(HealthLevel::Watch) && u.status.unstable)
    );
    assert!(ups.iter().all(|u| u.report.health.level == HealthLevel::Ok));
    fa.set(None, NOW + 10_000);
    let ups = scan_n(&mut e, &clock, 2);
    assert!(ups.iter().all(|u| u.status.health_forced.is_none()));
    assert_eq!(fa.state().changes.len(), 2);
    assert_eq!(GuardBackend::forced_health(&b), None);
}
