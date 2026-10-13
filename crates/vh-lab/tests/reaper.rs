use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use vh_act::{LiveProc, Liveness};
use vh_lab::cleanup::LabReaper;
use vh_lab::kernel::LabKernel;
use vh_lab::registry::LabRegistry;
use vh_model::ProcRef;

#[derive(Default)]
struct FakeKernel {
    procs: BTreeMap<i32, LiveProc>,
    pgrps: BTreeMap<i32, Vec<(i32, u64)>>,
    calls: Mutex<Vec<(String, i32, i32)>>,
}

impl FakeKernel {
    fn add(&mut self, pid: i32, start: u64, pgid: i32, uid: u32) {
        let mut l = LiveProc::alive(pid, start, 1, uid, Some("/x/lab-idle"));
        l.pgid = pgid;
        self.procs.insert(pid, l);
        self.pgrps.entry(pgid).or_default().push((pid, start));
    }
    fn calls(&self) -> Vec<(String, i32, i32)> {
        self.calls.lock().unwrap().clone()
    }
}

impl LabKernel for FakeKernel {
    fn probe(&self, pid: i32) -> LiveProc {
        self.procs
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| LiveProc::gone(pid))
    }
    fn pgrp_members(&self, pgid: i32) -> Vec<(i32, u64)> {
        self.pgrps.get(&pgid).cloned().unwrap_or_default()
    }
    fn kill(&self, pid: i32, sig: i32) -> Result<(), i32> {
        self.calls.lock().unwrap().push(("kill".into(), pid, sig));
        Ok(())
    }
    fn killpg(&self, pgid: i32, sig: i32) -> Result<(), i32> {
        self.calls
            .lock()
            .unwrap()
            .push(("killpg".into(), pgid, sig));
        Ok(())
    }
    fn now_ms(&self) -> u64 {
        0
    }
    fn sleep_ms(&self, _ms: u64) {}
}

fn r(pid: i32, st: u64) -> ProcRef {
    ProcRef {
        pid,
        start_time_unix_ms: st,
    }
}

#[test]
fn t_iso_5_reaper_signals_only_allowed_matching_start() {
    let mut k = FakeKernel::default();
    k.add(100, 10, 100, 501);
    k.add(101, 11, 100, 501);
    k.add(200, 20, 200, 501);
    let mut rp = LabReaper::new(&k, BTreeSet::from([r(100, 10), r(101, 99)]));
    assert!(!rp.signal(r(200, 20), libc::SIGKILL));
    assert!(!rp.signal(r(101, 99), libc::SIGKILL));
    assert!(rp.signal(r(100, 10), libc::SIGTERM));
    assert_eq!(k.calls(), vec![("kill".to_string(), 100, libc::SIGTERM)]);
    assert_eq!(rp.calls.iter().filter(|c| c.op == "refused").count(), 2);
}

#[test]
fn t_iso_5_killpg_only_when_every_member_allowed() {
    let mut k = FakeKernel::default();
    k.add(100, 10, 100, 501);
    k.add(101, 11, 100, 501);
    k.add(102, 12, 100, 501);
    let mut rp = LabReaper::new(&k, BTreeSet::from([r(100, 10), r(101, 11)]));
    rp.killpg_checked(100, libc::SIGKILL);
    let calls = k.calls();
    assert!(calls.iter().all(|c| c.0 == "kill"), "{calls:?}");
    assert_eq!(
        calls.iter().map(|c| c.1).collect::<BTreeSet<_>>(),
        BTreeSet::from([100, 101])
    );

    let mut k2 = FakeKernel::default();
    k2.add(100, 10, 100, 501);
    k2.add(101, 11, 100, 501);
    let mut rp2 = LabReaper::new(&k2, BTreeSet::from([r(100, 10), r(101, 11)]));
    assert!(rp2.killpg_checked(100, libc::SIGKILL));
    assert_eq!(k2.calls(), vec![("killpg".to_string(), 100, libc::SIGKILL)]);
}

#[test]
fn registry_admits_only_own_group_uid_and_time() {
    let mut k = FakeKernel::default();
    k.add(100, 5_000, 100, 501);
    k.add(101, 6_000, 100, 501);
    k.add(102, 6_000, 300, 501);
    k.add(103, 6_000, 100, 0);
    k.add(104, 1_000, 100, 501);
    k.add(106, 6_000, 100, 501);
    let mut z = LiveProc::alive(105, 6_500, 101, 501, None);
    z.liveness = Liveness::Zombie;
    z.pgid = 0;
    k.procs.insert(105, z);
    let mut reg = LabRegistry::new("T", r(100, 5_000), 5_000, 501);
    let ok = reg.register(&k, 101, "A", "s1", "idle", "node", false, None);
    assert_eq!(ok, Ok(r(101, 6_000)));
    assert!(
        reg.register(&k, 102, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 103, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 104, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 1, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 999, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(
            &k,
            105,
            "A",
            "s5",
            "zombie_child",
            "x",
            false,
            Some(r(101, 6_000))
        )
        .is_ok()
    );
    reg.freeze("A");
    assert!(
        reg.register(&k, 101, "A", "s", "idle", "node", false, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 101, "B", "s", "idle", "node", true, None)
            .is_err()
    );
    assert!(
        reg.register(&k, 106, "B", "s", "idle", "node", true, None)
            .is_ok()
    );
    assert_eq!(reg.lock_pids("A"), BTreeSet::from([101, 105]));
    assert!(reg.lock_pids("B").is_empty());
    assert_eq!(reg.decoys().len(), 1);
    assert!(reg.all_refs().contains(&r(100, 5_000)));
    assert_eq!(reg.tag("A"), "lab-T-A");
}
