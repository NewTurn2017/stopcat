//! 실제 신호 테스트(GUARD_7): 이 테스트가 띄운 CPU를 쓰는 자식 하나에게만. `AllowListSignaler`(허용 = 그 pid)가
//! 다른 pid를 막고 기록하며, 위반 0건을 단언한다. 엔진은 가짜 대본 스냅샷(자식 1개) + 진짜 prober·signaler.

use std::process::{Child, Command, Stdio};

use vh_act::{Prober, RealProber, RealSignaler};
use vh_guard::fake::*;
use vh_guard::{AllowListSignaler, Engine, GuardCommand, GuardEventKind};
use vh_model::*;

use crate::common::*;

/// 이 테스트의 자식. Drop에서 start_time이 같을 때만 SIGKILL 뒤 회수한다(패닉해도 남지 않게).
struct BusyChild {
    child: Child,
    r: ProcRef,
}

impl BusyChild {
    fn spawn() -> Self {
        let child = Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("자식 실행");
        let pid = child.id() as i32;
        let start = RealProber.probe(pid).start_time_unix_ms;
        BusyChild {
            child,
            r: ProcRef {
                pid,
                start_time_unix_ms: start,
            },
        }
    }
}

impl Drop for BusyChild {
    fn drop(&mut self) {
        let live = RealProber.probe(self.r.pid);
        if live.liveness == vh_act::Liveness::Alive
            && live.start_time_unix_ms == self.r.start_time_unix_ms
        {
            // SAFETY: 이 테스트가 띄운 자식이고 start_time이 같음을 방금 확인했다.
            unsafe { libc::kill(self.r.pid, libc::SIGKILL) };
        }
        let _ = self.child.wait();
    }
}

/// `proc_pidinfo(PROC_PIDTASKINFO).pti_priority`. DARWIN_BG면 4(MAXPRI_THROTTLE).
fn task_priority(pid: i32) -> Option<i32> {
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn scene_with(child: &BusyChild) -> Scene {
    let mut sc = Scene::new();
    let live = RealProber.probe(child.r.pid);
    sc.procs[0].pid = RealProber.self_pid();
    sc.procs[0].start_time_unix_ms = RealProber.probe(RealProber.self_pid()).start_time_unix_ms;
    let mut p = proc_(
        child.r.pid,
        live.ppid,
        live.uid,
        child.r.start_time_unix_ms,
        "sh",
    );
    p.exe = live.exe.clone();
    p.pgid = live.pgid;
    sc.procs.push(p);
    sc.classified
        .push(classified(child.r, Kind::DevServer, "바쁜 자식", None));
    sc
}

#[test]
fn live_demote_then_undo_and_shutdown_restore_own_busy_child() {
    let child = BusyChild::spawn();
    let p0 = task_priority(child.r.pid).expect("자식 task 우선순위");
    let sc = scene_with(&child);
    let clock = FakeClock::at(now_ms());
    let (mut s, r) = sc.build(clock.now());
    s.self_pid = RealProber.self_pid();
    s.self_uid = RealProber.self_uid();
    let lock = AllowListSignaler::new(
        Box::new(RealSignaler),
        std::collections::BTreeSet::from([child.r.pid]),
    );
    let mut be = FakeGuardBackend::scripted(vec![(s, r)], clock.clone())
        .with_kernel(Box::new(RealProber), Box::new(lock));
    be.cpu_rate_pct.insert(child.r.pid, 180.0);
    let probe = be.probe();
    let mut e = Engine::new(safe(), be);

    let mut last = None;
    for _ in 0..4 {
        last = e.scan();
        clock.advance(5000);
    }
    let u = last.expect("갱신");
    assert_eq!(
        u.status
            .demoted
            .iter()
            .map(|d| d.target)
            .collect::<Vec<_>>(),
        vec![child.r],
        "{:?}",
        u.status
    );
    let p_bg = task_priority(child.r.pid).unwrap();
    assert!(p_bg < p0, "demote 뒤 우선순위가 낮아야 함: {p0} → {p_bg}");
    eprintln!(
        "live: pid {} pti_priority {p0} → demote {p_bg}",
        child.r.pid
    );

    let u = e.handle(GuardCommand::UndoDemote(child.r)).unwrap();
    assert_eq!(kinds(&u.new_events), vec![GuardEventKind::Undemoted]);
    let p_back = task_priority(child.r.pid).unwrap();
    assert_eq!(p_back, p0, "undemote 뒤 원래 값");
    eprintln!("live: undo → {p_back}");

    for _ in 0..4 {
        e.scan();
        clock.advance(5000);
    }
    assert_eq!(e.status().demoted.len(), 1, "다시 폭주 → 다시 Demote");
    assert!(task_priority(child.r.pid).unwrap() < p0);
    let (report, _) = e.restore_all();
    assert_eq!(report.undemoted, vec![child.r]);
    assert!(report.failed.is_empty());
    assert_eq!(task_priority(child.r.pid).unwrap(), p0, "shutdown 되돌림");
    eprintln!("live: shutdown → {}", task_priority(child.r.pid).unwrap());

    let audit = std::fs::read_to_string(vh_act::audit_log_path(&probe.state_dir)).unwrap();
    assert!(audit.contains("\"demote\"") && audit.contains("\"undemote\""));
}
