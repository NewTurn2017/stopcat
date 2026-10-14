//! `RealGuardBackend::new()`가 `STOPCAT_E2E_ALLOW_PIDS`를 보고 잠금 signaler로 자동 감싸는지.
//! 환경 변수를 바꾸므로 이 파일에는 테스트가 하나뿐이다(다른 스레드가 env를 읽는 동안 set_var 하지 않게).
//! 신호 대상은 이 테스트가 띄운 `sleep` 자식 하나이고, 잠금이 커널 호출 전에 막는다(실제 신호 0).

use std::collections::BTreeSet;
use std::process::{Command, Stdio};

use stopcat_act::{Prober, RealProber};
use stopcat_guard::backend::notify_disabled_by_env;
use stopcat_guard::snap::bare_snapshot;
use stopcat_guard::{GuardBackend, RealGuardBackend};
use stopcat_model::{ActionPlan, FinalState, PlannedAction, ProcRef, Step};

#[test]
fn new_locks_everything_when_allow_list_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: 이 바이너리의 유일한 테스트. 다른 스레드가 env를 읽는 중이 아니다.
    unsafe {
        std::env::set_var("STOPCAT_STATE_DIR", dir.path());
        std::env::set_var("STOPCAT_E2E_ALLOW_PIDS", "");
        std::env::set_var("STOPCAT_NOTIFY", "off");
    }
    assert!(notify_disabled_by_env());
    let mut be = RealGuardBackend::new().unwrap();
    assert_eq!(be.locked_pids(), Some(&BTreeSet::new()));
    assert_eq!(be.state_dir(), dir.path());

    let mut child = Command::new("/bin/sleep")
        .arg("300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as i32;
    let start = RealProber.probe(pid).start_time_unix_ms;
    let target = ProcRef {
        pid,
        start_time_unix_ms: start,
    };
    let plan = ActionPlan {
        created_at_unix_ms: 0,
        total_deadline_ms: 5_000,
        items: vec![PlannedAction {
            finding_id: format!("undemote:{pid}:{start}"),
            target,
            include_descendants: false,
            descendant_count: 0,
            steps: vec![Step::Undemote],
            grace_ms: 0,
            reason_ko: "자식".into(),
            est_reclaim_bytes: 0,
        }],
        refused: Vec::new(),
    };
    let snap = bare_snapshot(std::process::id() as i32, RealProber.self_uid(), 0);
    let out = be.execute(&plan, &snap, "env-lock");
    assert_eq!(out[0].final_state, FinalState::StillAlive);
    let step = &out[0].steps[0];
    assert_eq!(
        (step.step, step.ok, step.errno),
        (Step::Undemote, false, Some(libc::EPERM))
    );

    // SAFETY: 방금 띄운 자기 자식.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    child.wait().unwrap();
    assert!(
        std::fs::read_to_string(stopcat_act::audit_log_path(dir.path()))
            .unwrap()
            .contains("\"undemote\""),
        "감사 로그는 임시 상태 폴더에만"
    );
}
