use std::path::Path;

use vh_lab::pty::{PtyVh, base_env};

fn run_to_end(prog: &str, args: &[&str], dir: &Path) -> PtyVh {
    let shim = Path::new(env!("CARGO_BIN_EXE_vh-lab"));
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut p = PtyVh::spawn_program(
        shim,
        Path::new(prog),
        &args,
        base_env(),
        &dir.join(format!("{}.json", prog.replace('/', "_"))),
        80,
        24,
    )
    .expect("spawn");
    p.child.wait().expect("shim exit");
    p
}

#[test]
fn shim_reports_restored_for_untouched_and_not_for_stty_raw() {
    let dir = tempfile::tempdir().unwrap();
    let ok = run_to_end("/usr/bin/true", &[], dir.path());
    let rep = ok.report().unwrap();
    assert_eq!(ok.termios_restored(), Some(true), "{rep:?}");
    assert_eq!(rep.stty_restored, Some(true));
    assert!(ok.pid > 0 && ok.pid != ok.child.id() as i32);

    let raw = run_to_end("/bin/stty", &["raw", "-echo"], dir.path());
    let rep = raw.report().unwrap();
    assert_eq!(raw.termios_restored(), Some(false), "{rep:?}");
    assert_eq!(rep.stty_restored, Some(false));
    assert_eq!(rep.exit_code, Some(0));
}

/// 3단계 오탐의 원인: 세션 리더가 끝난 뒤 실험실이 든 slave fd는 ENOTTY.
#[test]
fn slave_fd_is_revoked_after_session_leader_exits() {
    let dir = tempfile::tempdir().unwrap();
    let p = run_to_end("/usr/bin/true", &[], dir.path());
    assert_eq!(p.old_method_errno(), Some(libc::ENOTTY));
}

#[test]
fn missing_program_is_an_error_not_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let shim = Path::new(env!("CARGO_BIN_EXE_vh-lab"));
    let r = PtyVh::spawn_program(
        shim,
        Path::new("/nonexistent/vh-lab-test"),
        &[],
        base_env(),
        &dir.path().join("x.json"),
        80,
        24,
    );
    assert!(r.is_err());
}
