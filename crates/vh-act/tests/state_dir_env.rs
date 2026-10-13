//! `state_dir()`가 `VH_STATE_DIR`을 우선하고 없는 폴더를 0700으로 만드는지.
//! env를 바꾸므로 이 파일(별도 테스트 프로세스)에는 테스트를 하나만 둔다.

use std::os::unix::fs::PermissionsExt;

#[test]
fn state_dir_prefers_vh_state_dir_and_creates_0700() {
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("a").join("vibe-health");
    // SAFETY: 이 테스트 바이너리의 유일한 테스트라 다른 스레드가 env를 동시에 읽지 않는다.
    unsafe { std::env::set_var("VH_STATE_DIR", &nested) };
    let got = vh_act::state_dir().unwrap();
    assert_eq!(got, nested);
    let mode = std::fs::metadata(&got).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    assert_eq!(vh_act::audit_log_path(&got), nested.join("audit.jsonl"));
    assert_eq!(vh_act::revive_dir(&got), nested.join("revive"));
}
