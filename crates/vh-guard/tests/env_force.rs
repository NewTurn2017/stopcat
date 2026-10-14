//! `RealGuardBackend::new()`가 `VH_E2E_FORCE_HEALTH`를 `VH_E2E_ALLOW_PIDS`가 있을 때만 읽는지(W4).
//! 환경 변수를 바꾸므로 이 파일에는 테스트가 하나뿐이다. 수집·신호는 하지 않는다.

use vh_guard::{GuardBackend, RealGuardBackend};
use vh_model::HealthLevel;

#[test]
fn force_health_is_read_only_with_allow_pids_present() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: 이 바이너리의 유일한 테스트. 다른 스레드가 env를 읽는 중이 아니다.
    unsafe {
        std::env::set_var("VH_STATE_DIR", dir.path());
        std::env::set_var("VH_NOTIFY", "off");
        std::env::set_var("VH_E2E_FORCE_HEALTH", "critical");
        std::env::remove_var("VH_E2E_ALLOW_PIDS");
    }
    let be = RealGuardBackend::new().unwrap();
    assert_eq!(be.forced_health(), None, "허용 목록이 없으면 무시");
    assert_eq!(be.locked_pids(), None);

    // SAFETY: 위와 같다.
    unsafe { std::env::set_var("VH_E2E_ALLOW_PIDS", "") };
    let be = RealGuardBackend::new().unwrap();
    assert_eq!(be.forced_health(), Some(HealthLevel::Critical));
    let be = be.with_forced_health(None);
    assert_eq!(be.forced_health(), None, "빌더가 env 값을 덮어쓴다");
}
