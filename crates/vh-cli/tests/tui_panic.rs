//! 터미널 복구(가짜 TermOps + catch_unwind). 패닉 훅은 프로세스 전역이라 이 파일은 테스트 하나만 둔다.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vh_cli::tui::term::{TermGuard, TermOps, install_panic_hook, take_thread_panic};

#[derive(Default)]
struct Counting {
    enters: AtomicUsize,
    leaves: AtomicUsize,
}

impl TermOps for Counting {
    fn enter(&self) -> std::io::Result<()> {
        self.enters.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn leave(&self) -> std::io::Result<()> {
        self.leaves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn restore_once_on_ui_panic_never_on_guard_thread_panic() {
    let ops = Arc::new(Counting::default());
    let guard = TermGuard::enter(ops.clone()).unwrap();
    assert_eq!(ops.enters.load(Ordering::SeqCst), 1);
    install_panic_hook(std::thread::current().id(), guard.restorer());

    let joined = std::thread::spawn(|| panic!("지킴이 스레드에서 남")).join();
    assert!(joined.is_err());
    assert_eq!(
        ops.leaves.load(Ordering::SeqCst),
        0,
        "다른 스레드 패닉은 터미널을 건드리지 않음"
    );
    assert!(take_thread_panic().is_some_and(|m| m.contains("지킴이 스레드에서 남")));
    assert!(take_thread_panic().is_none());

    let r = std::panic::catch_unwind(|| panic!("화면 스레드에서 남"));
    assert!(r.is_err());
    assert_eq!(ops.leaves.load(Ordering::SeqCst), 1, "화면 패닉 → 복구 1번");

    guard.restore().unwrap();
    drop(guard);
    assert_eq!(ops.leaves.load(Ordering::SeqCst), 1, "복구는 한 번만");

    let _ = std::panic::take_hook();
}
