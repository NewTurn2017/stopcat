//! 터미널 수명: raw 모드·대체 화면·커서 숨김을 켜고, 어떤 종료(정상·Ctrl+C·신호·패닉)에서도
//! 한 번만 되돌린다. 패닉 훅은 화면 스레드의 패닉에서만 터미널을 되돌린다(지킴이 스레드 패닉은
//! 메시지만 보관해 화면에 알린다).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use crossterm::cursor::{Hide, Show};
use crossterm::execute;
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

pub trait TermOps: Send + Sync {
    fn enter(&self) -> io::Result<()>;
    fn leave(&self) -> io::Result<()>;
}

pub struct CrosstermOps;

impl TermOps for CrosstermOps {
    fn enter(&self) -> io::Result<()> {
        enable_raw_mode()?;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            Hide,
            Clear(ClearType::All)
        )
    }

    fn leave(&self) -> io::Result<()> {
        let raw = disable_raw_mode();
        let screen = execute!(io::stdout(), LeaveAlternateScreen, Show);
        raw.and(screen)
    }
}

/// 켜 둔 터미널. `restore`·Drop·패닉 훅 중 무엇이 먼저 와도 되돌리기는 한 번이다.
pub struct TermGuard {
    ops: Arc<dyn TermOps>,
    restored: Arc<AtomicBool>,
}

impl TermGuard {
    pub fn enter(ops: Arc<dyn TermOps>) -> io::Result<TermGuard> {
        let g = TermGuard {
            ops,
            restored: Arc::new(AtomicBool::new(false)),
        };
        g.ops.enter()?;
        Ok(g)
    }

    pub fn restore(&self) -> io::Result<()> {
        if self.restored.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.ops.leave()
    }

    pub fn restorer(&self) -> Arc<dyn Fn() + Send + Sync> {
        let ops = self.ops.clone();
        let restored = self.restored.clone();
        Arc::new(move || {
            if !restored.swap(true, Ordering::SeqCst) {
                let _ = ops.leave();
            }
        })
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

static THREAD_PANIC: Mutex<Option<String>> = Mutex::new(None);

pub fn install_panic_hook(main: ThreadId, restore: Arc<dyn Fn() + Send + Sync>) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == main {
            restore();
            prev(info);
        } else if let Ok(mut slot) = THREAD_PANIC.lock() {
            slot.get_or_insert_with(|| info.to_string());
        }
    }));
}

/// 화면 스레드가 아닌 곳(지킴이)에서 난 패닉 메시지. 한 번 꺼내면 비워진다.
pub fn take_thread_panic() -> Option<String> {
    THREAD_PANIC.lock().ok().and_then(|mut s| s.take())
}

static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    SIGNAL.store(sig, Ordering::SeqCst);
}

/// SIGTERM·SIGHUP·SIGINT는 번호만 기록한다(비동기 신호 안전). 화면 루프가 틱마다 보고 정상 종료한다.
pub fn install_signal_flags() {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
        // SAFETY: 핸들러는 원자 변수 하나에만 쓴다.
        unsafe {
            libc::signal(sig, handler);
        }
    }
}

pub fn take_signal() -> Option<i32> {
    match SIGNAL.swap(0, Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}
