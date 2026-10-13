//! 실제 연결: 설정 파일(vh_guard::config), 지킴이 스레드(vh_guard::GuardHandle), crossterm 터미널.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use crossterm::event::Event;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use vh_guard::{GuardCommand, GuardHandle, GuardUpdate, RealGuardBackend};
use vh_model::{AutoLevel, GuardPolicy, VhConfig, display_path};

use super::link::{Cmd, GuardLink, ManualResult, RecvState, ShutdownSummary, Update};
use super::state::{Mode, Model};
use super::term::{self, CrosstermOps, TermGuard, TermOps};
use super::{CrosstermEvents, Events, Host, exit_line, run_loop};
use crate::app::TuiOpts;

struct RealLink {
    handle: GuardHandle,
    rx: Receiver<GuardUpdate>,
}

fn to_guard(c: Cmd) -> GuardCommand {
    match c {
        Cmd::Pause => GuardCommand::Pause,
        Cmd::Resume => GuardCommand::Resume,
        Cmd::SetLevel(l) => GuardCommand::SetLevel(l),
        Cmd::SetScanInterval(ms) => GuardCommand::SetScanInterval(ms),
        Cmd::ResetCircuit => GuardCommand::ResetCircuit,
        Cmd::UndoDemote(t) => GuardCommand::UndoDemote(t),
        Cmd::ScanNow => GuardCommand::ScanNow,
        Cmd::RunPlan {
            request_id,
            plan,
            snapshot,
        } => GuardCommand::RunPlan {
            request_id,
            plan,
            snapshot,
        },
    }
}

fn from_guard(u: GuardUpdate) -> Update {
    Update {
        snapshot: u.snapshot,
        report: u.report,
        policy: u.policy,
        status: u.status,
        new_events: u.new_events,
        manual_result: u.manual_result.map(|m| ManualResult {
            request_id: m.request_id,
            outcomes: m.outcomes,
            state_dir: m.state_dir,
        }),
    }
}

impl GuardLink for RealLink {
    fn send(&mut self, cmd: Cmd) {
        let _ = self.handle.send(to_guard(cmd));
    }

    fn try_recv(&mut self) -> Result<Update, RecvState> {
        match self.rx.try_recv() {
            Ok(u) => Ok(from_guard(u)),
            Err(TryRecvError::Empty) => Err(RecvState::Empty),
            Err(TryRecvError::Disconnected) => Err(RecvState::Disconnected),
        }
    }

    fn shutdown(self: Box<Self>) -> ShutdownSummary {
        let r = self.handle.shutdown();
        ShutdownSummary {
            undemoted: r.undemoted,
            failed: r.failed,
        }
    }
}

/// 지킴이를 띄우지 못했을 때: 화면은 그대로 두고 '멈췄어요'를 보여 준다.
struct DeadLink;

impl GuardLink for DeadLink {
    fn send(&mut self, _cmd: Cmd) {}

    fn try_recv(&mut self) -> Result<Update, RecvState> {
        Err(RecvState::Disconnected)
    }

    fn shutdown(self: Box<Self>) -> ShutdownSummary {
        ShutdownSummary::default()
    }
}

struct RealHost {
    state_dir: PathBuf,
    locked_by_env: bool,
    start_error: Option<String>,
}

impl Host for RealHost {
    fn start_guard(&mut self, level: AutoLevel, interval_ms: Option<u32>) -> Box<dyn GuardLink> {
        let mut policy = GuardPolicy::for_level(level);
        if let Some(ms) = interval_ms {
            policy.scan_interval_ms = ms;
        }
        match RealGuardBackend::new() {
            Ok(backend) => {
                let (handle, rx) = GuardHandle::spawn_with(policy, backend, self.locked_by_env);
                Box::new(RealLink { handle, rx })
            }
            Err(e) => {
                self.start_error = Some(format!("상태 폴더를 준비하지 못했어요: {e}"));
                Box::new(DeadLink)
            }
        }
    }

    fn save_config(&mut self, cfg: &VhConfig) -> Result<(), String> {
        vh_guard::config::save(&self.state_dir, cfg).map_err(|e| e.to_string())
    }

    fn take_signal(&mut self) -> Option<i32> {
        term::take_signal()
    }

    fn take_thread_panic(&mut self) -> Option<String> {
        self.start_error.take().or_else(term::take_thread_panic)
    }
}

/// debug 빌드 전용(`VH_TUI_DEBUG_PANIC=1`): 첫 그리기 뒤 화면 스레드에서 패닉을 일으켜
/// 실제 터미널 복구를 확인한다. release에는 컴파일되지 않는다.
#[cfg(debug_assertions)]
struct DebugPanic<E: Events>(E);

#[cfg(debug_assertions)]
impl<E: Events> Events for DebugPanic<E> {
    fn next(&mut self, _timeout: Duration) -> io::Result<Option<Event>> {
        panic!("VH_TUI_DEBUG_PANIC=1: 터미널 복구 확인용 패닉");
    }
}

fn events() -> Box<dyn Events> {
    #[cfg(debug_assertions)]
    if std::env::var("VH_TUI_DEBUG_PANIC").as_deref() == Ok("1") {
        return Box::new(DebugPanic(CrosstermEvents));
    }
    Box::new(CrosstermEvents)
}

pub fn run(opts: TuiOpts) -> i32 {
    let state_dir = match vh_act::state_dir_path() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("vh: 상태 폴더 위치를 알 수 없어요: {e}");
            return 1;
        }
    };
    let config = vh_guard::config::load(&state_dir).unwrap_or(None);
    let env_raw = std::env::var(vh_guard::env::GUARD_LEVEL)
        .ok()
        .filter(|v| !v.trim().is_empty());
    let eff = vh_guard::config::effective_level(env_raw.as_deref(), config.as_ref());
    let e2e_lock = std::env::var_os(vh_guard::env::E2E_ALLOW_PIDS).is_some();
    let mut m = Model::new(config, env_raw.as_deref(), e2e_lock);
    if eff.warning_ko.is_some() {
        m.env_warning = eff.warning_ko.clone();
        m.flash = eff.warning_ko.clone();
    }
    m.no_color = opts.no_color;
    let home = std::env::var("HOME").unwrap_or_default();
    m.config_path = display_path(
        &vh_guard::config::config_path(&state_dir).to_string_lossy(),
        &home,
    );

    term::install_signal_flags();
    let ops: Arc<dyn TermOps> = Arc::new(CrosstermOps);
    let guard = match TermGuard::enter(ops) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("vh: 전체 화면을 열지 못했어요: {e}. vh --plain 을 쓰세요.");
            return 1;
        }
    };
    term::install_panic_hook(std::thread::current().id(), guard.restorer());

    let mut host = RealHost {
        state_dir,
        locked_by_env: eff.locked_by_env,
        start_error: None,
    };
    let result = (|| -> io::Result<_> {
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let size = terminal.size()?;
        m.set_size(size.width, size.height);
        let link = (m.mode != Mode::FirstRun)
            .then(|| host.start_guard(m.effective_level(), m.config.scan_interval_ms));
        let mut ev = events();
        run_loop(&mut terminal, &mut m, ev.as_mut(), &mut host, link)
    })();
    let restored = guard.restore();
    drop(guard);
    if let Err(e) = restored {
        eprintln!("vh: 터미널을 되돌리다 문제가 생겼어요: {e}. reset 을 입력하면 돌아와요.");
    }
    match result {
        Ok(end) => {
            println!("{}", exit_line(&m, &end));
            if let Some(p) = term::take_thread_panic() {
                eprintln!("vh: 지킴이에 문제가 있었어요: {p}");
            }
            end.code
        }
        Err(e) => {
            eprintln!("vh: 화면을 그리다 문제가 생겼어요: {e}");
            1
        }
    }
}
