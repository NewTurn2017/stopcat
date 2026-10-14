//! `stopcat` 전체 화면(TTY에서 하위 명령 없이 실행했을 때). 화면 스레드는 그리기·키만 하고,
//! 수집·분석·신호는 지킴이 스레드(stopcat-guard)가 한다.

pub mod link;
mod real;
pub mod state;
pub mod term;
pub mod theme;
pub mod view;

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::Backend;
use stopcat_model::{AutoLevel, StopcatConfig};

use link::{GuardLink, RecvState, ShutdownSummary};
use state::{Effect, Model, TICK_MS};

pub use real::run;

pub trait Events {
    fn next(&mut self, timeout: Duration) -> io::Result<Option<Event>>;
}

pub struct CrosstermEvents;

impl Events for CrosstermEvents {
    fn next(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        if event::poll(timeout)? {
            Ok(Some(event::read()?))
        } else {
            Ok(None)
        }
    }
}

/// 화면 루프가 바깥 세계와 닿는 곳. 실제는 stopcat-guard·설정 파일·신호, 테스트는 가짜.
pub trait Host {
    fn start_guard(&mut self, level: AutoLevel, interval_ms: Option<u32>) -> Box<dyn GuardLink>;
    fn save_config(&mut self, cfg: &StopcatConfig) -> Result<(), String>;
    fn take_signal(&mut self) -> Option<i32>;
    fn take_thread_panic(&mut self) -> Option<String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopEnd {
    pub code: i32,
    pub summary: Option<ShutdownSummary>,
    pub forced: bool,
    pub draws: u64,
}

const SHUTDOWN_POLL_MS: u64 = 100;

fn is_ctrl_c(k: &KeyEvent) -> bool {
    k.kind == KeyEventKind::Press
        && k.code == KeyCode::Char('c')
        && k.modifiers.contains(KeyModifiers::CONTROL)
}

/// 패닉으로 루프가 풀려도 지킴이를 정상 종료(낮춘 것 되돌리기)하게 붙잡아 둔다.
struct Linked(Option<Box<dyn GuardLink>>);

impl Drop for Linked {
    fn drop(&mut self) {
        if let Some(l) = self.0.take() {
            let _ = l.shutdown();
        }
    }
}

struct Flow {
    quitting: bool,
    forced: bool,
}

fn run_effects(
    fx: Vec<Effect>,
    m: &mut Model,
    link: &mut Option<Box<dyn GuardLink>>,
    host: &mut dyn Host,
    flow: &mut Flow,
) {
    for e in fx {
        match e {
            Effect::Send(c) => {
                if let Some(l) = link.as_mut() {
                    l.send(c);
                }
            }
            Effect::SaveConfig(cfg) => {
                if let Err(msg) = host.save_config(&cfg) {
                    m.flash = Some(format!("설정을 저장하지 못했어요: {msg}"));
                }
            }
            Effect::StartGuard { level, interval_ms } => {
                if link.is_none() {
                    *link = Some(host.start_guard(level, interval_ms));
                }
            }
            Effect::Quit => flow.quitting = true,
            Effect::ForceQuit => {
                flow.quitting = true;
                flow.forced = true;
            }
        }
    }
}

/// 갱신·키가 있을 때만 다시 그린다. 끝낼 때는 지킴이 shutdown(낮춘 것 되돌리기 + join)을 기다리되,
/// 그동안 Ctrl+C가 한 번 더 오면 기다리지 않는다.
pub fn run_loop<B: Backend>(
    term: &mut Terminal<B>,
    m: &mut Model,
    events: &mut dyn Events,
    host: &mut dyn Host,
    link: Option<Box<dyn GuardLink>>,
) -> io::Result<LoopEnd>
where
    B::Error: Send + Sync + 'static,
{
    let mut link = Linked(link);
    let mut draws = 0u64;
    let mut code = 0;
    let mut flow = Flow {
        quitting: false,
        forced: false,
    };
    let mut dirty = true;
    let to_io = |e: B::Error| io::Error::other(e);
    loop {
        if let Some(sig) = host.take_signal() {
            code = 128 + sig;
            m.mode = state::Mode::Quitting;
            flow.quitting = true;
        }
        if let Some(msg) = host.take_thread_panic() {
            m.guard_died(Some(msg));
            dirty = true;
        }
        while let Some(l) = link.0.as_mut() {
            match l.try_recv() {
                Ok(u) => {
                    let fx = m.apply(u);
                    run_effects(fx, m, &mut link.0, host, &mut flow);
                    dirty = true;
                }
                Err(RecvState::Empty) => break,
                Err(RecvState::Disconnected) => {
                    if m.guard_dead.is_none() {
                        m.guard_died(None);
                        dirty = true;
                    }
                    break;
                }
            }
        }
        if dirty || flow.quitting {
            term.draw(|f| view::draw(f, m)).map_err(to_io)?;
            draws += 1;
            dirty = false;
        }
        if flow.quitting {
            break;
        }
        match events.next(Duration::from_millis(TICK_MS))? {
            Some(Event::Key(k)) => {
                let fx = m.on_key(k);
                run_effects(fx, m, &mut link.0, host, &mut flow);
                dirty = true;
            }
            Some(Event::Resize(w, h)) => {
                m.set_size(w, h);
                dirty = true;
            }
            _ => {}
        }
    }
    let mut summary = None;
    if let Some(l) = link.0.take() {
        if flow.forced {
            std::mem::forget(l);
        } else {
            let handle = std::thread::spawn(move || l.shutdown());
            while !handle.is_finished() {
                if let Some(Event::Key(k)) = events.next(Duration::from_millis(SHUTDOWN_POLL_MS))?
                    && is_ctrl_c(&k)
                {
                    flow.forced = true;
                    break;
                }
            }
            if !flow.forced {
                summary = handle.join().ok();
            }
        }
    }
    if flow.forced {
        code = 130;
    }
    Ok(LoopEnd {
        code,
        summary,
        forced: flow.forced,
        draws,
    })
}

/// 끝낸 뒤 원래 화면에 남기는 한 줄.
pub fn exit_line(m: &Model, end: &LoopEnd) -> String {
    let t = m.tally;
    let mut s = "stopcat: 지킴이를 멈췄어요.".to_string();
    if t.auto_terminated > 0 {
        s.push_str(&format!(
            " 이번에 자동 종료 {}건(약 {}).",
            t.auto_terminated,
            crate::fmt::bytes(t.reclaimed_bytes)
        ));
    }
    match &end.summary {
        Some(sm) if !sm.undemoted.is_empty() => {
            s.push_str(&format!(
                " 낮춘 우선순위 {}건을 되돌렸어요.",
                sm.undemoted.len()
            ));
        }
        _ => {}
    }
    if let Some(sm) = &end.summary
        && !sm.failed.is_empty()
    {
        s.push_str(&format!(" 되돌리지 못한 것 {}건.", sm.failed.len()));
    }
    if end.forced {
        s.push_str(" 기다리지 않고 끝내서 낮춘 우선순위가 그대로일 수 있어요.");
    }
    s
}
