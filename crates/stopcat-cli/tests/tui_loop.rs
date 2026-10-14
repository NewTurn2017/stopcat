//! 화면 루프(가짜 이벤트·가짜 지킴이·TestBackend): 바뀔 때만 그리기, 모든 종료 길의 shutdown,
//! 지킴이 끊김·패닉 알림, 첫 실행 뒤 지킴이 시작.

mod common;
mod tui_common;

use std::collections::VecDeque;
use std::io;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tui_common::*;
use stopcat_cli::tui::link::{Cmd, GuardLink, RecvState, ShutdownSummary, Update};
use stopcat_cli::tui::state::{Mode, Model, TICK_MS};
use stopcat_cli::tui::{Events, Host, LoopEnd, run_loop};
use stopcat_model::{AutoLevel, StopcatConfig};

#[derive(Default)]
struct Shared {
    updates: VecDeque<Update>,
    sent: Vec<String>,
    disconnected: bool,
    shutdowns: u32,
}

struct FakeLink {
    shared: Arc<Mutex<Shared>>,
    block: Option<mpsc::Receiver<()>>,
}

impl GuardLink for FakeLink {
    fn send(&mut self, cmd: Cmd) {
        self.shared.lock().unwrap().sent.push(format!("{cmd:?}"));
    }

    fn try_recv(&mut self) -> Result<Update, RecvState> {
        let mut s = self.shared.lock().unwrap();
        match s.updates.pop_front() {
            Some(u) => Ok(u),
            None if s.disconnected => Err(RecvState::Disconnected),
            None => Err(RecvState::Empty),
        }
    }

    fn shutdown(self: Box<Self>) -> ShutdownSummary {
        self.shared.lock().unwrap().shutdowns += 1;
        if let Some(rx) = &self.block {
            let _ = rx.recv();
        }
        ShutdownSummary::default()
    }
}

enum Step {
    Tick,
    Key(KeyEvent),
    Update(Box<Update>),
    Disconnect,
    Panic,
}

struct FakeEvents {
    steps: VecDeque<Step>,
    shared: Arc<Mutex<Shared>>,
    timeouts: Vec<Duration>,
}

impl Events for FakeEvents {
    fn next(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        self.timeouts.push(timeout);
        match self.steps.pop_front() {
            None => Ok(Some(Event::Key(ch('q')))),
            Some(Step::Tick) => Ok(None),
            Some(Step::Key(k)) => Ok(Some(Event::Key(k))),
            Some(Step::Update(u)) => {
                self.shared.lock().unwrap().updates.push_back(*u);
                Ok(None)
            }
            Some(Step::Disconnect) => {
                self.shared.lock().unwrap().disconnected = true;
                Ok(None)
            }
            Some(Step::Panic) => panic!("화면 루프 시험용 패닉"),
        }
    }
}

#[derive(Default)]
struct FakeHost {
    shared: Arc<Mutex<Shared>>,
    started: Vec<AutoLevel>,
    saved: Vec<StopcatConfig>,
    signal: Option<i32>,
    thread_panic: Option<String>,
    save_fails: bool,
}

impl Host for FakeHost {
    fn start_guard(&mut self, level: AutoLevel, _interval_ms: Option<u32>) -> Box<dyn GuardLink> {
        self.started.push(level);
        Box::new(FakeLink {
            shared: self.shared.clone(),
            block: None,
        })
    }

    fn save_config(&mut self, cfg: &StopcatConfig) -> Result<(), String> {
        self.saved.push(cfg.clone());
        if self.save_fails {
            Err("권한 없음".into())
        } else {
            Ok(())
        }
    }

    fn take_signal(&mut self) -> Option<i32> {
        self.signal.take()
    }

    fn take_thread_panic(&mut self) -> Option<String> {
        self.thread_panic.take()
    }
}

fn go(
    m: &mut Model,
    host: &mut FakeHost,
    steps: Vec<Step>,
    link: bool,
) -> (LoopEnd, Vec<Duration>) {
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut ev = FakeEvents {
        steps: steps.into(),
        shared: host.shared.clone(),
        timeouts: vec![],
    };
    let l: Option<Box<dyn GuardLink>> = link.then(|| {
        Box::new(FakeLink {
            shared: host.shared.clone(),
            block: None,
        }) as Box<dyn GuardLink>
    });
    let end = run_loop(&mut term, m, &mut ev, host, l).unwrap();
    (end, ev.timeouts)
}

#[test]
fn draws_only_when_something_changed() {
    let mut host = FakeHost::default();
    let mut m = main_model();
    let (end, timeouts) = go(
        &mut m,
        &mut host,
        vec![Step::Tick, Step::Tick, Step::Tick],
        true,
    );
    assert_eq!(end.draws, 2, "첫 그리기 + 끝내는 중");
    assert!(timeouts.iter().all(|t| *t <= Duration::from_millis(250)));
    assert_eq!(TICK_MS, 250);

    let mut host = FakeHost::default();
    let mut m = main_model();
    let (end, _) = go(
        &mut m,
        &mut host,
        vec![
            Step::Tick,
            Step::Update(Box::new(normal_update())),
            Step::Tick,
            Step::Tick,
        ],
        true,
    );
    assert_eq!(end.draws, 3, "갱신 1개 = 그리기 1번 더");
}

#[test]
fn every_quit_path_shuts_guard_down_once() {
    for k in [ch('q'), key(KeyCode::Esc), ctrl_c()] {
        let mut host = FakeHost::default();
        let mut m = main_model();
        let (end, _) = go(&mut m, &mut host, vec![Step::Key(k)], true);
        assert_eq!(end.code, 0);
        assert!(!end.forced);
        assert_eq!(end.summary, Some(ShutdownSummary::default()));
        assert_eq!(host.shared.lock().unwrap().shutdowns, 1);
        assert_eq!(m.mode, Mode::Quitting);
    }
    let mut host = FakeHost {
        signal: Some(15),
        ..FakeHost::default()
    };
    let mut m = main_model();
    let (end, _) = go(&mut m, &mut host, vec![Step::Tick], true);
    assert_eq!(end.code, 143);
    assert_eq!(host.shared.lock().unwrap().shutdowns, 1);
}

#[test]
fn second_ctrl_c_does_not_wait_for_guard() {
    let mut host = FakeHost::default();
    let (_tx, rx) = mpsc::channel::<()>();
    let mut m = main_model();
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut ev = FakeEvents {
        steps: vec![Step::Key(ch('q')), Step::Key(ctrl_c())].into(),
        shared: host.shared.clone(),
        timeouts: vec![],
    };
    let link: Box<dyn GuardLink> = Box::new(FakeLink {
        shared: host.shared.clone(),
        block: Some(rx),
    });
    let end = run_loop(&mut term, &mut m, &mut ev, &mut host, Some(link)).unwrap();
    assert!(end.forced);
    assert_eq!(end.code, 130);
    assert_eq!(end.summary, None);
}

#[test]
fn guard_disconnect_and_thread_panic_show_banner() {
    let mut host = FakeHost::default();
    let mut m = main_model();
    go(&mut m, &mut host, vec![Step::Disconnect, Step::Tick], true);
    assert!(m.guard_dead.is_some());
    assert!(
        render(&mut m, 80, 24)[22].contains("멈췄어요"),
        "지킴이 줄은 키 줄 바로 위"
    );

    let mut host = FakeHost {
        thread_panic: Some("지킴이 스레드 패닉".into()),
        ..FakeHost::default()
    };
    let mut m = main_model();
    go(&mut m, &mut host, vec![Step::Tick], true);
    assert_eq!(m.guard_dead.as_deref(), Some("지킴이 스레드 패닉"));
}

#[test]
fn first_run_starts_guard_after_choice_and_reports_save_failure() {
    let mut host = FakeHost {
        save_fails: true,
        ..FakeHost::default()
    };
    let mut m = Model::new(None, None, false);
    let (end, _) = go(
        &mut m,
        &mut host,
        vec![
            Step::Tick,
            Step::Key(key(KeyCode::Enter)),
            Step::Update(Box::new(normal_update())),
            Step::Tick,
        ],
        false,
    );
    assert_eq!(host.started, vec![AutoLevel::Safe]);
    assert_eq!(host.saved.len(), 1);
    assert!(
        m.flash
            .as_deref()
            .is_some_and(|f| f.starts_with("설정을 저장하지 못했어요")),
        "{:?}",
        m.flash
    );
    assert_eq!(end.code, 0);
    assert_eq!(host.shared.lock().unwrap().shutdowns, 1);

    let mut host = FakeHost::default();
    let mut m = Model::new(None, None, false);
    go(&mut m, &mut host, vec![Step::Key(ch('q'))], false);
    assert!(host.started.is_empty() && host.saved.is_empty());
}

#[test]
fn commands_reach_the_guard() {
    let mut host = FakeHost::default();
    let mut m = main_model();
    go(&mut m, &mut host, vec![Step::Key(ch('p'))], true);
    assert_eq!(host.shared.lock().unwrap().sent, vec!["Pause".to_string()]);
}

#[test]
fn panic_in_loop_still_shuts_guard_down() {
    let mut host = FakeHost::default();
    let shared = host.shared.clone();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut m = main_model();
        go(&mut m, &mut host, vec![Step::Tick, Step::Panic], true)
    }));
    assert!(r.is_err());
    assert_eq!(shared.lock().unwrap().shutdowns, 1);
}

#[test]
fn exit_line_mentions_undemoted() {
    let m = main_model();
    let end = LoopEnd {
        code: 0,
        summary: Some(ShutdownSummary {
            undemoted: vec![stopcat_model::ProcRef {
                pid: 1234,
                start_time_unix_ms: 1,
            }],
            failed: vec![],
        }),
        forced: false,
        draws: 1,
    };
    assert_eq!(
        stopcat_cli::tui::exit_line(&m, &end),
        "stopcat: 지킴이를 멈췄어요. 낮춘 우선순위 1건을 되돌렸어요."
    );
}
