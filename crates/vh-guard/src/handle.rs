//! 지킴이 스레드 하나와 그 손잡이. 어떤 종료 경로(Shutdown·손잡이 Drop·수신자 끊김·스캔 패닉)에서도
//! 낮춘 우선순위를 되돌리고 나서 스레드가 끝난다.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use vh_model::{
    ActionOutcome, ActionPlan, AutoLevel, GuardEvent, GuardPolicy, GuardStatus, ProcRef, Report,
    Snapshot,
};

use crate::backend::GuardBackend;
use crate::engine::Engine;
use crate::mailbox::{UpdateReceiver, UpdateSender, mailbox};

/// 화면 → 지킴이. 보내기는 막히지 않는다.
#[derive(Debug, Clone)]
pub enum GuardCommand {
    Pause,
    Resume,
    SetLevel(AutoLevel),
    SetScanInterval(u32),
    ResetCircuit,
    UndoDemote(ProcRef),
    ScanNow,
    /// 화면에서 사용자가 확인한 정리. 자동 종료 속도 제한에는 세지 않고, 그 Demote는 종료 때 되돌린다.
    RunPlan {
        request_id: u64,
        plan: ActionPlan,
        snapshot: Arc<Snapshot>,
    },
    /// 낮춘 것을 되돌리고 스레드를 끝낸다.
    Shutdown,
}

/// `RunPlan`의 결과.
#[derive(Debug, Clone, PartialEq)]
pub struct ManualRunResult {
    pub request_id: u64,
    pub outcomes: Vec<ActionOutcome>,
    pub state_dir: PathBuf,
}

/// 지킴이 → 화면. 스캔마다 하나, 명령 처리 뒤에도 하나(스냅샷·리포트는 마지막 것을 공유).
#[derive(Debug, Clone)]
pub struct GuardUpdate {
    pub snapshot: Arc<Snapshot>,
    pub report: Arc<Report>,
    pub policy: Arc<GuardPolicy>,
    pub status: GuardStatus,
    pub new_events: Vec<GuardEvent>,
    pub manual_result: Option<ManualRunResult>,
}

/// 종료 요약.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShutdownReport {
    pub undemoted: Vec<ProcRef>,
    /// (대상, errno). 되돌리지 못한 것(감사 로그에도 남는다).
    pub failed: Vec<(ProcRef, i32)>,
}

/// 스레드가 이미 끝났다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardGone;

impl std::fmt::Display for GuardGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("지킴이 스레드가 멈췄어요")
    }
}

impl std::error::Error for GuardGone {}

/// 지킴이 손잡이. Drop하면 Shutdown을 보내고 join한다(패닉 되감기 중에도).
pub struct GuardHandle {
    tx: Sender<GuardCommand>,
    join: Option<JoinHandle<ShutdownReport>>,
}

impl std::fmt::Debug for GuardHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardHandle")
            .field("alive", &self.is_alive())
            .finish()
    }
}

impl GuardHandle {
    /// 스레드 이름 "vh-guard". 띄우자마자 첫 스캔을 하고 첫 `GuardUpdate`를 보낸다.
    pub fn spawn<B: GuardBackend>(
        policy: GuardPolicy,
        backend: B,
    ) -> (GuardHandle, UpdateReceiver) {
        Self::spawn_with(policy, backend, false)
    }

    /// `level_locked_by_env`가 true면 `SetLevel`을 거부한다(상태에 `level_locked_by_env`).
    pub fn spawn_with<B: GuardBackend>(
        policy: GuardPolicy,
        backend: B,
        level_locked_by_env: bool,
    ) -> (GuardHandle, UpdateReceiver) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<GuardCommand>();
        let (upd_tx, upd_rx) = mailbox();
        let join = std::thread::Builder::new()
            .name("vh-guard".to_string())
            .spawn(move || {
                let mut engine =
                    Engine::new(policy, backend).level_locked_by_env(level_locked_by_env);
                let _ = catch_unwind(AssertUnwindSafe(|| run_loop(&mut engine, &cmd_rx, &upd_tx)));
                let (report, events) = engine.restore_all();
                if let Some(final_update) = engine.update_after(events, None) {
                    let _ = upd_tx.send(final_update);
                }
                report
            })
            .expect("지킴이 스레드 생성");
        (
            GuardHandle {
                tx: cmd_tx,
                join: Some(join),
            },
            upd_rx,
        )
    }

    pub fn send(&self, cmd: GuardCommand) -> Result<(), GuardGone> {
        self.tx.send(cmd).map_err(|_| GuardGone)
    }

    pub fn pause(&self) -> Result<(), GuardGone> {
        self.send(GuardCommand::Pause)
    }

    pub fn resume(&self) -> Result<(), GuardGone> {
        self.send(GuardCommand::Resume)
    }

    pub fn set_level(&self, level: AutoLevel) -> Result<(), GuardGone> {
        self.send(GuardCommand::SetLevel(level))
    }

    pub fn set_scan_interval(&self, ms: u32) -> Result<(), GuardGone> {
        self.send(GuardCommand::SetScanInterval(ms))
    }

    pub fn reset_circuit(&self) -> Result<(), GuardGone> {
        self.send(GuardCommand::ResetCircuit)
    }

    pub fn undo_demote(&self, target: ProcRef) -> Result<(), GuardGone> {
        self.send(GuardCommand::UndoDemote(target))
    }

    pub fn scan_now(&self) -> Result<(), GuardGone> {
        self.send(GuardCommand::ScanNow)
    }

    pub fn run_plan(
        &self,
        request_id: u64,
        plan: ActionPlan,
        snapshot: Arc<Snapshot>,
    ) -> Result<(), GuardGone> {
        self.send(GuardCommand::RunPlan {
            request_id,
            plan,
            snapshot,
        })
    }

    pub fn is_alive(&self) -> bool {
        self.join.as_ref().is_some_and(|j| !j.is_finished())
    }

    /// Shutdown을 보내고 스레드가 낮춘 것을 되돌릴 때까지 기다린다(join).
    pub fn shutdown(mut self) -> ShutdownReport {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> ShutdownReport {
        let _ = self.tx.send(GuardCommand::Shutdown);
        match self.join.take() {
            Some(j) => j.join().unwrap_or_default(),
            None => ShutdownReport::default(),
        }
    }
}

impl Drop for GuardHandle {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.shutdown_inner();
        }
    }
}

fn run_loop<B: GuardBackend>(
    engine: &mut Engine<B>,
    rx: &Receiver<GuardCommand>,
    tx: &UpdateSender,
) {
    if !scan_and_send(engine, tx) {
        return;
    }
    loop {
        let wait = engine
            .next_scan_at_unix_ms()
            .saturating_sub(engine.now_unix_ms());
        match rx.recv_timeout(Duration::from_millis(wait)) {
            Ok(GuardCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
            Ok(GuardCommand::ScanNow) | Err(RecvTimeoutError::Timeout) => {
                if !scan_and_send(engine, tx) {
                    return;
                }
            }
            Ok(cmd) => {
                let update = match catch_unwind(AssertUnwindSafe(|| engine.handle(cmd))) {
                    Ok(u) => u,
                    Err(p) => engine.record_panic("명령 처리", &p),
                };
                if let Some(u) = update
                    && tx.send(u).is_err()
                {
                    return;
                }
            }
        }
    }
}

/// false = 수신자가 사라졌다(되돌리고 끝낸다).
fn scan_and_send<B: GuardBackend>(engine: &mut Engine<B>, tx: &UpdateSender) -> bool {
    let update = match catch_unwind(AssertUnwindSafe(|| engine.scan())) {
        Ok(u) => u,
        Err(p) => engine.record_panic("스캔", &p),
    };
    match update {
        Some(u) => tx.send(u).is_ok(),
        None => true,
    }
}
