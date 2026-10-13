//! 수집·분석·계획·실행·알림·시계를 바꿔 끼우는 trait과 진짜 구현.

use std::path::{Path, PathBuf};

use vh_act::{ExecEnv, Policy, PriorityTarget, RealProber, RealSignaler, Selection, Signaler};
use vh_model::{ActionOutcome, ActionPlan, Report, Snapshot};
use vh_sample::CollectOptions;

use crate::notify::{Notifier, NullNotifier, OsascriptNotifier};
use crate::{env, lock::AllowListSignaler};

/// 지킴이 백엔드. 스레드로 옮겨지므로 `Send + 'static`. 신호는 `execute` 안에서만 나간다.
pub trait GuardBackend: Send + 'static {
    /// 한 번만 샘플(`cpu_interval_ms: None`). CPU%는 엔진이 이전 스캔과의 차이로 채운다.
    fn collect(&mut self) -> Result<Snapshot, String>;
    fn analyze(&mut self, s: &Snapshot) -> Report;
    fn plan(&mut self, s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan;
    fn plan_priority(
        &mut self,
        s: &Snapshot,
        r: Option<&Report>,
        targets: &[PriorityTarget],
        policy: &Policy,
    ) -> ActionPlan;
    fn execute(&mut self, plan: &ActionPlan, s: &Snapshot, run_id: &str) -> Vec<ActionOutcome>;
    fn notify(&mut self, title: &str, body: &str) -> Result<(), String>;
    fn now_unix_ms(&self) -> u64;
    fn state_dir(&self) -> &Path;
}

/// 진짜 백엔드: vh-sample·vh-analyze·vh-act(RealProber)·osascript.
pub struct RealGuardBackend {
    state_dir: PathBuf,
    signaler: Box<dyn Signaler + Send>,
    notifier: Box<dyn Notifier>,
}

impl std::fmt::Debug for RealGuardBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealGuardBackend")
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl RealGuardBackend {
    /// 환경을 보고 만든다: `VH_E2E_ALLOW_PIDS`가 있으면(비어 있어도) 잠금 signaler로 감싸고,
    /// `VH_NOTIFY=off`면 알림을 보내지 않는다. 상태 폴더는 `vh_act::state_dir()`(없으면 0700으로 만든다).
    pub fn new() -> std::io::Result<Self> {
        let signaler: Box<dyn Signaler + Send> = match std::env::var(env::E2E_ALLOW_PIDS) {
            Ok(raw) => Box::new(AllowListSignaler::from_env_value(
                Box::new(RealSignaler),
                &raw,
            )),
            Err(_) => Box::new(RealSignaler),
        };
        let notifier: Box<dyn Notifier> = if notify_disabled_by_env() {
            Box::new(NullNotifier)
        } else {
            Box::new(OsascriptNotifier::default())
        };
        Self::with(signaler, notifier)
    }

    /// signaler·notifier 주입. 상태 폴더는 `vh_act::state_dir()`.
    pub fn with(
        signaler: Box<dyn Signaler + Send>,
        notifier: Box<dyn Notifier>,
    ) -> std::io::Result<Self> {
        Ok(Self::with_state_dir(
            vh_act::state_dir()?,
            signaler,
            notifier,
        ))
    }

    pub fn with_state_dir(
        state_dir: PathBuf,
        signaler: Box<dyn Signaler + Send>,
        notifier: Box<dyn Notifier>,
    ) -> Self {
        RealGuardBackend {
            state_dir,
            signaler,
            notifier,
        }
    }
}

/// `VH_NOTIFY=off|0|false|no`(대소문자 무시).
pub fn notify_disabled_by_env() -> bool {
    std::env::var(env::NOTIFY)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "no"
            )
        })
        .unwrap_or(false)
}

impl GuardBackend for RealGuardBackend {
    fn collect(&mut self) -> Result<Snapshot, String> {
        Ok(vh_sample::collect(&CollectOptions {
            cpu_interval_ms: None,
            launchd: true,
            project_roots: true,
        }))
    }

    fn analyze(&mut self, s: &Snapshot) -> Report {
        vh_analyze::analyze(s)
    }

    fn plan(&mut self, s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
        vh_act::plan(s, r, sel, policy)
    }

    fn plan_priority(
        &mut self,
        s: &Snapshot,
        r: Option<&Report>,
        targets: &[PriorityTarget],
        policy: &Policy,
    ) -> ActionPlan {
        vh_act::plan_priority(s, r, targets, policy)
    }

    fn execute(&mut self, plan: &ActionPlan, s: &Snapshot, run_id: &str) -> Vec<ActionOutcome> {
        let env = ExecEnv {
            signaler: &*self.signaler,
            prober: &RealProber,
            state_dir: self.state_dir.clone(),
            snapshot: s,
            run_id: run_id.to_string(),
        };
        vh_act::execute(plan, &env)
    }

    fn notify(&mut self, title: &str, body: &str) -> Result<(), String> {
        self.notifier.notify(title, body)
    }

    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}
