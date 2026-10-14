//! 수집·분석·계획·실행·알림·시계를 바꿔 끼우는 trait과 진짜 구현.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use vh_act::{ExecEnv, Policy, PriorityTarget, RealProber, RealSignaler, Selection, Signaler};
use vh_model::{ActionOutcome, ActionPlan, HealthLevel, Report, Snapshot};
use vh_sample::CollectOptions;

use crate::notify::{Notifier, NullNotifier, OsascriptNotifier};
use crate::stability::forced_health_from;
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
    /// 시험용 강제 건강 값(W4). 엔진이 스캔마다 부르고, 실제 건강과 둘 중 높은 쪽으로 불안정을 판단한다.
    /// `Report.health`는 바꾸지 않는다. 진짜 백엔드는 `VH_E2E_FORCE_HEALTH`(+`VH_E2E_ALLOW_PIDS`)에서 읽는다.
    fn forced_health(&self) -> Option<HealthLevel> {
        None
    }
}

/// 진짜 백엔드: vh-sample·vh-analyze·vh-act(RealProber)·osascript.
pub struct RealGuardBackend {
    state_dir: PathBuf,
    signaler: Box<dyn Signaler + Send>,
    notifier: Box<dyn Notifier>,
    locked: Option<BTreeSet<i32>>,
    forced: Option<HealthLevel>,
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
        let allow = std::env::var(env::E2E_ALLOW_PIDS).ok();
        let (signaler, locked) = signaler_from_env(allow.as_deref());
        let notifier: Box<dyn Notifier> = if notify_disabled_by_env() {
            Box::new(NullNotifier)
        } else {
            Box::new(OsascriptNotifier::default())
        };
        let mut be = Self::with(signaler, notifier)?;
        be.locked = locked;
        be.forced = forced_health_from(
            std::env::var(env::E2E_FORCE_HEALTH).ok().as_deref(),
            allow.as_deref(),
        );
        Ok(be)
    }

    /// `VH_E2E_ALLOW_PIDS`로 잠겼으면 허용 목록(빈 목록 = 전부 거부). 잠기지 않았으면 None.
    pub fn locked_pids(&self) -> Option<&BTreeSet<i32>> {
        self.locked.as_ref()
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
            locked: None,
            forced: None,
        }
    }

    /// 시험용 강제 건강 값(같은 프로세스 실험실용 빌더, env를 읽지 않는다).
    pub fn with_forced_health(mut self, forced: Option<HealthLevel>) -> Self {
        self.forced = forced;
        self
    }
}

/// `VH_E2E_ALLOW_PIDS` 값이 있으면(비어 있어도) 진짜 signaler를 잠금으로 감싼다. 없으면 진짜 signaler 그대로.
/// 돌려주는 두 번째 값은 잠금 목록(없으면 None).
pub fn signaler_from_env(
    allow_pids: Option<&str>,
) -> (Box<dyn Signaler + Send>, Option<BTreeSet<i32>>) {
    match allow_pids {
        Some(raw) => {
            let lock = AllowListSignaler::from_env_value(Box::new(RealSignaler), raw);
            let allowed = lock.allowed().clone();
            (Box::new(lock), Some(allowed))
        }
        None => (Box::new(RealSignaler), None),
    }
}

/// `VH_NOTIFY=off|0|false|no`(대소문자 무시).
pub fn notify_disabled(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no"
        )
    })
}

pub fn notify_disabled_by_env() -> bool {
    notify_disabled(std::env::var(env::NOTIFY).ok().as_deref())
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

    fn forced_health(&self) -> Option<HealthLevel> {
        self.forced
    }
}
