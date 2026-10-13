//! `VH_E2E_ALLOW_PIDS` 잠금 signaler(소유형·Send, 지킴이 스레드용). vh-cli의 W1 잠금과 같은 규칙:
//! 목록 밖 pid에는 send·demote·undemote 모두 EPERM. 값이 비었거나 숫자가 없으면 전부 거부(닫힌 쪽).

use std::collections::BTreeSet;
use std::sync::Mutex;

use vh_act::Signaler;

/// macOS `EPERM`.
pub const EPERM: i32 = 1;

pub struct AllowListSignaler {
    inner: Box<dyn Signaler + Send>,
    allowed: BTreeSet<i32>,
    blocked: Mutex<Vec<i32>>,
}

impl std::fmt::Debug for AllowListSignaler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowListSignaler")
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

impl AllowListSignaler {
    pub fn new(inner: Box<dyn Signaler + Send>, allowed: BTreeSet<i32>) -> Self {
        AllowListSignaler {
            inner,
            allowed,
            blocked: Mutex::new(Vec::new()),
        }
    }

    /// 환경 변수 값(쉼표 구분 pid)으로 만든다.
    pub fn from_env_value(inner: Box<dyn Signaler + Send>, raw: &str) -> Self {
        Self::new(inner, Self::parse_allow(raw))
    }

    pub fn parse_allow(raw: &str) -> BTreeSet<i32> {
        raw.split(',')
            .filter_map(|p| p.trim().parse::<i32>().ok())
            .filter(|p| *p > 1)
            .collect()
    }

    pub fn allowed(&self) -> &BTreeSet<i32> {
        &self.allowed
    }

    /// 막힌 시도의 pid(순서대로, 중복 포함).
    pub fn blocked_pids(&self) -> Vec<i32> {
        self.blocked.lock().map(|b| b.clone()).unwrap_or_default()
    }

    fn permit(&self, pid: i32) -> bool {
        if self.allowed.contains(&pid) {
            return true;
        }
        if let Ok(mut b) = self.blocked.lock() {
            b.push(pid);
        }
        false
    }
}

impl Signaler for AllowListSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        if !self.permit(pid) {
            return Err(EPERM);
        }
        self.inner.send(pid, sig)
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        if !self.permit(pid) {
            return Err(EPERM);
        }
        self.inner.demote(pid)
    }

    fn undemote(&self, pid: i32) -> Result<(), i32> {
        if !self.permit(pid) {
            return Err(EPERM);
        }
        self.inner.undemote(pid)
    }
}
