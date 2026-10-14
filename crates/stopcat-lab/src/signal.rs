//! 2겹 격리: stopcat-guard `AllowListSignaler`(실험실 pid만) 바깥에서 모든 신호 호출을 기록한다.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use stopcat_act::Signaler;
use stopcat_guard::AllowListSignaler;

use crate::notify::NotifyRec;
use crate::util::now_ms;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalCall {
    pub at_ms: u64,
    pub op: String,
    pub pid: i32,
    pub sig: Option<i32>,
    pub allowed: bool,
    pub ok: bool,
    pub errno: Option<i32>,
}

pub type SignalLog = Arc<Mutex<Vec<SignalCall>>>;

pub struct RecordingSignaler {
    inner: AllowListSignaler,
    log: SignalLog,
}

impl RecordingSignaler {
    pub fn new(real: Box<dyn Signaler + Send>, allowed: BTreeSet<i32>) -> (Self, SignalLog) {
        let log: SignalLog = Arc::default();
        (
            RecordingSignaler {
                inner: AllowListSignaler::new(real, allowed),
                log: log.clone(),
            },
            log,
        )
    }

    fn record(&self, op: &str, pid: i32, sig: Option<i32>, r: Result<(), i32>) -> Result<(), i32> {
        let call = SignalCall {
            at_ms: now_ms(),
            op: op.to_string(),
            pid,
            sig,
            allowed: self.inner.allowed().contains(&pid),
            ok: r.is_ok(),
            errno: r.err(),
        };
        if let Ok(mut l) = self.log.lock() {
            l.push(call);
        }
        r
    }
}

impl Signaler for RecordingSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        let r = self.inner.send(pid, sig);
        self.record("send", pid, Some(sig), r)
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        let r = self.inner.demote(pid);
        self.record("demote", pid, None, r)
    }

    fn undemote(&self, pid: i32) -> Result<(), i32> {
        let r = self.inner.undemote(pid);
        self.record("undemote", pid, None, r)
    }
}

/// 기록용 가짜 notifier(실제 osascript 0회).
pub struct RecordingNotifier {
    log: Arc<Mutex<Vec<NotifyRec>>>,
}

impl RecordingNotifier {
    pub fn new() -> (Self, Arc<Mutex<Vec<NotifyRec>>>) {
        let log: Arc<Mutex<Vec<NotifyRec>>> = Arc::default();
        (RecordingNotifier { log: log.clone() }, log)
    }
}

impl stopcat_guard::Notifier for RecordingNotifier {
    fn notify(&mut self, title: &str, body: &str) -> Result<(), String> {
        if let Ok(mut l) = self.log.lock() {
            l.push(NotifyRec {
                at_ms: now_ms(),
                title: title.to_string(),
                body: body.to_string(),
            });
        }
        Ok(())
    }
}
