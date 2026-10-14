//! 지킴이 → 화면 갱신 우편함. 받지 않은 갱신은 쌓지 않고 최신 하나로 합친다.
//! 합칠 때 스냅샷·리포트·정책·상태는 새것을 쓰고, `new_events`는 옛것 뒤에 새것을 이어 붙여
//! 하나도 버리지 않는다. 수동 실행 결과(`manual_result`)도 잃지 않는다: 둘 다 있으면 합치지 않고
//! 뒤에 붙이므로 큐 길이는 1 + 아직 받지 않은 수동 결과 수를 넘지 않는다.

use std::collections::VecDeque;
use std::sync::mpsc::{RecvError, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::handle::GuardUpdate;

struct Inner {
    queue: VecDeque<GuardUpdate>,
    sender_alive: bool,
    receiver_alive: bool,
}

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// 보내는 쪽(지킴이 스레드). Drop하면 받는 쪽은 남은 갱신을 다 받은 뒤 `Disconnected`를 본다.
pub struct UpdateSender {
    shared: Arc<Shared>,
}

/// 받는 쪽(화면). 오류 형은 `std::sync::mpsc`의 것을 그대로 쓴다.
pub struct UpdateReceiver {
    shared: Arc<Shared>,
}

pub fn mailbox() -> (UpdateSender, UpdateReceiver) {
    let shared = Arc::new(Shared {
        inner: Mutex::new(Inner {
            queue: VecDeque::new(),
            sender_alive: true,
            receiver_alive: true,
        }),
        cv: Condvar::new(),
    });
    (
        UpdateSender {
            shared: Arc::clone(&shared),
        },
        UpdateReceiver { shared },
    )
}

fn merge_into(last: &mut GuardUpdate, mut new: GuardUpdate) -> GuardUpdate {
    let mut events = std::mem::take(&mut last.new_events);
    events.append(&mut new.new_events);
    new.new_events = events;
    if new.manual_result.is_none() {
        new.manual_result = last.manual_result.take();
    }
    std::mem::replace(last, new)
}

impl UpdateSender {
    /// 받는 쪽이 사라졌으면 갱신을 그대로 돌려준다.
    pub fn send(&self, u: GuardUpdate) -> Result<(), Box<GuardUpdate>> {
        let mut g = self.shared.lock();
        if !g.receiver_alive {
            return Err(Box::new(u));
        }
        let mut displaced = None;
        match g.queue.back_mut() {
            Some(last) if !(last.manual_result.is_some() && u.manual_result.is_some()) => {
                displaced = Some(merge_into(last, u));
            }
            _ => g.queue.push_back(u),
        }
        drop(g);
        self.shared.cv.notify_all();
        drop(displaced);
        Ok(())
    }
}

impl Drop for UpdateSender {
    fn drop(&mut self) {
        self.shared.lock().sender_alive = false;
        self.shared.cv.notify_all();
    }
}

impl UpdateReceiver {
    pub fn try_recv(&self) -> Result<GuardUpdate, TryRecvError> {
        let mut g = self.shared.lock();
        match g.queue.pop_front() {
            Some(u) => Ok(u),
            None if g.sender_alive => Err(TryRecvError::Empty),
            None => Err(TryRecvError::Disconnected),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<GuardUpdate, RecvTimeoutError> {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return self.recv().map_err(|_| RecvTimeoutError::Disconnected);
        };
        let mut g = self.shared.lock();
        loop {
            if let Some(u) = g.queue.pop_front() {
                return Ok(u);
            }
            if !g.sender_alive {
                return Err(RecvTimeoutError::Disconnected);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(RecvTimeoutError::Timeout);
            }
            g = self
                .shared
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    pub fn recv(&self) -> Result<GuardUpdate, RecvError> {
        let mut g = self.shared.lock();
        loop {
            if let Some(u) = g.queue.pop_front() {
                return Ok(u);
            }
            if !g.sender_alive {
                return Err(RecvError);
            }
            g = self
                .shared
                .cv
                .wait(g)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// `Receiver::iter`와 같다: 보내는 쪽이 끝날 때까지 기다리며 받는다.
    pub fn iter(&self) -> impl Iterator<Item = GuardUpdate> + '_ {
        std::iter::from_fn(move || self.recv().ok())
    }

    /// `Receiver::try_iter`와 같다: 지금 있는 것만 받고 기다리지 않는다.
    pub fn try_iter(&self) -> impl Iterator<Item = GuardUpdate> + '_ {
        std::iter::from_fn(move || self.try_recv().ok())
    }

    /// 아직 받지 않은 갱신 수(합친 뒤). 보통 0 또는 1.
    pub fn pending(&self) -> usize {
        self.shared.lock().queue.len()
    }
}

impl Drop for UpdateReceiver {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.receiver_alive = false;
        let queued = std::mem::take(&mut g.queue);
        drop(g);
        drop(queued);
    }
}

impl std::fmt::Debug for UpdateSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateSender").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for UpdateReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateReceiver")
            .field("pending", &self.pending())
            .finish()
    }
}
