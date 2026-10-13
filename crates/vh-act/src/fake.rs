//! 테스트용 가짜 prober·signaler. 커널 호출 0회.

use crate::{FakeProber, FakeSignaler, FakeWorld, LiveProc, Prober, SharedWorld, Signaler};

impl FakeWorld {
    /// 프로세스를 넣고 부모의 자식 목록에 붙인다.
    pub fn insert(&mut self, p: LiveProc) {
        let kids = self.children.entry(p.ppid).or_default();
        if !kids.contains(&p.pid) {
            kids.push(p.pid);
        }
        self.procs.insert(p.pid, p);
    }

    /// 프로세스를 없애고 그 자식을 launchd(1) 아래로 옮긴다(커널과 같은 재부모화).
    pub fn remove(&mut self, pid: i32) {
        self.procs.remove(&pid);
        for kid in self.children.remove(&pid).unwrap_or_default() {
            if let Some(k) = self.procs.get_mut(&kid) {
                k.ppid = 1;
                self.children.entry(1).or_default().push(kid);
            }
        }
    }

    /// 공유 핸들로 감싼다.
    pub fn shared(self) -> SharedWorld {
        std::rc::Rc::new(std::cell::RefCell::new(self))
    }
}

impl FakeProber {
    /// 가짜 세계와 자기 pid·uid로 만든다(조상 없음, 시계 0).
    pub fn with_world(world: SharedWorld, self_pid: i32, self_uid: u32) -> Self {
        FakeProber {
            world,
            self_pid,
            self_uid,
            ..FakeProber::default()
        }
    }
}

impl FakeSignaler {
    /// 신호 효과를 가짜 세계에 반영하는 signaler.
    pub fn with_world(world: SharedWorld) -> Self {
        FakeSignaler {
            world: Some(world),
            ..FakeSignaler::default()
        }
    }

    /// 지금까지 받은 호출 수(신호 + demote).
    pub fn calls(&self) -> usize {
        self.sent.borrow().len() + self.demoted.borrow().len()
    }
}

impl Prober for FakeProber {
    fn probe(&self, pid: i32) -> LiveProc {
        self.world
            .borrow()
            .procs
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| LiveProc::gone(pid))
    }

    fn children(&self, pid: i32) -> Vec<i32> {
        let w = self.world.borrow();
        w.children
            .get(&pid)
            .map(|kids| {
                kids.iter()
                    .copied()
                    .filter(|k| w.procs.contains_key(k))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn self_pid(&self) -> i32 {
        self.self_pid
    }

    fn self_uid(&self) -> u32 {
        self.self_uid
    }

    fn ancestors_of_self(&self) -> Vec<i32> {
        self.ancestors.clone()
    }

    fn get_bg(&self, pid: i32) -> Result<i32, i32> {
        let w = self.world.borrow();
        if !w.procs.contains_key(&pid) {
            return Err(libc::ESRCH);
        }
        Ok(w.bg.get(&pid).copied().unwrap_or(0))
    }

    fn now_unix_ms(&self) -> u64 {
        self.clock_ms.get()
    }

    fn sleep_ms(&self, ms: u64) {
        self.clock_ms.set(self.clock_ms.get() + ms);
    }
}

impl Signaler for FakeSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        self.sent.borrow_mut().push((pid, sig));
        if let Some(e) = self.fail_with {
            return Err(e);
        }
        let Some(world) = &self.world else {
            return Ok(());
        };
        let mut w = world.borrow_mut();
        if !w.procs.contains_key(&pid) {
            return Err(libc::ESRCH);
        }
        match sig {
            libc::SIGCONT => {
                if let Some(p) = w.procs.get_mut(&pid) {
                    p.stopped = false;
                }
            }
            libc::SIGTERM => {
                for kid in w.spawn_on_term.remove(&pid).unwrap_or_default() {
                    w.insert(kid);
                }
                if !w.ignore_term.contains(&pid) {
                    w.remove(pid);
                }
            }
            libc::SIGKILL => w.remove(pid),
            _ => return Err(libc::EINVAL),
        }
        Ok(())
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        self.demoted.borrow_mut().push(pid);
        if let Some(e) = self.fail_with {
            return Err(e);
        }
        let Some(world) = &self.world else {
            return Ok(());
        };
        let mut w = world.borrow_mut();
        if !w.procs.contains_key(&pid) {
            return Err(libc::ESRCH);
        }
        w.bg.insert(pid, libc::PRIO_DARWIN_BG);
        Ok(())
    }
}
