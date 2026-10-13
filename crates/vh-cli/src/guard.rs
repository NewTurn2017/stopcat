//! e2e 안전 잠금: `VH_E2E_ALLOW_PIDS`(쉼표 구분 pid)가 있으면 목록 밖 pid에는 신호·demote를
//! 보내지 않고 EPERM으로 거부한다. 값이 비었거나 숫자가 없으면 모두 거부(닫힌 쪽으로 실패).

use std::cell::RefCell;
use std::collections::BTreeSet;

use vh_act::Signaler;

pub const ENV: &str = "VH_E2E_ALLOW_PIDS";

/// macOS `EPERM`.
pub const EPERM: i32 = 1;

pub fn parse_allow(raw: &str) -> BTreeSet<i32> {
    raw.split(',')
        .filter_map(|p| p.trim().parse::<i32>().ok())
        .filter(|p| *p > 1)
        .collect()
}

pub struct AllowListSignaler<'a> {
    inner: &'a dyn Signaler,
    allowed: BTreeSet<i32>,
    echo_stderr: bool,
    pub blocked: RefCell<Vec<i32>>,
}

impl<'a> AllowListSignaler<'a> {
    pub fn new(inner: &'a dyn Signaler, allowed: BTreeSet<i32>, echo_stderr: bool) -> Self {
        AllowListSignaler {
            inner,
            allowed,
            echo_stderr,
            blocked: RefCell::new(Vec::new()),
        }
    }

    fn permit(&self, pid: i32, what: &str) -> bool {
        if self.allowed.contains(&pid) {
            return true;
        }
        self.blocked.borrow_mut().push(pid);
        if self.echo_stderr {
            eprintln!(
                "vh: {ENV} 잠금 — pid {pid} 은 허용 목록에 없어 {what}을(를) 보내지 않았어요"
            );
        }
        false
    }
}

impl Signaler for AllowListSignaler<'_> {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        if !self.permit(pid, &format!("신호 {sig}")) {
            return Err(EPERM);
        }
        self.inner.send(pid, sig)
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        if !self.permit(pid, "우선순위 낮추기") {
            return Err(EPERM);
        }
        self.inner.demote(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vh_act::FakeSignaler;

    const TERM: i32 = 15;

    #[test]
    fn parse_is_closed_by_default() {
        assert_eq!(parse_allow("123, 456,abc,"), BTreeSet::from([123, 456]));
        assert!(parse_allow("").is_empty());
        assert!(parse_allow("0,1,-5").is_empty());
    }

    #[test]
    fn only_listed_pids_reach_inner() {
        let fake = FakeSignaler::default();
        let g = AllowListSignaler::new(&fake, BTreeSet::from([4242]), false);
        assert_eq!(g.send(4242, TERM), Ok(()));
        assert_eq!(g.send(777, TERM), Err(EPERM));
        assert_eq!(g.demote(777), Err(EPERM));
        assert_eq!(g.demote(4242), Ok(()));
        assert_eq!(*fake.sent.borrow(), vec![(4242, TERM)]);
        assert_eq!(*fake.demoted.borrow(), vec![4242]);
        assert_eq!(*g.blocked.borrow(), vec![777, 777]);
    }

    #[test]
    fn empty_list_blocks_everything() {
        let fake = FakeSignaler::default();
        let g = AllowListSignaler::new(&fake, parse_allow(""), false);
        assert_eq!(g.send(4242, TERM), Err(EPERM));
        assert_eq!(fake.calls(), 0);
    }
}
