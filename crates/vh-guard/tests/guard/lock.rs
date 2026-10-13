//! VH_E2E_ALLOW_PIDS 잠금(Q4 A). 커널 호출 0회(안쪽은 FakeSignaler).

use std::collections::BTreeSet;

use vh_act::Signaler;
use vh_guard::AllowListSignaler;
use vh_guard::fake::{SignalLog, SyncSignaler, SyncWorld};
use vh_guard::lock::EPERM;

fn fake() -> Box<SyncSignaler> {
    let world = SyncWorld::default();
    world.with(|w| w.insert(vh_act::LiveProc::alive(4242, 1, 1, 501, None)));
    Box::new(SyncSignaler {
        world,
        log: SignalLog::default(),
        fail_with: None,
    })
}

#[test]
fn blocks_all_three_methods_outside_the_list() {
    let g = AllowListSignaler::new(fake(), BTreeSet::from([4242]));
    assert_eq!(g.send(4242, libc::SIGCONT), Ok(()));
    assert_eq!(g.demote(4242), Ok(()));
    assert_eq!(g.undemote(4242), Ok(()));
    assert_eq!(g.send(777, libc::SIGTERM), Err(EPERM));
    assert_eq!(g.demote(777), Err(EPERM));
    assert_eq!(g.undemote(777), Err(EPERM));
    assert_eq!(g.blocked_pids(), vec![777, 777, 777]);
}

#[test]
fn empty_or_garbage_list_blocks_everything() {
    for raw in ["", " ", "abc", "0,1,-5"] {
        let g = AllowListSignaler::from_env_value(fake(), raw);
        assert!(g.allowed().is_empty(), "{raw:?}");
        assert_eq!(g.send(4242, libc::SIGTERM), Err(EPERM));
        assert_eq!(g.undemote(4242), Err(EPERM));
    }
    assert_eq!(
        AllowListSignaler::parse_allow("123, 456,abc,"),
        BTreeSet::from([123, 456])
    );
}

#[test]
fn default_trait_undemote_refuses() {
    struct OnlyKill;
    impl Signaler for OnlyKill {
        fn send(&self, _: i32, _: i32) -> Result<(), i32> {
            Ok(())
        }
        fn demote(&self, _: i32) -> Result<(), i32> {
            Ok(())
        }
    }
    assert_eq!(OnlyKill.undemote(4242), Err(libc::EPERM));
}

#[test]
fn signaler_from_env_locks_when_value_present_even_empty() {
    use vh_guard::backend::{notify_disabled, signaler_from_env};
    let (s, locked) = signaler_from_env(Some(""));
    assert_eq!(locked, Some(BTreeSet::new()));
    assert_eq!(s.send(4242, libc::SIGTERM), Err(EPERM));
    assert_eq!(s.demote(4242), Err(EPERM));
    assert_eq!(s.undemote(4242), Err(EPERM));
    let (s, locked) = signaler_from_env(Some("4242, 77"));
    assert_eq!(locked, Some(BTreeSet::from([77, 4242])));
    assert_eq!(s.undemote(5000), Err(EPERM));
    let (_, locked) = signaler_from_env(None);
    assert_eq!(locked, None);
    for v in ["off", "OFF", "0", "false", "no"] {
        assert!(notify_disabled(Some(v)), "{v}");
    }
    for v in ["on", "", "1"] {
        assert!(!notify_disabled(Some(v)), "{v}");
    }
    assert!(!notify_disabled(None));
}
