//! W4 계획 출처(PlanOrigin)와 R18(쓰고 있음)·R19(자동 우선순위 낮추기) 바닥 규칙. 커널 호출 0회.

use vh_act::rule::*;
use vh_act::*;
use vh_model::*;

use crate::common::*;

const DEMO: &str = "/Users/demo/dev/shop/node_modules/.bin/vite";

fn user(pid: i32, ppid: i32, start: u64) -> Proc {
    proc_(pid, ppid, SELF_UID, start, Some(DEMO))
}

fn usage(state: UsageState, reasons: Vec<UsageReason>) -> Usage {
    Usage {
        state,
        reasons,
        ..Usage::default()
    }
}

fn classified_with(t: ProcRef, u: Usage) -> Classified {
    let mut c = classified(t, Kind::DevServer);
    c.usage = u;
    c
}

fn policy(origin: PlanOrigin) -> Policy {
    Policy {
        origin,
        allow_demote: true,
        ..Policy::default()
    }
}

fn terminate(t: ProcRef) -> Finding {
    finding(
        "orphan:a",
        Confidence::Confirmed,
        vec![t],
        Suggestion::Terminate {
            include_descendants: true,
        },
    )
}

fn rule_of(p: &ActionPlan, t: ProcRef) -> Option<&str> {
    p.refused
        .iter()
        .find(|r| r.target == t)
        .map(|r| r.rule.as_str())
}

fn all_selection() -> Selection {
    Selection {
        min_confidence: Confidence::Possible,
        ..Selection::default()
    }
}

fn signals_after_execute(s: &Snapshot, p: &ActionPlan) -> usize {
    let world = world_from(s).shared();
    let prober = FakeProber::with_world(world.clone(), SELF_PID, SELF_UID);
    let sig = FakeSignaler::with_world(world);
    let dir = tempfile::tempdir().unwrap();
    let env = ExecEnv {
        signaler: &sig,
        prober: &prober,
        state_dir: dir.path().to_path_buf(),
        snapshot: s,
        run_id: "origin".into(),
    };
    let _ = execute(p, &env);
    sig.sent.borrow().len() + sig.demoted.borrow().len()
}

#[test]
fn policy_default_origin_is_bulk_and_missing_field_reads_as_bulk() {
    assert_eq!(Policy::default().origin, PlanOrigin::Bulk);
    let json = r#"{"grace_ms":3000,"include_descendants":null,"allow_demote":false,"total_deadline_ms":60000,"max_actions":50}"#;
    let p: Policy = serde_json::from_str(json).unwrap();
    assert_eq!(p.origin, PlanOrigin::Bulk);
    assert_eq!(
        serde_json::to_string(&PlanOrigin::Pointed).unwrap(),
        "\"pointed\""
    );
}

#[test]
fn r18_auto_and_bulk_refuse_active_target_pointed_plans_it() {
    let t = pref(2000, 5);
    let s = snapshot(SELF_PID, SELF_UID, vec![user(2000, 1, 5)]);
    let r = report(
        vec![classified_with(
            t,
            usage(UsageState::Active, vec![UsageReason::CpuActive]),
        )],
        vec![terminate(t)],
    );
    for origin in [PlanOrigin::Auto, PlanOrigin::Bulk] {
        let p = plan(&s, &r, &all_selection(), &policy(origin));
        assert!(p.items.is_empty(), "{origin:?}: {:?}", p.items);
        assert_eq!(rule_of(&p, t), Some(R18_IN_USE), "{origin:?}");
        assert!(p.refused[0].reason_ko.contains("CPU를 쓰는 중"));
        assert_eq!(signals_after_execute(&s, &p), 0, "{origin:?}");
    }
    let p = plan(&s, &r, &all_selection(), &policy(PlanOrigin::Pointed));
    assert_eq!(p.items.len(), 1);
    assert!(p.refused.is_empty());
    let u = in_use_reasons(&s, &r, t).expect("직접 지목 경고용 근거");
    assert_eq!(u.at, t);
    assert_eq!(u.state, Some(UsageState::Active));
    assert_eq!(u.reasons, vec![UsageReason::CpuActive]);
}

#[test]
fn r18_unknown_usage_and_missing_classification_count_as_in_use() {
    let a = pref(2000, 5);
    let b = pref(2001, 5);
    let s = snapshot(SELF_PID, SELF_UID, vec![user(2000, 1, 5), user(2001, 1, 5)]);
    let r = report(
        vec![classified_with(
            a,
            usage(UsageState::Unknown, vec![UsageReason::DiskUnknown]),
        )],
        vec![terminate(a), {
            let mut f = terminate(b);
            f.id = "orphan:b".into();
            f
        }],
    );
    let p = plan(&s, &r, &all_selection(), &policy(PlanOrigin::Auto));
    assert!(p.items.is_empty());
    assert_eq!(rule_of(&p, a), Some(R18_IN_USE));
    assert_eq!(rule_of(&p, b), Some(R18_IN_USE));
    assert_eq!(
        in_use_reasons(&s, &r, a).unwrap().state,
        Some(UsageState::Unknown)
    );
    let none = in_use_reasons(&s, &r, b).unwrap();
    assert_eq!(
        (none.at, none.state),
        (b, None),
        "분류 없음 = 쓰고 있음(닫힌 쪽)"
    );
}

#[test]
fn r18_descendant_in_use_refuses_parent_and_zombie_descendant_is_ignored() {
    let parent = pref(2000, 5);
    let child = pref(2001, 6);
    let mut zombie = user(2002, 2000, 7);
    zombie.status = ProcStatus::Zombie;
    let s = snapshot(
        SELF_PID,
        SELF_UID,
        vec![user(2000, 1, 5), user(2001, 2000, 6), zombie],
    );
    let r = report(
        vec![
            classified_with(parent, idle_usage()),
            classified_with(
                child,
                usage(UsageState::Active, vec![UsageReason::PeerOutsideSubtree]),
            ),
        ],
        vec![terminate(parent)],
    );
    let p = plan(&s, &r, &all_selection(), &policy(PlanOrigin::Bulk));
    assert!(p.items.is_empty());
    assert_eq!(rule_of(&p, parent), Some(R18_IN_USE));
    assert!(p.refused[0].reason_ko.contains("자손 pid 2001"));
    assert_eq!(in_use_reasons(&s, &r, parent).unwrap().at, child);

    let mut idle = r.clone();
    idle.classified[1].usage = idle_usage();
    let p = plan(&s, &idle, &all_selection(), &policy(PlanOrigin::Auto));
    assert_eq!(
        p.items.len(),
        1,
        "자손이 모두 안 씀이면 자동도 계획(좀비 자손은 보지 않음)"
    );
    assert!(in_use_reasons(&s, &idle, parent).is_none());
}

#[test]
fn r18_direct_target_bulk_refused_pointed_allowed() {
    let t = pref(2000, 5);
    let s = snapshot(SELF_PID, SELF_UID, vec![user(2000, 1, 5)]);
    let r = report(
        vec![classified_with(
            t,
            usage(UsageState::Active, vec![UsageReason::HasTty]),
        )],
        Vec::new(),
    );
    let sel = Selection {
        direct: vec![DirectTarget {
            target: t,
            include_descendants: false,
        }],
        ..Selection::default()
    };
    let p = plan(&s, &r, &sel, &Policy::default());
    assert_eq!(rule_of(&p, t), Some(R18_IN_USE));
    let p = plan(&s, &r, &sel, &policy(PlanOrigin::Pointed));
    assert_eq!(p.items.len(), 1);
}

#[test]
fn r18_does_not_touch_resume() {
    let t = pref(2000, 5);
    let mut stopped = user(2000, 1, 5);
    stopped.status = ProcStatus::Stopped;
    let s = snapshot(SELF_PID, SELF_UID, vec![stopped]);
    let r = report(
        vec![classified_with(
            t,
            usage(UsageState::Active, vec![UsageReason::OwnerAlive]),
        )],
        vec![finding(
            "stopped:a",
            Confidence::Confirmed,
            vec![t],
            Suggestion::Resume,
        )],
    );
    let p = plan(&s, &r, &all_selection(), &policy(PlanOrigin::Auto));
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].steps, vec![Step::Cont]);
}

#[test]
fn r19_auto_demote_refused_in_plan_and_plan_priority_undemote_allowed() {
    let t = pref(2000, 5);
    let s = snapshot(SELF_PID, SELF_UID, vec![user(2000, 1, 5)]);
    let r = report(
        vec![classified_with(t, idle_usage())],
        vec![finding(
            "cpu:a",
            Confidence::Confirmed,
            vec![t],
            Suggestion::Demote,
        )],
    );
    let p = plan(&s, &r, &all_selection(), &policy(PlanOrigin::Auto));
    assert!(p.items.is_empty());
    assert_eq!(rule_of(&p, t), Some(R19_AUTO_DEMOTE_OFF));
    assert_eq!(signals_after_execute(&s, &p), 0);
    for origin in [PlanOrigin::Bulk, PlanOrigin::Pointed] {
        let p = plan(&s, &r, &all_selection(), &policy(origin));
        assert_eq!(p.items.len(), 1, "{origin:?}");
        assert_eq!(p.items[0].steps, vec![Step::Demote]);
    }

    let demote = [PriorityTarget {
        target: t,
        step: Step::Demote,
        reason_ko: "합성".into(),
    }];
    let p = plan_priority(&s, Some(&r), &demote, &policy(PlanOrigin::Auto));
    assert_eq!(rule_of(&p, t), Some(R19_AUTO_DEMOTE_OFF));
    let p = plan_priority(&s, Some(&r), &demote, &policy(PlanOrigin::Pointed));
    assert_eq!(p.items.len(), 1);
    let undo = [PriorityTarget {
        target: t,
        step: Step::Undemote,
        reason_ko: "합성".into(),
    }];
    let p = plan_priority(&s, Some(&r), &undo, &policy(PlanOrigin::Auto));
    assert_eq!(p.items.len(), 1, "되돌리기는 자동이어도 허용");
}

#[test]
fn usage_reason_ko_covers_every_code() {
    let all = [
        UsageReason::OwnerAlive,
        UsageReason::UserOwned,
        UsageReason::HasTty,
        UsageReason::PeerOutsideSubtree,
        UsageReason::PeerExternal,
        UsageReason::PeerUnresolved,
        UsageReason::CpuActive,
        UsageReason::DiskActive,
        UsageReason::Young,
        UsageReason::NoPeers,
        UsageReason::InfraPeersOnly,
        UsageReason::CpuIdle,
        UsageReason::DiskIdle,
        UsageReason::LifetimeCpuLow,
        UsageReason::CpuUnknown,
        UsageReason::DiskUnknown,
        UsageReason::PeersUnknown,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for r in all {
        let ko = usage_reason_ko(r);
        assert!(!ko.is_empty());
        assert!(seen.insert(ko), "문구 중복: {ko}");
    }
}
