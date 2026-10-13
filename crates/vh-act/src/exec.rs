//! execute: 신호 사다리. 신호는 여기서만, `Signaler`를 거쳐 나간다.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vh_model::{
    ActionOutcome, ActionPlan, ENV_ALLOWLIST, FinalState, PlannedAction, ProcRef, ReviveRecord,
    Step, StepResult,
};

use crate::planner::SnapIndex;
use crate::protect::check;
use crate::rule::R15_RUNTIME_CHILD_GUARD;
use crate::store::{append_audit, ensure_dir, write_revive};
use crate::{AuditEntry, AuditEvent, ExecEnv, LiveProc, Liveness, ProtectCtx};

const POLL_MS: u64 = 50;
const CONFIRM_MS: u64 = 1000;
const LATE_CHILD_GRACE_MS: u64 = 1000;
const MAX_VICTIMS: usize = 512;

struct Victim {
    r: ProcRef,
    depth: u32,
    exited: bool,
    /// 더 이상 신호하지 않는다(재사용·보호 규칙·EPERM 등).
    dropped: bool,
    killed: bool,
}

impl Victim {
    fn new(r: ProcRef, depth: u32) -> Self {
        Victim {
            r,
            depth,
            exited: false,
            dropped: false,
            killed: false,
        }
    }
    fn pending(&self) -> bool {
        !self.exited && !self.dropped
    }
}

enum Abort {
    Reused,
    Refused(String),
}

struct Run<'e, 'a> {
    env: &'e ExecEnv<'a>,
    idx: SnapIndex<'a>,
    self_pid: i32,
    self_uid: u32,
    ancestors: Vec<i32>,
    audit_failures: u32,
}

struct Item<'p> {
    a: &'p PlannedAction,
    steps: Vec<StepResult>,
    /// 자손 수집에서 이미 거부·기록한 pid(재수집 때 다시 기록하지 않는다).
    rejected: BTreeSet<i32>,
}

fn exited(live: &LiveProc, r: ProcRef) -> bool {
    live.liveness != Liveness::Alive || live.start_time_unix_ms != r.start_time_unix_ms
}

impl<'e, 'a> Run<'e, 'a> {
    fn now(&self) -> u64 {
        self.env.prober.now_unix_ms()
    }

    fn audit(
        &mut self,
        finding_id: &str,
        target: ProcRef,
        subject_pid: i32,
        event: AuditEvent,
        (ok, errno): (bool, Option<i32>),
        reason_ko: &str,
    ) {
        let entry = AuditEntry {
            at_unix_ms: self.now(),
            run_id: self.env.run_id.clone(),
            finding_id: finding_id.to_string(),
            target,
            subject_pid,
            event,
            ok,
            errno,
            reason_ko: reason_ko.to_string(),
        };
        if append_audit(&self.env.state_dir, &entry).is_err() {
            self.audit_failures += 1;
        }
    }

    fn ev(
        &mut self,
        it: &Item<'_>,
        subject: i32,
        event: AuditEvent,
        ok: bool,
        errno: Option<i32>,
        why: &str,
    ) {
        let (fid, t) = (it.a.finding_id.clone(), it.a.target);
        self.audit(&fid, t, subject, event, (ok, errno), why);
    }

    /// 신호 직전 보호 규칙(R01~R10, 실시간 값).
    fn guard(&self, r: ProcRef, live: &LiveProc) -> Option<(String, String)> {
        let ctx = ProtectCtx {
            target: r,
            live: Some(live),
            snap: self.idx.get(r),
            kind: None,
            self_pid: self.self_pid,
            self_uid: self.self_uid,
            self_ancestors: &self.ancestors,
            subtree_kinds: &[],
        };
        check(&ctx).map(|rf| (rf.rule, rf.reason_ko))
    }

    fn send(&mut self, it: &mut Item<'_>, pid: i32, step: Step) -> Result<(), i32> {
        let (sig, event) = match step {
            Step::Cont => (libc::SIGCONT, AuditEvent::Cont),
            Step::Term => (libc::SIGTERM, AuditEvent::Term),
            Step::Kill => (libc::SIGKILL, AuditEvent::Kill),
            Step::Demote => unreachable!("demote는 send를 쓰지 않는다"),
        };
        let res = self.env.signaler.send(pid, sig);
        it.steps.push(StepResult {
            step,
            pid,
            at_unix_ms: self.now(),
            ok: res.is_ok(),
            errno: res.err(),
        });
        self.ev(it, pid, event, res.is_ok(), res.err(), "");
        res
    }

    fn outcome(&mut self, it: Item<'_>, state: FinalState, note: String) -> ActionOutcome {
        let event = match state {
            FinalState::Exited => AuditEvent::Exited,
            FinalState::StillAlive => AuditEvent::StillAlive,
            FinalState::Reused => AuditEvent::Reused,
            FinalState::Vanished => AuditEvent::Vanished,
            FinalState::Skipped | FinalState::Refused => AuditEvent::Skipped,
        };
        let ok = matches!(state, FinalState::Exited);
        self.ev(&it, it.a.target.pid, event, ok, None, &note);
        self.ev(&it, it.a.target.pid, AuditEvent::ExecEnd, ok, None, "");
        let note = if self.audit_failures > 0 {
            format!("{note} (감사 로그 쓰기 실패 {}건)", self.audit_failures)
        } else {
            note
        };
        ActionOutcome {
            action: it.a.clone(),
            steps: it.steps,
            final_state: state,
            note_ko: note,
        }
    }

    fn one(&mut self, a: &PlannedAction, deadline: u64) -> ActionOutcome {
        let mut it = Item {
            a,
            steps: Vec::new(),
            rejected: BTreeSet::new(),
        };
        let t = a.target;
        self.ev(&it, t.pid, AuditEvent::ExecStart, true, None, &a.reason_ko);
        if self.now() >= deadline {
            return self.outcome(
                it,
                FinalState::Skipped,
                "전체 시간 상한을 넘어 실행하지 않았습니다".into(),
            );
        }
        let live = self.env.prober.probe(t.pid);
        if live.liveness == Liveness::Gone {
            return self.outcome(it, FinalState::Vanished, "이미 끝난 프로세스입니다".into());
        }
        if live.start_time_unix_ms != t.start_time_unix_ms {
            return self.outcome(
                it,
                FinalState::Reused,
                "PID가 다른 프로세스에 재사용되었습니다. 건드리지 않았습니다".into(),
            );
        }
        if live.liveness == Liveness::Zombie {
            return self.outcome(
                it,
                FinalState::Vanished,
                "이미 끝난 좀비 프로세스입니다(부모가 회수해야 사라집니다)".into(),
            );
        }
        if let Some((rule, why)) = self.guard(t, &live) {
            self.ev(
                &it,
                t.pid,
                AuditEvent::Precheck,
                false,
                None,
                &format!("{rule}: {why}"),
            );
            return self.outcome(it, FinalState::Refused, format!("{rule}: {why}"));
        }
        self.ev(&it, t.pid, AuditEvent::Precheck, true, None, "");

        if a.steps.iter().any(|s| matches!(s, Step::Term | Step::Kill)) {
            return self.ladder(it, &live, deadline);
        }
        if a.steps.contains(&Step::Demote) {
            let res = self.env.signaler.demote(t.pid);
            it.steps.push(StepResult {
                step: Step::Demote,
                pid: t.pid,
                at_unix_ms: self.now(),
                ok: res.is_ok(),
                errno: res.err(),
            });
            self.ev(&it, t.pid, AuditEvent::Demote, res.is_ok(), res.err(), "");
            let note = match res {
                Ok(()) => "우선순위를 백그라운드로 낮췄습니다".to_string(),
                Err(e) => format!("우선순위 낮추기 실패(errno {e})"),
            };
            return self.outcome(it, FinalState::StillAlive, note);
        }
        if a.steps.contains(&Step::Cont) {
            let note = match self.send(&mut it, t.pid, Step::Cont) {
                Ok(()) => "재개했습니다. 다음 vh 실행에서 다시 판단합니다".to_string(),
                Err(e) => format!("재개 실패(errno {e})"),
            };
            return self.outcome(it, FinalState::StillAlive, note);
        }
        self.outcome(it, FinalState::Skipped, "실행할 단계가 없습니다".into())
    }

    fn revive(&mut self, it: &Item<'_>, live: &LiveProc) -> Result<(), String> {
        let t = it.a.target;
        let snap = self.idx.get(t);
        let rec = ReviveRecord {
            target: t,
            exe: snap
                .and_then(|p| p.exe.clone())
                .or_else(|| live.exe.clone()),
            argv: snap.map(|p| p.argv.clone()).unwrap_or_default(),
            cwd: snap.and_then(|p| p.cwd.clone()),
            env: snap
                .map(|p| {
                    p.env
                        .iter()
                        .filter(|(k, _)| ENV_ALLOWLIST.contains(&k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            recorded_at_unix_ms: self.now(),
        };
        match write_revive(&self.env.state_dir, &rec, self.self_pid) {
            Ok(_) => {
                self.ev(it, t.pid, AuditEvent::ReviveSaved, true, None, "");
                Ok(())
            }
            Err(e) => {
                let errno = e.raw_os_error();
                self.ev(
                    it,
                    t.pid,
                    AuditEvent::ReviveSaved,
                    false,
                    errno,
                    &e.to_string(),
                );
                Err(e.to_string())
            }
        }
    }

    /// 실행 시점 자손 수집: 커널 재열거 ∪ 스냅샷 자손. `known`에 없는 것만 돌려준다.
    fn collect(&mut self, it: &mut Item<'_>, known: &[Victim]) -> Result<Vec<Victim>, ()> {
        let root = it.a.target;
        let mut seen: BTreeSet<i32> = known.iter().map(|v| v.r.pid).collect();
        let mut out: Vec<Victim> = Vec::new();
        let mut expanded: BTreeSet<i32> = BTreeSet::new();
        let mut q: VecDeque<(i32, u32)> = VecDeque::from([(root.pid, 0)]);
        while let Some((pid, depth)) = q.pop_front() {
            if !expanded.insert(pid) {
                continue;
            }
            let mut cands: BTreeMap<i32, Option<u64>> = self
                .env
                .prober
                .children(pid)
                .into_iter()
                .map(|c| (c, None))
                .collect();
            for p in self.idx.children(pid) {
                cands.insert(p.pid, Some(p.start_time_unix_ms));
            }
            for (c, snap_start) in cands {
                if it.rejected.contains(&c) {
                    continue;
                }
                if !seen.insert(c) {
                    if let Some(v) = known.iter().find(|v| v.r.pid == c) {
                        q.push_back((c, v.depth));
                    }
                    continue;
                }
                let live = self.env.prober.probe(c);
                if live.liveness != Liveness::Alive {
                    continue;
                }
                let r = ProcRef {
                    pid: c,
                    start_time_unix_ms: live.start_time_unix_ms,
                };
                if snap_start.is_some_and(|s| s != live.start_time_unix_ms) {
                    self.ev(
                        it,
                        c,
                        AuditEvent::Reused,
                        false,
                        None,
                        "자손 PID가 재사용되었습니다. 건너뜁니다",
                    );
                    it.rejected.insert(c);
                    continue;
                }
                if live.start_time_unix_ms < root.start_time_unix_ms {
                    self.ev(
                        it,
                        c,
                        AuditEvent::Skipped,
                        false,
                        None,
                        &format!("{R15_RUNTIME_CHILD_GUARD}: 대상보다 먼저 시작한 프로세스는 자손일 수 없습니다"),
                    );
                    it.rejected.insert(c);
                    continue;
                }
                if let Some((rule, why)) = self.guard(r, &live) {
                    self.ev(
                        it,
                        c,
                        AuditEvent::Skipped,
                        false,
                        None,
                        &format!("{R15_RUNTIME_CHILD_GUARD}: {rule}: {why}"),
                    );
                    it.rejected.insert(c);
                    continue;
                }
                out.push(Victim::new(r, depth + 1));
                if known.len() + out.len() > MAX_VICTIMS {
                    return Err(());
                }
                q.push_back((c, depth + 1));
            }
        }
        Ok(out)
    }

    /// 자손 → 대상 순으로 (필요하면 CONT 뒤) TERM. 대상이 재사용·거부면 중단.
    fn term_all(
        &mut self,
        it: &mut Item<'_>,
        vs: &mut [Victim],
        cont_target: bool,
    ) -> Result<(), Abort> {
        for v in vs.iter_mut() {
            if !v.pending() {
                continue;
            }
            let is_target = v.r == it.a.target;
            let live = self.env.prober.probe(v.r.pid);
            if live.liveness != Liveness::Alive {
                v.exited = true;
                continue;
            }
            if live.start_time_unix_ms != v.r.start_time_unix_ms {
                self.ev(
                    it,
                    v.r.pid,
                    AuditEvent::Reused,
                    false,
                    None,
                    "PID 재사용, 건너뜀",
                );
                if is_target {
                    return Err(Abort::Reused);
                }
                v.dropped = true;
                continue;
            }
            if let Some((rule, why)) = self.guard(v.r, &live) {
                let msg = format!("{rule}: {why}");
                self.ev(it, v.r.pid, AuditEvent::Skipped, false, None, &msg);
                if is_target {
                    return Err(Abort::Refused(msg));
                }
                v.dropped = true;
                continue;
            }
            if live.stopped || (is_target && cont_target) {
                let _ = self.send(it, v.r.pid, Step::Cont);
            }
            match self.send(it, v.r.pid, Step::Term) {
                Ok(()) => {}
                Err(libc::ESRCH) => v.exited = true,
                Err(_) => {}
            }
        }
        Ok(())
    }

    fn wait_exit(&mut self, vs: &mut [Victim], budget_ms: u64) {
        let t0 = self.now();
        loop {
            for v in vs.iter_mut().filter(|v| v.pending()) {
                if exited(&self.env.prober.probe(v.r.pid), v.r) {
                    v.exited = true;
                }
            }
            if !vs.iter().any(Victim::pending) || self.now().saturating_sub(t0) >= budget_ms {
                return;
            }
            self.env.prober.sleep_ms(POLL_MS);
        }
    }

    fn kill_rest(&mut self, it: &mut Item<'_>, vs: &mut [Victim]) {
        for v in vs.iter_mut() {
            if !v.pending() {
                continue;
            }
            let live = self.env.prober.probe(v.r.pid);
            if live.liveness != Liveness::Alive {
                v.exited = true;
                continue;
            }
            if live.start_time_unix_ms != v.r.start_time_unix_ms {
                self.ev(
                    it,
                    v.r.pid,
                    AuditEvent::Reused,
                    false,
                    None,
                    "PID 재사용, 건너뜀",
                );
                v.dropped = true;
                continue;
            }
            if let Some((rule, why)) = self.guard(v.r, &live) {
                self.ev(
                    it,
                    v.r.pid,
                    AuditEvent::Skipped,
                    false,
                    None,
                    &format!("{rule}: {why}"),
                );
                v.dropped = true;
                continue;
            }
            match self.send(it, v.r.pid, Step::Kill) {
                Ok(()) => v.killed = true,
                Err(libc::ESRCH) => v.exited = true,
                Err(_) => v.dropped = true,
            }
        }
    }

    fn ladder(&mut self, mut it: Item<'_>, live: &LiveProc, deadline: u64) -> ActionOutcome {
        let a = it.a;
        let t = a.target;
        if let Err(e) = self.revive(&it, live) {
            return self.outcome(
                it,
                FinalState::Skipped,
                format!("부활 기록을 저장하지 못해 실행하지 않았습니다({e})"),
            );
        }
        let mut vs = vec![Victim::new(t, 0)];
        if a.include_descendants {
            match self.collect(&mut it, &vs) {
                Ok(more) => vs.extend(more),
                Err(()) => {
                    return self.outcome(
                        it,
                        FinalState::Skipped,
                        format!("자손이 {MAX_VICTIMS}개를 넘어 실행하지 않았습니다"),
                    );
                }
            }
        }
        sort_bottom_up(&mut vs);

        let cont_target = a.steps.contains(&Step::Cont);
        if let Err(abort) = self.term_all(&mut it, &mut vs, cont_target) {
            return self.aborted(it, abort);
        }
        let grace = u64::from(a.grace_ms).min(deadline.saturating_sub(self.now()));
        self.wait_exit(&mut vs, grace);

        if a.include_descendants {
            if let Ok(mut late) = self.collect(&mut it, &vs) {
                if !late.is_empty() {
                    sort_bottom_up(&mut late);
                    let _ = self.term_all(&mut it, &mut late, false);
                    self.wait_exit(&mut late, u64::from(a.grace_ms).min(LATE_CHILD_GRACE_MS));
                    vs.extend(late);
                    sort_bottom_up(&mut vs);
                }
            }
        }

        if a.steps.contains(&Step::Kill) {
            self.kill_rest(&mut it, &mut vs);
        }
        self.wait_exit(&mut vs, CONFIRM_MS);

        let target = vs.iter().find(|v| v.r == t).map(|v| (v.exited, v.killed));
        let descendants: Vec<&Victim> = vs.iter().filter(|v| v.r != t).collect();
        let desc_note = if a.include_descendants {
            format!(
                ", 자손 {}/{}개 종료",
                descendants.iter().filter(|v| v.exited).count(),
                descendants.len()
            )
        } else {
            String::new()
        };
        match target {
            Some((true, false)) => self.outcome(
                it,
                FinalState::Exited,
                format!("TERM으로 정상 종료했습니다{desc_note}"),
            ),
            Some((true, true)) => self.outcome(
                it,
                FinalState::Exited,
                format!("유예 시간 안에 끝나지 않아 KILL로 종료했습니다{desc_note}"),
            ),
            _ => self.outcome(
                it,
                FinalState::StillAlive,
                format!("신호를 보냈지만 아직 살아 있습니다{desc_note}"),
            ),
        }
    }

    fn aborted(&mut self, it: Item<'_>, abort: Abort) -> ActionOutcome {
        match abort {
            Abort::Reused => self.outcome(
                it,
                FinalState::Reused,
                "신호 직전 PID 재사용을 발견해 멈췄습니다".into(),
            ),
            Abort::Refused(msg) => self.outcome(it, FinalState::Refused, msg),
        }
    }
}

fn sort_bottom_up(vs: &mut [Victim]) {
    vs.sort_by(|a, b| b.depth.cmp(&a.depth).then(a.r.pid.cmp(&b.r.pid)));
}

pub(crate) fn execute(plan: &ActionPlan, env: &ExecEnv<'_>) -> Vec<ActionOutcome> {
    let p = env.prober;
    let idx = SnapIndex::new(env.snapshot);
    let self_pid = p.self_pid();
    let mut ancestors = p.ancestors_of_self();
    for a in idx.ancestors(env.snapshot.self_pid) {
        if !ancestors.contains(&a) {
            ancestors.push(a);
        }
    }
    let mut run = Run {
        env,
        idx,
        self_pid,
        self_uid: p.self_uid(),
        ancestors,
        audit_failures: u32::from(ensure_dir(&env.state_dir).is_err()),
    };
    for r in &plan.refused {
        run.audit(
            "",
            r.target,
            r.target.pid,
            AuditEvent::PlanRefused,
            (false, None),
            &format!("{}: {}", r.rule, r.reason_ko),
        );
    }
    for a in &plan.items {
        run.audit(
            &a.finding_id,
            a.target,
            a.target.pid,
            AuditEvent::PlanItem,
            (true, None),
            &a.reason_ko,
        );
    }
    let deadline = p.now_unix_ms().saturating_add(plan.total_deadline_ms);
    plan.items.iter().map(|a| run.one(a, deadline)).collect()
}
