//! 동기 엔진. 스레드 없이 테스트한다. 한 스캔 = 수집 → CPU% 보간 → 분석 → 판정 → 계획·실행 → 이벤트·알림.

use std::collections::HashSet;
use std::sync::Arc;

use vh_act::{Policy, PriorityTarget, Selection};
use vh_model::{
    ActionOutcome, ActionPlan, AutoLevel, DemotedProc, FinalState, GuardEvent, GuardEventKind,
    GuardPolicy, GuardStatus, PendingAction, ProcRef, Report, Snapshot, Step,
};

use crate::backend::GuardBackend;
use crate::cpu::{fill_cpu_pct, remember};
use crate::decide::{Candidate, NotifyItem, SkipReason, decide_lean};
use crate::handle::{GuardCommand, GuardUpdate, ManualRunResult, ShutdownReport};
use crate::memory::{Demoted, GuardMemory};
use crate::notify::NotifyBatcher;
use crate::snap::bare_snapshot;

/// 한 번의 자동 실행(execute)이 쓸 수 있는 총 시간.
pub const EXEC_DEADLINE_MS: u64 = 20_000;

/// 첫 스캔 전(첫 수집이 계속 실패할 때) 모아 두는 이벤트 상한. 넘으면 오래된 것부터 버린다.
pub const MAX_BUFFERED_EVENTS: usize = 100;

const GUARD_LABEL: &str = "지킴이";

pub struct Engine<B: GuardBackend> {
    policy: Arc<GuardPolicy>,
    mem: GuardMemory,
    backend: B,
    batcher: NotifyBatcher,
    last: Option<(Arc<Snapshot>, Arc<Report>)>,
    level_locked_by_env: bool,
    last_scan_at_unix_ms: u64,
    last_scan_ms: f64,
    next_scan_at_unix_ms: u64,
    scan_error_streak: u32,
    pending: Vec<PendingAction>,
    buffered_events: Vec<GuardEvent>,
}

impl<B: GuardBackend> Engine<B> {
    pub fn new(policy: GuardPolicy, backend: B) -> Self {
        let now = backend.now_unix_ms();
        Engine {
            batcher: NotifyBatcher::new(policy.notify_min_interval_ms),
            mem: GuardMemory::new(policy.level),
            policy: Arc::new(policy),
            backend,
            last: None,
            level_locked_by_env: false,
            last_scan_at_unix_ms: 0,
            last_scan_ms: 0.0,
            next_scan_at_unix_ms: now,
            scan_error_streak: 0,
            pending: Vec::new(),
            buffered_events: Vec::new(),
        }
    }

    pub fn level_locked_by_env(mut self, locked: bool) -> Self {
        self.level_locked_by_env = locked;
        self
    }

    pub fn now_unix_ms(&self) -> u64 {
        self.backend.now_unix_ms()
    }

    pub fn next_scan_at_unix_ms(&self) -> u64 {
        self.next_scan_at_unix_ms
    }

    pub fn memory(&self) -> &GuardMemory {
        &self.mem
    }

    pub fn policy(&self) -> &GuardPolicy {
        &self.policy
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn status(&self) -> GuardStatus {
        let now = self.now_unix_ms();
        GuardStatus {
            level: self.policy.level,
            level_locked_by_env: self.level_locked_by_env,
            paused: self.mem.paused,
            circuit_open: self.mem.circuit_open,
            circuit_opened_at_unix_ms: self.mem.circuit_opened_at_unix_ms,
            terminations_in_window: self
                .mem
                .terminations_in_window(now, self.policy.rate_window_ms),
            scan_seq: self.mem.scan_seq,
            scan_error_streak: self.scan_error_streak,
            last_scan_at_unix_ms: self.last_scan_at_unix_ms,
            last_scan_ms: self.last_scan_ms,
            next_scan_at_unix_ms: self.next_scan_at_unix_ms,
            demoted: self
                .mem
                .demoted
                .iter()
                .map(|(t, d)| DemotedProc {
                    target: *t,
                    label_ko: d.label_ko.clone(),
                    at_unix_ms: d.at_unix_ms,
                })
                .collect(),
            pending: self.pending.clone(),
        }
    }

    /// 마지막 스냅샷·리포트에 상태·이벤트를 붙인 갱신. 아직 스캔 전이면 이벤트를 모아 두고 None.
    pub fn update_after(
        &mut self,
        mut events: Vec<GuardEvent>,
        manual_result: Option<ManualRunResult>,
    ) -> Option<GuardUpdate> {
        let Some((snapshot, report)) = self.last.clone() else {
            self.buffered_events.append(&mut events);
            let over = self
                .buffered_events
                .len()
                .saturating_sub(MAX_BUFFERED_EVENTS);
            self.buffered_events.drain(..over);
            return None;
        };
        let mut new_events = std::mem::take(&mut self.buffered_events);
        new_events.append(&mut events);
        Some(GuardUpdate {
            snapshot,
            report,
            policy: Arc::clone(&self.policy),
            status: self.status(),
            new_events,
            manual_result,
        })
    }

    /// 스캔 한 번. 첫 수집이 실패해 보여 줄 스냅샷이 없으면 None(다음 간격에 다시).
    pub fn scan(&mut self) -> Option<GuardUpdate> {
        let t0 = self.now_unix_ms();
        let mut snapshot = match self.backend.collect() {
            Ok(s) => s,
            Err(e) => {
                self.scan_error_streak += 1;
                let ev = self.event(
                    GuardEventKind::ScanError,
                    None,
                    None,
                    None,
                    GUARD_LABEL,
                    &format!("수집 실패: {e}"),
                );
                self.next_scan_at_unix_ms = t0 + u64::from(self.policy.scan_interval_ms);
                return self.update_after(vec![ev], None);
            }
        };
        fill_cpu_pct(&mut snapshot, &self.mem);
        let report = self.backend.analyze(&snapshot);
        let now = self.now_unix_ms();
        let d = decide_lean(&self.mem, &snapshot, &report, &self.policy, now);
        self.mem.term_streak = d.next_term_streak;
        self.mem.cpu_streak = d.next_cpu_streak;
        remember(&mut self.mem, &snapshot);
        self.mem.prune_window(now, self.policy.rate_window_ms);

        let mut events = Vec::new();
        if d.trip_circuit && !self.mem.circuit_open {
            self.mem.circuit_open = true;
            self.mem.circuit_opened_at_unix_ms = Some(now);
            let n = d
                .notify
                .iter()
                .filter(|n| n.reason == SkipReason::QuotaExceeded)
                .count();
            let detail = format!(
                "자동 종료 후보 {n}개가 한꺼번에 나와(10분에 {}개 제한) 자동 종료를 멈췄어요. 화면에서 r로 다시 켤 수 있어요",
                self.policy.max_auto_terminations
            );
            events.push(self.event(
                GuardEventKind::CircuitOpen,
                None,
                None,
                None,
                GUARD_LABEL,
                &detail,
            ));
            self.batcher.push(detail);
        }
        if !d.terminate.is_empty() {
            self.run_terminations(&d.terminate, &snapshot, &report, now, &mut events);
        }
        if !d.demote.is_empty() {
            self.run_demotes(&d.demote, &snapshot, &report, &mut events);
        }
        for n in &d.notify {
            if self.mem.notified.insert((n.target, n.reason)) {
                self.batcher.push(notify_line(n));
            }
        }
        let alive: HashSet<ProcRef> = snapshot
            .processes
            .iter()
            .map(|p| ProcRef {
                pid: p.pid,
                start_time_unix_ms: p.start_time_unix_ms,
            })
            .collect();
        self.mem.notified.retain(|(t, _)| alive.contains(t));
        self.mem.refused.retain(|t| alive.contains(t));
        self.prune_gone_demoted(&alive, &mut events);

        self.flush_notifications(now, &mut events);

        self.mem.scan_seq += 1;
        self.scan_error_streak = 0;
        self.pending = d.pending;
        self.last_scan_at_unix_ms = now;
        self.last_scan_ms = self.now_unix_ms().saturating_sub(t0) as f64;
        self.next_scan_at_unix_ms = self.now_unix_ms() + u64::from(d.next_scan_interval_ms);
        self.last = Some((Arc::new(snapshot), Arc::new(report)));
        self.update_after(events, None)
    }

    /// 명령 하나. 상태만 담은 갱신을 돌려준다(ScanNow는 스캔 결과).
    pub fn handle(&mut self, cmd: GuardCommand) -> Option<GuardUpdate> {
        let mut events = Vec::new();
        match cmd {
            GuardCommand::Pause => {
                if !self.mem.paused {
                    self.mem.paused = true;
                    self.mem.reset_streaks();
                    self.pending.clear();
                    events.push(self.event(
                        GuardEventKind::Paused,
                        None,
                        None,
                        None,
                        GUARD_LABEL,
                        "일시정지했어요. 자동 조치·알림을 멈춥니다(스캔은 계속)",
                    ));
                }
            }
            GuardCommand::Resume => {
                if self.mem.paused {
                    self.mem.paused = false;
                    events.push(self.event(
                        GuardEventKind::Resumed,
                        None,
                        None,
                        None,
                        GUARD_LABEL,
                        "다시 시작했어요. 조치 전에 다시 연속 확인합니다",
                    ));
                }
            }
            GuardCommand::SetLevel(level) => self.set_level(level, &mut events),
            GuardCommand::SetScanInterval(ms) => {
                let ms = ms.max(1_000);
                if ms != self.policy.scan_interval_ms {
                    Arc::make_mut(&mut self.policy).scan_interval_ms = ms;
                    let now = self.now_unix_ms();
                    self.next_scan_at_unix_ms = self.next_scan_at_unix_ms.min(now + u64::from(ms));
                }
            }
            GuardCommand::ResetCircuit => {
                if self.mem.circuit_open {
                    self.mem.circuit_open = false;
                    self.mem.circuit_opened_at_unix_ms = None;
                    self.mem.terminations.clear();
                    self.mem.reset_streaks();
                    events.push(self.event(
                        GuardEventKind::CircuitReset,
                        None,
                        None,
                        None,
                        GUARD_LABEL,
                        "차단기를 풀었어요. 자동 종료를 다시 시작합니다(다시 연속 확인 뒤)",
                    ));
                }
            }
            GuardCommand::UndoDemote(target) => {
                let _ = self.undo_demote(&[target], "guard-undo", &mut events);
            }
            GuardCommand::ScanNow => return self.scan(),
            GuardCommand::RunPlan {
                request_id,
                plan,
                snapshot,
            } => {
                let result = self.run_manual(request_id, &plan, snapshot, &mut events);
                return self.update_after(events, Some(result));
            }
            GuardCommand::Shutdown => {
                let (_, mut ev) = self.restore_all();
                events.append(&mut ev);
            }
        }
        self.update_after(events, None)
    }

    /// 패닉을 ScanError 이벤트로 바꾼다(스레드는 계속 산다).
    pub fn record_panic(
        &mut self,
        what: &str,
        payload: &Box<dyn std::any::Any + Send>,
    ) -> Option<GuardUpdate> {
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "알 수 없는 패닉".to_string());
        self.scan_error_streak += 1;
        let now = self.now_unix_ms();
        self.next_scan_at_unix_ms = now + u64::from(self.policy.scan_interval_ms);
        let ev = self.event(
            GuardEventKind::ScanError,
            None,
            None,
            None,
            GUARD_LABEL,
            &format!("{what} 중 오류: {msg}"),
        );
        self.update_after(vec![ev], None)
    }

    /// 낮춘 것 전부 되돌린다. 어떤 종료 경로에서도 호출된다.
    pub fn restore_all(&mut self) -> (ShutdownReport, Vec<GuardEvent>) {
        let targets: Vec<ProcRef> = self.mem.demoted.keys().copied().collect();
        let mut events = Vec::new();
        let report = self.undo_demote(&targets, "guard-shutdown", &mut events);
        (report, events)
    }

    fn set_level(&mut self, level: AutoLevel, events: &mut Vec<GuardEvent>) {
        if self.level_locked_by_env {
            events.push(self.event(
                GuardEventKind::Refused,
                None,
                None,
                None,
                GUARD_LABEL,
                "VH_GUARD_LEVEL 환경 변수로 수준이 고정되어 있어 바꿀 수 없어요",
            ));
            return;
        }
        if level == self.policy.level {
            return;
        }
        let old = self.policy.level;
        let interval = self.policy.scan_interval_ms;
        let mut policy = GuardPolicy::for_level(level);
        policy.scan_interval_ms = interval;
        self.policy = Arc::new(policy);
        self.batcher
            .set_min_interval_ms(self.policy.notify_min_interval_ms);
        self.mem.level = level;
        self.mem.reset_streaks();
        self.pending.clear();
        events.push(self.event(
            GuardEventKind::LevelChanged,
            None,
            None,
            None,
            GUARD_LABEL,
            &format!("{} → {}", level_ko(old), level_ko(level)),
        ));
    }

    fn act_policy(&self, grace_ms: u32, max_actions: usize) -> Policy {
        Policy {
            grace_ms,
            include_descendants: None,
            allow_demote: false,
            total_deadline_ms: EXEC_DEADLINE_MS,
            max_actions,
        }
    }

    fn run_terminations(
        &mut self,
        cands: &[Candidate],
        snapshot: &Snapshot,
        report: &Report,
        now: u64,
        events: &mut Vec<GuardEvent>,
    ) {
        let pol = self.act_policy(self.policy.grace_ms, 1);
        let mut items = Vec::new();
        for c in cands {
            let sel = Selection {
                finding_ids: vec![c.finding_id.clone()],
                pids: vec![c.target.pid],
                min_confidence: c.confidence,
                direct: Vec::new(),
            };
            let plan = self.backend.plan(snapshot, report, &sel, &pol);
            for rf in &plan.refused {
                self.mem.refused.insert(rf.target);
                events.push(self.event(
                    GuardEventKind::Refused,
                    Some(rf.target),
                    Some(&c.finding_id),
                    None,
                    &c.label_ko,
                    &format!("{}: {}", rf.rule, rf.reason_ko),
                ));
            }
            items.extend(plan.items);
        }
        if items.is_empty() {
            return;
        }
        for _ in &items {
            self.mem.terminations.push_back(now);
        }
        let plan = ActionPlan {
            created_at_unix_ms: now,
            total_deadline_ms: EXEC_DEADLINE_MS,
            items,
            refused: Vec::new(),
        };
        let run_id = format!("guard-{}", self.mem.scan_seq + 1);
        let outcomes = self.backend.execute(&plan, snapshot, &run_id);
        for o in outcomes {
            let label = cands
                .iter()
                .find(|c| c.target == o.action.target)
                .map(|c| c.label_ko.clone())
                .unwrap_or_else(|| o.action.reason_ko.clone());
            self.record_termination(&o, &label, &run_id, events);
        }
    }

    fn record_termination(
        &mut self,
        o: &ActionOutcome,
        label: &str,
        run_id: &str,
        events: &mut Vec<GuardEvent>,
    ) {
        let t = o.action.target;
        let fid = o.action.finding_id.as_str();
        match o.final_state {
            FinalState::Exited => {
                events.push(self.event_with_bytes(
                    GuardEventKind::AutoTerminated,
                    Some(t),
                    Some(fid),
                    Some(run_id),
                    label,
                    &o.note_ko,
                    o.action.est_reclaim_bytes,
                ));
                self.batcher.push(format!(
                    "{label} 종료({} 회수)",
                    fmt_bytes(o.action.est_reclaim_bytes)
                ));
            }
            FinalState::Refused => {
                self.mem.refused.insert(t);
                events.push(self.event(
                    GuardEventKind::Refused,
                    Some(t),
                    Some(fid),
                    Some(run_id),
                    label,
                    &o.note_ko,
                ));
            }
            FinalState::StillAlive
            | FinalState::Skipped
            | FinalState::Reused
            | FinalState::Vanished => {
                if o.final_state == FinalState::StillAlive {
                    self.mem.refused.insert(t);
                }
                events.push(self.event(
                    GuardEventKind::Skipped,
                    Some(t),
                    Some(fid),
                    Some(run_id),
                    label,
                    &o.note_ko,
                ));
            }
        }
    }

    fn run_demotes(
        &mut self,
        cands: &[Candidate],
        snapshot: &Snapshot,
        report: &Report,
        events: &mut Vec<GuardEvent>,
    ) {
        let targets: Vec<PriorityTarget> = cands
            .iter()
            .map(|c| PriorityTarget {
                target: c.target,
                step: Step::Demote,
                reason_ko: c.label_ko.clone(),
            })
            .collect();
        let pol = self.act_policy(0, cands.len().max(1));
        let plan = self
            .backend
            .plan_priority(snapshot, Some(report), &targets, &pol);
        for rf in &plan.refused {
            self.mem.refused.insert(rf.target);
            let label = label_of(cands, rf.target);
            events.push(self.event(
                GuardEventKind::Refused,
                Some(rf.target),
                None,
                None,
                &label,
                &format!("{}: {}", rf.rule, rf.reason_ko),
            ));
        }
        if plan.items.is_empty() {
            return;
        }
        let run_id = format!("guard-{}-demote", self.mem.scan_seq + 1);
        let now = self.now_unix_ms();
        let outcomes = self.backend.execute(&plan, snapshot, &run_id);
        for o in outcomes {
            let t = o.action.target;
            let label = label_of(cands, t);
            let fid = cands
                .iter()
                .find(|c| c.target == t)
                .map(|c| c.finding_id.clone())
                .unwrap_or_else(|| o.action.finding_id.clone());
            if step_ok(&o, Step::Demote) {
                self.mem.demoted.insert(
                    t,
                    Demoted {
                        at_unix_ms: now,
                        label_ko: label.clone(),
                        finding_id: fid.clone(),
                    },
                );
                events.push(self.event(
                    GuardEventKind::Demoted,
                    Some(t),
                    Some(&fid),
                    Some(&run_id),
                    &label,
                    &o.note_ko,
                ));
                self.batcher.push(format!("{label} 우선순위 낮춤"));
            } else {
                self.mem.refused.insert(t);
                let kind = if o.final_state == FinalState::Refused {
                    GuardEventKind::Refused
                } else {
                    GuardEventKind::Skipped
                };
                events.push(self.event(
                    kind,
                    Some(t),
                    Some(&fid),
                    Some(&run_id),
                    &label,
                    &o.note_ko,
                ));
            }
        }
    }

    fn run_manual(
        &mut self,
        request_id: u64,
        plan: &ActionPlan,
        snapshot: Arc<Snapshot>,
        events: &mut Vec<GuardEvent>,
    ) -> ManualRunResult {
        let run_id = format!("manual-{request_id}");
        let outcomes = self.backend.execute(plan, &snapshot, &run_id);
        let now = self.now_unix_ms();
        for o in &outcomes {
            let t = o.action.target;
            if step_ok(o, Step::Demote) {
                self.mem.demoted.insert(
                    t,
                    Demoted {
                        at_unix_ms: now,
                        label_ko: o.action.reason_ko.clone(),
                        finding_id: o.action.finding_id.clone(),
                    },
                );
                events.push(self.event(
                    GuardEventKind::Demoted,
                    Some(t),
                    Some(&o.action.finding_id),
                    Some(&run_id),
                    &o.action.reason_ko,
                    "화면에서 직접 낮췄어요(끝낼 때 되돌립니다)",
                ));
            }
            if step_ok(o, Step::Undemote) {
                self.mem.demoted.remove(&t);
                events.push(self.event(
                    GuardEventKind::Undemoted,
                    Some(t),
                    Some(&o.action.finding_id),
                    Some(&run_id),
                    &o.action.reason_ko,
                    "화면에서 직접 되돌렸어요",
                ));
            }
        }
        if self.last.is_none() {
            let report = self.backend.analyze(&snapshot);
            self.last = Some((snapshot, Arc::new(report)));
        }
        ManualRunResult {
            request_id,
            outcomes,
            state_dir: self.backend.state_dir().to_path_buf(),
        }
    }

    fn undo_demote(
        &mut self,
        targets: &[ProcRef],
        run_prefix: &str,
        events: &mut Vec<GuardEvent>,
    ) -> ShutdownReport {
        let mut report = ShutdownReport::default();
        let mut known = Vec::new();
        for t in targets {
            if self.mem.demoted.contains_key(t) {
                known.push(*t);
            } else {
                events.push(self.event(
                    GuardEventKind::Refused,
                    Some(*t),
                    None,
                    None,
                    &format!("pid {}", t.pid),
                    "이 세션이 낮춘 것이 아니라 되돌리지 않아요",
                ));
            }
        }
        if known.is_empty() {
            return report;
        }
        let (snapshot, analyzed) = match &self.last {
            Some((s, r)) => (s.clone(), Some(r.clone())),
            None => (
                Arc::new(bare_snapshot(
                    std::process::id() as i32,
                    // SAFETY: 인자 없는 시스템 호출.
                    unsafe { libc::getuid() },
                    self.now_unix_ms(),
                )),
                None,
            ),
        };
        let pt: Vec<PriorityTarget> = known
            .iter()
            .map(|t| PriorityTarget {
                target: *t,
                step: Step::Undemote,
                reason_ko: self
                    .mem
                    .demoted
                    .get(t)
                    .map(|d| d.label_ko.clone())
                    .unwrap_or_default(),
            })
            .collect();
        let pol = self.act_policy(0, pt.len());
        let plan = self
            .backend
            .plan_priority(&snapshot, analyzed.as_deref(), &pt, &pol);
        for rf in &plan.refused {
            let label = self.demoted_label(rf.target);
            events.push(self.event(
                GuardEventKind::Refused,
                Some(rf.target),
                None,
                None,
                &label,
                &format!("{}: {}", rf.rule, rf.reason_ko),
            ));
            report.failed.push((rf.target, 0));
        }
        if plan.items.is_empty() {
            return report;
        }
        let run_id = format!("{run_prefix}-{}", self.mem.scan_seq);
        let outcomes = self.backend.execute(&plan, &snapshot, &run_id);
        for o in &outcomes {
            let t = o.action.target;
            let label = self.demoted_label(t);
            let fid = self
                .mem
                .demoted
                .get(&t)
                .map(|d| d.finding_id.clone())
                .unwrap_or_else(|| o.action.finding_id.clone());
            if step_ok(o, Step::Undemote) {
                self.mem.demoted.remove(&t);
                report.undemoted.push(t);
                events.push(self.event(
                    GuardEventKind::Undemoted,
                    Some(t),
                    Some(&fid),
                    Some(&run_id),
                    &label,
                    &o.note_ko,
                ));
            } else if matches!(o.final_state, FinalState::Vanished | FinalState::Reused) {
                self.mem.demoted.remove(&t);
                report.undemoted.push(t);
                events.push(self.event(
                    GuardEventKind::Undemoted,
                    Some(t),
                    Some(&fid),
                    Some(&run_id),
                    &label,
                    "이미 끝난 프로세스라 되돌릴 것이 없어요",
                ));
            } else {
                let errno = o
                    .steps
                    .iter()
                    .find(|s| s.step == Step::Undemote)
                    .and_then(|s| s.errno)
                    .unwrap_or(0);
                report.failed.push((t, errno));
                events.push(self.event(
                    GuardEventKind::Refused,
                    Some(t),
                    Some(&fid),
                    Some(&run_id),
                    &label,
                    &format!("되돌리지 못했어요: {}", o.note_ko),
                ));
            }
        }
        report
    }

    /// 스냅샷에서 사라진 낮춘 대상을 기존 되돌리기 경로로 정리한다. vh-act의 신호 직전 확인이
    /// 끝남·PID 재사용을 신호 없이 판정하므로 보통 Undemoted('이미 끝난') 이벤트 1회로 끝나고,
    /// 수집에서만 빠지고 살아 있으면 실제로 되돌린다. 되돌리기에 실패한 것은 목록에 남겨 종료 때
    /// 다시 시도하되 스캔마다 반복하지 않는다.
    fn prune_gone_demoted(&mut self, alive: &HashSet<ProcRef>, events: &mut Vec<GuardEvent>) {
        let gone: Vec<ProcRef> = self
            .mem
            .demoted
            .keys()
            .filter(|t| !alive.contains(t) && !self.mem.undemote_failed.contains(t))
            .copied()
            .collect();
        if !gone.is_empty() {
            let report = self.undo_demote(&gone, "guard-gone", events);
            self.mem
                .undemote_failed
                .extend(report.failed.iter().map(|(t, _)| *t));
        }
        let demoted = &self.mem.demoted;
        self.mem.undemote_failed.retain(|t| demoted.contains_key(t));
    }

    fn demoted_label(&self, t: ProcRef) -> String {
        self.mem
            .demoted
            .get(&t)
            .map(|d| d.label_ko.clone())
            .unwrap_or_else(|| format!("pid {}", t.pid))
    }

    fn flush_notifications(&mut self, now: u64, events: &mut Vec<GuardEvent>) {
        let backend = &mut self.backend;
        let mut send = |title: &str, body: &str| backend.notify(title, body);
        if let Some((body, res)) = self.batcher.flush(now, &mut send) {
            let detail = match res {
                Ok(()) => body,
                Err(e) => format!("{body} (알림 보내기 실패: {e})"),
            };
            events.push(self.event(
                GuardEventKind::Notified,
                None,
                None,
                None,
                GUARD_LABEL,
                &detail,
            ));
        }
    }

    fn event(
        &self,
        kind: GuardEventKind,
        target: Option<ProcRef>,
        finding_id: Option<&str>,
        run_id: Option<&str>,
        label_ko: &str,
        detail_ko: &str,
    ) -> GuardEvent {
        self.event_with_bytes(kind, target, finding_id, run_id, label_ko, detail_ko, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn event_with_bytes(
        &self,
        kind: GuardEventKind,
        target: Option<ProcRef>,
        finding_id: Option<&str>,
        run_id: Option<&str>,
        label_ko: &str,
        detail_ko: &str,
        reclaimed_bytes: u64,
    ) -> GuardEvent {
        GuardEvent {
            at_unix_ms: self.now_unix_ms(),
            kind,
            target,
            finding_id: finding_id.map(str::to_string),
            run_id: run_id.map(str::to_string),
            label_ko: label_ko.to_string(),
            detail_ko: detail_ko.to_string(),
            reclaimed_bytes,
        }
    }
}

fn step_ok(o: &ActionOutcome, step: Step) -> bool {
    o.steps.iter().any(|s| s.step == step && s.ok)
}

fn label_of(cands: &[Candidate], t: ProcRef) -> String {
    cands
        .iter()
        .find(|c| c.target == t)
        .map(|c| c.label_ko.clone())
        .unwrap_or_else(|| format!("pid {}", t.pid))
}

fn notify_line(n: &NotifyItem) -> String {
    match n.reason {
        SkipReason::KindNotifyOnly => format!(
            "{}: 정리 후보지만 자동으로 끄지 않아요(알림만, {})",
            n.label_ko,
            fmt_bytes(n.reclaim_bytes)
        ),
        SkipReason::LevelNotifyOnly => format!(
            "{}: 정리 후보({}). 화면에서 고르면 정리해요",
            n.label_ko,
            fmt_bytes(n.reclaim_bytes)
        ),
        SkipReason::CircuitOpen => {
            format!("{}: 차단기가 열려 있어 끄지 않았어요", n.label_ko)
        }
        SkipReason::QuotaExceeded => {
            format!("{}: 한꺼번에 너무 많아 끄지 않았어요", n.label_ko)
        }
        SkipReason::RunawayNoDemote => {
            format!("{}: CPU 폭주(우선순위는 낮추지 않아요)", n.label_ko)
        }
        _ => format!("{}: 자동 조치하지 않았어요", n.label_ko),
    }
}

pub(crate) fn level_ko(l: AutoLevel) -> &'static str {
    match l {
        AutoLevel::NotifyOnly => "알림만",
        AutoLevel::Safe => "안전 자동",
        AutoLevel::Aggressive => "적극 자동",
    }
}

pub(crate) fn fmt_bytes(b: u64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let f = b as f64;
    if f >= GB {
        format!("{:.1}GB", f / GB)
    } else if f >= MB {
        format!("{:.0}MB", f / MB)
    } else {
        format!("{}KB", b / 1024)
    }
}
