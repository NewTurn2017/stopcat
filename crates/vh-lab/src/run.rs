//! 범위 지킴이 하나 띄우기와 기록(스캔·필터·신호·알림·커널 독립 관측).

use std::collections::BTreeSet;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use vh_act::{Liveness, RealSignaler};
use vh_guard::{GuardHandle, GuardUpdate, RealGuardBackend, ShutdownReport};
use vh_model::{
    Confidence, FindingKind, GuardEvent, GuardPolicy, GuardStatus, Kind, ProcRef, ProcStatus,
    Suggestion,
};

use crate::kernel::{LabKernel, RealKernel, task_priority, usage};
use crate::notify::NotifyRec;
use crate::scope::{LabScope, ScopeLog, ScopedBackend, Shadow, pref};
use crate::signal::{RecordingNotifier, RecordingSignaler, SignalCall, SignalLog};
use crate::util::{now_ms, sha256_hex, write_json, write_jsonl};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingLite {
    pub id: String,
    pub kind: FindingKind,
    pub confidence: Confidence,
    pub suggestion: Suggestion,
    pub targets: Vec<ProcRef>,
    pub short_ko: String,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClsLite {
    pub target: ProcRef,
    pub kind: Kind,
    pub signature_id: Option<String>,
    pub owner_alive: Option<bool>,
    pub owner_source: Option<String>,
    pub label_ko: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcLite {
    pub r: ProcRef,
    pub ppid: i32,
    pub pgid: i32,
    pub name: String,
    pub status: ProcStatus,
    pub has_tty: bool,
    pub footprint_bytes: Option<u64>,
    pub cpu_pct: Option<f32>,
    pub argv_len: usize,
    pub argv_sha256: String,
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListenLite {
    pub r: ProcRef,
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRec {
    pub recv_ms: u64,
    pub taken_at_ms: u64,
    pub status: GuardStatus,
    pub events: Vec<GuardEvent>,
    pub findings: Vec<FindingLite>,
    pub classified: Vec<ClsLite>,
    pub procs: Vec<ProcLite>,
    pub listeners: Vec<ListenLite>,
    pub collection_errors: usize,
    pub timings_total_ms: f64,
}

impl ScanRec {
    pub fn from_update(u: &GuardUpdate) -> Self {
        let s = &u.snapshot;
        ScanRec {
            recv_ms: now_ms(),
            taken_at_ms: s.taken_at_unix_ms,
            status: u.status.clone(),
            events: u.new_events.clone(),
            findings: u
                .report
                .findings
                .iter()
                .map(|f| FindingLite {
                    id: f.id.clone(),
                    kind: f.kind,
                    confidence: f.confidence,
                    suggestion: f.suggestion.clone(),
                    targets: f.targets.clone(),
                    short_ko: f.short_ko.clone(),
                    reason_codes: f.reason_codes.clone(),
                })
                .collect(),
            classified: u
                .report
                .classified
                .iter()
                .map(|c| ClsLite {
                    target: c.target,
                    kind: c.kind,
                    signature_id: c.signature_id.clone(),
                    owner_alive: c.owner_alive,
                    owner_source: c.owner_source.clone(),
                    label_ko: c.label_ko.clone(),
                })
                .collect(),
            procs: s
                .processes
                .iter()
                .map(|p| {
                    let joined = p.argv.join("\u{0}");
                    ProcLite {
                        r: pref(p),
                        ppid: p.ppid,
                        pgid: p.pgid,
                        name: p.name.clone(),
                        status: p.status,
                        has_tty: p.has_tty,
                        footprint_bytes: p.footprint_bytes,
                        cpu_pct: p.cpu_pct,
                        argv_len: joined.len(),
                        argv_sha256: sha256_hex(joined.as_bytes()),
                        argv: (joined.len() <= 1024).then(|| p.argv.clone()),
                    }
                })
                .collect(),
            listeners: s
                .listeners
                .iter()
                .map(|l| ListenLite {
                    r: ProcRef {
                        pid: l.pid,
                        start_time_unix_ms: l.start_time_unix_ms,
                    },
                    addr: l.local_addr.clone(),
                    port: l.port,
                })
                .collect(),
            collection_errors: s.collection_errors.len(),
            timings_total_ms: s.timings_ms.total_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KernelRec {
    pub at_ms: u64,
    pub r: ProcRef,
    pub alive: bool,
    pub zombie: bool,
    pub stopped: bool,
    pub ppid: i32,
    pub pgid: i32,
    pub priority: Option<i32>,
    pub footprint_bytes: Option<u64>,
    pub cpu_ns: Option<u64>,
}

pub fn sample_kernel(refs: &BTreeSet<ProcRef>) -> Vec<KernelRec> {
    let k = RealKernel;
    let at = now_ms();
    refs.iter()
        .map(|r| {
            let live = k.probe(r.pid);
            let same =
                live.liveness != Liveness::Gone && live.start_time_unix_ms == r.start_time_unix_ms;
            let running = same && live.liveness == Liveness::Alive;
            let u = running.then(|| usage(r.pid)).flatten();
            KernelRec {
                at_ms: at,
                r: *r,
                alive: running,
                zombie: same && live.liveness == Liveness::Zombie,
                stopped: running && live.stopped,
                ppid: if same { live.ppid } else { 0 },
                pgid: if same { live.pgid } else { 0 },
                priority: running.then(|| task_priority(r.pid)).flatten(),
                footprint_bytes: u.map(|u| u.footprint_bytes),
                cpu_ns: u.map(|u| u.cpu_ns),
            }
        })
        .collect()
}

pub struct GuardRun {
    pub sub: String,
    pub dir: PathBuf,
    pub scope: LabScope,
    pub lock: BTreeSet<i32>,
    pub started_at_ms: u64,
    handle: Option<GuardHandle>,
    poll: Box<dyn FnMut() -> Option<GuardUpdate>>,
    pub seq_gaps: Vec<(u64, u64)>,
    pub scope_log: Arc<Mutex<ScopeLog>>,
    pub signals: SignalLog,
    pub notes: Arc<Mutex<Vec<NotifyRec>>>,
    pub scans: Vec<ScanRec>,
    pub shutdown: Option<ShutdownReport>,
}

impl GuardRun {
    /// 실기기 커널 위의 Safe 지킴이. 반드시 두 겹(범위 + 잠금)으로만 띄운다.
    pub fn start(
        dir: &Path,
        sub: &str,
        scope: LabScope,
        lock: BTreeSet<i32>,
        watch: BTreeSet<ProcRef>,
        policy: GuardPolicy,
    ) -> io::Result<GuardRun> {
        let state = dir.join("state");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state)?;
        let (sig, signals) = RecordingSignaler::new(Box::new(RealSignaler), lock.clone());
        let (notifier, notes) = RecordingNotifier::new();
        let real = RealGuardBackend::with_state_dir(state, Box::new(sig), Box::new(notifier));
        let shadow = Shadow::new(policy.clone(), watch);
        let (scoped, scope_log) = ScopedBackend::new(real, scope.clone(), Some(shadow));
        let (handle, rx) = GuardHandle::spawn_with(policy, scoped, true);
        let poll: Box<dyn FnMut() -> Option<GuardUpdate>> = Box::new(move || rx.try_recv().ok());
        Ok(GuardRun {
            sub: sub.to_string(),
            dir: dir.to_path_buf(),
            scope,
            lock,
            started_at_ms: now_ms(),
            handle: Some(handle),
            poll,
            seq_gaps: Vec::new(),
            scope_log,
            signals,
            notes,
            scans: Vec::new(),
            shutdown: None,
        })
    }

    pub fn pump(&mut self) -> usize {
        let mut n = 0;
        while let Some(u) = (self.poll)() {
            let prev = self.last_seq();
            let seq = u.status.scan_seq;
            if !self.scans.is_empty() && seq > prev + 1 {
                self.seq_gaps.push((prev, seq));
            }
            self.scans.push(ScanRec::from_update(&u));
            n += 1;
        }
        n
    }

    pub fn last_seq(&self) -> u64 {
        self.scans.last().map_or(0, |s| s.status.scan_seq)
    }

    pub fn shutdown(&mut self) -> ShutdownReport {
        let rep = self.handle.take().map(|h| h.shutdown()).unwrap_or_default();
        self.pump();
        self.shutdown = Some(rep.clone());
        rep
    }

    pub fn signal_calls(&self) -> Vec<SignalCall> {
        self.signals.lock().map(|v| v.clone()).unwrap_or_default()
    }

    pub fn notifications(&self) -> Vec<NotifyRec> {
        self.notes.lock().map(|v| v.clone()).unwrap_or_default()
    }

    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        let p = vh_act::audit_log_path(&self.dir.join("state"));
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn write(&self) -> io::Result<()> {
        write_jsonl(&self.dir.join("scans.jsonl"), &self.scans)?;
        if let Ok(l) = self.scope_log.lock() {
            write_jsonl(&self.dir.join("filter.jsonl"), &l.scans)?;
            write_json(&self.dir.join("violations.json"), &l.violations)?;
        }
        write_jsonl(&self.dir.join("signals.jsonl"), &self.signal_calls())?;
        write_jsonl(&self.dir.join("notifications.jsonl"), &self.notifications())?;
        write_json(&self.dir.join("seq_gaps.json"), &self.seq_gaps)?;
        if let Some(s) = &self.shutdown {
            write_json(
                &self.dir.join("shutdown.json"),
                &serde_json::json!({
                    "undemoted": s.undemoted,
                    "failed": s.failed,
                }),
            )?;
        }
        Ok(())
    }

    /// 격리 불변식 검사(실행마다 공통).
    pub fn isolation_check(&self, registry_refs: &BTreeSet<ProcRef>) -> IsoInvariants {
        let l = self.scope_log.lock();
        let (filter_scans, dropped_min, unreg_max, violations) = match &l {
            Ok(l) => (
                l.scans.len(),
                l.scans.iter().map(|s| s.stats.dropped).min().unwrap_or(0),
                l.scans
                    .iter()
                    .map(|s| s.stats.unregistered_tagged)
                    .max()
                    .unwrap_or(0),
                l.violations.len(),
            ),
            Err(_) => (0, 0, 0, usize::MAX),
        };
        let outside = |r: &ProcRef| !registry_refs.contains(r);
        let mut targets_outside = 0;
        for s in &self.scans {
            targets_outside += s.procs.iter().filter(|p| outside(&p.r)).count();
            targets_outside += s
                .findings
                .iter()
                .flat_map(|f| f.targets.iter())
                .filter(|t| outside(t))
                .count();
            targets_outside += s
                .status
                .pending
                .iter()
                .filter(|p| outside(&p.target))
                .count();
            targets_outside += s
                .events
                .iter()
                .filter_map(|e| e.target)
                .filter(|t| outside(t))
                .count();
        }
        let calls = self.signal_calls();
        let reg_pids: BTreeSet<i32> = registry_refs.iter().map(|r| r.pid).collect();
        IsoInvariants {
            filter_scans,
            dropped_min,
            unregistered_tagged_max: unreg_max,
            scope_violations: violations,
            guard_visible_outside_lab: targets_outside,
            signal_calls: calls.len(),
            signal_calls_not_allowed: calls.iter().filter(|c| !c.allowed).count(),
            signal_calls_outside_registry: calls
                .iter()
                .filter(|c| !reg_pids.contains(&c.pid))
                .count(),
            real_notifications: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IsoInvariants {
    pub filter_scans: usize,
    pub dropped_min: usize,
    pub unregistered_tagged_max: usize,
    pub scope_violations: usize,
    pub guard_visible_outside_lab: usize,
    pub signal_calls: usize,
    pub signal_calls_not_allowed: usize,
    pub signal_calls_outside_registry: usize,
    pub real_notifications: usize,
}

impl IsoInvariants {
    pub fn holds(&self, allow_unregistered_tagged: bool) -> bool {
        self.filter_scans > 0
            && self.dropped_min > 0
            && (allow_unregistered_tagged || self.unregistered_tagged_max == 0)
            && self.scope_violations == 0
            && self.guard_visible_outside_lab == 0
            && self.signal_calls_not_allowed == 0
            && self.signal_calls_outside_registry == 0
    }
}
