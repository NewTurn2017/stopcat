//! 격리 실증(≤ 3분): 미끼 1 + 범위 안 고아 1 + 범위 안 CPU 많이 쓰는 것 1, Safe 지킴이(두 겹), 감독 SIGKILL 시험.

use std::collections::BTreeSet;
use std::io::{self, BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;
use stopcat_model::{AutoLevel, GuardEventKind, GuardPolicy, Kind, ProcRef};

use crate::cleanup::LabReaper;
use crate::kernel::{RealKernel, task_priority};
use crate::lab::{Lab, Meta};
use crate::run::{GuardRun, IsoInvariants, KernelRec, sample_kernel};
use crate::scope::LabScope;
use crate::spec::{self, Role};
use crate::util::{new_run_id, now_ms, write_json, write_jsonl};

const SUB: &str = "I";

#[derive(Debug, Serialize)]
pub struct SupervisorKill {
    pub helpers_before: usize,
    pub helpers_after_30s: usize,
    pub seconds: Option<f64>,
    pub stopped_helpers_before: usize,
    pub killed_by_lab_after_timeout: usize,
    pub roles: Vec<String>,
}

fn mcp_argv(dir: &Path) -> Vec<String> {
    vec![
        "node".into(),
        dir.join("node_modules/chrome-devtools-mcp/build/src/index.js")
            .to_string_lossy()
            .into_owned(),
    ]
}

pub fn run_isolation(out: &Path, report: &Path) -> io::Result<bool> {
    let run_id = new_run_id()?;
    std::fs::create_dir_all(out)?;
    let t0 = Instant::now();
    let mut lab = Lab::create(&run_id)?;
    let observed = observe(&mut lab, out);
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let mut summary = observed?;
    let kill = supervisor_kill_probe(&out.join("kill"))?;
    let kill_ok = kill.helpers_before > 0 && kill.helpers_after_30s == 0;
    let all_ok = summary["criteria_all"].as_bool() == Some(true)
        && cleanup.leftover_processes == 0
        && kill_ok;
    summary["run_id"] = json!(run_id);
    summary["wall_seconds"] = json!(t0.elapsed().as_secs_f64());
    summary["supervisor_kill"] = json!(kill);
    summary["cleanup"] = json!({
        "leftover_processes": cleanup.leftover_processes,
        "pgrp_remaining": cleanup.pgrp_remaining,
        "tagged_remaining": cleanup.tagged_remaining,
        "killpg_used": cleanup.killpg_used,
        "sigterm_sent": cleanup.sigterm_sent,
        "direct_children_waited": cleanup.direct_children_waited,
        "tmp_files_removed": cleanup.tmp_files_removed,
        "seconds": cleanup.seconds,
    });
    summary["all_pass"] = json!(all_ok);
    write_json(report, &summary)?;
    write_json(&out.join("summary.json"), &summary)?;
    Ok(all_ok)
}

fn observe(lab: &mut Lab, out: &Path) -> io::Result<serde_json::Value> {
    let tag = lab.tag(SUB);
    let dead = lab.dead_pid()?;

    let decoy_spec = {
        let mut s = lab.exec_spec(
            "lab-spin",
            Role::Spin,
            &["lab-spin", "decoy"],
            None,
            &[
                (spec::SPIN_THREADS, "2".into()),
                (spec::SPIN_SECS, "150".into()),
            ],
            170,
        );
        s.cwd = lab.dir("decoy")?.to_string_lossy().into_owned();
        s
    };
    let (decoy, _) = lab.spawn_direct(Meta::decoy(SUB, "decoy"), decoy_spec, vec![])?;

    let mcp_dir = lab.dir("iso-mcp")?;
    std::fs::write(
        mcp_dir.join("package.json"),
        b"{\"name\":\"lab-iso-mcp\"}\n",
    )?;
    let argv = mcp_argv(&mcp_dir);
    let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut orphan_spec = lab.exec_spec(
        "node",
        Role::Idle,
        &argv_ref,
        Some(&tag),
        &[("CLAUDE_PID", dead.to_string())],
        300,
    );
    orphan_spec.cwd = mcp_dir.to_string_lossy().into_owned();
    let orphan = lab.spawn_orphans(vec![(Meta::new(SUB, "orphan"), orphan_spec)])?[0];

    let mut spin_spec = lab.exec_spec(
        "lab-spin",
        Role::Spin,
        &["lab-spin", "runaway"],
        Some(&tag),
        &[
            (spec::SPIN_THREADS, "2".into()),
            (spec::SPIN_SECS, "120".into()),
            (spec::SPIN_STOP_ON_DEMOTE, "1".into()),
        ],
        300,
    );
    spin_spec.cwd = lab.dir("runaway")?.to_string_lossy().into_owned();
    let (spinner, _) = lab.spawn_direct(Meta::new(SUB, "runaway"), spin_spec, vec![])?;

    lab.registry.freeze(SUB);
    let scope = LabScope {
        tag: tag.clone(),
        refs: lab.registry.scope_refs(SUB),
    };
    let lock = lab.registry.lock_pids(SUB);
    let decoys = lab.registry.decoys();
    std::thread::sleep(Duration::from_millis(500));
    let base_spin = task_priority(spinner.pid);
    let base_decoy = task_priority(decoy.pid);
    let mut gr = GuardRun::start(
        out,
        SUB,
        scope.clone(),
        lock.clone(),
        decoys.clone(),
        GuardPolicy::for_level(AutoLevel::Safe),
    )?;

    let watch: BTreeSet<ProcRef> = lab.registry.all_refs();
    let mut kernel: Vec<KernelRec> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut demoted_seq: Option<u64> = None;
    let mut last_sample = Instant::now() - Duration::from_secs(2);
    while Instant::now() < deadline {
        gr.pump();
        if last_sample.elapsed() >= Duration::from_secs(1) {
            kernel.extend(sample_kernel(&watch));
            last_sample = Instant::now();
        }
        if demoted_seq.is_none()
            && gr.scans.iter().any(|s| {
                s.events
                    .iter()
                    .any(|e| e.kind == GuardEventKind::Demoted && e.target == Some(spinner))
            })
        {
            demoted_seq = Some(gr.last_seq());
        }
        if let Some(seq) = demoted_seq
            && gr.last_seq() >= seq + 2
            && task_priority(spinner.pid) == Some(4)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let prio_before_shutdown = task_priority(spinner.pid);
    let shutdown = gr.shutdown();
    let mut restored_after_ms = None;
    let sd_at = now_ms();
    for _ in 0..50 {
        kernel.extend(sample_kernel(&watch));
        if task_priority(spinner.pid).is_some() && task_priority(spinner.pid) == base_spin {
            restored_after_ms = Some(now_ms() - sd_at);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let prio_after_shutdown = task_priority(spinner.pid);
    let decoy_alive_at_end = lab.alive(decoy);
    let decoy_prio_end = task_priority(decoy.pid);
    gr.write()?;
    write_jsonl(&out.join("kernel.jsonl"), &kernel)?;
    write_json(&out.join("registry.json"), &lab.registry)?;

    let registry_refs: BTreeSet<ProcRef> = lab.registry.scope_refs(SUB);
    let inv: IsoInvariants = gr.isolation_check(&registry_refs);

    let filter = gr
        .scope_log
        .lock()
        .map(|l| l.scans.clone())
        .unwrap_or_default();
    let decoy_in_kept = filter
        .iter()
        .filter(|s| s.stats.kept_refs.contains(&decoy))
        .count();
    let decoy_in_pending = gr
        .scans
        .iter()
        .filter(|s| s.status.pending.iter().any(|p| p.target == decoy))
        .count();
    let decoy_in_events = gr
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.target == Some(decoy))
        .count();
    let decoy_in_findings = gr
        .scans
        .iter()
        .flat_map(|s| s.findings.iter())
        .filter(|f| f.targets.contains(&decoy))
        .count();
    let calls = gr.signal_calls();
    let decoy_signals = calls.iter().filter(|c| c.pid == decoy.pid).count();
    let control_decoy_demote_scans = filter
        .iter()
        .filter_map(|s| s.shadow.as_ref())
        .filter(|sh| sh.watched_in_demote.contains(&decoy))
        .count();
    let shadow_max = |f: fn(&crate::scope::ShadowRec) -> usize| {
        filter
            .iter()
            .filter_map(|s| s.shadow.as_ref())
            .map(f)
            .max()
            .unwrap_or(0)
    };

    let demoted_ev = gr
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .any(|e| e.kind == GuardEventKind::Demoted && e.target == Some(spinner));
    let undemoted_ev = gr
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .any(|e| e.kind == GuardEventKind::Undemoted && e.target == Some(spinner));
    let pending_demote_seen: Vec<u32> = gr
        .scans
        .iter()
        .flat_map(|s| s.status.pending.iter())
        .filter(|p| p.target == spinner)
        .map(|p| p.seen_scans)
        .collect();
    let kernel_prio_4 = kernel
        .iter()
        .any(|k| k.r == spinner && k.priority == Some(4));
    let orphan_cls = gr
        .scans
        .last()
        .and_then(|s| s.classified.iter().find(|c| c.target == orphan).cloned());
    let orphan_seen_scans = gr
        .scans
        .iter()
        .filter(|s| s.procs.iter().any(|p| p.r == orphan))
        .count();
    let auto_terminated = gr
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.kind == GuardEventKind::AutoTerminated)
        .count();

    let c1 = decoy_in_kept == 0
        && decoy_in_pending == 0
        && decoy_in_events == 0
        && decoy_in_findings == 0
        && decoy_signals == 0
        && decoy_alive_at_end;
    let c2 = demoted_ev
        && kernel_prio_4
        && shutdown.undemoted.contains(&spinner)
        && undemoted_ev
        && prio_after_shutdown == base_spin
        && base_spin.is_some();
    let c3 = inv.guard_visible_outside_lab == 0;
    let c4 = inv.signal_calls_not_allowed == 0
        && inv.signal_calls_outside_registry == 0
        && inv.scope_violations == 0;

    let guard_secs = (now_ms() - gr.started_at_ms) as f64 / 1000.0;
    let criteria_all = c1 && c2 && c3 && c4 && inv.holds(false);
    Ok(json!({
        "schema": "stopcat-lab/isolation/v1",
        "recorded_at_ms": now_ms(),
        "guard_seconds": guard_secs,
        "guard_level": "safe",
        "policy": "GuardPolicy::for_level(Safe) 그대로",
        "tag": tag,
        "refs": {"decoy": decoy, "orphan": orphan, "runaway": spinner, "dead_owner_pid": dead},
        "scans": gr.scans.len(),
        "scan_seq_gaps": gr.seq_gaps,
        "criteria": {
            "c1_decoy_never_seen": c1,
            "c2_runaway_demoted_and_restored": c2,
            "c3_real_orphans_not_candidates": c3,
            "c4_lock_violations_zero": c4,
        },
        "criteria_all": criteria_all,
        "c1": {
            "decoy_in_filtered_snapshot_scans": decoy_in_kept,
            "decoy_in_pending_scans": decoy_in_pending,
            "decoy_in_events": decoy_in_events,
            "decoy_in_findings": decoy_in_findings,
            "decoy_signal_calls": decoy_signals,
            "decoy_alive_at_end": decoy_alive_at_end,
            "decoy_priority_base": base_decoy,
            "decoy_priority_end": decoy_prio_end,
            "control_shadow_decoy_demote_candidate_scans": control_decoy_demote_scans,
        },
        "c2": {
            "priority_base": base_spin,
            "pending_demote_seen_scans": pending_demote_seen,
            "demoted_event": demoted_ev,
            "kernel_priority_4_observed": kernel_prio_4,
            "priority_before_shutdown": prio_before_shutdown,
            "shutdown_undemoted_contains": shutdown.undemoted.contains(&spinner),
            "shutdown_failed": shutdown.failed,
            "undemoted_event": undemoted_ev,
            "priority_after_shutdown": prio_after_shutdown,
            "restored_after_ms": restored_after_ms,
        },
        "c3": {
            "guard_visible_outside_lab": inv.guard_visible_outside_lab,
            "control_shadow_outside_orphan_findings_max": shadow_max(|s| s.outside_orphan_findings),
            "control_shadow_outside_terminate_candidates_max": shadow_max(|s| s.outside_terminate_candidates),
            "control_shadow_outside_demote_candidates_max": shadow_max(|s| s.outside_demote_candidates),
            "control_shadow_outside_pending_max": shadow_max(|s| s.outside_pending),
            "control_shadow_full_procs_max": shadow_max(|s| s.full_procs),
            "in_scope_orphan_seen_scans": orphan_seen_scans,
            "in_scope_orphan_kind": orphan_cls.as_ref().map(|c| c.kind),
            "in_scope_orphan_kind_is_mcp": orphan_cls.as_ref().is_some_and(|c| c.kind == Kind::McpServer),
            "in_scope_orphan_owner_alive": orphan_cls.as_ref().and_then(|c| c.owner_alive),
            "auto_terminated_events": auto_terminated,
        },
        "c4": inv,
        "real_notifications": 0,
    }))
}

/// 하위 감독(setsid)을 띄워 작은 실험실(멈춘 자식 포함)을 만들게 하고, 그 감독을 SIGKILL한 뒤
/// 도우미 전부가 30초 안에 스스로 끝나는지 잰다. 남으면 기록한 ProcRef로만 정리한다.
pub fn supervisor_kill_probe(out: &Path) -> io::Result<SupervisorKill> {
    std::fs::create_dir_all(out)?;
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.args(["__supervise", "kill-probe-lab", "--out"])
        .arg(out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // SAFETY: fork 뒤 exec 전 setsid만 부른다(async-signal-safe).
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout"))?;
    let mut refs: Vec<(ProcRef, String, bool)> = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        if line == "ready" {
            break;
        }
        if let Some(rest) = line.strip_prefix("ref ") {
            let mut it = rest.split_whitespace();
            if let (Some(r), Some(role)) = (it.next().and_then(spec::parse_proc_ref), it.next()) {
                let stopped = it.next() == Some("stopped");
                refs.push((r, role.to_string(), stopped));
            }
        }
    }
    let k = RealKernel;
    let sup_pid = child.id() as i32;
    let sup_ref = ProcRef {
        pid: sup_pid,
        start_time_unix_ms: crate::kernel::LabKernel::probe(&k, sup_pid).start_time_unix_ms,
    };
    let set: BTreeSet<ProcRef> = refs.iter().map(|r| r.0).collect();
    let reaper_allowed: BTreeSet<ProcRef> = set.iter().copied().chain([sup_ref]).collect();
    let mut reaper = LabReaper::new(&k, reaper_allowed);
    let before = reaper.alive_of(&set).len();
    let stopped_before = refs
        .iter()
        .filter(|(r, _, s)| *s && reaper.is_alive(*r))
        .count();
    reaper.signal(sup_ref, libc::SIGKILL);
    let _ = child.wait();
    let t = Instant::now();
    let mut seconds = None;
    while t.elapsed() < Duration::from_secs(30) {
        if reaper.alive_of(&set).is_empty() {
            seconds = Some(t.elapsed().as_secs_f64());
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let after = reaper.alive_of(&set);
    let mut killed = 0;
    for r in &after {
        if reaper.signal(*r, libc::SIGKILL) {
            killed += 1;
        }
    }
    let res = SupervisorKill {
        helpers_before: before,
        helpers_after_30s: after.len(),
        seconds,
        stopped_helpers_before: stopped_before,
        killed_by_lab_after_timeout: killed,
        roles: refs.iter().map(|r| r.1.clone()).collect(),
    };
    write_json(&out.join("supervisor_kill.json"), &res)?;
    write_json(&out.join("reaper_calls.json"), &reaper.calls)?;
    if let Some(root) = refs_root(out) {
        crate::lab::remove_tree_files(&root);
    }
    Ok(res)
}

fn refs_root(out: &Path) -> Option<std::path::PathBuf> {
    let raw = std::fs::read_to_string(out.join("lab_root.txt")).ok()?;
    Some(std::path::PathBuf::from(raw.trim()))
}

/// 하위 감독 본체: anchor, 주인 claude(+ 멈출 개발 서버 자식), ppid 1 고아, 좀비 부모, idle을 띄우고
/// "ref <pid:start> <역할> [stopped]"를 알린 뒤 잠든다(최대 300초 뒤 스스로 정리).
pub fn kill_probe_lab(out: &Path) -> io::Result<()> {
    let run_id = new_run_id()?;
    let mut lab = Lab::create(&run_id)?;
    std::fs::write(
        out.join("lab_root.txt"),
        lab.root.to_string_lossy().as_bytes(),
    )?;
    let tag = lab.tag("K");
    let dead = lab.dead_pid()?;
    let dev_dir = lab.dir("k-dev")?;
    let dev_argv = [
        "node".to_string(),
        dev_dir
            .join("node_modules/.bin/next")
            .to_string_lossy()
            .into_owned(),
        "dev".to_string(),
    ];
    let dev_ref: Vec<&str> = dev_argv.iter().map(String::as_str).collect();
    let mut dev = lab.exec_spec("node", Role::Idle, &dev_ref, Some(&tag), &[], 300);
    dev.cwd = dev_dir.to_string_lossy().into_owned();
    let owner = lab.exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], 300);
    let (owner_ref, kids) = lab.spawn_direct(
        Meta::new("K", "owner"),
        owner,
        vec![(Meta::new("K", "stopped_dev"), dev)],
    )?;
    let mcp_dir = lab.dir("k-mcp")?;
    let argv = mcp_argv(&mcp_dir);
    let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut orphan = lab.exec_spec(
        "node",
        Role::Idle,
        &argv_ref,
        Some(&tag),
        &[("CLAUDE_PID", dead.to_string())],
        300,
    );
    orphan.cwd = mcp_dir.to_string_lossy().into_owned();
    let orphan_ref = lab.spawn_orphans(vec![(Meta::new("K", "orphan"), orphan)])?[0];
    let z = lab.exec_spec(
        "lab-zombie",
        Role::Zombie,
        &["lab-zombie"],
        Some(&tag),
        &[],
        300,
    );
    let (z_ref, _) = lab.spawn_direct(Meta::new("K", "zombie_parent"), z, vec![])?;
    let idle = lab.exec_spec("lab-idle", Role::Idle, &["lab-idle"], Some(&tag), &[], 300);
    let (idle_ref, _) = lab.spawn_direct(Meta::new("K", "idle"), idle, vec![])?;
    let stopped = kids.first().copied();
    if let Some(s) = stopped {
        lab.signal(s, libc::SIGSTOP);
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut lines = vec![
        (lab.registry.anchor, "anchor", false),
        (owner_ref, "owner_claude", false),
        (orphan_ref, "orphan_ppid1", false),
        (z_ref, "zombie_parent", false),
        (idle_ref, "idle", false),
    ];
    if let Some(s) = stopped {
        lines.push((s, "stopped_dev", true));
    }
    for (r, role, st) in &lines {
        println!(
            "ref {}:{} {role}{}",
            r.pid,
            r.start_time_unix_ms,
            if *st { " stopped" } else { "" }
        );
    }
    println!("ready");
    use std::io::Write;
    let _ = io::stdout().flush();
    std::thread::sleep(Duration::from_secs(300));
    let _ = lab.cleanup();
    Ok(())
}
