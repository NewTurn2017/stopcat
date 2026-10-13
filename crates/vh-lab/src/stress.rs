//! 부하: nice 19, 동시 실험실 ≤ 300, 폭풍 ≤ 60초. 범위 지킴이(Safe)는 잠금 목록이 비어 어떤 신호도 나갈 수 없다.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;
use vh_model::{AutoLevel, GuardEventKind, GuardPolicy};

use crate::kernel::usage;
use crate::lab::{Lab, Meta};
use crate::preflight::load_ok;
use crate::run::GuardRun;
use crate::scope::LabScope;
use crate::spec::{self, ExecSpec, Role};
use crate::util::{new_run_id, now_ms, write_json};

pub const HARD_MAX_PROCS: usize = 300;
pub const HARD_MAX_STORM_SECS: u64 = 60;
const BASELINE_SECS: u64 = 30;

pub fn pctl(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let i = ((s.len() - 1) as f64 * p).round() as usize;
    Some(s[i])
}

/// 폭풍 구성: anchor 1 + 주인 1 + 자식 `kids` + 고아 `orphans` + 깜빡이 1 + 깜빡이 자식 ≤ `blips`.
pub fn storm_shape(max_procs: usize) -> (u32, u32, u32) {
    let blips = 50u32;
    let orphans = 100u32;
    let fixed = 3 + blips as usize + orphans as usize;
    let kids = max_procs.saturating_sub(fixed + 2) as u32;
    (kids, orphans, blips)
}

pub fn run(max_procs: usize, storm_secs: u64, out: &Path) -> io::Result<bool> {
    if max_procs > HARD_MAX_PROCS || storm_secs > HARD_MAX_STORM_SECS {
        return Err(io::Error::other(format!(
            "상한 초과 거부: 프로세스 ≤ {HARD_MAX_PROCS}, 폭풍 ≤ {HARD_MAX_STORM_SECS}초"
        )));
    }
    std::fs::create_dir_all(out)?;
    let (ok, why) = load_ok();
    if !ok {
        write_json(
            &out.join("result.json"),
            &json!({"schema": "vh-lab/stress/v1", "verdict": "INCONCLUSIVE", "skipped_ko": why}),
        )?;
        return Ok(false);
    }
    let mut lab = Lab::create(&new_run_id()?)?;
    let res = drive(&mut lab, max_procs, storm_secs, out);
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let mut v = res?;
    v["leftover_processes"] = json!(cleanup.leftover_processes);
    let pass = v["verdict"] == "PASS" && cleanup.leftover_processes == 0;
    write_json(&out.join("result.json"), &v)?;
    Ok(pass)
}

fn drive(
    lab: &mut Lab,
    max_procs: usize,
    storm_secs: u64,
    out: &Path,
) -> io::Result<serde_json::Value> {
    let tag = lab.tag("S");
    let scope = LabScope {
        tag: tag.clone(),
        refs: BTreeSet::new(),
    };
    let mut g = GuardRun::start(
        &out.join("S"),
        "S",
        scope,
        BTreeSet::new(),
        BTreeSet::new(),
        GuardPolicy::for_level(AutoLevel::Safe),
    )?;
    let me = std::process::id() as i32;
    let u0 = usage(me);
    let t_base = Instant::now();
    while t_base.elapsed() < Duration::from_secs(BASELINE_SECS) {
        g.pump();
        std::thread::sleep(Duration::from_millis(250));
    }
    let base_scans = g.scans.len();
    let u1 = usage(me);
    let (load_ok2, why2) = load_ok();
    if !load_ok2 {
        g.shutdown();
        g.write()?;
        return Ok(
            json!({"schema": "vh-lab/stress/v1", "verdict": "INCONCLUSIVE", "skipped_ko": why2}),
        );
    }
    let (kids, orphans, blips) = storm_shape(max_procs);
    let max_secs = storm_secs + 30;
    let storm_start = now_ms();
    let t_storm = Instant::now();
    let dead = lab.dead_pid()?;
    let base = lab.dir("st")?;
    for i in 0..kids.max(orphans) {
        std::fs::create_dir_all(base.join(format!("c{i}")))?;
        std::fs::create_dir_all(base.join(format!("o{i}")))?;
    }
    let mut child = lab.exec_spec(
        "node",
        Role::Idle,
        &[
            "node",
            &format!("{}/c{{i}}/node_modules/.bin/vite", base.display()),
        ],
        Some(&tag),
        &[],
        max_secs,
    );
    child.cwd = format!("{}/c{{i}}", base.display());
    child.count = kids;
    let owner = lab.exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], max_secs);
    lab.spawn_direct(
        Meta::new("S", "owner"),
        owner,
        vec![(Meta::new("S", "owner_child"), child)],
    )?;
    let mut orph = lab.exec_spec(
        "node",
        Role::Idle,
        &[
            "node",
            &format!(
                "{}/o{{i}}/node_modules/chrome-devtools-mcp/build/src/index.js",
                base.display()
            ),
        ],
        Some(&tag),
        &[("CLAUDE_PID", dead.to_string())],
        max_secs,
    );
    orph.cwd = format!("{}/o{{i}}", base.display());
    orph.count = orphans;
    lab.spawn_orphans(vec![(Meta::new("S", "orphan"), orph)])?;
    let flick: ExecSpec = lab.exec_spec(
        "lab-flicker",
        Role::Flicker,
        &["lab-flicker"],
        Some(&tag),
        &[
            (spec::FLICKER_MAX, blips.to_string()),
            (spec::FLICKER_SECS, storm_secs.saturating_sub(5).to_string()),
        ],
        max_secs,
    );
    lab.spawn_direct(Meta::new("S", "flicker"), flick, vec![])?;
    let spawn_secs = t_storm.elapsed().as_secs_f64();
    let mut aborted = None;
    while t_storm.elapsed() < Duration::from_secs(storm_secs) {
        g.pump();
        let kept_max = g
            .scope_log
            .lock()
            .map(|l| l.scans.iter().map(|s| s.stats.kept).max().unwrap_or(0))
            .unwrap_or(0);
        if kept_max > HARD_MAX_PROCS {
            aborted = Some(kept_max);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let u2 = usage(me);
    g.shutdown();
    let storm_end = now_ms();
    g.write()?;

    let storm_scans = &g.scans[base_scans.min(g.scans.len())..];
    let base_ms: Vec<f64> = g.scans[..base_scans]
        .iter()
        .map(|s| s.status.last_scan_ms)
        .collect();
    let storm_ms: Vec<f64> = storm_scans.iter().map(|s| s.status.last_scan_ms).collect();
    let base_coll: Vec<f64> = g.scans[..base_scans]
        .iter()
        .map(|s| s.timings_total_ms)
        .collect();
    let storm_coll: Vec<f64> = storm_scans.iter().map(|s| s.timings_total_ms).collect();
    let kept_max = g
        .scope_log
        .lock()
        .map(|l| l.scans.iter().map(|s| s.stats.kept).max().unwrap_or(0))
        .unwrap_or(0);
    let pending = g
        .scans
        .iter()
        .map(|s| s.status.pending.len())
        .sum::<usize>();
    let demoted = g
        .scans
        .iter()
        .map(|s| s.status.demoted.len())
        .sum::<usize>();
    let targeted_events = g
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.target.is_some())
        .count();
    let scan_errors = g
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.kind == GuardEventKind::ScanError)
        .count();
    let signal_calls = g.signal_calls().len();
    let limit_nearing = g.scans.iter().any(|s| {
        s.findings
            .iter()
            .any(|f| f.kind == vh_model::FindingKind::LimitNearing)
    });
    let cpu = |a: Option<crate::kernel::Usage>, b: Option<crate::kernel::Usage>, secs: f64| match (
        a, b,
    ) {
        (Some(a), Some(b)) if secs > 0.0 => {
            Some(b.cpu_ns.saturating_sub(a.cpu_ns) as f64 / (secs * 1e9) * 100.0)
        }
        _ => None,
    };
    let false_positives = pending + demoted + targeted_events + signal_calls;
    let storm_secs_actual = (storm_end - storm_start) as f64 / 1000.0;
    let verdict = if aborted.is_some() {
        "FAIL"
    } else if false_positives == 0
        && scan_errors == 0
        && kept_max <= HARD_MAX_PROCS
        && storm_secs_actual <= HARD_MAX_STORM_SECS as f64 + 1.0
    {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(json!({
        "schema": "vh-lab/stress/v1",
        "shape": {"owner_children": kids, "orphans_ppid1": orphans, "flicker_max_concurrent": blips, "anchor_owner_flicker": 3},
        "limits": {"max_concurrent_lab_processes": max_procs, "storm_max_secs": storm_secs, "nice": 19},
        "storm_start_ms": storm_start, "storm_end_ms": storm_end,
        "storm_secs_actual": storm_secs_actual, "spawn_secs": spawn_secs,
        "kept_max_in_scope": kept_max, "aborted_over_limit": aborted,
        "scans_baseline": base_scans, "scans_storm": storm_scans.len(),
        "scan_ms_baseline": {"p50": pctl(&base_ms, 0.5), "p95": pctl(&base_ms, 0.95), "max": pctl(&base_ms, 1.0)},
        "scan_ms_storm": {"p50": pctl(&storm_ms, 0.5), "p95": pctl(&storm_ms, 0.95), "max": pctl(&storm_ms, 1.0)},
        "collect_ms_baseline": {"p50": pctl(&base_coll, 0.5), "p95": pctl(&base_coll, 0.95)},
        "collect_ms_storm": {"p50": pctl(&storm_coll, 0.5), "p95": pctl(&storm_coll, 0.95)},
        "supervisor_cpu_pct_baseline": cpu(u0, u1, BASELINE_SECS as f64),
        "supervisor_cpu_pct_storm_incl_spawning": cpu(u1, u2, t_storm.elapsed().as_secs_f64()),
        "false_positives": {"pending": pending, "demoted": demoted, "targeted_events": targeted_events, "signal_calls": signal_calls, "total": false_positives},
        "scan_errors": scan_errors,
        "limit_nearing_seen": limit_nearing,
        "scan_seq_gaps": g.seq_gaps,
        "verdict": verdict,
        "note_ko": "실제 vh 지킴이 CPU는 같은 시간대의 soak 표본(storm_start_ms~storm_end_ms)으로 findings가 계산한다",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_stays_under_limit() {
        let (k, o, b) = storm_shape(300);
        assert!(k as usize + o as usize + b as usize + 3 <= 300);
        assert_eq!(pctl(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
    }
}
