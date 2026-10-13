//! 측정 대상 vh(복사본, sha 확인) 장시간 실행과 스캔 간격 A/B(PM-1). 모두 notify, 신호 잠금 빈 목록.

use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;

use crate::kernel::usage;
use crate::pty::{PtyVh, write_config};
use crate::util::{now_ms, sha256_file, write_json, write_jsonl};

pub const RSS_MAX_MB: f64 = 25.0;
pub const CPU_MAX_PCT: f64 = 1.0;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Sample {
    pub at_ms: u64,
    pub rss_bytes: u64,
    pub footprint_bytes: u64,
    pub cpu_ns: u64,
}

/// 최소제곱 기울기(y per x).
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    let n = points.len() as f64;
    if points.len() < 2 {
        return None;
    }
    let mx = points.iter().map(|p| p.0).sum::<f64>() / n;
    let my = points.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx == 0.0 {
        return None;
    }
    Some(points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum::<f64>() / sxx)
}

/// RSS MB/분 기울기(`from_min`분 이후 표본만).
pub fn rss_slope_mb_per_min(s: &[Sample], from_min: f64) -> Option<f64> {
    let t0 = s.first()?.at_ms;
    let pts: Vec<(f64, f64)> = s
        .iter()
        .map(|x| {
            (
                (x.at_ms - t0) as f64 / 60_000.0,
                x.rss_bytes as f64 / 1_048_576.0,
            )
        })
        .filter(|p| p.0 >= from_min)
        .collect();
    slope(&pts)
}

pub fn cpu_pct(s: &[Sample], from_ms: u64) -> Option<f64> {
    let a = s.iter().find(|x| x.at_ms >= from_ms)?;
    let b = s.last()?;
    let wall = b.at_ms.checked_sub(a.at_ms)? as f64 * 1e6;
    (wall > 0.0).then(|| b.cpu_ns.saturating_sub(a.cpu_ns) as f64 / wall * 100.0)
}

fn verify_vh(vh: &Path, sha: &str) -> io::Result<()> {
    let got = sha256_file(vh)?;
    if got != sha {
        return Err(io::Error::other(format!(
            "측정 대상 sha256 불일치: {got} ≠ {sha}"
        )));
    }
    Ok(())
}

fn sample(pid: i32) -> Option<Sample> {
    usage(pid).map(|u| Sample {
        at_ms: now_ms(),
        rss_bytes: u.rss_bytes,
        footprint_bytes: u.footprint_bytes,
        cpu_ns: u.cpu_ns,
    })
}

pub fn soak(vh: &Path, sha: &str, minutes: u64, every_s: u64, out: &Path) -> io::Result<bool> {
    verify_vh(vh, sha)?;
    std::fs::create_dir_all(out)?;
    let state = out.join("state");
    write_config(&state, None)?;
    let mut p = PtyVh::spawn(vh, &state, 80, 24)?;
    let mut samples = Vec::new();
    let t = Instant::now();
    let total = Duration::from_secs(minutes * 60);
    let mut saw_guard_line = false;
    let mut died_early = false;
    while t.elapsed() < total {
        if !p.alive() {
            died_early = true;
            break;
        }
        if let Some(s) = sample(p.pid) {
            samples.push(s);
        }
        saw_guard_line |= p.contains("알림만", 0);
        std::thread::sleep(Duration::from_secs(every_s));
    }
    let exit = p.quit(Duration::from_secs(10));
    let restored = p.termios_restored();
    write_jsonl(&out.join("samples.jsonl"), &samples)?;
    let half = minutes as f64 / 2.0;
    let last_slope_10m = rss_slope_mb_per_min(&samples, half).map(|v| v * 10.0);
    let max_rss = samples.iter().map(|s| s.rss_bytes).max().unwrap_or(0) as f64 / 1_048_576.0;
    let t_half = samples
        .first()
        .map(|s| s.at_ms + (half * 60_000.0) as u64)
        .unwrap_or(0);
    let cpu_all = samples.first().and_then(|s| cpu_pct(&samples, s.at_ms));
    let cpu_last = cpu_pct(&samples, t_half);
    let leak = match last_slope_10m {
        Some(v) if v <= 0.2 && max_rss <= RSS_MAX_MB => "PASS",
        Some(v) if v <= 1.0 && max_rss <= RSS_MAX_MB => "INCONCLUSIVE",
        Some(_) => "FAIL",
        None => "INCONCLUSIVE",
    };
    let cpu_v = match cpu_all {
        Some(c) if c <= CPU_MAX_PCT => "PASS",
        Some(_) => "FAIL",
        None => "INCONCLUSIVE",
    };
    let ok_exit = exit.is_some_and(|e| e.success());
    let series_30s: Vec<_> = samples
        .iter()
        .step_by((30 / every_s.max(1)).max(1) as usize)
        .map(|s| json!({"at_ms": s.at_ms, "rss_mb": s.rss_bytes as f64 / 1_048_576.0}))
        .collect();
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "vh-lab/soak/v1",
            "vh": vh, "vh_sha256": sha,
            "minutes": minutes, "sample_secs": every_s, "samples": samples.len(),
            "series_30s": series_30s,
            "rss_first_mb": samples.first().map(|s| s.rss_bytes as f64 / 1_048_576.0),
            "rss_last_mb": samples.last().map(|s| s.rss_bytes as f64 / 1_048_576.0),
            "rss_max_mb": max_rss,
            "rss_slope_last_half_mb_per_10min": last_slope_10m,
            "cpu_avg_pct": cpu_all, "cpu_last_half_pct": cpu_last,
            "leak_verdict": leak, "cpu_verdict": cpu_v,
            "died_early": died_early,
            "exit_ok": ok_exit, "exit_code": exit.and_then(|e| e.code()),
            "termios_restored": restored,
            "notify_level_text_seen": saw_guard_line,
            "screen_bytes": p.bytes.load(std::sync::atomic::Ordering::Relaxed),
            "rss_source": "proc_pid_rusage ri_resident_size(ps -o rss=와 같은 값, 외부 명령 없이)",
        }),
    )?;
    Ok(!died_early && ok_exit && restored)
}

/// `vmmap --summary <pid>`(그 vh만, 읽기 전용)에서 MALLOC 관련 줄만 남긴다(경로가 들어간 줄은 버린다).
pub fn vmmap_malloc(pid: i32) -> Vec<String> {
    let Ok(o) = Command::new("/usr/bin/vmmap")
        .args(["--summary", &pid.to_string()])
        .output()
    else {
        return vec!["vmmap 실행 실패".into()];
    };
    let text = String::from_utf8_lossy(&o.stdout);
    let mut keep = Vec::new();
    let mut in_zone = false;
    for l in text.lines() {
        let t = l.trim_start();
        if t.starts_with("MALLOC ZONE") {
            in_zone = true;
        }
        let interesting = in_zone
            || t.starts_with("Physical footprint")
            || t.starts_with("MALLOC")
            || t.starts_with("TOTAL")
            || t.starts_with("ReadOnly portion")
            || t.starts_with("Writable regions");
        if interesting && !l.contains('/') {
            keep.push(l.to_string());
        }
        if in_zone && t.is_empty() && keep.len() > 2 {
            in_zone = false;
        }
    }
    keep
}

pub fn interval_ab(
    vh: &Path,
    sha: &str,
    minutes: u64,
    intervals: &[u32],
    out: &Path,
) -> io::Result<bool> {
    verify_vh(vh, sha)?;
    std::fs::create_dir_all(out)?;
    let mut runs = Vec::new();
    for &iv in intervals {
        let state = out.join(format!("state-{iv}"));
        write_config(&state, Some(iv))?;
        runs.push((
            iv,
            PtyVh::spawn(vh, &state, 80, 24)?,
            Vec::<Sample>::new(),
            Vec::new(),
            Vec::new(),
        ));
    }
    let t = Instant::now();
    let total = Duration::from_secs(minutes * 60);
    let (mut did1, mut did14) = (false, false);
    while t.elapsed() < total {
        for (_, p, s, _, _) in runs.iter_mut() {
            if let Some(x) = sample(p.pid) {
                s.push(x);
            }
        }
        let el = t.elapsed();
        if !did1 && el >= Duration::from_secs(60) {
            for (_, p, _, v1, _) in runs.iter_mut() {
                *v1 = vmmap_malloc(p.pid);
            }
            did1 = true;
        }
        if !did14 && el >= Duration::from_secs(14 * 60) {
            for (_, p, _, _, v14) in runs.iter_mut() {
                *v14 = vmmap_malloc(p.pid);
            }
            did14 = true;
        }
        std::thread::sleep(
            Duration::from_secs(30)
                .min(total.saturating_sub(t.elapsed()))
                .max(Duration::from_millis(100)),
        );
    }
    let mut res = Vec::new();
    let mut all_ok = true;
    for (iv, mut p, s, v1, v14) in runs {
        let exit = p.quit(Duration::from_secs(10));
        let restored = p.termios_restored();
        all_ok &= exit.is_some_and(|e| e.success()) && restored;
        write_jsonl(&out.join(format!("samples-{iv}.jsonl")), &s)?;
        let first = s.first().map(|x| x.at_ms).unwrap_or(0);
        res.push(json!({
            "scan_interval_ms": iv,
            "samples": s.len(),
            "rss_first_mb": s.first().map(|x| x.rss_bytes as f64 / 1_048_576.0),
            "rss_last_mb": s.last().map(|x| x.rss_bytes as f64 / 1_048_576.0),
            "slope_mb_per_min": rss_slope_mb_per_min(&s, 0.0),
            "slope_second_half_mb_per_min": rss_slope_mb_per_min(&s, minutes as f64 / 2.0),
            "cpu_avg_pct": cpu_pct(&s, first),
            "vmmap_1min_malloc": v1,
            "vmmap_14min_malloc": v14,
            "exit_code": exit.and_then(|e| e.code()),
            "termios_restored": restored,
        }));
    }
    let sl = |i: usize| res.get(i).and_then(|r| r["slope_mb_per_min"].as_f64());
    let ratio = match (sl(0), sl(1)) {
        (Some(a), Some(b)) if b.abs() > 1e-9 => Some(a / b),
        _ => None,
    };
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "vh-lab/interval-ab/v1",
            "experiment": "PM-1",
            "vh": vh, "vh_sha256": sha, "minutes": minutes,
            "runs": res,
            "slope_ratio_first_over_second": ratio,
            "reading_ko": "비율 ≈ 6(간격 비 30000/5000)이면 스캔당 할당 churn, ≈ 1이면 시간 기반 원인(PM-1 판별 기준)",
        }),
    )?;
    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slope_of_line() {
        let pts: Vec<(f64, f64)> = (0..10).map(|i| (i as f64, 2.0 * i as f64 + 1.0)).collect();
        assert!((slope(&pts).unwrap() - 2.0).abs() < 1e-9);
        assert!(slope(&[(1.0, 1.0)]).is_none());
    }

    #[test]
    fn cpu_pct_from_samples() {
        let s = [
            Sample {
                at_ms: 0,
                rss_bytes: 0,
                footprint_bytes: 0,
                cpu_ns: 0,
            },
            Sample {
                at_ms: 10_000,
                rss_bytes: 0,
                footprint_bytes: 0,
                cpu_ns: 100_000_000,
            },
        ];
        assert!((cpu_pct(&s, 0).unwrap() - 1.0).abs() < 1e-9);
    }
}
