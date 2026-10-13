//! 하위 실행 결과를 `LAB/FINDINGS.json` 하나로 모으고, evidence에 실험실 밖 절대 경로가 없는지 센다.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::util::write_json;

fn read(p: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub struct Inputs<'a> {
    pub run_dir: &'a Path,
    pub out: &'a Path,
    pub repo: &'a Path,
    pub lab_build_sha: &'a str,
    pub vh_sha256: &'a str,
    pub isolation: Option<&'a Path>,
}

/// 같은 id의 재실행(Q6)은 `reruns`로 붙인다(두 결과 모두 기록).
pub fn merge_items(primary: Vec<Value>, reruns: Vec<Value>) -> Vec<Value> {
    let mut by: BTreeMap<String, Value> = BTreeMap::new();
    let mut order = Vec::new();
    for it in primary {
        let id = it["id"].as_str().unwrap_or("").to_string();
        order.push(id.clone());
        by.insert(id, it);
    }
    for it in reruns {
        let id = it["id"].as_str().unwrap_or("").to_string();
        match by.get_mut(&id) {
            Some(p) => {
                if !p["reruns"].is_array() {
                    p["reruns"] = json!([]);
                }
                if let Some(a) = p["reruns"].as_array_mut() {
                    a.push(it);
                }
            }
            None => {
                order.push(id.clone());
                by.insert(id, it);
            }
        }
    }
    order.into_iter().filter_map(|id| by.remove(&id)).collect()
}

fn items_of(v: &Option<Value>) -> Vec<Value> {
    v.as_ref()
        .and_then(|v| v["items"].as_array().cloned())
        .unwrap_or_default()
}

pub fn build(i: &Inputs<'_>) -> io::Result<Value> {
    let d = i.run_dir;
    let scen = read(&d.join("scenarios/result.json"));
    let mut reruns = Vec::new();
    for sub in ["A", "B", "C"] {
        reruns.extend(items_of(&read(
            &d.join(format!("scenarios-rerun-{sub}/result.json")),
        )));
    }
    let edge = read(&d.join("edge/result.json"));
    let tty = read(&d.join("termios/result.json"));
    let mut items = merge_items(items_of(&scen), reruns);
    items.extend(items_of(&edge));
    items.extend(items_of(&tty));
    let soak = read(&d.join("soak/result.json"));
    let stress = read(&d.join("stress/result.json"));
    let interval = read(&d.join("interval/result.json"));
    let soak_samples: Vec<Value> = std::fs::read_to_string(d.join("soak/samples.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let vh_cpu_storm = stress.as_ref().and_then(|s| {
        let (a, b) = (s["storm_start_ms"].as_u64()?, s["storm_end_ms"].as_u64()?);
        let win: Vec<&Value> = soak_samples
            .iter()
            .filter(|x| x["at_ms"].as_u64().is_some_and(|t| t >= a && t <= b))
            .collect();
        let (f, l) = (win.first()?, win.last()?);
        let wall = (l["at_ms"].as_u64()? - f["at_ms"].as_u64()?) as f64 * 1e6;
        let cpu = l["cpu_ns"].as_u64()?.saturating_sub(f["cpu_ns"].as_u64()?) as f64;
        (wall > 0.0).then_some(cpu / wall * 100.0)
    });
    let leftover: u64 = [
        d.join("scenarios/cleanup.json"),
        d.join("stress/cleanup.json"),
        d.join("edge/cleanup.json"),
    ]
    .iter()
    .chain(
        ["A", "B", "C"]
            .iter()
            .map(|s| d.join(format!("scenarios-rerun-{s}/cleanup.json")))
            .collect::<Vec<PathBuf>>()
            .iter(),
    )
    .filter_map(|p| read(p))
    .filter_map(|v| v["leftover_processes"].as_u64())
    .sum();
    let started = std::fs::metadata(d.join("preflight.json"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|x| x.as_millis() as u64);
    let commit_of = |path: &str| {
        git(
            i.repo,
            &["log", "-1", "--format=%H %s", i.lab_build_sha, "--", path],
        )
    };
    Ok(json!({
        "run_id": scen.as_ref().and_then(|s| s["run_id"].as_str().map(str::to_string)),
        "head_sha": git(i.repo, &["rev-parse", "HEAD"]),
        "vh_sha256": i.vh_sha256,
        "lab_build_sha": i.lab_build_sha,
        "lab_build_vh_guard_commit": commit_of("crates/vh-guard"),
        "lab_build_vh_act_commit": commit_of("crates/vh-act"),
        "started_at_ms": started,
        "ended_at_ms": crate::util::now_ms(),
        "items": items,
        "soak": soak,
        "soak_vh_cpu_pct_during_storm": vh_cpu_storm,
        "stress": stress,
        "edge": {"result": edge.as_ref().map(|e| json!({"all_pass": e["all_pass"], "leftover_processes": e["leftover_processes"]}))},
        "interval_ab": interval,
        "termios_check": tty.as_ref().map(|v| json!({"all_pass": v["all_pass"], "cases": v["cases"]})),
        "isolation": {
            "stage2": i.isolation.and_then(read).map(|v| json!({"all_pass": v["all_pass"], "supervisor_kill": v["supervisor_kill"]})),
            "scenarios": read(&d.join("scenarios/isolation.json")),
            "scenarios_isolation_ok": scen.as_ref().map(|s| s["isolation_ok"].clone()),
        },
        "preflight": read(&d.join("preflight.json")),
        "leftover_processes": leftover,
    }))
}

pub fn write_findings(i: &Inputs<'_>) -> io::Result<()> {
    let v = build(i)?;
    write_json(i.out, &v)
}

/// 절대 경로처럼 보이는 조각 중 허용 접두사 밖인 것의 개수(값은 남기지 않는다).
pub fn foreign_paths(text: &str, allowed: &[String]) -> usize {
    let mut n = 0;
    for tok in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ',' | '[' | ']' | '{' | '}' | '(' | ')' | '='
            )
    }) {
        let t = tok.trim_matches(|c: char| c == ':' || c == ';');
        if !t.starts_with('/') || t.len() < 2 || !t[1..].contains('/') && t.len() < 6 {
            continue;
        }
        if !allowed.iter().any(|a| t.starts_with(a.as_str())) {
            n += 1;
        }
    }
    n
}

pub fn default_allowed(extra: &[String]) -> Vec<String> {
    let mut v: Vec<String> = vec!["/usr/bin".into(), "/bin".into(), "/dev/null".into()];
    if let Ok(t) = std::env::var("TMPDIR") {
        let t = t.trim_end_matches('/').to_string();
        v.push(format!("{t}/vh-lab-"));
        v.push(format!("/private{t}/vh-lab-"));
    }
    v.extend(extra.iter().cloned());
    v
}

pub fn privacy_check(dir: &Path, allowed: &[String]) -> io::Result<Value> {
    let mut per_file = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut total = 0;
    let mut files = 0;
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)?.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let ok_ext = p.extension().is_some_and(|x| {
                matches!(x.to_str(), Some("json" | "jsonl" | "txt" | "log" | "md"))
            });
            if !ok_ext {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let n = foreign_paths(&text, allowed);
            if n > 0 {
                total += n;
                per_file.insert(p.to_string_lossy().into_owned(), n);
            }
        }
    }
    Ok(
        json!({"files_scanned": files, "foreign_path_tokens": total, "files_with_foreign_paths": per_file, "allowed_prefixes": allowed}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reruns_attach_to_primary() {
        let m = merge_items(
            vec![json!({"id": "S3", "verdict": "INCONCLUSIVE"})],
            vec![json!({"id": "S3", "verdict": "PASS"})],
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["reruns"][0]["verdict"], "PASS");
    }

    #[test]
    fn foreign_paths_counts_only_outside_allowed() {
        let allowed = vec!["/ev/".to_string(), "/usr/bin".to_string()];
        assert_eq!(foreign_paths("\"/ev/a/b\" /usr/bin:/bin x", &allowed), 0);
        assert_eq!(foreign_paths("\"/ev/a/b\" /opt/other/tool", &allowed), 1);
        assert_eq!(
            foreign_paths("{\"p\":\"/Users/demo/secret/x\"}", &allowed),
            1
        );
        assert_eq!(foreign_paths("10/20 a/b", &allowed), 0);
    }
}
