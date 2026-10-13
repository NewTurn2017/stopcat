use std::io::Read;
use std::time::Instant;

use vh_analyze::analyze;
use vh_model::Snapshot;

const RUNS: usize = 5;

fn main() {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("표준 입력에서 스냅샷 JSON을 읽지 못함");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("JSON이 아님");
    let snap = v.get("snapshot").cloned().unwrap_or(v);
    let s: Snapshot = serde_json::from_value(snap).expect("계약 모양 Snapshot이 아님");
    let report = analyze(&s);
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        let r = analyze(&s);
        runs.push(t.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(r, report);
    }
    let mut sorted = runs.clone();
    sorted.sort_by(f64::total_cmp);
    let out = serde_json::json!({
        "n": s.processes.len(),
        "runs_ms": runs,
        "p50_ms": sorted[RUNS / 2],
        "report": report,
    });
    println!("{out}");
}
