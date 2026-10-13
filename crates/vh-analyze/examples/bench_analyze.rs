use std::time::Instant;

use vh_analyze::analyze;
use vh_analyze::synth::synth_snapshot;

const N: usize = 2000;
const RUNS: usize = 5;
const BUDGET_MS: f64 = 20.0;

fn main() {
    let s = synth_snapshot(N, 7);
    let warm = analyze(&s);
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        let r = analyze(&s);
        runs.push(t.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(r.findings.len(), warm.findings.len());
    }
    let mut sorted = runs.clone();
    sorted.sort_by(f64::total_cmp);
    let p50 = sorted[RUNS / 2];
    let runs_json: Vec<String> = runs.iter().map(|v| format!("{v:.3}")).collect();
    println!(
        "{{\"n\":{N},\"warmup\":1,\"runs_ms\":[{}],\"p50_ms\":{p50:.3},\"budget_ms\":{BUDGET_MS},\"pass\":{},\"findings\":{}}}",
        runs_json.join(","),
        p50 <= BUDGET_MS,
        warm.findings.len()
    );
}
