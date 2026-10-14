//! 실기기 읽기 전용 스캔 시간 측정(#[ignore]). 결과에는 시간·개수만 쓴다.
//!
//! 실행: STOPCAT_CROSSCHECK_OUT=<폴더> STOPCAT_TIMING_TAG=<이름> cargo test -p stopcat-sample --release --test scan_timing -- --ignored

use std::path::PathBuf;

use stopcat_sample::{CollectOptions, collect};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[test]
#[ignore]
fn scan_timing_no_cpu() {
    let opts = CollectOptions {
        cpu_interval_ms: None,
        ..CollectOptions::default()
    };
    let _ = collect(&opts);
    let runs: Vec<_> = (0..15).map(|_| collect(&opts)).collect();
    let pick =
        |f: fn(&stopcat_model::Timings) -> f64| median(runs.iter().map(|s| f(&s.timings_ms)).collect());
    let body = serde_json::json!({
        "tag": std::env::var("STOPCAT_TIMING_TAG").unwrap_or_default(),
        "runs": runs.len(),
        "cpu_interval_ms": null,
        "median_total_ms": pick(|t| t.total_ms),
        "median_procs_ms": pick(|t| t.procs_ms),
        "median_sockets_ms": pick(|t| t.sockets_ms),
        "median_list_ms": pick(|t| t.list_ms),
        "processes_median": median(runs.iter().map(|s| s.processes.len() as f64).collect()),
    });
    let dir = std::env::var_os("STOPCAT_CROSSCHECK_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("stopcat-crosscheck"));
    std::fs::create_dir_all(&dir).expect("결과 폴더");
    let name = format!(
        "scan_timing_{}.json",
        std::env::var("STOPCAT_TIMING_TAG").unwrap_or_else(|_| "run".into())
    );
    std::fs::write(
        dir.join(name),
        serde_json::to_string_pretty(&body).unwrap() + "\n",
    )
    .expect("결과 쓰기");
}
