//! 성능 측정: collect 한 번 하고 수치만 JSON 한 줄로 낸다(argv·env·경로 없음).
//! 사용: bench_collect --mode no-cpu|cpu

use vh_sample::{CollectOptions, collect};

fn main() {
    let mode = std::env::args()
        .skip_while(|a| a != "--mode")
        .nth(1)
        .unwrap_or_else(|| "no-cpu".to_string());
    let opts = match mode.as_str() {
        "cpu" => CollectOptions::default(),
        "no-cpu" => CollectOptions {
            cpu_interval_ms: None,
            ..CollectOptions::default()
        },
        other => {
            eprintln!("알 수 없는 모드: {other} (no-cpu | cpu)");
            std::process::exit(1);
        }
    };
    let t = std::time::Instant::now();
    let s = collect(&opts);
    let wall_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t_ = &s.timings_ms;
    println!(
        "{{\"mode\":\"{mode}\",\"wall_ms\":{wall_ms:.3},\"timings_ms\":{{\"list_ms\":{:.3},\"procs_ms\":{:.3},\"sockets_ms\":{:.3},\"system_ms\":{:.3},\"launchd_ms\":{:.3},\"roots_ms\":{:.3},\"cpu_wait_ms\":{:.3},\"total_ms\":{:.3}}},\"processes\":{},\"own_processes\":{},\"listeners\":{},\"project_roots\":{},\"launchd_jobs\":{},\"collection_errors\":{}}}",
        t_.list_ms,
        t_.procs_ms,
        t_.sockets_ms,
        t_.system_ms,
        t_.launchd_ms,
        t_.roots_ms,
        t_.cpu_wait_ms,
        t_.total_ms,
        s.processes.len(),
        s.limits.user_proc_count,
        s.listeners.len(),
        s.project_roots.len(),
        s.launchd_job_pids.len(),
        s.collection_errors.len(),
    );
}
