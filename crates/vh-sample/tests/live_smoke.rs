//! 실기기 읽기 전용 스모크 테스트. 값(argv·env·경로)은 출력하지 않고 성질만 확인한다.

use std::collections::HashSet;

use vh_model::{ENV_ALLOWLIST, ProcStatus};
use vh_sample::{CollectOptions, collect};

#[test]
fn collect_smoke_live_no_cpu() {
    let s = collect(&CollectOptions {
        cpu_interval_ms: None,
        ..CollectOptions::default()
    });
    assert_eq!(s.schema_version, vh_model::SCHEMA_VERSION);
    assert!(s.processes.len() > 10, "프로세스 수 {}", s.processes.len());
    assert!(s.cpu_sample_interval_ms.is_none());
    assert!(s.processes.iter().all(|p| p.cpu_pct.is_none()));
    let me = s
        .processes
        .iter()
        .find(|p| p.pid == s.self_pid)
        .expect("자기 프로세스");
    assert_eq!(me.uid, s.self_uid);
    assert!(me.argv_readable);
    assert!(me.exe.is_some() && me.cwd.is_some() && me.footprint_bytes.is_some());
    assert!(me.threads.is_some() && me.nice.is_some());
    let allow: HashSet<&str> = ENV_ALLOWLIST.iter().copied().collect();
    for p in &s.processes {
        assert!(
            p.env.keys().all(|k| allow.contains(k.as_str())),
            "pid {} 허용 목록 밖 env 키",
            p.pid
        );
        if p.uid != s.self_uid {
            assert!(!p.argv_readable && p.argv.is_empty() && p.env.is_empty() && p.cwd.is_none());
        }
        if p.status == ProcStatus::Zombie {
            assert!(p.exe.is_none() && p.footprint_bytes.is_none());
        }
    }
    let pids: HashSet<i32> = s.processes.iter().map(|p| p.pid).collect();
    assert_eq!(pids.len(), s.processes.len(), "pid 중복");
    assert!(s.processes.iter().any(|p| p.pid == 1));
    for l in &s.listeners {
        assert!(pids.contains(&l.pid));
        assert!(l.port > 0);
    }
    assert!(s.memory.page_size > 0 && s.memory.pressure_level > 0);
    assert!(s.host.ncpu > 0 && s.host.mem_total_bytes > 0 && !s.host.home_dir.is_empty());
    assert!(
        s.limits.user_proc_count > 0 && s.limits.total_proc_count as usize == s.processes.len()
    );
    assert!(!s.launchd_job_pids.is_empty());
    assert!(s.timings_ms.total_ms > 0.0);
}

#[test]
fn collect_live_with_cpu_interval() {
    let s = collect(&CollectOptions {
        cpu_interval_ms: Some(100),
        launchd: false,
        project_roots: false,
    });
    assert_eq!(s.cpu_sample_interval_ms, Some(100));
    assert!(s.timings_ms.cpu_wait_ms > 0.0);
    let with_pct = s.processes.iter().filter(|p| p.cpu_pct.is_some()).count();
    assert!(with_pct > 10, "cpu_pct 있는 프로세스 {with_pct}");
    assert!(
        s.processes
            .iter()
            .filter_map(|p| p.cpu_pct)
            .all(|c| c >= 0.0 && c.is_finite())
    );
    assert!(s.launchd_job_pids.is_empty() && s.project_roots.is_empty());
}
