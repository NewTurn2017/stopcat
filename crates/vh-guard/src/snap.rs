use std::collections::BTreeMap;

use vh_model::{
    Classified, Health, HealthLevel, HostInfo, LimitsInfo, MemoryInfo, Report, SCHEMA_VERSION,
    Snapshot, Timings, Totals,
};

/// 프로세스가 없는 스냅샷(되돌리기 계획용, 가짜 백엔드의 바탕).
pub fn bare_snapshot(self_pid: i32, self_uid: u32, taken_at_unix_ms: u64) -> Snapshot {
    Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms,
        host: HostInfo {
            model: String::new(),
            os_version: String::new(),
            arch: String::new(),
            ncpu: 1,
            perf_cores: None,
            eff_cores: None,
            mem_total_bytes: 0,
            boot_time_unix_ms: 0,
            loadavg: [0.0; 3],
            home_dir: String::new(),
        },
        memory: MemoryInfo {
            pressure_level: 1,
            page_size: 16384,
            free_bytes: 0,
            active_bytes: 0,
            inactive_bytes: 0,
            speculative_bytes: 0,
            wired_bytes: 0,
            compressor_bytes: 0,
            compressed_logical_bytes: 0,
            purgeable_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            swapins: 0,
            swapouts: 0,
        },
        limits: LimitsInfo {
            maxproc: 0,
            maxprocperuid: 0,
            maxfiles: 0,
            maxfilesperproc: 0,
            num_files: 0,
            user_proc_count: 0,
            total_proc_count: 0,
        },
        processes: Vec::new(),
        listeners: Vec::new(),
        launchd_job_pids: Vec::new(),
        launchd_job_labels: BTreeMap::new(),
        project_roots: BTreeMap::new(),
        self_pid,
        self_uid,
        cpu_sample_interval_ms: None,
        collection_errors: Vec::new(),
        timings_ms: Timings {
            list_ms: 0.0,
            procs_ms: 0.0,
            sockets_ms: 0.0,
            system_ms: 0.0,
            launchd_ms: 0.0,
            roots_ms: 0.0,
            cpu_wait_ms: 0.0,
            total_ms: 0.0,
        },
    }
}

/// 발견이 없는 리포트.
pub fn bare_report(taken_at_unix_ms: u64, classified: Vec<Classified>) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: String::new(),
            reasons_ko: Vec::new(),
        },
        classified,
        groups: Vec::new(),
        findings: Vec::new(),
        listeners: Vec::new(),
        totals: Totals {
            reclaimable_confirmed_bytes: 0,
            reclaimable_likely_bytes: 0,
            unneeded_bytes: 0,
            check_bytes: 0,
            manual_bytes: 0,
        },
    }
}
