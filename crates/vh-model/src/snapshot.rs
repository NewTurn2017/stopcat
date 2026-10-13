//! 수집 결과 타입 (vh-sample이 만든다).
//!
//! 시간은 unix 밀리초, 크기는 바이트. `start_time_unix_ms`는
//! `p_starttime.tv_sec * 1000 + p_starttime.tv_usec / 1000` 한 식으로만 만든다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 한 번의 수집 결과 전체.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub taken_at_unix_ms: u64,
    pub host: HostInfo,
    pub memory: MemoryInfo,
    pub limits: LimitsInfo,
    /// 좀비 포함.
    pub processes: Vec<Proc>,
    pub listeners: Vec<Listener>,
    /// `launchctl list` PID 열(사용자 도메인).
    pub launchd_job_pids: Vec<i32>,
    /// 같은 출력의 pid → label.
    pub launchd_job_labels: BTreeMap<i32, String>,
    /// cwd → 프로젝트 루트. cwd에서 위로 올라가며 .git·package.json·pyproject.toml·Cargo.toml·go.mod 가
    /// 처음 나오는 폴더(홈 디렉터리와 / 는 루트로 치지 않는다). 못 찾은 cwd는 키가 없다.
    pub project_roots: BTreeMap<String, String>,
    pub self_pid: i32,
    pub self_uid: u32,
    pub cpu_sample_interval_ms: Option<u32>,
    pub collection_errors: Vec<CollectionError>,
    pub timings_ms: Timings,
}

/// 기계 정보.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostInfo {
    pub model: String,
    pub os_version: String,
    pub arch: String,
    pub ncpu: u32,
    pub perf_cores: Option<u32>,
    pub eff_cores: Option<u32>,
    pub mem_total_bytes: u64,
    pub boot_time_unix_ms: u64,
    pub loadavg: [f64; 3],
    pub home_dir: String,
}

/// 시스템 메모리 상태.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// kern.memorystatus_vm_pressure_level. 1=정상, 2=경고, 4=위험. 다른 값은 그대로 둔다.
    pub pressure_level: u32,
    pub page_size: u64,
    pub free_bytes: u64,
    pub active_bytes: u64,
    pub inactive_bytes: u64,
    pub speculative_bytes: u64,
    pub wired_bytes: u64,
    /// compressor_page_count × page_size (압축본이 차지하는 물리 메모리. 화면의 "압축 N GB").
    pub compressor_bytes: u64,
    /// total_uncompressed_pages_in_compressor × page_size (압축 전 크기).
    pub compressed_logical_bytes: u64,
    pub purgeable_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swapins: u64,
    pub swapouts: u64,
}

/// 커널 한도와 현재 사용량.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimitsInfo {
    pub maxproc: u32,
    pub maxprocperuid: u32,
    pub maxfiles: u32,
    pub maxfilesperproc: u32,
    pub num_files: u32,
    pub user_proc_count: u32,
    pub total_proc_count: u32,
}

/// 프로세스 상태(kinfo_proc p_stat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Idle,
    Unknown,
}

/// 프로세스 한 개.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    /// kinfo_proc e_ucred.cr_uid
    pub uid: u32,
    pub start_time_unix_ms: u64,
    /// 자기 uid: pbi_name → pbi_comm, 남의 uid: kinfo_proc p_comm
    pub name: String,
    /// proc_pidpath
    pub exe: Option<String>,
    /// KERN_PROCARGS2 원문. 표시는 `redact_argv`를 거친다.
    pub argv: Vec<String>,
    pub argv_readable: bool,
    /// ENV_ALLOWLIST 키만.
    pub env: BTreeMap<String, String>,
    pub env_readable: bool,
    pub cwd: Option<String>,
    pub status: ProcStatus,
    pub has_tty: bool,
    /// ri_phys_footprint
    pub footprint_bytes: Option<u64>,
    pub rss_bytes: Option<u64>,
    pub cpu_time_ns: Option<u64>,
    /// 두 샘플 사이 cpu_time 차 / 간격 × 100 (코어 1개 = 100)
    pub cpu_pct: Option<f32>,
    pub threads: Option<u32>,
    /// 자기 uid만.
    pub nice: Option<i32>,
    /// kinfo_proc p_flag & P_TRANSLATED
    pub translated: bool,
}

/// 소켓 주소 계열.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V4,
    V6,
}

/// TCP LISTEN 소켓 한 개.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listener {
    pub pid: i32,
    pub start_time_unix_ms: u64,
    pub family: Family,
    /// "127.0.0.1", "::1", "0.0.0.0", "::"
    pub local_addr: String,
    pub port: u16,
    /// 0.0.0.0 또는 ::
    pub all_interfaces: bool,
    pub loopback: bool,
    /// v6 소켓이 IPv4도 받음(INI_IPV4|INI_IPV6)
    pub dual_stack: bool,
}

/// 수집 중 난 오류. 0으로 채우지 않고 여기에 남긴다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionError {
    pub pid: Option<i32>,
    pub stage: String,
    pub errno: Option<i32>,
    pub message: String,
}

/// 수집 단계별 시간(밀리초).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timings {
    pub list_ms: f64,
    pub procs_ms: f64,
    pub sockets_ms: f64,
    pub system_ms: f64,
    pub launchd_ms: f64,
    pub roots_ms: f64,
    pub cpu_wait_ms: f64,
    pub total_ms: f64,
}
