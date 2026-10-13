//! 실행 전 점검: 부하·메모리 압력·프로세스 수 여유, 도우미 이름별 1회 실행, 감독에 제어 터미널 없음,
//! 측정 대상 vh 복사·sha256 확인.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Serialize;

use crate::kernel::{loadavg_1m, pressure_level};
use crate::lab::Lab;
use crate::spec::{HELPER_NAMES, Role};
use crate::util::{new_run_id, sha256_file, write_json};

pub const MAX_LOAD_1M: f64 = 12.0;
pub const MAX_LAB_PROCS: usize = 300;

#[derive(Debug, Serialize)]
pub struct HelperCheck {
    pub name: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_ok: bool,
}

#[derive(Debug, Serialize)]
pub struct Preflight {
    pub loadavg_1m: Option<f64>,
    pub pressure_level: Option<u32>,
    pub user_proc_count: u32,
    pub maxprocperuid: u32,
    pub room_for_lab: bool,
    pub supervisor_has_tty: Option<bool>,
    pub helpers: Vec<HelperCheck>,
    pub vh_copy: Option<VhCopy>,
    pub ok: bool,
    pub reasons_ko: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VhCopy {
    pub src: String,
    pub dest: String,
    pub expected_sha256: String,
    pub src_sha256: String,
    pub dest_sha256: String,
    pub matches: bool,
}

pub fn load_ok() -> (bool, Vec<String>) {
    let mut why = Vec::new();
    match loadavg_1m() {
        Some(l) if l <= MAX_LOAD_1M => {}
        Some(l) => why.push(format!("1분 부하 {l:.2} > {MAX_LOAD_1M}")),
        None => why.push("부하 읽기 실패".into()),
    }
    match pressure_level() {
        Some(1) => {}
        other => why.push(format!("메모리 압력 {other:?} ≠ 1")),
    }
    (why.is_empty(), why)
}

pub fn copy_vh(src: &Path, dest: &Path, expected: &str) -> io::Result<VhCopy> {
    let src_sha = sha256_file(src)?;
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d)?;
    }
    if src_sha == expected {
        std::fs::copy(src, dest)?;
    }
    let dest_sha = if dest.is_file() {
        sha256_file(dest)?
    } else {
        String::new()
    };
    Ok(VhCopy {
        src: src.to_string_lossy().into_owned(),
        dest: dest.to_string_lossy().into_owned(),
        expected_sha256: expected.to_string(),
        matches: src_sha == expected && dest_sha == expected,
        src_sha256: src_sha,
        dest_sha256: dest_sha,
    })
}

pub fn run(out: &Path, vh: Option<(&Path, &Path, &str)>) -> io::Result<bool> {
    let (load_ok, mut reasons) = load_ok();
    let s = vh_sample::collect(&vh_sample::CollectOptions {
        cpu_interval_ms: None,
        launchd: false,
        project_roots: false,
    });
    let me = std::process::id() as i32;
    let has_tty = s.processes.iter().find(|p| p.pid == me).map(|p| p.has_tty);
    let room =
        (s.limits.user_proc_count as usize + MAX_LAB_PROCS) * 2 <= s.limits.maxprocperuid as usize;
    if !room {
        reasons.push("자기 uid 프로세스 수 + 300이 maxprocperuid의 50%를 넘음".into());
    }
    if has_tty != Some(false) {
        reasons.push(format!("감독 has_tty = {has_tty:?}(false여야 함)"));
    }
    let lab = Lab::create(&new_run_id()?)?;
    let mut helpers = Vec::new();
    for name in HELPER_NAMES {
        let spec = lab.exec_spec(name, Role::Selftest, &[name], None, &[], 5);
        let out = Command::new(&spec.exe)
            .env_clear()
            .envs(&spec.env)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        let hc = match out {
            Ok(o) => HelperCheck {
                name: name.to_string(),
                exit_code: o.status.code(),
                signal: o.status.signal(),
                stdout_ok: String::from_utf8_lossy(&o.stdout).trim() == "ok",
            },
            Err(_) => HelperCheck {
                name: name.to_string(),
                exit_code: None,
                signal: None,
                stdout_ok: false,
            },
        };
        if hc.exit_code != Some(0) || !hc.stdout_ok {
            reasons.push(format!("도우미 {name} 실행 실패"));
        }
        helpers.push(hc);
    }
    let cleanup = lab.cleanup();
    if cleanup.leftover_processes != 0 {
        reasons.push(format!(
            "점검 실험실 남은 프로세스 {}",
            cleanup.leftover_processes
        ));
    }
    let vh_copy = match vh {
        Some((src, dest, sha)) => {
            let c = copy_vh(src, dest, sha)?;
            if !c.matches {
                reasons.push("측정 대상 vh sha256 불일치".into());
            }
            Some(c)
        }
        None => None,
    };
    let ok = reasons.is_empty() && load_ok;
    let pf = Preflight {
        loadavg_1m: loadavg_1m(),
        pressure_level: pressure_level(),
        user_proc_count: s.limits.user_proc_count,
        maxprocperuid: s.limits.maxprocperuid,
        room_for_lab: room,
        supervisor_has_tty: has_tty,
        helpers,
        vh_copy,
        ok,
        reasons_ko: reasons,
    };
    write_json(out, &pf)?;
    Ok(ok)
}
