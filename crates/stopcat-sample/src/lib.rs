//! stopcat-sample: macOS 프로세스·메모리·포트 수집기 (CORE 소유).
//!
//! 공개 API는 [`CollectOptions`]와 [`collect`] 두 개다. 수집은 실패하지 않는다.
//! 부분 실패는 `Snapshot::collection_errors`에 남기고 값은 0으로 채우지 않는다.
//!
//! 출처: 기본 표는 `sysctl(KERN_PROC_ALL)`(모든 uid, 좀비 포함). 자기 uid 프로세스만
//! libproc(TASKALLINFO, VNODEPATHINFO, LISTFDS, FDSOCKETINFO)과 KERN_PROCARGS2를 읽는다.
//! FDSOCKETINFO 한 번으로 LISTEN(`listeners`)과 ESTABLISHED(`Proc::tcp`)를 함께 얻는다.
//! 디스크 누적 바이트는 CPU와 같은 rusage v4에서 읽는다.
//! `proc_pidpath`·`proc_pid_rusage`는 모든 uid에 시도한다. 외부 명령은 `launchctl list` 1회.

mod ffi;
mod launchd;
mod list;
mod peers;
mod procargs;
mod procinfo;
mod roots;
mod sockets;
mod system;
mod timebase;

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use stopcat_model::{CollectionError, Proc, ProcStatus, SCHEMA_VERSION, Snapshot, Timings};

/// 수집 옵션.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectOptions {
    /// CPU 사용률용 두 번째 샘플 간격(밀리초). `None`이면 한 번만 샘플(`--no-cpu`).
    pub cpu_interval_ms: Option<u32>,
    /// `launchctl list`를 실행해 launchd 잡 PID를 채운다.
    pub launchd: bool,
    /// cwd에서 위로 올라가며 프로젝트 루트를 찾는다.
    pub project_roots: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            cpu_interval_ms: Some(250),
            launchd: true,
            project_roots: true,
        }
    }
}

const OTHER_UID_MSG: &str = "권한 없음(정상)";

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn err(
    pid: Option<i32>,
    stage: &str,
    errno: Option<i32>,
    message: impl Into<String>,
) -> CollectionError {
    CollectionError {
        pid,
        stage: stage.to_string(),
        errno,
        message: message.into(),
    }
}

fn status_of(stat: i8) -> ProcStatus {
    match stat {
        ffi::SIDL => ProcStatus::Idle,
        ffi::SRUN => ProcStatus::Running,
        ffi::SSLEEP => ProcStatus::Sleeping,
        ffi::SSTOP => ProcStatus::Stopped,
        ffi::SZOMB => ProcStatus::Zombie,
        _ => ProcStatus::Unknown,
    }
}

/// CPU 첫 샘플.
#[derive(Clone, Copy)]
struct CpuSample {
    at: Instant,
    cpu_ns: u64,
    start_abs: u64,
    /// 첫 샘플의 디스크 읽기+쓰기 누적 바이트.
    disk: u64,
}

/// 이 맥의 현재 상태를 읽어 스냅샷을 만든다. 읽기 전용이며 패닉하지 않는다.
pub fn collect(opts: &CollectOptions) -> Snapshot {
    let t_total = Instant::now();
    let taken_at_unix_ms = now_unix_ms();
    let self_pid = std::process::id() as i32;
    // SAFETY: getuid는 항상 성공한다.
    let self_uid = unsafe { libc::getuid() };
    let mut errors: Vec<CollectionError> = Vec::new();
    let mut timings = Timings {
        list_ms: 0.0,
        procs_ms: 0.0,
        sockets_ms: 0.0,
        system_ms: 0.0,
        launchd_ms: 0.0,
        roots_ms: 0.0,
        cpu_wait_ms: 0.0,
        total_ms: 0.0,
    };

    // 1. 목록
    let t = Instant::now();
    let raw = list::list_all().unwrap_or_else(|e| {
        errors.push(err(
            None,
            "list",
            Some(e),
            "프로세스 목록(KERN_PROC_ALL) 읽기 실패",
        ));
        Vec::new()
    });
    match list::listallpids() {
        Ok(pids) => {
            let known: HashSet<i32> = raw.iter().map(|r| r.pid).collect();
            let extra = pids.iter().filter(|p| !known.contains(p)).count();
            if extra > 0 {
                errors.push(err(
                    None,
                    "list_race",
                    None,
                    format!("두 목록 사이에 새로 생긴 프로세스 {extra}개(이번 스냅샷에서 빠짐)"),
                ));
            }
        }
        Err(e) => errors.push(err(None, "list_race", Some(e), "proc_listallpids 실패")),
    }
    timings.list_ms = ms(t.elapsed());

    // launchctl은 먼저 띄워 두고 끝에서 결과를 받는다.
    let t = Instant::now();
    let launchd_child = if opts.launchd {
        match launchd::spawn() {
            Ok(c) => Some(c),
            Err(e) => {
                errors.push(err(
                    None,
                    "launchd",
                    e.raw_os_error(),
                    format!("launchctl list 실행 실패: {e}"),
                ));
                None
            }
        }
    } else {
        None
    };
    let mut launchd_ms = ms(t.elapsed());

    // 2. 프로세스별 정보
    let t_procs = Instant::now();
    let (numer, denom) = timebase::timebase();
    let rusage_start = Instant::now();
    let mut procs: Vec<Proc> = Vec::with_capacity(raw.len());
    let mut first: Vec<Option<CpuSample>> = Vec::with_capacity(raw.len());
    let mut other_live = 0usize;
    let mut other_rusage_fail = 0usize;
    let mut other_path_fail = 0usize;
    for r in &raw {
        let zombie = r.stat == ffi::SZOMB;
        let own = r.uid == self_uid;
        if !own && !zombie {
            other_live += 1;
        }
        let mut p = Proc {
            pid: r.pid,
            ppid: r.ppid,
            pgid: r.pgid,
            uid: r.uid,
            start_time_unix_ms: r.start_time_unix_ms,
            name: r.comm.clone(),
            exe: None,
            argv: Vec::new(),
            argv_readable: false,
            env: BTreeMap::new(),
            env_readable: false,
            cwd: None,
            status: status_of(r.stat),
            has_tty: r.tdev != ffi::NODEV,
            footprint_bytes: None,
            rss_bytes: None,
            cpu_time_ns: None,
            cpu_pct: None,
            threads: None,
            nice: None,
            translated: r.flag & ffi::P_TRANSLATED != 0,
            tcp: None,
            disk_read_bytes: None,
            disk_written_bytes: None,
            disk_io_delta_bytes: None,
        };
        let mut sample = None;
        if !zombie && r.pid > 0 {
            match procinfo::rusage(r.pid) {
                Ok(ri) => {
                    let cpu_ns = timebase::ticks_to_ns(
                        ri.ri_user_time.saturating_add(ri.ri_system_time),
                        numer,
                        denom,
                    );
                    p.footprint_bytes = Some(ri.ri_phys_footprint);
                    p.rss_bytes = Some(ri.ri_resident_size);
                    p.cpu_time_ns = Some(cpu_ns);
                    p.disk_read_bytes = Some(ri.ri_diskio_bytesread);
                    p.disk_written_bytes = Some(ri.ri_diskio_byteswritten);
                    sample = Some(CpuSample {
                        at: Instant::now(),
                        cpu_ns,
                        start_abs: ri.ri_proc_start_abstime,
                        disk: ri
                            .ri_diskio_bytesread
                            .saturating_add(ri.ri_diskio_byteswritten),
                    });
                }
                Err(e) if own => {
                    errors.push(err(Some(r.pid), "rusage", Some(e), "proc_pid_rusage 실패"))
                }
                Err(_) => other_rusage_fail += 1,
            }
        }
        procs.push(p);
        first.push(sample);
    }

    let mut path_buf = [0u8; ffi::PROC_PIDPATHINFO_MAXSIZE];
    let mut args_buf = vec![0u8; procargs::argmax()];
    let mut fd_buf: Vec<ffi::ProcFdInfo> = Vec::new();
    let mut sock_buf = ffi::SocketFdInfo([0; ffi::SOCKET_FDINFO_SIZE]);
    let mut listeners = Vec::new();
    let mut sockets_time = Duration::ZERO;
    let mut socket_fd_errors = 0usize;
    let mut conns: Vec<peers::Conn> = Vec::new();
    let mut estab: Vec<sockets::EstabSock> = Vec::new();
    let mut tcp_known = vec![false; procs.len()];
    let mut conn_cap_hit = 0usize;
    for (idx, p) in procs.iter_mut().enumerate() {
        if p.status == ProcStatus::Zombie || p.pid <= 0 {
            continue;
        }
        let own = p.uid == self_uid;
        match procinfo::pidpath(p.pid, &mut path_buf) {
            Ok(path) => p.exe = Some(path),
            Err(e) if own => errors.push(err(Some(p.pid), "pidpath", Some(e), "proc_pidpath 실패")),
            Err(_) => other_path_fail += 1,
        }
        if !own {
            continue;
        }
        let mut nfiles = 0usize;
        match procinfo::task_all_info(p.pid) {
            Ok(info) => {
                let name = ffi::c_str(&info.pbsd.pbi_name);
                let comm = ffi::c_str(&info.pbsd.pbi_comm);
                if !name.is_empty() {
                    p.name = name;
                } else if !comm.is_empty() {
                    p.name = comm;
                }
                p.nice = Some(info.pbsd.pbi_nice);
                p.threads = u32::try_from(info.ptinfo.pti_threadnum).ok();
                nfiles = info.pbsd.pbi_nfiles as usize;
            }
            Err(e) => errors.push(err(
                Some(p.pid),
                "bsdinfo",
                Some(e),
                "PROC_PIDTASKALLINFO 실패",
            )),
        }
        match procargs::read(p.pid, &mut args_buf) {
            Ok(n) => {
                let parsed = procargs::parse(&args_buf[..n]);
                p.argv = parsed.argv;
                p.argv_readable = parsed.argv_readable;
                p.env = parsed.env;
                p.env_readable = parsed.env_readable;
            }
            Err(e) => errors.push(err(Some(p.pid), "procargs", Some(e), "KERN_PROCARGS2 실패")),
        }
        match procinfo::cwd(p.pid) {
            Ok(c) => p.cwd = c,
            Err(e) => errors.push(err(
                Some(p.pid),
                "cwd",
                Some(e),
                "PROC_PIDVNODEPATHINFO 실패",
            )),
        }
        let ts = Instant::now();
        estab.clear();
        match sockets::sockets_of(
            p.pid,
            p.start_time_unix_ms,
            nfiles,
            &mut fd_buf,
            &mut sock_buf,
            &mut estab,
        ) {
            Ok(s) => {
                listeners.extend(s.listeners);
                socket_fd_errors += s.fd_errors;
                if conns.len() + estab.len() > peers::MAX_CONNS {
                    conn_cap_hit += 1;
                } else {
                    tcp_known[idx] = true;
                    conns.extend(estab.iter().map(|&sock| peers::Conn {
                        proc_idx: idx,
                        sock,
                    }));
                }
            }
            Err(e) => errors.push(err(Some(p.pid), "fds", Some(e), "PROC_PIDLISTFDS 실패")),
        }
        sockets_time += ts.elapsed();
    }
    if other_live > 0 {
        let msg = format!("남의 사용자 프로세스 {other_live}개: {OTHER_UID_MSG}");
        for stage in ["bsdinfo", "procargs", "cwd", "fds"] {
            errors.push(err(None, stage, None, msg.clone()));
        }
    }
    if other_rusage_fail > 0 {
        errors.push(err(
            None,
            "rusage",
            Some(libc::EPERM),
            format!("남의 사용자 프로세스 {other_rusage_fail}개: {OTHER_UID_MSG}"),
        ));
    }
    if other_path_fail > 0 {
        errors.push(err(
            None,
            "pidpath",
            None,
            format!("남의 사용자 프로세스 {other_path_fail}개: 실행 파일 경로 읽기 실패"),
        ));
    }
    let ts = Instant::now();
    let pids: Vec<i32> = procs.iter().map(|p| p.pid).collect();
    for (p, tcp) in procs
        .iter_mut()
        .zip(peers::summarize(&conns, &pids, &tcp_known))
    {
        p.tcp = tcp;
    }
    drop(conns);
    sockets_time += ts.elapsed();
    if conn_cap_hit > 0 {
        errors.push(err(
            None,
            "tcp",
            None,
            format!(
                "ESTABLISHED 기록 상한({}개)을 넘어 프로세스 {conn_cap_hit}개의 연결 요약을 비움(모름)",
                peers::MAX_CONNS
            ),
        ));
    }
    if socket_fd_errors > 0 {
        errors.push(err(
            None,
            "socket",
            None,
            format!("소켓 fd {socket_fd_errors}개: 정보 읽기 실패(그 사이 닫힌 것 포함)"),
        ));
    }
    timings.sockets_ms = ms(sockets_time);
    timings.procs_ms = ms(t_procs.elapsed().saturating_sub(sockets_time));

    // 3. 시스템
    let t = Instant::now();
    let mut sys = system::read(&mut errors);
    sys.limits.total_proc_count = procs.len() as u32;
    sys.limits.user_proc_count = procs.iter().filter(|p| p.uid == self_uid).count() as u32;
    timings.system_ms = ms(t.elapsed());

    // 4. 프로젝트 루트
    let t = Instant::now();
    let project_roots = if opts.project_roots {
        let mut cwds: Vec<&str> = procs.iter().filter_map(|p| p.cwd.as_deref()).collect();
        cwds.sort_unstable();
        cwds.dedup();
        roots::project_roots(cwds, &sys.host.home_dir, &roots::RealFs)
    } else {
        BTreeMap::new()
    };
    timings.roots_ms = ms(t.elapsed());

    // 5. launchd 결과
    let t = Instant::now();
    let (launchd_job_pids, launchd_job_labels) = match launchd_child {
        Some(child) => match launchd::finish(child) {
            Ok(v) => v,
            Err(m) => {
                errors.push(err(None, "launchd", None, m));
                (Vec::new(), BTreeMap::new())
            }
        },
        None => (Vec::new(), BTreeMap::new()),
    };
    launchd_ms += ms(t.elapsed());
    timings.launchd_ms = launchd_ms;

    // 6. CPU 두 번째 샘플
    let t = Instant::now();
    if let Some(interval) = opts.cpu_interval_ms {
        let target = rusage_start + Duration::from_millis(u64::from(interval));
        let now = Instant::now();
        if target > now {
            std::thread::sleep(target - now);
        }
        for (p, s) in procs.iter_mut().zip(&first) {
            let Some(s) = s else { continue };
            let Ok(ri) = procinfo::rusage(p.pid) else {
                continue;
            };
            if ri.ri_proc_start_abstime != s.start_abs {
                continue;
            }
            let cpu_ns = timebase::ticks_to_ns(
                ri.ri_user_time.saturating_add(ri.ri_system_time),
                numer,
                denom,
            );
            let wall_ns = s.at.elapsed().as_nanos() as f64;
            if wall_ns > 0.0 {
                p.cpu_pct = Some((cpu_ns.saturating_sub(s.cpu_ns) as f64 / wall_ns * 100.0) as f32);
            }
            p.cpu_time_ns = Some(cpu_ns);
            let disk = ri
                .ri_diskio_bytesread
                .saturating_add(ri.ri_diskio_byteswritten);
            p.disk_read_bytes = Some(ri.ri_diskio_bytesread);
            p.disk_written_bytes = Some(ri.ri_diskio_byteswritten);
            p.disk_io_delta_bytes = Some(disk.saturating_sub(s.disk));
        }
    }
    timings.cpu_wait_ms = ms(t.elapsed());
    timings.total_ms = ms(t_total.elapsed());

    Snapshot {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms,
        host: sys.host,
        memory: sys.memory,
        limits: sys.limits,
        processes: procs,
        listeners,
        launchd_job_pids,
        launchd_job_labels,
        project_roots,
        self_pid,
        self_uid,
        cpu_sample_interval_ms: opts.cpu_interval_ms,
        collection_errors: errors,
        timings_ms: timings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(status_of(ffi::SZOMB), ProcStatus::Zombie);
        assert_eq!(status_of(ffi::SSTOP), ProcStatus::Stopped);
        assert_eq!(status_of(ffi::SRUN), ProcStatus::Running);
        assert_eq!(status_of(ffi::SSLEEP), ProcStatus::Sleeping);
        assert_eq!(status_of(ffi::SIDL), ProcStatus::Idle);
        assert_eq!(status_of(9), ProcStatus::Unknown);
    }
}
