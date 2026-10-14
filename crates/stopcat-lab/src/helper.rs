//! 도우미 바이너리(`stopcat-lab-helper`) 본체. 하나의 바이너리를 여러 이름으로 복사해 역할(`STOPCAT_LAB_ROLE`)대로 돈다.
//! 감독(ProcRef)이 사라지거나 최대 수명이 지나면 자기 자식을 SIGKILL하고 스스로 끝난다.

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use stopcat_act::{Liveness, Prober, RealProber};
use stopcat_model::ProcRef;

use crate::kernel::task_priority;
use crate::spec::{self, ExecSpec, Role};

fn env_u64(k: &str, default: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn supervisor() -> Option<ProcRef> {
    std::env::var(spec::SUPERVISOR)
        .ok()
        .and_then(|s| spec::parse_proc_ref(&s))
}

fn alive(r: ProcRef) -> bool {
    let live = RealProber.probe(r.pid);
    live.liveness == Liveness::Alive && live.start_time_unix_ms == r.start_time_unix_ms
}

fn log_file() -> Option<std::fs::File> {
    let p = std::env::var(spec::LOG).ok()?;
    OpenOptions::new().create(true).append(true).open(p).ok()
}

pub fn main_helper() -> i32 {
    let role = std::env::var(spec::ROLE)
        .ok()
        .and_then(|r| Role::parse(&r))
        .unwrap_or(Role::Idle);
    match role {
        Role::Selftest => {
            println!("ok");
            0
        }
        Role::Exit => 0,
        Role::Blip => {
            let ms = (std::process::id() as u64).wrapping_mul(7919) % 300 + 1;
            std::thread::sleep(Duration::from_millis(ms));
            0
        }
        Role::Fanout => fanout(),
        _ => long_lived(role),
    }
}

fn spawn_spec(s: &ExecSpec) -> std::io::Result<Child> {
    let argv = s.argv_bytes();
    let mut cmd = Command::new(&s.exe);
    if let Some(a0) = argv.first() {
        cmd.arg0(OsStr::from_bytes(a0));
    }
    let me = std::process::id().to_string();
    let env = s.env.iter().map(|(k, v)| {
        let v = if v == spec::PARENT_PID_TOKEN {
            me.clone()
        } else {
            v.clone()
        };
        (k.clone(), v)
    });
    cmd.args(argv.iter().skip(1).map(|a| OsStr::from_bytes(a)))
        .env_clear()
        .envs(env)
        .current_dir(&s.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    match log_file() {
        Some(f) => cmd.stderr(f),
        None => cmd.stderr(Stdio::null()),
    };
    cmd.spawn()
}

fn redirect_stdout_to_null() {
    if let Ok(null) = OpenOptions::new().write(true).open("/dev/null") {
        // SAFETY: 두 fd 모두 유효. stdout을 /dev/null로 바꿔 감독의 파이프를 닫는다.
        unsafe { libc::dup2(null.as_raw_fd(), 1) };
    }
}

fn long_lived(role: Role) -> i32 {
    let started = Instant::now();
    let max = Duration::from_secs(env_u64(spec::MAX_SECS, 600));
    let sup = supervisor();
    let mut out = std::io::stdout();

    if role == Role::Zombie {
        // SAFETY: 아직 스레드를 만들기 전(단일 스레드). 자식은 곧바로 _exit만 한다.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: fork 자식에서 async-signal-safe 호출만.
            unsafe { libc::_exit(0) };
        }
        if pid > 0 {
            let _ = writeln!(out, "child {pid}");
        }
    }

    let _listener = (std::env::var(spec::LISTEN).as_deref() == Ok("1"))
        .then(|| crate::net::bind_loopback("127.0.0.1:0").ok())
        .flatten();

    if role == Role::Serve {
        match start_server() {
            Ok(port) => {
                let _ = writeln!(out, "port {port}");
            }
            Err(e) => {
                let _ = writeln!(out, "error serve {e}");
                return 1;
            }
        }
    }
    let hold = Duration::from_secs(env_u64(spec::HOLD_SECS, 0));
    let mut held: Option<std::net::TcpStream> = None;
    if role == Role::Client {
        let port = env_u64(spec::CONNECT_PORT, 0) as u16;
        match crate::net::connect_and_get(port, Duration::from_secs(5)) {
            Ok(s) => held = Some(s),
            Err(e) => {
                let _ = writeln!(out, "error connect {e}");
                return 1;
            }
        }
    }

    let mut children: Vec<Child> = Vec::new();
    if let Ok(raw) = std::env::var(spec::SPAWN)
        && let Ok(specs) = serde_json::from_str::<Vec<ExecSpec>>(&raw)
    {
        for s in specs.iter().flat_map(ExecSpec::expand) {
            match spawn_spec(&s) {
                Ok(c) => {
                    let _ = writeln!(out, "child {}", c.id());
                    children.push(c);
                }
                Err(e) => {
                    let _ = writeln!(out, "error {e}");
                }
            }
        }
    }

    let stop_spin = Arc::new(AtomicBool::new(false));
    if role == Role::Spin {
        for _ in 0..env_u64(spec::SPIN_THREADS, 2).clamp(1, 4) {
            let stop = stop_spin.clone();
            std::thread::spawn(move || {
                let mut x: u64 = 1;
                while !stop.load(Ordering::Relaxed) {
                    for _ in 0..10_000 {
                        x = std::hint::black_box(
                            x.wrapping_mul(6364136223846793005).wrapping_add(1),
                        );
                    }
                }
            });
        }
    }
    if role == Role::Mem {
        let kb_s = env_u64(spec::MEM_KB_PER_SEC, 853);
        let max_mb = env_u64(spec::MEM_MAX_MB, 400);
        std::thread::spawn(move || {
            let mut hold: Vec<Vec<u8>> = Vec::new();
            let mut total: u64 = 0;
            while total + kb_s * 1024 <= max_mb * 1024 * 1024 {
                let mut chunk = vec![0u8; (kb_s * 1024) as usize];
                for i in (0..chunk.len()).step_by(4096) {
                    chunk[i] = 1;
                }
                total += chunk.len() as u64;
                hold.push(std::hint::black_box(chunk));
                std::thread::sleep(Duration::from_secs(1));
            }
            loop {
                std::thread::sleep(Duration::from_secs(3600));
                std::hint::black_box(&hold);
            }
        });
    }

    let _ = writeln!(out, "ready");
    let _ = out.flush();
    redirect_stdout_to_null();

    let spin_secs = Duration::from_secs(env_u64(spec::SPIN_SECS, 120));
    let stop_on_demote = std::env::var(spec::SPIN_STOP_ON_DEMOTE).as_deref() == Ok("1");
    let me = std::process::id() as i32;
    let flicker_max = env_u64(spec::FLICKER_MAX, 0) as usize;
    let flicker_until = Duration::from_secs(env_u64(spec::FLICKER_SECS, 0));
    let self_exe = std::env::current_exe().ok();
    let mut blips: Vec<Child> = Vec::new();
    let mut tick: u64 = 0;
    loop {
        tick += 1;
        let elapsed = started.elapsed();
        let sup_gone = tick.is_multiple_of(10) && sup.is_some_and(|s| !alive(s));
        if sup_gone || elapsed >= max {
            for c in children.iter_mut().chain(blips.iter_mut()) {
                let _ = c.kill();
                let _ = c.wait();
            }
            return 0;
        }
        if held.is_some() && elapsed >= hold {
            drop(held.take());
            return 0;
        }
        children.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        if role == Role::Spin
            && !stop_spin.load(Ordering::Relaxed)
            && (elapsed >= spin_secs || (stop_on_demote && task_priority(me) == Some(4)))
        {
            stop_spin.store(true, Ordering::Relaxed);
        }
        if role == Role::Flicker {
            blips.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
            if elapsed < flicker_until
                && let Some(exe) = &self_exe
            {
                while blips.len() < flicker_max {
                    let mut cmd = Command::new(exe);
                    cmd.arg0("lab-flicker")
                        .env(spec::ROLE, Role::Blip.as_str())
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    match cmd.spawn() {
                        Ok(c) => blips.push(c),
                        Err(_) => break,
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(if role == Role::Flicker {
            20
        } else {
            200
        }));
    }
}

/// 127.0.0.1 임시 포트에서 듣고, 포트를 cwd의 `port` 파일에 쓴다(쓰기 뒤 이름 바꾸기).
fn start_server() -> std::io::Result<u16> {
    let l = crate::net::bind_loopback("127.0.0.1:0")?;
    let port = l.local_addr()?.port();
    let tmp = format!("{}.tmp", spec::PORT_FILE);
    std::fs::write(&tmp, port.to_string())?;
    std::fs::rename(&tmp, spec::PORT_FILE)?;
    crate::net::serve(l);
    Ok(port)
}

struct Prepared {
    exe: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    cwd: CString,
}

fn prepare(s: &ExecSpec) -> Option<Prepared> {
    Some(Prepared {
        exe: CString::new(s.exe.as_bytes()).ok()?,
        argv: s
            .argv_bytes()
            .into_iter()
            .map(CString::new)
            .collect::<Result<_, _>>()
            .ok()?,
        envp: s
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<Result<_, _>>()
            .ok()?,
        cwd: CString::new(s.cwd.as_bytes()).ok()?,
    })
}

/// FANOUT 명세마다 fork + execve. 이 프로세스가 곧 끝나므로 자식은 ppid 1이 된다(pgid는 유지).
fn fanout() -> i32 {
    let specs: Vec<ExecSpec> = std::env::var(spec::FANOUT)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    let prepared: Vec<Prepared> = specs
        .iter()
        .flat_map(ExecSpec::expand)
        .filter_map(|s| prepare(&s))
        .collect();
    let null = OpenOptions::new().read(true).write(true).open("/dev/null");
    let Ok(null) = null else {
        return 1;
    };
    let log = log_file();
    let null_fd = null.as_raw_fd();
    let log_fd = log.as_ref().map_or(null_fd, |f| f.as_raw_fd());
    let mut out = std::io::stdout();
    for p in &prepared {
        let mut argv: Vec<*const libc::c_char> = p.argv.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<*const libc::c_char> = p.envp.iter().map(|a| a.as_ptr()).collect();
        envp.push(std::ptr::null());
        // SAFETY: 이 역할은 스레드를 만들지 않는다. 자식은 미리 만든 버퍼로 dup2·chdir·execve·_exit만 부른다.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: fork 자식, async-signal-safe 호출만.
            unsafe {
                libc::dup2(null_fd, 0);
                libc::dup2(null_fd, 1);
                libc::dup2(log_fd, 2);
                libc::chdir(p.cwd.as_ptr());
                libc::execve(p.exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        if pid > 0 {
            let _ = writeln!(out, "child {pid}");
        } else {
            let _ = writeln!(out, "error fork");
        }
    }
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    0
}

pub fn env_map(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}
