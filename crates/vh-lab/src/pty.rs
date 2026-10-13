//! 측정 대상 프로그램(`vh`, 비교용 `less` 등)을 자체 pty에 띄운다. 화면 출력은 메모리 격자에만 두고
//! (실기기 이름이 나오므로) 저장하지 않는다.
//! `vh` env는 언제나 `VH_GUARD_LEVEL=notify VH_NOTIFY=off VH_STATE_DIR=<임시> VH_E2E_ALLOW_PIDS=`(신호 전부 거부).
//!
//! 세션 리더는 측정 대상이 아니라 `vh-lab __pty-shim`이다. macOS는 제어 터미널을 가진 세션 리더가
//! 끝나면 그 터미널을 revoke해서, 실험실이 들고 있던 slave fd의 `tcgetattr`가 ENOTTY로 실패한다
//! (W3 3단계 termios_restored false 6건의 원인). 실제 사용도 셸(세션 리더) 아래에서 vh가 끝나므로,
//! shim이 셸 역할로 남아 대상이 끝난 뒤의 터미널 모드와 `stty -g`를 직접 읽어 보고서에 쓴다.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::screen::Screen;

pub const SHIM_CMD: &str = "__pty-shim";

pub struct PtyVh {
    pub child: Child,
    /// 측정 대상(shim의 자식) pid. shim pid는 `child.id()`.
    pub pid: i32,
    master: File,
    slave_fd: RawFd,
    report: PathBuf,
    screen: Arc<Mutex<Screen>>,
    pub bytes: Arc<AtomicU64>,
}

pub fn notify_only_env(state_dir: &Path) -> Vec<(String, String)> {
    let mut v = base_env();
    v.extend([
        ("VH_GUARD_LEVEL".to_string(), "notify".to_string()),
        ("VH_NOTIFY".to_string(), "off".to_string()),
        ("VH_E2E_ALLOW_PIDS".to_string(), String::new()),
        (
            "VH_STATE_DIR".to_string(),
            state_dir.to_string_lossy().into_owned(),
        ),
    ]);
    v
}

pub fn base_env() -> Vec<(String, String)> {
    let mut v = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("LANG".to_string(), "ko_KR.UTF-8".to_string()),
    ];
    if let Ok(h) = std::env::var("HOME") {
        v.push(("HOME".into(), h));
    }
    v
}

/// 처음 실행 안내 없이 시작하도록 `config.json`을 미리 쓴다(PM 지시 형식).
pub fn write_config(state_dir: &Path, scan_interval_ms: Option<u32>) -> io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let iv = scan_interval_ms.map_or("null".to_string(), |v| v.to_string());
    std::fs::write(
        state_dir.join("config.json"),
        format!(
            "{{\"schema_version\":1,\"auto_level\":\"notify_only\",\"first_run_done\":true,\"scan_interval_ms\":{iv}}}\n"
        ),
    )
}

fn winsize(cols: u16, rows: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermiosHex {
    pub iflag: String,
    pub oflag: String,
    pub cflag: String,
    pub lflag: String,
    pub cc: String,
}

fn read_termios(fd: RawFd) -> Result<libc::termios, i32> {
    // SAFETY: 0으로 채운 C 구조체에 tcgetattr가 쓴다.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd는 호출자가 연 fd, t는 유효한 지역 값.
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    Ok(t)
}

fn hex(t: &libc::termios) -> TermiosHex {
    TermiosHex {
        iflag: format!("{:#x}", t.c_iflag),
        oflag: format!("{:#x}", t.c_oflag),
        cflag: format!("{:#x}", t.c_cflag),
        lflag: format!("{:#x}", t.c_lflag),
        cc: t.c_cc.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// 플래그 네 개가 같은지(PENDIN 상태 비트는 뺀다).
pub fn flags_equal(a: &libc::termios, b: &libc::termios) -> bool {
    let mask = !(libc::PENDIN as libc::tcflag_t);
    a.c_iflag == b.c_iflag
        && a.c_oflag == b.c_oflag
        && a.c_cflag == b.c_cflag
        && (a.c_lflag & mask) == (b.c_lflag & mask)
}

fn stty_g() -> Option<String> {
    let o = Command::new("/bin/stty")
        .arg("-g")
        .stdin(Stdio::inherit())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// shim이 쓰는 보고서. `child_pid`만 있으면 대상이 아직 도는 중이다.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShimReport {
    pub child_pid: Option<i32>,
    pub spawn_error: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub termios_before: Option<TermiosHex>,
    pub termios_after: Option<TermiosHex>,
    pub termios_after_errno: Option<i32>,
    /// 플래그 네 개 비교(이전 방식과 같은 기준).
    pub flags_restored: Option<bool>,
    pub cc_restored: Option<bool>,
    pub stty_before: Option<String>,
    pub stty_after: Option<String>,
    pub stty_restored: Option<bool>,
    pub finished: bool,
}

fn write_report(path: &Path, r: &ShimReport) {
    let tmp = path.with_extension("tmp");
    if let Ok(s) = serde_json::to_string(r)
        && std::fs::write(&tmp, s).is_ok()
    {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// `vh-lab __pty-shim <보고서> <프로그램> [인자…]`. 세션 리더로 남아 대상을 띄우고, 끝난 뒤
/// fd 0(pty slave)의 모드와 `stty -g`를 읽어 보고서에 쓴다. 대상의 종료 코드로 끝난다.
pub fn shim_main(args: &[String]) -> i32 {
    let (Some(report), Some(prog)) = (args.first(), args.get(1)) else {
        return 2;
    };
    let report = PathBuf::from(report);
    let before = read_termios(0).ok();
    let mut r = ShimReport {
        termios_before: before.as_ref().map(hex),
        stty_before: stty_g(),
        ..ShimReport::default()
    };
    let mut child = match Command::new(prog).args(&args[2..]).spawn() {
        Ok(c) => c,
        Err(e) => {
            r.spawn_error = Some(e.to_string());
            r.finished = true;
            write_report(&report, &r);
            return 127;
        }
    };
    r.child_pid = Some(child.id() as i32);
    write_report(&report, &r);
    let status = child.wait();
    let after = read_termios(0);
    r.exit_code = status.as_ref().ok().and_then(|s| s.code());
    r.signal = status.as_ref().ok().and_then(|s| s.signal());
    r.termios_after = after.as_ref().ok().map(hex);
    r.termios_after_errno = after.as_ref().err().copied();
    if let (Some(b), Ok(a)) = (before.as_ref(), after.as_ref()) {
        r.flags_restored = Some(flags_equal(b, a));
        r.cc_restored = Some(b.c_cc == a.c_cc);
    }
    r.stty_after = stty_g();
    if let (Some(b), Some(a)) = (&r.stty_before, &r.stty_after) {
        r.stty_restored = Some(b == a);
    }
    r.finished = true;
    write_report(&report, &r);
    match (r.exit_code, r.signal) {
        (Some(c), _) => c,
        (None, Some(s)) => 128 + s,
        _ => 1,
    }
}

impl PtyVh {
    /// 측정 대상 vh(notify env). shim은 지금 실행 중인 vh-lab 자신.
    pub fn spawn(vh: &Path, state_dir: &Path, cols: u16, rows: u16) -> io::Result<PtyVh> {
        let shim = std::env::current_exe()?;
        PtyVh::spawn_program(
            &shim,
            vh,
            &[],
            notify_only_env(state_dir),
            &state_dir.join("pty-shim.json"),
            cols,
            rows,
        )
    }

    pub fn spawn_program(
        shim: &Path,
        prog: &Path,
        args: &[String],
        env: Vec<(String, String)>,
        report: &Path,
        cols: u16,
        rows: u16,
    ) -> io::Result<PtyVh> {
        if let Some(d) = report.parent() {
            std::fs::create_dir_all(d)?;
        }
        let _ = std::fs::remove_file(report);
        let mut m: RawFd = -1;
        let mut s: RawFd = -1;
        let mut ws = winsize(cols, rows);
        // SAFETY: m·s·ws는 유효한 지역 변수, name·termp는 null.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut s,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut ws,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: m은 openpty가 준 fd이고 여기서 소유권을 넘긴다.
        let master = unsafe { File::from_raw_fd(m) };
        let dup = |fd: RawFd| -> io::Result<Stdio> {
            // SAFETY: fd는 열린 slave, dup 결과는 Stdio가 소유한다.
            let d = unsafe { libc::dup(fd) };
            if d < 0 {
                Err(io::Error::last_os_error())
            } else {
                // SAFETY: d는 방금 만든 fd.
                Ok(unsafe { Stdio::from_raw_fd(d) })
            }
        };
        let mut cmd = Command::new(shim);
        cmd.arg(SHIM_CMD)
            .arg(report)
            .arg(prog)
            .args(args)
            .env_clear()
            .envs(env)
            .stdin(dup(s)?)
            .stdout(dup(s)?)
            .stderr(dup(s)?);
        // SAFETY: fork 뒤 exec 전 setsid·ioctl만(async-signal-safe). stdin(0)이 slave다.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let screen = Arc::new(Mutex::new(Screen::new(cols, rows)));
        let bytes = Arc::new(AtomicU64::new(0));
        let mut reader = master.try_clone()?;
        let mut answer = master.try_clone()?;
        let (sc, n2) = (screen.clone(), bytes.clone());
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        n2.fetch_add(n as u64, Ordering::Relaxed);
                        if chunk[..n].windows(4).any(|w| w == b"\x1b[6n") {
                            let _ = answer.write_all(b"\x1b[1;1R");
                        }
                        if let Ok(mut g) = sc.lock() {
                            g.feed(&chunk[..n]);
                        }
                    }
                }
            }
        });
        let mut p = PtyVh {
            child,
            pid: 0,
            master,
            slave_fd: s,
            report: report.to_path_buf(),
            screen,
            bytes,
        };
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) {
            let r = p.report();
            if let Some(pid) = r.as_ref().and_then(|r| r.child_pid) {
                p.pid = pid;
                return Ok(p);
            }
            if r.is_some_and(|r| r.finished) || !p.alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let why = p
            .report()
            .and_then(|r| r.spawn_error)
            .unwrap_or_else(|| "shim이 대상 pid를 보고하지 않음".into());
        Err(io::Error::other(why))
    }

    pub fn report(&self) -> Option<ShimReport> {
        serde_json::from_str(&std::fs::read_to_string(&self.report).ok()?).ok()
    }

    pub fn resize(&self, cols: u16, rows: u16) -> bool {
        if let Ok(mut g) = self.screen.lock() {
            g.resize(cols, rows);
        }
        let ws = winsize(cols, rows);
        // SAFETY: master fd는 열려 있고 ws는 유효한 지역 값.
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) == 0 }
    }

    pub fn send(&mut self, b: &[u8]) -> io::Result<()> {
        self.master.write_all(b)
    }

    /// 지금까지 받은 바이트 수(`bytes_since`의 기준점).
    pub fn mark(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn bytes_since(&self, mark: u64) -> u64 {
        self.mark().saturating_sub(mark)
    }

    /// 지금 화면 격자에 글자가 있는지.
    pub fn contains(&self, needle: &str) -> bool {
        self.screen.lock().is_ok_and(|g| g.contains(needle))
    }

    pub fn nonblank_rows(&self) -> usize {
        self.screen.lock().map(|g| g.nonblank_rows()).unwrap_or(0)
    }

    /// 화면에 글자가 나타날 때까지(최대 `timeout`) 기다린다.
    pub fn wait_for(&mut self, needle: &str, timeout: Duration) -> Option<Duration> {
        let t = Instant::now();
        while t.elapsed() < timeout {
            if self.contains(needle) {
                return Some(t.elapsed());
            }
            if !self.alive() {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// shim이 살아 있는 동안 = 대상이 도는 동안(shim은 대상이 끝나면 곧 끝난다).
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn kill_group(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            // SAFETY: shim은 아직 회수되지 않은 자식이고 setsid로 만든 그룹의 리더라 pgid가 재사용될 수 없다.
            unsafe { libc::killpg(self.child.id() as i32, libc::SIGKILL) };
        }
        let _ = self.child.wait();
    }

    pub fn quit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let _ = self.send(b"q");
        let t = Instant::now();
        while t.elapsed() < timeout {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.kill_group();
        None
    }

    /// 대상이 끝난 뒤 터미널 모드가 시작 때와 같은지(shim 보고서). 보고서가 없으면 None(판정 불가).
    pub fn termios_restored(&self) -> Option<bool> {
        self.report()
            .filter(|r| r.finished)
            .and_then(|r| r.flags_restored)
    }

    /// 이전 방식(실험실이 든 slave fd로 대상 종료 뒤 tcgetattr)의 결과: 성공이면 None, 실패면 errno.
    pub fn old_method_errno(&self) -> Option<i32> {
        read_termios(self.slave_fd).err()
    }
}

impl Drop for PtyVh {
    fn drop(&mut self) {
        self.kill_group();
        // SAFETY: slave_fd는 이 구조체만 닫는다.
        unsafe { libc::close(self.slave_fd) };
    }
}
