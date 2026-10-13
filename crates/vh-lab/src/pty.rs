//! 측정 대상 `vh` 화면을 자체 pty에 띄운다. 화면 출력은 메모리에만 두고(실기기 이름이 나오므로) 저장하지 않는다.
//! env는 언제나 `VH_GUARD_LEVEL=notify VH_NOTIFY=off VH_STATE_DIR=<임시> VH_E2E_ALLOW_PIDS=`(신호 전부 거부).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const KEEP_BYTES: usize = 512 * 1024;

pub struct PtyVh {
    pub child: Child,
    pub pid: i32,
    master: File,
    slave_fd: RawFd,
    termios_before: libc::termios,
    buf: Arc<Mutex<Vec<u8>>>,
    pub bytes: Arc<AtomicU64>,
}

pub fn notify_only_env(state_dir: &Path) -> Vec<(String, String)> {
    let mut v = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("LANG".to_string(), "ko_KR.UTF-8".to_string()),
        ("VH_GUARD_LEVEL".to_string(), "notify".to_string()),
        ("VH_NOTIFY".to_string(), "off".to_string()),
        ("VH_E2E_ALLOW_PIDS".to_string(), String::new()),
        (
            "VH_STATE_DIR".to_string(),
            state_dir.to_string_lossy().into_owned(),
        ),
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

impl PtyVh {
    pub fn spawn(vh: &Path, state_dir: &Path, cols: u16, rows: u16) -> io::Result<PtyVh> {
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
        // SAFETY: 0으로 채운 C 구조체에 tcgetattr가 쓴다.
        let mut before: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: s는 방금 연 pty slave.
        unsafe { libc::tcgetattr(s, &mut before) };
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
        let mut cmd = Command::new(vh);
        cmd.env_clear()
            .envs(notify_only_env(state_dir))
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
        let pid = child.id() as i32;
        let buf = Arc::new(Mutex::new(Vec::new()));
        let bytes = Arc::new(AtomicU64::new(0));
        let mut reader = master.try_clone()?;
        let mut answer = master.try_clone()?;
        let (b2, n2) = (buf.clone(), bytes.clone());
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
                        if let Ok(mut b) = b2.lock() {
                            b.extend_from_slice(&chunk[..n]);
                            if b.len() > KEEP_BYTES {
                                let cut = b.len() - KEEP_BYTES;
                                b.drain(..cut);
                            }
                        }
                    }
                }
            }
        });
        Ok(PtyVh {
            child,
            pid,
            master,
            slave_fd: s,
            termios_before: before,
            buf,
            bytes,
        })
    }

    pub fn resize(&self, cols: u16, rows: u16) -> bool {
        let ws = winsize(cols, rows);
        // SAFETY: master fd는 열려 있고 ws는 유효한 지역 값.
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) == 0 }
    }

    pub fn send(&mut self, b: &[u8]) -> io::Result<()> {
        self.master.write_all(b)
    }

    pub fn mark(&self) -> usize {
        self.buf.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// 화면 버퍼(최근 512KB)에 글자가 있는지. `since`는 [`Self::mark`]로 얻은 위치(버퍼가 잘렸으면 처음부터).
    pub fn contains(&self, needle: &str, since: usize) -> bool {
        self.buf.lock().is_ok_and(|b| {
            let from = since.min(b.len());
            String::from_utf8_lossy(&b[from..]).contains(needle)
        })
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
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
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }

    /// 끝난 뒤 pty 모드가 시작 때와 같은지(PENDIN 상태 비트는 뺀다).
    pub fn termios_restored(&self) -> bool {
        // SAFETY: 0으로 채운 C 구조체에 tcgetattr가 쓴다.
        let mut now: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: slave_fd는 이 구조체가 열어 둔 fd.
        if unsafe { libc::tcgetattr(self.slave_fd, &mut now) } != 0 {
            return false;
        }
        let mask = !(libc::PENDIN as libc::tcflag_t);
        let b = &self.termios_before;
        b.c_iflag == now.c_iflag
            && b.c_oflag == now.c_oflag
            && b.c_cflag == now.c_cflag
            && (b.c_lflag & mask) == (now.c_lflag & mask)
    }
}

impl Drop for PtyVh {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        // SAFETY: slave_fd는 이 구조체만 닫는다.
        unsafe { libc::close(self.slave_fd) };
    }
}
