//! 실제 pty(openpty)에서 `stopcat` 화면을 띄웠다가 q로 끝낸 뒤 터미널 모드(termios)가 처음과 같은지.
//! macOS는 세션 리더가 끝나면 pty slave를 끊어 `tcgetattr`가 ENOTTY로 실패하므로(W3 LAB T1 오탐의
//! 원인), `sh`를 세션 리더로 두고 stopcat이 끝난 뒤 sh가 살아 있는 동안 모드를 읽는다.
//! stopcat은 언제나 알림만·알림 끔·임시 상태 폴더·신호 잠금(STOPCAT_E2E_ALLOW_PIDS 빈 값)으로 띄운다.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(30);

struct Pty {
    master: File,
    slave: RawFd,
    before: libc::termios,
    out: Arc<(Mutex<Vec<u8>>, Condvar)>,
    child: Child,
}

fn winsize(cols: u16, rows: u16) -> libc::winsize {
    libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

impl Pty {
    /// `sh -c '<prog>; echo EXITED=$?; read _'`를 새 세션 리더로 띄운다. sh는 줄 하나를 받을 때까지 남는다.
    fn spawn(prog: &str, cols: u16, rows: u16, envs: &[(&str, String)]) -> Pty {
        let (mut m, mut s): (RawFd, RawFd) = (-1, -1);
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
        assert_eq!(rc, 0, "openpty");
        // SAFETY: 0으로 채운 C 구조체에 tcgetattr가 쓴다. s는 방금 연 slave.
        let mut before: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(s, &mut before) }, 0);
        let stdio = || {
            // SAFETY: s는 열린 slave, dup 결과는 Stdio가 소유한다.
            let d = unsafe { libc::dup(s) };
            assert!(d >= 0);
            unsafe { Stdio::from_raw_fd(d) }
        };
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("{prog}; echo; echo EXITED=$?; read _"))
            .env_clear()
            .envs(envs.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(stdio())
            .stdout(stdio())
            .stderr(stdio());
        // SAFETY: fork 뒤 exec 전 setsid·ioctl만(async-signal-safe). stdin(0)이 slave다.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn sh");
        // SAFETY: m은 openpty가 준 fd이고 여기서 소유권을 넘긴다.
        let master = unsafe { File::from_raw_fd(m) };
        let out = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let (mut reader, mut answer) = (
            master.try_clone().expect("clone"),
            master.try_clone().expect("clone"),
        );
        let o = out.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = reader.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if chunk[..n].windows(4).any(|w| w == b"\x1b[6n") {
                    let _ = answer.write_all(b"\x1b[1;1R");
                }
                let (buf, cv) = &*o;
                buf.lock().unwrap().extend_from_slice(&chunk[..n]);
                cv.notify_all();
            }
        });
        Pty {
            master,
            slave: s,
            before,
            out,
            child,
        }
    }

    /// 출력에 `needle`이 나올 때까지(최대 [`WAIT`]) 기다린다.
    fn wait_for(&self, needle: &[u8]) {
        let (buf, cv) = &*self.out;
        let deadline = Instant::now() + WAIT;
        let mut g = buf.lock().unwrap();
        while !g.windows(needle.len()).any(|w| w == needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{} 를 기다리다 시간 초과",
                String::from_utf8_lossy(needle)
            );
            g = cv.wait_timeout(g, left).unwrap().0;
        }
    }

    fn exit_code(&self) -> Option<i32> {
        let g = self.out.0.lock().unwrap();
        let t = String::from_utf8_lossy(&g);
        t.rsplit("EXITED=")
            .next()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
    }

    fn resize(&self, cols: u16, rows: u16) {
        let ws = winsize(cols, rows);
        use std::os::unix::io::AsRawFd;
        // SAFETY: master fd는 열려 있고 ws는 유효한 지역 값.
        assert_eq!(
            unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) },
            0
        );
    }

    /// 처음과 다른 termios 필드 이름(PENDIN 상태 비트는 커널이 켜는 것이라 뺀다).
    fn termios_diff(&self) -> Vec<&'static str> {
        // SAFETY: 0으로 채운 C 구조체에 tcgetattr가 쓴다. slave는 열려 있고 sh 세션이 살아 있다.
        let mut now: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave, &mut now) },
            0,
            "세션 리더가 살아 있는 동안 읽어야 한다"
        );
        let b = &self.before;
        let pend = libc::PENDIN as libc::tcflag_t;
        let mut d = Vec::new();
        if b.c_iflag != now.c_iflag {
            d.push("iflag");
        }
        if b.c_oflag != now.c_oflag {
            d.push("oflag");
        }
        if b.c_cflag != now.c_cflag {
            d.push("cflag");
        }
        if b.c_lflag & !pend != now.c_lflag & !pend {
            d.push("lflag");
        }
        if b.c_cc != now.c_cc {
            d.push("cc");
        }
        d
    }

    fn finish(mut self) {
        let _ = self.master.write_all(b"\n");
        let status = self.child.wait().expect("wait sh");
        assert!(status.success(), "sh: {status:?}");
        // SAFETY: slave는 이 구조체만 닫는다.
        unsafe { libc::close(self.slave) };
    }
}

fn stopcat_env(state: &std::path::Path) -> Vec<(&'static str, String)> {
    std::fs::write(
        state.join("config.json"),
        "{\"schema_version\":1,\"auto_level\":\"notify_only\",\"first_run_done\":true,\"scan_interval_ms\":null}\n",
    )
    .expect("config");
    vec![
        ("PATH", "/usr/bin:/bin".to_string()),
        ("HOME", std::env::var("HOME").unwrap_or_default()),
        ("TERM", "xterm-256color".to_string()),
        ("LANG", "ko_KR.UTF-8".to_string()),
        ("STOPCAT_GUARD_LEVEL", "notify".to_string()),
        ("STOPCAT_NOTIFY", "off".to_string()),
        ("STOPCAT_E2E_ALLOW_PIDS", String::new()),
        ("STOPCAT_STATE_DIR", state.to_string_lossy().into_owned()),
    ]
}

/// 대체 화면 진입·나가기 순서. 화면 글자는 한글마다 커서 이동이 끼어 붙어 나오지 않으므로 이것만 본다.
const ENTERED: &[u8] = b"\x1b[?1049h";
const LEFT: &[u8] = b"\x1b[?1049l";

fn run_stopcat(cols: u16, rows: u16, resizes: bool) -> (Option<i32>, Vec<&'static str>) {
    let state = tempfile::tempdir().expect("tempdir");
    let stopcat = env!("CARGO_BIN_EXE_stopcat");
    let p = Pty::spawn(&format!("'{stopcat}'"), cols, rows, &stopcat_env(state.path()));
    p.wait_for(ENTERED);
    if resizes {
        let sizes = [(80u16, 24u16), (120, 40), (60, 20)];
        for i in 0..20 {
            let (c, r) = sizes[i % 3];
            p.resize(c, r);
        }
        p.resize(80, 24);
    }
    let _ = (&p.master).write_all(b"q");
    p.wait_for(LEFT);
    p.wait_for(b"EXITED=");
    let code = p.exit_code();
    let diff = p.termios_diff();
    p.finish();
    (code, diff)
}

#[test]
fn quit_restores_termios() {
    let (code, diff) = run_stopcat(80, 24, false);
    assert_eq!(code, Some(0));
    assert!(diff.is_empty(), "q 뒤 달라진 termios: {diff:?}");
}

#[test]
fn small_window_and_resizes_restore_termios() {
    let (code, diff) = run_stopcat(60, 20, true);
    assert_eq!(code, Some(0));
    assert!(
        diff.is_empty(),
        "창 크기 변경·q 뒤 달라진 termios: {diff:?}"
    );
}

/// 측정 방법이 실제로 실패를 잡는지: 모드를 되돌리지 않는 프로그램은 차이가 나야 한다.
#[test]
fn measurement_detects_unrestored_mode() {
    let p = Pty::spawn("stty raw", 80, 24, &[("PATH", "/usr/bin:/bin".to_string())]);
    p.wait_for(b"EXITED=");
    let diff = p.termios_diff();
    p.finish();
    assert!(
        diff.contains(&"lflag") && diff.contains(&"iflag"),
        "{diff:?}"
    );
}
