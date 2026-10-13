//! 진짜 커널 읽기와 신호.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{LiveProc, Liveness, Prober, RealProber, RealSignaler, Signaler};

// `struct kinfo_proc` (arm64·x86_64 macOS 공통 LP64 배치). 2026-10-13 이 맥에서 offsetof로 실측:
// sizeof 648, p_starttime 0(tv_sec i64, tv_usec i32 @8), p_stat 36, p_pid 40,
// e_ucred.cr_uid 420, e_ppid 560, e_pgid 564. `probe_self_matches_libc` 테스트가 이 값을 검증한다.
const KINFO_PROC_SIZE: usize = 648;
const OFF_START_SEC: usize = 0;
const OFF_START_USEC: usize = 8;
const OFF_P_STAT: usize = 36;
const OFF_P_PID: usize = 40;
const OFF_CR_UID: usize = 420;
const OFF_E_PPID: usize = 560;
const OFF_E_PGID: usize = 564;

const MAX_ANCESTORS: usize = 64;
const MAX_CHILDREN: usize = 4096;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn i32_at(buf: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn i64_at(buf: &[u8], off: usize) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    i64::from_ne_bytes(b)
}

/// `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)`. 없는 pid는 길이 0으로 돌아온다.
fn read_kinfo(pid: i32) -> Option<[u8; KINFO_PROC_SIZE]> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut buf = [0u8; KINFO_PROC_SIZE];
    let mut len: libc::size_t = KINFO_PROC_SIZE;
    // SAFETY: mib는 정수 4개, buf는 len 바이트 쓰기 가능, newp는 null(읽기 전용 호출).
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len < KINFO_PROC_SIZE || i32_at(&buf, OFF_P_PID) != pid {
        return None;
    }
    Some(buf)
}

fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buf는 buffersize 바이트 쓰기 가능.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

impl Prober for RealProber {
    fn probe(&self, pid: i32) -> LiveProc {
        if pid < 0 {
            return LiveProc::gone(pid);
        }
        let Some(buf) = read_kinfo(pid) else {
            return LiveProc::gone(pid);
        };
        let stat = u32::from(buf[OFF_P_STAT]);
        let sec = i64_at(&buf, OFF_START_SEC);
        let usec = i32_at(&buf, OFF_START_USEC);
        let start_ms = (sec.max(0) as u64) * 1000 + (usec.max(0) as u64) / 1000;
        let liveness = if stat == libc::SZOMB {
            Liveness::Zombie
        } else {
            Liveness::Alive
        };
        LiveProc {
            pid,
            liveness,
            start_time_unix_ms: start_ms,
            ppid: i32_at(&buf, OFF_E_PPID),
            pgid: i32_at(&buf, OFF_E_PGID),
            uid: i32_at(&buf, OFF_CR_UID) as u32,
            stopped: stat == libc::SSTOP,
            exe: if liveness == Liveness::Alive {
                exe_path(pid)
            } else {
                None
            },
        }
    }

    fn children(&self, pid: i32) -> Vec<i32> {
        if pid <= 0 {
            return Vec::new();
        }
        let mut buf = vec![0i32; MAX_CHILDREN];
        let bytes = (buf.len() * std::mem::size_of::<i32>()) as libc::c_int;
        // SAFETY: buf는 bytes 바이트 쓰기 가능.
        let n = unsafe { libc::proc_listchildpids(pid, buf.as_mut_ptr().cast(), bytes) };
        if n <= 0 {
            return Vec::new();
        }
        buf.truncate((n as usize).min(MAX_CHILDREN));
        buf.retain(|&p| p > 0 && p != pid);
        buf.sort_unstable();
        buf.dedup();
        buf
    }

    fn self_pid(&self) -> i32 {
        // SAFETY: 인자 없는 시스템 호출.
        unsafe { libc::getpid() }
    }

    fn self_uid(&self) -> u32 {
        // SAFETY: 인자 없는 시스템 호출.
        unsafe { libc::geteuid() }
    }

    fn ancestors_of_self(&self) -> Vec<i32> {
        let mut out = Vec::new();
        // SAFETY: 인자 없는 시스템 호출.
        let mut p = unsafe { libc::getppid() };
        while p > 0 && out.len() < MAX_ANCESTORS && !out.contains(&p) {
            out.push(p);
            if p == 1 {
                break;
            }
            let live = self.probe(p);
            if live.liveness == Liveness::Gone {
                break;
            }
            p = live.ppid;
        }
        out
    }

    fn get_bg(&self, pid: i32) -> Result<i32, i32> {
        if pid <= 0 {
            return Err(libc::EINVAL);
        }
        // SAFETY: errno 위치에 0을 쓴다(getpriority의 -1 반환과 오류를 구분하려고).
        unsafe { *libc::__error() = 0 };
        // SAFETY: 읽기 전용 호출.
        let v = unsafe { libc::getpriority(libc::PRIO_DARWIN_PROCESS, pid as libc::id_t) };
        let e = errno();
        if v == -1 && e != 0 { Err(e) } else { Ok(v) }
    }

    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

impl Signaler for RealSignaler {
    fn send(&self, pid: i32, sig: i32) -> Result<(), i32> {
        // pid ≤ 1 은 kill(0)=프로세스 그룹, kill(-1)=모든 프로세스, launchd 다. 어떤 경로로도 보내지 않는다.
        if pid <= 1 {
            return Err(libc::EPERM);
        }
        if ![libc::SIGCONT, libc::SIGTERM, libc::SIGKILL].contains(&sig) {
            return Err(libc::EINVAL);
        }
        // SAFETY: pid > 1 단일 프로세스 대상, 허용된 신호만.
        if unsafe { libc::kill(pid, sig) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    fn demote(&self, pid: i32) -> Result<(), i32> {
        if pid <= 1 {
            return Err(libc::EPERM);
        }
        // SAFETY: pid > 1 단일 프로세스 대상.
        let rc = unsafe {
            libc::setpriority(
                libc::PRIO_DARWIN_PROCESS,
                pid as libc::id_t,
                libc::PRIO_DARWIN_BG,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_self_matches_libc() {
        let p = RealProber;
        let me = p.probe(p.self_pid());
        assert_eq!(me.liveness, Liveness::Alive);
        assert_eq!(me.pid, p.self_pid());
        // SAFETY: 인자 없는 시스템 호출.
        assert_eq!(me.ppid, unsafe { libc::getppid() });
        // SAFETY: 인자 없는 시스템 호출.
        assert_eq!(me.pgid, unsafe { libc::getpgrp() });
        assert_eq!(me.uid, p.self_uid());
        let now = p.now_unix_ms();
        assert!(me.start_time_unix_ms > 1_600_000_000_000 && me.start_time_unix_ms <= now);
        assert!(me.exe.is_some());
    }

    #[test]
    fn probe_missing_pid_is_gone() {
        assert_eq!(RealProber.probe(-5).liveness, Liveness::Gone);
        assert_eq!(RealProber.probe(99_999_999).liveness, Liveness::Gone);
    }

    #[test]
    fn real_signaler_refuses_pid_le_1_without_syscall() {
        for pid in [-1, 0, 1] {
            assert_eq!(RealSignaler.send(pid, libc::SIGTERM), Err(libc::EPERM));
            assert_eq!(RealSignaler.demote(pid), Err(libc::EPERM));
        }
    }

    #[test]
    fn real_signaler_refuses_other_signals() {
        // 신호 번호에서 먼저 막힌다(kill 호출 없음). pid도 존재할 수 없는 값(pid_max 99999 초과).
        assert_eq!(
            RealSignaler.send(99_999_999, libc::SIGHUP),
            Err(libc::EINVAL)
        );
    }
}
