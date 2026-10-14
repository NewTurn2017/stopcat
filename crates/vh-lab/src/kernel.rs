//! 실험실이 쓰는 커널 읽기와 신호. 실험실 자체 신호는 [`crate::cleanup::LabReaper`]만 이 trait로 보낸다.

use vh_act::{LiveProc, Prober, RealProber};

pub trait LabKernel: Send + Sync {
    fn probe(&self, pid: i32) -> LiveProc;
    /// `sysctl KERN_PROC_PGRP`: (pid, start_time_unix_ms).
    fn pgrp_members(&self, pgid: i32) -> Vec<(i32, u64)>;
    fn kill(&self, pid: i32, sig: i32) -> Result<(), i32>;
    fn killpg(&self, pgid: i32, sig: i32) -> Result<(), i32>;
    fn now_ms(&self) -> u64;
    fn sleep_ms(&self, ms: u64);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RealKernel;

// vh-act real.rs와 같은 kinfo_proc 배치(2026-10-13 실측): 크기 648, p_starttime 0/8, p_pid 40.
const KINFO_PROC_SIZE: usize = 648;
const OFF_START_SEC: usize = 0;
const OFF_START_USEC: usize = 8;
const OFF_P_PID: usize = 40;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn i64_at(b: &[u8], o: usize) -> i64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[o..o + 8]);
    i64::from_ne_bytes(x)
}

fn allowed_sig(sig: i32) -> bool {
    [libc::SIGSTOP, libc::SIGCONT, libc::SIGTERM, libc::SIGKILL].contains(&sig)
}

impl LabKernel for RealKernel {
    fn probe(&self, pid: i32) -> LiveProc {
        RealProber.probe(pid)
    }

    fn pgrp_members(&self, pgid: i32) -> Vec<(i32, u64)> {
        if pgid <= 1 {
            return Vec::new();
        }
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PGRP, pgid];
        for _ in 0..4 {
            let mut len: libc::size_t = 0;
            // SAFETY: 크기만 묻는 호출(oldp null).
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    4,
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                return Vec::new();
            }
            let mut buf = vec![0u8; len + KINFO_PROC_SIZE * 16];
            let mut len2: libc::size_t = buf.len();
            // SAFETY: buf는 len2 바이트 쓰기 가능, 읽기 전용 호출.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    4,
                    buf.as_mut_ptr().cast(),
                    &mut len2,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                if errno() == libc::ENOMEM {
                    continue;
                }
                return Vec::new();
            }
            return buf[..len2]
                .as_chunks::<KINFO_PROC_SIZE>()
                .0
                .iter()
                .map(|e| {
                    let sec = i64_at(e, OFF_START_SEC).max(0) as u64;
                    let usec = i32_at(e, OFF_START_USEC).max(0) as u64;
                    (i32_at(e, OFF_P_PID), sec * 1000 + usec / 1000)
                })
                .collect();
        }
        Vec::new()
    }

    fn kill(&self, pid: i32, sig: i32) -> Result<(), i32> {
        if pid <= 1 || !allowed_sig(sig) {
            return Err(libc::EPERM);
        }
        // SAFETY: pid > 1 단일 프로세스, 허용된 신호만.
        if unsafe { libc::kill(pid, sig) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    fn killpg(&self, pgid: i32, sig: i32) -> Result<(), i32> {
        if pgid <= 1 || !allowed_sig(sig) {
            return Err(libc::EPERM);
        }
        // SAFETY: pgid > 1 단일 그룹, 허용된 신호만. 호출자는 구성원 전수를 확인한 뒤에만 부른다.
        if unsafe { libc::killpg(pgid, sig) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    fn now_ms(&self) -> u64 {
        crate::util::now_ms()
    }

    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// `PROC_PIDTASKINFO.pti_priority`(demote되면 4).
pub fn task_priority(pid: i32) -> Option<i32> {
    // SAFETY: 0으로 채운 평범한 C 구조체.
    let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: ti는 size 바이트 쓰기 가능.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut ti as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    (n == size).then_some(ti.pti_priority)
}

/// `getpriority(PRIO_PROCESS, pid)`(nice 값). 결과 -1은 정상 값일 수 있어 errno로 실패를 가린다.
pub fn nice_of(pid: i32) -> Option<i32> {
    // SAFETY: errno 위치 포인터는 이 스레드 것이고, getpriority는 읽기 전용 호출이다.
    let v = unsafe {
        *libc::__error() = 0;
        libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t)
    };
    (v != -1 || errno() == 0).then_some(v)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Usage {
    pub footprint_bytes: u64,
    pub rss_bytes: u64,
    pub cpu_ns: u64,
}

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
}

fn timebase() -> (u64, u64) {
    let mut tb = MachTimebaseInfo { numer: 0, denom: 0 };
    // SAFETY: tb는 유효한 출력 포인터.
    let rc = unsafe { mach_timebase_info(&mut tb) };
    if rc != 0 || tb.denom == 0 || tb.numer == 0 {
        (1, 1)
    } else {
        (u64::from(tb.numer), u64::from(tb.denom))
    }
}

/// `proc_pid_rusage(RUSAGE_INFO_V4)`. cpu는 mach tick을 timebase로 나노초로 바꾼다.
pub fn usage(pid: i32) -> Option<Usage> {
    // SAFETY: 0으로 채운 평범한 C 구조체.
    let mut ri: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: ri는 rusage_info_v4 크기만큼 쓰기 가능.
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V4,
            (&mut ri as *mut libc::rusage_info_v4).cast(),
        )
    };
    if rc != 0 {
        return None;
    }
    let (n, d) = timebase();
    let ticks = ri.ri_user_time.saturating_add(ri.ri_system_time);
    Some(Usage {
        footprint_bytes: ri.ri_phys_footprint,
        rss_bytes: ri.ri_resident_size,
        cpu_ns: (u128::from(ticks) * u128::from(n) / u128::from(d)) as u64,
    })
}

/// `getloadavg` 1분 값.
pub fn loadavg_1m() -> Option<f64> {
    let mut v = [0f64; 3];
    // SAFETY: v는 3칸.
    let n = unsafe { libc::getloadavg(v.as_mut_ptr(), 3) };
    (n >= 1).then_some(v[0])
}

/// `kern.memorystatus_vm_pressure_level`.
pub fn pressure_level() -> Option<u32> {
    let name = c"kern.memorystatus_vm_pressure_level";
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: v는 int 하나, 읽기 전용 호출.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(v as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_pgrp_contains_self() {
        let me = std::process::id() as i32;
        let live = RealKernel.probe(me);
        let members = RealKernel.pgrp_members(live.pgid);
        assert!(
            members
                .iter()
                .any(|&(p, s)| p == me && s == live.start_time_unix_ms)
        );
    }

    #[test]
    fn self_usage_and_priority_readable() {
        let me = std::process::id() as i32;
        assert!(usage(me).is_some_and(|u| u.rss_bytes > 0));
        assert!(task_priority(me).is_some());
        assert!(nice_of(me).is_some());
        assert_eq!(nice_of(i32::MAX), None);
    }

    #[test]
    fn kernel_refuses_low_pids_and_other_signals() {
        assert_eq!(RealKernel.kill(1, libc::SIGTERM), Err(libc::EPERM));
        assert_eq!(RealKernel.kill(0, libc::SIGTERM), Err(libc::EPERM));
        assert_eq!(RealKernel.killpg(1, libc::SIGKILL), Err(libc::EPERM));
        assert_eq!(
            RealKernel.kill(std::process::id() as i32, libc::SIGHUP),
            Err(libc::EPERM)
        );
    }
}
