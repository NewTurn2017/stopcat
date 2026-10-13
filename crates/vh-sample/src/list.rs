//! 프로세스 목록: sysctl KERN_PROC_ALL(모든 uid, 좀비 포함) 한 번 + proc_listallpids 대조.

use std::ptr::null_mut;

use libc::c_int;

use crate::ffi::{self, KINFO_PROC_SIZE, KinfoProc};

/// kinfo_proc에서 읽은 기본 필드.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RawProc {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub uid: u32,
    pub start_time_unix_ms: u64,
    pub comm: String,
    pub stat: i8,
    pub flag: i32,
    pub tdev: i32,
}

impl RawProc {
    pub(crate) fn from_kinfo(k: &KinfoProc) -> RawProc {
        let b = &k.0[..];
        let sec = ffi::rd_i64(b, ffi::KP_STARTTIME_SEC);
        let usec = ffi::rd_i32(b, ffi::KP_STARTTIME_USEC);
        RawProc {
            pid: ffi::rd_i32(b, ffi::KP_PID),
            ppid: ffi::rd_i32(b, ffi::KP_E_PPID),
            pgid: ffi::rd_i32(b, ffi::KP_E_PGID),
            uid: ffi::rd_u32(b, ffi::KP_E_UCRED_UID),
            start_time_unix_ms: start_time_ms(sec, usec),
            comm: ffi::c_str(&b[ffi::KP_COMM..ffi::KP_COMM + ffi::KP_COMM_LEN]),
            stat: b[ffi::KP_STAT] as i8,
            flag: ffi::rd_i32(b, ffi::KP_FLAG),
            tdev: ffi::rd_i32(b, ffi::KP_E_TDEV),
        }
    }
}

/// 계약의 식: tv_sec * 1000 + tv_usec / 1000.
pub(crate) fn start_time_ms(sec: i64, usec: i32) -> u64 {
    (sec.max(0) as u64) * 1000 + (usec.max(0) as u64) / 1000
}

pub(crate) fn list_all() -> Result<Vec<RawProc>, i32> {
    let mut mib: [c_int; 4] = [libc::CTL_KERN, ffi::KERN_PROC, ffi::KERN_PROC_ALL, 0];
    for _ in 0..4 {
        let mut size: usize = 0;
        // SAFETY: 크기 질의(oldp NULL). mib는 4개 원소 배열.
        let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 4, null_mut(), &mut size, null_mut(), 0) };
        if rc != 0 {
            return Err(ffi::errno());
        }
        let n = size / KINFO_PROC_SIZE + 64;
        let mut buf = vec![KinfoProc([0; KINFO_PROC_SIZE]); n];
        let mut len = n * KINFO_PROC_SIZE;
        // SAFETY: buf는 len 바이트를 가진다.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr().cast(),
                &mut len,
                null_mut(),
                0,
            )
        };
        if rc != 0 {
            let e = ffi::errno();
            if e == libc::ENOMEM {
                continue;
            }
            return Err(e);
        }
        let count = len / KINFO_PROC_SIZE;
        return Ok(buf[..count].iter().map(RawProc::from_kinfo).collect());
    }
    Err(libc::ENOMEM)
}

pub(crate) fn listallpids() -> Result<Vec<i32>, i32> {
    // SAFETY: NULL 버퍼로 개수 질의.
    let n = unsafe { ffi::proc_listallpids(null_mut(), 0) };
    if n <= 0 {
        return Err(ffi::errno());
    }
    let cap = n as usize + 64;
    let mut v = vec![0i32; cap];
    // SAFETY: v는 cap × 4 바이트.
    let got = unsafe { ffi::proc_listallpids(v.as_mut_ptr().cast(), (cap * 4) as c_int) };
    if got <= 0 {
        return Err(ffi::errno());
    }
    v.truncate((got as usize).min(cap));
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_time_formula() {
        assert_eq!(start_time_ms(1_791_267_584, 115_173), 1_791_267_584_115);
        assert_eq!(start_time_ms(0, 999), 0);
    }

    #[test]
    fn kinfo_offsets_decode() {
        let mut k = KinfoProc([0; KINFO_PROC_SIZE]);
        k.0[ffi::KP_PID..ffi::KP_PID + 4].copy_from_slice(&4242i32.to_ne_bytes());
        k.0[ffi::KP_E_PPID..ffi::KP_E_PPID + 4].copy_from_slice(&1i32.to_ne_bytes());
        k.0[ffi::KP_E_PGID..ffi::KP_E_PGID + 4].copy_from_slice(&4242i32.to_ne_bytes());
        k.0[ffi::KP_E_UCRED_UID..ffi::KP_E_UCRED_UID + 4].copy_from_slice(&501u32.to_ne_bytes());
        k.0[ffi::KP_STARTTIME_SEC..ffi::KP_STARTTIME_SEC + 8]
            .copy_from_slice(&1_791_000_000i64.to_ne_bytes());
        k.0[ffi::KP_STARTTIME_USEC..ffi::KP_STARTTIME_USEC + 4]
            .copy_from_slice(&250_000i32.to_ne_bytes());
        k.0[ffi::KP_STAT] = ffi::SZOMB as u8;
        k.0[ffi::KP_COMM..ffi::KP_COMM + 4].copy_from_slice(b"node");
        k.0[ffi::KP_FLAG..ffi::KP_FLAG + 4].copy_from_slice(&ffi::P_TRANSLATED.to_ne_bytes());
        k.0[ffi::KP_E_TDEV..ffi::KP_E_TDEV + 4].copy_from_slice(&ffi::NODEV.to_ne_bytes());
        let r = RawProc::from_kinfo(&k);
        assert_eq!(
            r,
            RawProc {
                pid: 4242,
                ppid: 1,
                pgid: 4242,
                uid: 501,
                start_time_unix_ms: 1_791_000_000_250,
                comm: "node".to_string(),
                stat: ffi::SZOMB,
                flag: ffi::P_TRANSLATED,
                tdev: ffi::NODEV,
            }
        );
    }
}
