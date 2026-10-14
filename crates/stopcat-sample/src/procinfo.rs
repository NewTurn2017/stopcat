//! libproc 안전 래퍼. 실패는 errno로 돌려준다.

use std::mem::size_of;

use libc::c_int;

use crate::ffi::{
    self, ProcFdInfo, ProcTaskAllInfo, ProcVnodePathInfo, RusageInfoV4, SocketFdInfo,
};

pub(crate) fn task_all_info(pid: i32) -> Result<ProcTaskAllInfo, i32> {
    // SAFETY: 정수 필드만 가진 repr(C) 구조체라 0 비트 패턴이 유효하다.
    let mut info: ProcTaskAllInfo = unsafe { std::mem::zeroed() };
    let size = size_of::<ProcTaskAllInfo>() as c_int;
    // SAFETY: info는 size 바이트다.
    let rc = unsafe {
        ffi::proc_pidinfo(
            pid,
            ffi::PROC_PIDTASKALLINFO,
            0,
            (&mut info as *mut ProcTaskAllInfo).cast(),
            size,
        )
    };
    if rc == size {
        Ok(info)
    } else {
        Err(ffi::errno())
    }
}

pub(crate) fn pidpath(
    pid: i32,
    buf: &mut [u8; ffi::PROC_PIDPATHINFO_MAXSIZE],
) -> Result<String, i32> {
    // SAFETY: buf는 PROC_PIDPATHINFO_MAXSIZE 바이트다.
    let rc = unsafe { ffi::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if rc > 0 {
        let n = (rc as usize).min(buf.len());
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    } else {
        Err(ffi::errno())
    }
}

pub(crate) fn rusage(pid: i32) -> Result<RusageInfoV4, i32> {
    // SAFETY: 정수 필드만 가진 repr(C) 구조체.
    let mut ri: RusageInfoV4 = unsafe { std::mem::zeroed() };
    // SAFETY: RUSAGE_INFO_V4 flavor는 rusage_info_v4 크기만큼 쓴다.
    let rc = unsafe {
        ffi::proc_pid_rusage(
            pid,
            ffi::RUSAGE_INFO_V4,
            (&mut ri as *mut RusageInfoV4).cast(),
        )
    };
    if rc == 0 { Ok(ri) } else { Err(ffi::errno()) }
}

pub(crate) fn cwd(pid: i32) -> Result<Option<String>, i32> {
    // SAFETY: 정수·바이트 배열만 가진 repr(C) 구조체.
    let mut v: ProcVnodePathInfo = unsafe { std::mem::zeroed() };
    let size = size_of::<ProcVnodePathInfo>() as c_int;
    // SAFETY: v는 size 바이트다.
    let rc = unsafe {
        ffi::proc_pidinfo(
            pid,
            ffi::PROC_PIDVNODEPATHINFO,
            0,
            (&mut v as *mut ProcVnodePathInfo).cast(),
            size,
        )
    };
    if rc != size {
        return Err(ffi::errno());
    }
    let path = ffi::c_str(&v.cdir_path);
    Ok(if path.is_empty() { None } else { Some(path) })
}

/// fd 목록. buf를 재사용하고 읽은 개수를 돌려준다.
pub(crate) fn list_fds(pid: i32, buf: &mut Vec<ProcFdInfo>, hint: usize) -> Result<usize, i32> {
    let mut cap = (hint + 16).max(64);
    for _ in 0..4 {
        if buf.len() < cap {
            buf.resize(
                cap,
                ProcFdInfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                },
            );
        }
        let bytes = (cap * size_of::<ProcFdInfo>()) as c_int;
        ffi::clear_errno();
        // SAFETY: buf는 최소 cap개 원소(bytes 바이트)를 가진다.
        let rc = unsafe {
            ffi::proc_pidinfo(pid, ffi::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), bytes)
        };
        if rc < 0 || (rc == 0 && ffi::raw_errno() != 0) {
            return Err(ffi::errno());
        }
        if rc < bytes {
            return Ok(rc as usize / size_of::<ProcFdInfo>());
        }
        cap *= 2;
    }
    Err(libc::ENOBUFS)
}

pub(crate) fn socket_info(pid: i32, fd: i32, out: &mut SocketFdInfo) -> Result<(), i32> {
    let size = ffi::SOCKET_FDINFO_SIZE as c_int;
    // SAFETY: out은 SOCKET_FDINFO_SIZE 바이트다.
    let rc = unsafe {
        ffi::proc_pidfdinfo(
            pid,
            fd,
            ffi::PROC_PIDFDSOCKETINFO,
            out.0.as_mut_ptr().cast(),
            size,
        )
    };
    if rc == size {
        Ok(())
    } else {
        Err(ffi::errno())
    }
}
