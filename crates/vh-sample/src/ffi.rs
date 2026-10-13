//! raw FFI 선언.
//!
//! 크기·오프셋은 SDK 헤더(`xcrun --show-sdk-path`/usr/include)를 C로 컴파일한 프로브 값이다
//! (evidence `CORE/FFI-LAYOUT.json`). 아래 const assert가 그 값과 다르면 컴파일되지 않는다.
//! union이 들어 있는 구조체(kinfo_proc, socket_fdinfo)는 바이트 버퍼로 두고 필요한 필드만 오프셋으로 읽는다.

use std::mem::{offset_of, size_of};

use libc::{c_int, c_void};

pub const PROC_PIDLISTFDS: c_int = 1;
pub const PROC_PIDTASKALLINFO: c_int = 2;
pub const PROC_PIDVNODEPATHINFO: c_int = 9;
pub const PROC_PIDFDSOCKETINFO: c_int = 3;
pub const PROX_FDTYPE_SOCKET: u32 = 2;
pub const SOCKINFO_TCP: i32 = 2;
pub const TSI_S_LISTEN: i32 = 1;
pub const INI_IPV4: u8 = 1;
pub const RUSAGE_INFO_V4: c_int = 4;
pub const KERN_PROCARGS2: c_int = 49;
pub const KERN_PROC: c_int = 14;
pub const KERN_PROC_ALL: c_int = 0;
pub const KERN_ARGMAX: c_int = 8;
pub const HOST_VM_INFO64: c_int = 4;
pub const P_TRANSLATED: i32 = 0x0002_0000;
pub const SIDL: i8 = 1;
pub const SRUN: i8 = 2;
pub const SSLEEP: i8 = 3;
pub const SSTOP: i8 = 4;
pub const SZOMB: i8 = 5;
pub const NODEV: i32 = -1;
pub const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 30;

/// struct proc_bsdinfo (sys/proc_info.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcBsdInfo {
    pub _pbi_flags: u32,
    pub _pbi_status: u32,
    pub _pbi_xstatus: u32,
    pub _pbi_pid: u32,
    pub _pbi_ppid: u32,
    pub _pbi_uid: u32,
    pub _pbi_gid: u32,
    pub _pbi_ruid: u32,
    pub _pbi_rgid: u32,
    pub _pbi_svuid: u32,
    pub _pbi_svgid: u32,
    pub _rfu_1: u32,
    pub pbi_comm: [u8; 16],
    pub pbi_name: [u8; 32],
    pub pbi_nfiles: u32,
    pub _pbi_pgid: u32,
    pub _pbi_pjobc: u32,
    pub _e_tdev: u32,
    pub _e_tpgid: u32,
    pub pbi_nice: i32,
    pub _pbi_start_tvsec: u64,
    pub _pbi_start_tvusec: u64,
}

/// struct proc_taskinfo (sys/proc_info.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcTaskInfo {
    pub _pti_virtual_size: u64,
    pub _pti_resident_size: u64,
    pub _pti_total_user: u64,
    pub _pti_total_system: u64,
    pub _pti_threads_user: u64,
    pub _pti_threads_system: u64,
    pub _pti_counters: [i32; 9],
    pub pti_threadnum: i32,
    pub _pti_numrunning: i32,
    pub _pti_priority: i32,
}

/// struct proc_taskallinfo (sys/proc_info.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcTaskAllInfo {
    pub pbsd: ProcBsdInfo,
    pub ptinfo: ProcTaskInfo,
}

/// struct rusage_info_v4 (sys/resource.h). 시간 필드는 mach absolute time 단위.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RusageInfoV4 {
    pub _ri_uuid: [u8; 16],
    pub ri_user_time: u64,
    pub ri_system_time: u64,
    pub _ri_pkg_idle_wkups: u64,
    pub _ri_interrupt_wkups: u64,
    pub _ri_pageins: u64,
    pub _ri_wired_size: u64,
    pub ri_resident_size: u64,
    pub ri_phys_footprint: u64,
    pub ri_proc_start_abstime: u64,
    pub _ri_rest: [u64; 26],
}

/// struct proc_vnodepathinfo (sys/proc_info.h). vnode_info 부분은 쓰지 않으므로 바이트로 둔다.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct ProcVnodePathInfo {
    pub _cdir_vi: [u8; 152],
    pub cdir_path: [u8; 1024],
    pub _rdir: [u8; 1176],
}

/// struct proc_fdinfo (sys/proc_info.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcFdInfo {
    pub proc_fd: i32,
    pub proc_fdtype: u32,
}

/// struct vm_statistics64 (mach/vm_statistics.h, 이 SDK의 최신 rev 전체 크기).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmStatistics64 {
    pub free_count: u32,
    pub active_count: u32,
    pub inactive_count: u32,
    pub wire_count: u32,
    pub _counters: [u64; 9],
    pub purgeable_count: u32,
    pub speculative_count: u32,
    pub _decompressions: u64,
    pub _compressions: u64,
    pub swapins: u64,
    pub swapouts: u64,
    pub compressor_page_count: u32,
    pub _throttled_count: u32,
    pub _external_page_count: u32,
    pub _internal_page_count: u32,
    pub total_uncompressed_pages_in_compressor: u64,
    pub _rest: [u64; 33],
}

/// struct xsw_usage (sys/sysctl.h)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XswUsage {
    pub xsu_total: u64,
    pub _xsu_avail: u64,
    pub xsu_used: u64,
    pub _xsu_pagesize: u32,
    pub _xsu_encrypted: i32,
}

/// struct mach_timebase_info (mach/mach_time.h)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

/// struct kinfo_proc (sys/sysctl.h). 바이트 버퍼 + 오프셋.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct KinfoProc(pub [u8; KINFO_PROC_SIZE]);
pub const KINFO_PROC_SIZE: usize = 648;
pub const KP_STARTTIME_SEC: usize = 0;
pub const KP_STARTTIME_USEC: usize = 8;
pub const KP_FLAG: usize = 32;
pub const KP_STAT: usize = 36;
pub const KP_PID: usize = 40;
pub const KP_COMM: usize = 243;
pub const KP_COMM_LEN: usize = 17;
pub const KP_E_UCRED_UID: usize = 420;
pub const KP_E_PPID: usize = 560;
pub const KP_E_PGID: usize = 564;
pub const KP_E_TDEV: usize = 572;

/// struct socket_fdinfo (sys/proc_info.h). 바이트 버퍼 + 오프셋.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct SocketFdInfo(pub [u8; SOCKET_FDINFO_SIZE]);
pub const SOCKET_FDINFO_SIZE: usize = 792;
pub const SOI_FAMILY: usize = 184;
pub const SOI_KIND: usize = 256;
pub const INSI_LPORT: usize = 268;
pub const INSI_VFLAG: usize = 288;
pub const INSI_LADDR6: usize = 312;
pub const INSI_LADDR4: usize = 324;
pub const TCPSI_STATE: usize = 344;

// 프로브 값(CORE/FFI-LAYOUT.json)과의 대조. 다르면 컴파일 오류.
const _: () = {
    assert!(size_of::<ProcBsdInfo>() == 136);
    assert!(offset_of!(ProcBsdInfo, pbi_comm) == 48);
    assert!(offset_of!(ProcBsdInfo, pbi_name) == 64);
    assert!(offset_of!(ProcBsdInfo, pbi_nfiles) == 96);
    assert!(offset_of!(ProcBsdInfo, pbi_nice) == 116);
    assert!(offset_of!(ProcBsdInfo, _pbi_start_tvsec) == 120);
    assert!(size_of::<ProcTaskInfo>() == 96);
    assert!(offset_of!(ProcTaskInfo, pti_threadnum) == 84);
    assert!(offset_of!(ProcTaskInfo, _pti_numrunning) == 88);
    assert!(size_of::<ProcTaskAllInfo>() == 232);
    assert!(offset_of!(ProcTaskAllInfo, ptinfo) == 136);
    assert!(size_of::<RusageInfoV4>() == 296);
    assert!(offset_of!(RusageInfoV4, ri_user_time) == 16);
    assert!(offset_of!(RusageInfoV4, ri_system_time) == 24);
    assert!(offset_of!(RusageInfoV4, ri_resident_size) == 64);
    assert!(offset_of!(RusageInfoV4, ri_phys_footprint) == 72);
    assert!(offset_of!(RusageInfoV4, ri_proc_start_abstime) == 80);
    assert!(size_of::<ProcVnodePathInfo>() == 2352);
    assert!(offset_of!(ProcVnodePathInfo, cdir_path) == 152);
    assert!(size_of::<ProcFdInfo>() == 8);
    assert!(size_of::<VmStatistics64>() == 416);
    assert!(offset_of!(VmStatistics64, purgeable_count) == 88);
    assert!(offset_of!(VmStatistics64, speculative_count) == 92);
    assert!(offset_of!(VmStatistics64, swapins) == 112);
    assert!(offset_of!(VmStatistics64, swapouts) == 120);
    assert!(offset_of!(VmStatistics64, compressor_page_count) == 128);
    assert!(offset_of!(VmStatistics64, total_uncompressed_pages_in_compressor) == 144);
    assert!(size_of::<XswUsage>() == 32);
    assert!(offset_of!(XswUsage, xsu_used) == 16);
    assert!(size_of::<MachTimebaseInfo>() == 8);
    assert!(size_of::<KinfoProc>() == 648);
    assert!(size_of::<SocketFdInfo>() == 792);
};

/// HOST_VM_INFO64_COUNT (= sizeof(vm_statistics64) / sizeof(integer_t)), 프로브 값 104.
pub const HOST_VM_INFO64_COUNT: u32 = (size_of::<VmStatistics64>() / 4) as u32;
const _: () = assert!(HOST_VM_INFO64_COUNT == 104);

unsafe extern "C" {
    pub fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
    pub fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    pub fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    pub fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    pub fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *mut c_void) -> c_int;
    pub fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
    pub fn mach_host_self() -> u32;
    pub fn host_statistics64(host: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
    pub fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    pub static mach_task_self_: u32;
}

/// 마지막 errno. 0이면 EIO로 바꾼다(실패인데 errno가 비어 있는 경우).
pub fn errno() -> i32 {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(0) | None => libc::EIO,
        Some(e) => e,
    }
}

/// errno를 0으로 지운다(0 반환이 정상일 수 있는 호출 전에).
pub fn clear_errno() {
    // SAFETY: __error()는 이 스레드의 errno 위치를 돌려준다. 항상 유효한 포인터다.
    unsafe { *libc::__error() = 0 };
}

pub fn raw_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn bytes<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    let mut a = [0u8; N];
    if let Some(s) = b.get(off..off + N) {
        a.copy_from_slice(s);
    }
    a
}

pub fn rd_i32(b: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes(bytes::<4>(b, off))
}

pub fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes::<4>(b, off))
}

pub fn rd_i64(b: &[u8], off: usize) -> i64 {
    i64::from_ne_bytes(bytes::<8>(b, off))
}

pub fn rd_array<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    bytes::<N>(b, off)
}

/// NUL 종단 바이트열 → 문자열(UTF-8이 아니면 손실 변환).
pub fn c_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}
