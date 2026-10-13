//! 기계·메모리·한도: sysctl과 host_statistics64.

use std::ffi::CString;
use std::ptr::null_mut;

use vh_model::{CollectionError, HostInfo, LimitsInfo, MemoryInfo};

use crate::ffi::{self, VmStatistics64, XswUsage};

fn sysctl_raw(name: &str, out: &mut [u8]) -> Result<usize, i32> {
    let c = CString::new(name).map_err(|_| libc::EINVAL)?;
    let mut len = out.len();
    // SAFETY: out은 len 바이트다.
    let rc =
        unsafe { libc::sysctlbyname(c.as_ptr(), out.as_mut_ptr().cast(), &mut len, null_mut(), 0) };
    if rc == 0 {
        Ok(len.min(out.len()))
    } else {
        Err(ffi::errno())
    }
}

fn sysctl_u64(name: &str) -> Result<u64, i32> {
    let mut b = [0u8; 8];
    match sysctl_raw(name, &mut b)? {
        4 => Ok(u64::from(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))),
        8 => Ok(u64::from_ne_bytes(b)),
        _ => Err(libc::EINVAL),
    }
}

fn sysctl_string(name: &str) -> Result<String, i32> {
    let mut b = [0u8; 256];
    let n = sysctl_raw(name, &mut b)?;
    Ok(ffi::c_str(&b[..n]))
}

fn sysctl_struct<T: Copy>(name: &str, zero: T) -> Result<T, i32> {
    let mut v = zero;
    let size = std::mem::size_of::<T>();
    // SAFETY: v를 size 바이트 슬라이스로 본다. T는 정수 필드만 가진 repr(C) 구조체다.
    let bytes = unsafe { std::slice::from_raw_parts_mut((&mut v as *mut T).cast::<u8>(), size) };
    let n = sysctl_raw(name, bytes)?;
    if n == size { Ok(v) } else { Err(libc::EINVAL) }
}

struct Errs<'a>(&'a mut Vec<CollectionError>);

impl Errs<'_> {
    fn get<T: Default>(&mut self, name: &str, r: Result<T, i32>) -> T {
        r.unwrap_or_else(|e| {
            self.0.push(CollectionError {
                pid: None,
                stage: "system".to_string(),
                errno: Some(e),
                message: format!("{name} 읽기 실패"),
            });
            T::default()
        })
    }
}

fn home_dir() -> Option<String> {
    let mut pw: libc::passwd = unsafe_zeroed_passwd();
    let mut result: *mut libc::passwd = null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: 모든 포인터는 유효하고 buf 길이를 넘겨 준다.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r가 채운 NUL 종단 문자열(buf 안).
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
    let s = dir.to_string_lossy().into_owned();
    if s.is_empty() { None } else { Some(s) }
}

fn unsafe_zeroed_passwd() -> libc::passwd {
    // SAFETY: passwd는 포인터·정수 필드만 가진다. 널 포인터 0 패턴은 유효하다.
    unsafe { std::mem::zeroed() }
}

fn vm_stats() -> Result<VmStatistics64, i32> {
    // SAFETY: 정수 필드만 가진 repr(C) 구조체.
    let mut v: VmStatistics64 = unsafe { std::mem::zeroed() };
    let mut count = ffi::HOST_VM_INFO64_COUNT;
    // SAFETY: mach_host_self는 send right를 돌려준다. 아래에서 돌려놓는다.
    let host = unsafe { ffi::mach_host_self() };
    // SAFETY: v는 count × 4 바이트다.
    let kr = unsafe {
        ffi::host_statistics64(
            host,
            ffi::HOST_VM_INFO64,
            (&mut v as *mut VmStatistics64).cast(),
            &mut count,
        )
    };
    // SAFETY: 위에서 얻은 host 포트 참조를 돌려놓는다.
    unsafe {
        ffi::mach_port_deallocate(ffi::mach_task_self_, host);
    }
    if kr != 0 {
        return Err(kr);
    }
    // compressor·total_uncompressed 필드(오프셋 152 바이트까지)가 채워졌는지 확인한다.
    if (count as usize) * 4 < 152 {
        return Err(libc::ENOTSUP);
    }
    Ok(v)
}

pub(crate) struct System {
    pub host: HostInfo,
    pub memory: MemoryInfo,
    pub limits: LimitsInfo,
}

pub(crate) fn read(errors: &mut Vec<CollectionError>) -> System {
    let mut e = Errs(errors);
    let page_size = e.get("vm.pagesize", sysctl_u64("vm.pagesize"));
    let boot = e.get(
        "kern.boottime",
        sysctl_struct(
            "kern.boottime",
            libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        ),
    );
    let mut loadavg = [0f64; 3];
    // SAFETY: loadavg는 f64 3개.
    if unsafe { libc::getloadavg(loadavg.as_mut_ptr(), 3) } != 3 {
        e.0.push(CollectionError {
            pid: None,
            stage: "system".to_string(),
            errno: None,
            message: "부하 평균(getloadavg) 읽기 실패".to_string(),
        });
    }
    let arm = sysctl_u64("hw.optional.arm64").unwrap_or(0) == 1;
    let home = match home_dir() {
        Some(h) => h,
        None => {
            e.0.push(CollectionError {
                pid: None,
                stage: "home".to_string(),
                errno: None,
                message: "홈 디렉터리(getpwuid_r) 읽기 실패, HOME 사용".to_string(),
            });
            std::env::var("HOME").unwrap_or_default()
        }
    };
    let host = HostInfo {
        model: e.get("hw.model", sysctl_string("hw.model")),
        os_version: e.get(
            "kern.osproductversion",
            sysctl_string("kern.osproductversion"),
        ),
        arch: if arm { "arm64" } else { "x86_64" }.to_string(),
        ncpu: e.get("hw.ncpu", sysctl_u64("hw.ncpu")) as u32,
        perf_cores: sysctl_u64("hw.perflevel0.logicalcpu")
            .ok()
            .map(|v| v as u32),
        eff_cores: sysctl_u64("hw.perflevel1.logicalcpu")
            .ok()
            .map(|v| v as u32),
        mem_total_bytes: e.get("hw.memsize", sysctl_u64("hw.memsize")),
        boot_time_unix_ms: crate::list::start_time_ms(boot.tv_sec, boot.tv_usec),
        loadavg,
        home_dir: home,
    };
    let swap = e.get(
        "vm.swapusage",
        sysctl_struct(
            "vm.swapusage",
            XswUsage {
                xsu_total: 0,
                _xsu_avail: 0,
                xsu_used: 0,
                _xsu_pagesize: 0,
                _xsu_encrypted: 0,
            },
        ),
    );
    let pressure = e.get(
        "kern.memorystatus_vm_pressure_level",
        sysctl_u64("kern.memorystatus_vm_pressure_level"),
    ) as u32;
    let memory = match vm_stats() {
        Ok(v) => {
            let p = |n: u32| u64::from(n) * page_size;
            MemoryInfo {
                pressure_level: pressure,
                page_size,
                free_bytes: p(v.free_count),
                active_bytes: p(v.active_count),
                inactive_bytes: p(v.inactive_count),
                speculative_bytes: p(v.speculative_count),
                wired_bytes: p(v.wire_count),
                compressor_bytes: p(v.compressor_page_count),
                compressed_logical_bytes: v.total_uncompressed_pages_in_compressor * page_size,
                purgeable_bytes: p(v.purgeable_count),
                swap_total_bytes: swap.xsu_total,
                swap_used_bytes: swap.xsu_used,
                swapins: v.swapins,
                swapouts: v.swapouts,
            }
        }
        Err(kr) => {
            e.0.push(CollectionError {
                pid: None,
                stage: "vm_stats".to_string(),
                errno: Some(kr),
                message: "host_statistics64(HOST_VM_INFO64) 실패".to_string(),
            });
            MemoryInfo {
                pressure_level: pressure,
                page_size,
                free_bytes: 0,
                active_bytes: 0,
                inactive_bytes: 0,
                speculative_bytes: 0,
                wired_bytes: 0,
                compressor_bytes: 0,
                compressed_logical_bytes: 0,
                purgeable_bytes: 0,
                swap_total_bytes: swap.xsu_total,
                swap_used_bytes: swap.xsu_used,
                swapins: 0,
                swapouts: 0,
            }
        }
    };
    let limits = LimitsInfo {
        maxproc: e.get("kern.maxproc", sysctl_u64("kern.maxproc")) as u32,
        maxprocperuid: e.get("kern.maxprocperuid", sysctl_u64("kern.maxprocperuid")) as u32,
        maxfiles: e.get("kern.maxfiles", sysctl_u64("kern.maxfiles")) as u32,
        maxfilesperproc: e.get("kern.maxfilesperproc", sysctl_u64("kern.maxfilesperproc")) as u32,
        num_files: e.get("kern.num_files", sysctl_u64("kern.num_files")) as u32,
        user_proc_count: 0,
        total_proc_count: 0,
    };
    System {
        host,
        memory,
        limits,
    }
}
