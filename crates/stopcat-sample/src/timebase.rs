//! mach absolute time → 나노초. proc_pid_rusage의 시간 필드는 mach tick 단위다
//! (이 맥 실측 timebase 125/3).

use std::sync::OnceLock;

use crate::ffi::{self, MachTimebaseInfo};

static TIMEBASE: OnceLock<(u32, u32)> = OnceLock::new();

pub(crate) fn timebase() -> (u32, u32) {
    *TIMEBASE.get_or_init(|| {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: info는 유효한 출력 포인터.
        let rc = unsafe { ffi::mach_timebase_info(&mut info) };
        if rc != 0 || info.denom == 0 || info.numer == 0 {
            (1, 1)
        } else {
            (info.numer, info.denom)
        }
    })
}

pub(crate) fn ticks_to_ns(ticks: u64, numer: u32, denom: u32) -> u64 {
    let ns = u128::from(ticks) * u128::from(numer) / u128::from(denom.max(1));
    u64::try_from(ns).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_to_ns_converts_and_saturates() {
        assert_eq!(ticks_to_ns(24, 125, 3), 1000);
        assert_eq!(ticks_to_ns(u64::MAX, 125, 3), u64::MAX);
        assert_eq!(ticks_to_ns(u64::MAX, 1, 1), u64::MAX);
        assert_eq!(ticks_to_ns(7, 1, 1), 7);
    }
}
