//! 실기기 읽기 전용: rusage v4 diskio 오프셋 확인. 자기 임시 파일에만 쓴다.

use std::io::Write;
use std::os::fd::AsRawFd;

use stopcat_sample::{CollectOptions, collect};

fn own_disk() -> (u64, u64) {
    let s = collect(&CollectOptions {
        cpu_interval_ms: None,
        launchd: false,
        project_roots: false,
    });
    let me = s
        .processes
        .iter()
        .find(|p| p.pid == s.self_pid)
        .expect("자기");
    (
        me.disk_read_bytes.expect("read"),
        me.disk_written_bytes.expect("written"),
    )
}

#[test]
fn rusage_diskio_counts_own_fsync_writes() {
    const MIB: u64 = 1 << 20;
    let (r0, w0) = own_disk();
    let mut f = tempfile::tempfile().expect("임시 파일");
    let chunk = vec![0x5au8; MIB as usize];
    for _ in 0..8 {
        f.write_all(&chunk).expect("쓰기");
    }
    // SAFETY: f는 열린 파일이고 F_FULLFSYNC는 인자가 없다.
    let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) };
    assert_eq!(rc, 0, "F_FULLFSYNC");
    let (r1, w1) = own_disk();
    let grew = w1.saturating_sub(w0);
    assert!(r1 >= r0, "읽기 누적이 줄어듦 {r0} → {r1}");
    assert!(
        (4 * MIB..=64 * MIB).contains(&grew),
        "쓰기 증가 {grew}바이트(기대 4MiB~64MiB)"
    );
}
