//! 화면 갱신(apply) 한 번이 할당하는 양. 이 테스트 바이너리에만 계수 할당기를 둔다.
//! 프로세스 수에 비례하는 색인을 갱신마다 만들지 않는지(PM-1 화면 쪽) 본다.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::*;
use vh_cli::tui::link::Update;
use vh_cli::tui::state::Model;
use vh_model::*;

struct Counting;

static COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    // 재는 스레드에서만 센다(테스트 하네스의 다른 스레드 할당 제외).
    static ON: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: System에 그대로 넘기고 계수기만 올린다.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ON.with(Cell::get) {
            COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(l.size() as u64, Ordering::Relaxed);
        }
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if ON.with(Cell::get) {
            COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(new as u64, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

#[derive(Debug, Clone, Copy)]
struct Counted {
    count: u64,
    bytes: u64,
}

fn measure(f: impl FnOnce()) -> Counted {
    COUNT.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ON.with(|o| o.set(true));
    f();
    ON.with(|o| o.set(false));
    Counted {
        count: COUNT.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
    }
}

/// 고정 데이터 + 상관없는 프로세스 `extra`개(분류 항목도 같은 수).
fn big(extra: usize) -> (Snapshot, Report) {
    let mut s = snapshot();
    let mut rep = report(&s);
    for i in 0..extra {
        let pid = 100_000 + i as i32;
        let mut p = s.processes[1].clone();
        p.pid = pid;
        p.ppid = 1;
        p.name = format!("helper-{i}");
        s.processes.push(p.clone());
        rep.classified.push(Classified {
            target: ProcRef {
                pid,
                start_time_unix_ms: p.start_time_unix_ms,
            },
            kind: Kind::Other,
            label_ko: format!("helper-{i}"),
            signature_id: None,
            project: None,
            owner_session: None,
            owner_pid: None,
            owner_source: None,
            owner_label_ko: None,
            owner_alive: None,
        });
    }
    (s, rep)
}

fn update(s: &Arc<Snapshot>, r: &Arc<Report>) -> Update {
    Update {
        snapshot: s.clone(),
        report: r.clone(),
        policy: GuardPolicy::for_level(AutoLevel::Safe).into(),
        status: status(),
        new_events: vec![],
        manual_result: None,
    }
}

fn status() -> GuardStatus {
    GuardStatus {
        level: AutoLevel::Safe,
        level_locked_by_env: false,
        paused: false,
        circuit_open: false,
        circuit_opened_at_unix_ms: None,
        terminations_in_window: 0,
        scan_seq: 1,
        scan_error_streak: 0,
        last_scan_at_unix_ms: T0,
        last_scan_ms: 38.0,
        next_scan_at_unix_ms: T0 + 5_000,
        demoted: vec![],
        pending: vec![],
    }
}

/// (같은 Arc 갱신, 내용 같은 새 스캔 갱신, 크기가 바뀐 새 스캔 갱신)
fn run(extra: usize) -> [Counted; 3] {
    let (s, r) = big(extra);
    let s = Arc::new(s);
    let r = Arc::new(r);
    let mut m = Model::new(
        Some(VhConfig {
            schema_version: 1,
            auto_level: AutoLevel::Safe,
            first_run_done: true,
            scan_interval_ms: None,
        }),
        None,
        false,
    );
    m.apply(update(&s, &r));

    let same = update(&s, &r);
    let a = measure(|| {
        m.apply(same);
    });

    let s2 = Arc::new((*s).clone());
    let r2 = Arc::new((*r).clone());
    let equal = update(&s2, &r2);
    let b = measure(|| {
        m.apply(equal);
    });

    let mut r3 = (*r).clone();
    for f in r3.findings.iter_mut() {
        f.reclaim_bytes += 4096;
    }
    let changed = update(&Arc::new((*s).clone()), &Arc::new(r3));
    let c = measure(|| {
        m.apply(changed);
    });
    [a, b, c]
}

/// `--nocapture`로 측정값을 찍는다(DONE `alloc_counts`의 근거).
#[test]
fn apply_allocations() {
    let small = run(2_000);
    let large = run(4_000);
    let names = ["same_arc", "equal_content", "changed"];
    for (i, n) in names.iter().enumerate() {
        println!(
            "ALLOC {n}: procs+2000 count={} bytes={} | procs+4000 count={} bytes={}",
            small[i].count, small[i].bytes, large[i].count, large[i].bytes
        );
    }
    // 상한은 W3 2단계 첫 측정값(바꾸기 전: 갱신마다 157회, +2000 프로세스 353,868B · +4000 697,932B).
    let bound = [(1, 33), (21, 1_627), (100, 8_612)];
    for (i, (count, bytes)) in bound.into_iter().enumerate() {
        assert!(
            small[i].count <= count && small[i].bytes <= bytes,
            "{}: {:?}",
            names[i],
            small[i]
        );
        assert_eq!(
            (small[i].count, small[i].bytes),
            (large[i].count, large[i].bytes),
            "{}: 프로세스 수에 따라 늘면 안 됨",
            names[i]
        );
    }
}
