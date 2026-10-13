//! 실기기 e2e(자기 자식만). 모든 vh 실행에 VH_STATE_DIR=임시 폴더와 VH_E2E_ALLOW_PIDS=자기 pid들.
//! `--yes` 전에는 같은 명령의 `--json` 미리보기에서 계획 대상 pid 집합이 자기 pid 집합과 같은지 먼저 단언한다.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use vh_act::{Liveness, Prober, RealProber};
use vh_cli::render::action::{FIX_NOT_RUN, FIX_YES_ONLY_CONFIRMED};

const HELPER_ENV: &str = "VH_E2E_HELPER";
const SELF_LIFETIME_SECS: u64 = 120;

fn alive_with_start(pid: i32, start: u64) -> bool {
    let live = RealProber.probe(pid);
    live.liveness == Liveness::Alive && live.start_time_unix_ms == start
}

/// pid와 지금 살아 있는 자손 전부(커널 열거).
fn with_descendants(pid: i32) -> BTreeSet<i32> {
    let mut out = BTreeSet::from([pid]);
    let mut q = vec![pid];
    while let Some(p) = q.pop() {
        for c in RealProber.children(p) {
            if RealProber.probe(c).liveness == Liveness::Alive && out.insert(c) {
                q.push(c);
            }
        }
    }
    out
}

fn vh(args: &[&str], state: &Path, allow: &BTreeSet<i32>) -> Output {
    let allow: Vec<String> = allow.iter().map(i32::to_string).collect();
    Command::new(env!("CARGO_BIN_EXE_vh"))
        .args(args)
        .env("VH_STATE_DIR", state)
        .env("VH_E2E_ALLOW_PIDS", allow.join(","))
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .expect("vh 실행")
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "JSON 아님({e}): stdout={} stderr={}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn plan_pids(v: &serde_json::Value) -> BTreeSet<i32> {
    v["plan"]["items"]
        .as_array()
        .expect("plan.items")
        .iter()
        .map(|i| i["target"]["pid"].as_i64().unwrap() as i32)
        .collect()
}

fn audit_lines(state: &Path) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(vh_act::audit_log_path(state)) {
        Ok(s) => s
            .lines()
            .map(|l| serde_json::from_str(l).expect("감사 로그 줄"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn assert_preview_matches(preview: &Output, mine: &BTreeSet<i32>) {
    assert_eq!(preview.status.code(), Some(0), "미리보기 실패");
    let v = json(preview);
    assert_eq!(v["mode"], "non_interactive_preview", "미리보기가 아님: {v}");
    let planned = plan_pids(&v);
    assert_eq!(
        &planned, mine,
        "미리보기 대상 pid가 자기 pid 집합과 다름 → --yes 실행하지 않음"
    );
}

/// 임시 폴더에 `node`라는 이름으로 복사한 이 테스트 바이너리(sleep 모드)를 부모 셸 종료로 launchd 밑에 둔 자작 고아.
/// `/bin/sleep` 복사본은 macOS가 실행 즉시 SIGKILL 한다(플랫폼 바이너리 서명, 2026-10-13 실측 rc -9).
struct Orphan {
    pid: i32,
    start: u64,
    dir: tempfile::TempDir,
}

impl Orphan {
    fn spawn() -> Orphan {
        let dir = tempfile::tempdir().expect("임시 폴더");
        let node: PathBuf = dir.path().join("node");
        std::fs::copy(std::env::current_exe().expect("테스트 바이너리"), &node)
            .expect("테스트 바이너리 복사");
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#""$0" --exact e2e_helper --test-threads=1 </dev/null >/dev/null 2>&1 & echo $!"#)
            .arg(&node)
            .env(HELPER_ENV, "sleep")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
            .expect("부모 셸 실행");
        let pid: i32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("고아 pid");
        let dir_real = std::fs::canonicalize(dir.path()).expect("임시 폴더 실제 경로");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let live = RealProber.probe(pid);
            let execed = live
                .exe
                .as_deref()
                .is_some_and(|e| Path::new(e).starts_with(&dir_real));
            if live.liveness == Liveness::Alive && live.ppid == 1 && execed {
                return Orphan {
                    pid,
                    start: live.start_time_unix_ms,
                    dir,
                };
            }
            assert!(
                Instant::now() < deadline,
                "5초 안에 ppid 1 + node 실행이 되지 않음(pid {pid}, ppid {}, exe {:?})",
                live.ppid,
                live.exe
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 커널 경로는 `/private/var/…`, 임시 폴더는 `/var/…`라 실제 경로로 비교한다.
    fn exe_is_mine(&self) -> bool {
        let dir = std::fs::canonicalize(self.dir.path()).expect("임시 폴더 실제 경로");
        RealProber
            .probe(self.pid)
            .exe
            .is_some_and(|e| Path::new(&e).starts_with(&dir))
    }
}

impl Drop for Orphan {
    fn drop(&mut self) {
        if alive_with_start(self.pid, self.start) && self.exe_is_mine() {
            // SAFETY: 이 테스트가 띄운 자작 고아이고 start_time·실행 파일 경로가 같음을 방금 확인했다.
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
        }
    }
}

/// 같은 테스트 바이너리를 도우미로 다시 실행: 자식 pid가 곧 127.0.0.1:0 리스너.
struct Listener {
    child: Child,
    port: u16,
}

impl Listener {
    fn spawn() -> Listener {
        let mut child = Command::new(std::env::current_exe().expect("테스트 바이너리"))
            .args(["--exact", "e2e_helper", "--nocapture", "--test-threads=1"])
            .env(HELPER_ENV, "listen")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("도우미 실행");
        let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
        let port = loop {
            let line = lines
                .next()
                .expect("도우미가 포트를 알리기 전에 끝남")
                .expect("줄");
            if let Some((_, p)) = line.split_once("VH_PORT=") {
                break p.trim().parse().expect("포트");
            }
        };
        Listener { child, port }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 도우미 모드(`VH_E2E_HELPER`): listen = 127.0.0.1:0 대기, sleep = 그냥 기다림. 둘 다 최대 120초 뒤 스스로 끝난다.
#[test]
fn e2e_helper() {
    match std::env::var(HELPER_ENV).as_deref() {
        Ok("listen") => {}
        Ok("sleep") => {
            std::thread::sleep(Duration::from_secs(SELF_LIFETIME_SECS));
            return;
        }
        _ => return,
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut out = std::io::stdout();
    writeln!(out, "VH_PORT={}", l.local_addr().unwrap().port()).unwrap();
    out.flush().unwrap();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(SELF_LIFETIME_SECS));
        std::process::exit(0);
    });
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

#[test]
fn e2e2_self_made_orphan_fixed_with_only() {
    let o = Orphan::spawn();
    let mine = with_descendants(o.pid);
    let state = tempfile::tempdir().unwrap();
    let pid = o.pid.to_string();

    let preview = vh(
        &["fix", "--json", "--no-cpu", "--only", &pid],
        state.path(),
        &mine,
    );
    assert_preview_matches(&preview, &mine);

    let run = vh(
        &["fix", "--yes", "--json", "--no-cpu", "--only", &pid],
        state.path(),
        &mine,
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("허용 목록에 없어"), "{stderr}");
    let v = json(&run);
    assert_eq!(v["mode"], "executed");
    assert_eq!(plan_pids(&v), mine);
    for out in v["outcomes"].as_array().unwrap() {
        assert_eq!(out["final_state"], "exited", "{out}");
    }
    assert!(
        !alive_with_start(o.pid, o.start),
        "자작 고아가 아직 살아 있음"
    );
    let audit = audit_lines(state.path());
    assert!(!audit.is_empty(), "감사 로그 없음");
    for e in &audit {
        let subject = e["subject_pid"].as_i64().unwrap() as i32;
        assert!(mine.contains(&subject), "자기 pid 밖 감사 항목: {e}");
    }
    println!("E2E2 pid={} audit_lines={}", o.pid, audit.len());
}

#[test]
fn e2e3_port_zero_listener_killed() {
    let l = Listener::spawn();
    let mine = with_descendants(l.pid());
    let state = tempfile::tempdir().unwrap();
    let port = format!(":{}", l.port);

    let preview = vh(&["kill", &port, "--json", "--no-cpu"], state.path(), &mine);
    assert_preview_matches(&preview, &mine);

    let mut l = l;
    let run = vh(
        &["kill", &port, "--yes", "--json", "--no-cpu"],
        state.path(),
        &mine,
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert_eq!(run.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("허용 목록에 없어"), "{stderr}");
    let v = json(&run);
    assert_eq!(v["mode"], "executed");
    assert_eq!(v["outcomes"][0]["final_state"], "exited", "{v}");
    let status = l.child.wait().expect("도우미 회수");
    use std::os::unix::process::ExitStatusExt;
    assert!(
        matches!(status.signal(), Some(libc::SIGTERM) | Some(libc::SIGKILL)),
        "신호로 끝나지 않음: {status:?}"
    );
    let audit = audit_lines(state.path());
    assert!(!audit.is_empty());
    for e in &audit {
        let subject = e["subject_pid"].as_i64().unwrap() as i32;
        assert!(mine.contains(&subject), "자기 pid 밖 감사 항목: {e}");
    }
    println!(
        "E2E3 pid={} port={} audit_lines={}",
        l.pid(),
        l.port,
        audit.len()
    );
}

#[test]
fn e2e4_non_tty_fix_kills_nothing() {
    let o = Orphan::spawn();
    let mine = with_descendants(o.pid);
    let state = tempfile::tempdir().unwrap();

    let run = vh(&["fix", "--no-cpu"], state.path(), &mine);
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert_eq!(run.status.code(), Some(0));
    assert!(
        run.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let last = stdout.lines().last().unwrap_or_default();
    assert!(
        last == FIX_NOT_RUN || last == FIX_YES_ONLY_CONFIRMED || last == "정리할 것이 없어요.",
        "마지막 줄: {last}"
    );
    if last == FIX_YES_ONLY_CONFIRMED {
        let ls: Vec<&str> = stdout.lines().collect();
        assert_eq!(ls[ls.len() - 2], FIX_NOT_RUN);
    }
    assert!(
        alive_with_start(o.pid, o.start),
        "비 TTY fix 뒤 자작 고아가 사라짐"
    );
    assert!(audit_lines(state.path()).is_empty(), "감사 로그가 생김");

    let run = vh(&["fix", "--json", "--no-cpu"], state.path(), &mine);
    let v = json(&run);
    assert!(
        v["mode"] == "non_interactive_preview" || v["mode"] == "nothing_to_do",
        "{}",
        v["mode"]
    );
    assert_eq!(v["outcomes"], serde_json::json!([]));
    assert!(alive_with_start(o.pid, o.start));
    println!("E2E4 orphan_pid={} last_line={last}", o.pid);
}
