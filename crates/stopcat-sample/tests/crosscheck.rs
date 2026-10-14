//! 실기기 교차 검사(읽기 전용, #[ignore]). 기준은 inputs/CORE.md CORE_4.
//!
//! 실행: STOPCAT_CROSSCHECK_OUT=<폴더> cargo test -p stopcat-sample --release --test crosscheck -- --ignored --test-threads=1
//! 결과 파일에는 pid·개수·수치·일치 여부만 쓴다(argv·env·경로 원문 없음).
//! 외부 명령(ps, top, lsof, sysctl, vm_stat)은 이 테스트에서만 쓴다.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};
use stopcat_model::{ProcStatus, Snapshot};
use stopcat_sample::{CollectOptions, collect};

fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd).args(args).output().expect("명령 실행");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn snapshot() -> Snapshot {
    collect(&CollectOptions {
        cpu_interval_ms: None,
        launchd: false,
        project_roots: false,
    })
}

fn write_result(name: &str, pass: bool, body: Value) {
    let dir = std::env::var_os("STOPCAT_CROSSCHECK_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("stopcat-crosscheck"));
    std::fs::create_dir_all(&dir).expect("결과 폴더");
    let v = json!({"check": name, "result": if pass { "PASS" } else { "FAIL" }, "kind": "live", "detail": body});
    std::fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .expect("결과 쓰기");
}

fn error_stages(s: &Snapshot) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for e in &s.collection_errors {
        *m.entry(format!(
            "{}:{}",
            e.stage,
            if e.pid.is_some() { "pid" } else { "summary" }
        ))
        .or_insert(0) += 1;
    }
    m
}

/// pid → (ppid, pgid, zombie)
fn ps_table() -> HashMap<i32, (i32, i32, bool)> {
    run("/bin/ps", &["-axo", "pid=,ppid=,pgid=,stat="])
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            let ppid = it.next()?.parse().ok()?;
            let pgid = it.next()?.parse().ok()?;
            let stat = it.next().unwrap_or("");
            Some((pid, (ppid, pgid, stat.starts_with('Z'))))
        })
        .collect()
}

#[test]
#[ignore]
fn crosscheck_1_pids() {
    let before = ps_table();
    let s = snapshot();
    let after = ps_table();
    let stopcat: HashMap<i32, (i32, i32)> = s
        .processes
        .iter()
        .map(|p| (p.pid, (p.ppid, p.pgid)))
        .collect();
    let stable: Vec<i32> = before
        .keys()
        .filter(|p| after.contains_key(p))
        .copied()
        .collect();
    let in_stopcat = stable.iter().filter(|p| stopcat.contains_key(p)).count();
    let overlap = in_stopcat as f64 / stable.len().max(1) as f64;
    let mut mismatch = Vec::new();
    let mut ps_changed = 0usize;
    for pid in &stable {
        let (b, a) = (before[pid], after[pid]);
        if (b.0, b.1) != (a.0, a.1) {
            ps_changed += 1;
            continue;
        }
        if let Some(&(ppid, pgid)) = stopcat.get(pid)
            && (ppid, pgid) != (b.0, b.1)
        {
            mismatch.push(json!({"pid": pid, "stopcat": [ppid, pgid], "ps": [b.0, b.1]}));
        }
    }
    let missing: Vec<i32> = stable
        .iter()
        .filter(|p| !stopcat.contains_key(p))
        .copied()
        .collect();
    let z_before = before.values().filter(|v| v.2).count();
    let z_after = after.values().filter(|v| v.2).count();
    let z_stopcat = s
        .processes
        .iter()
        .filter(|p| p.status == ProcStatus::Zombie)
        .count();
    let zombie_ok = if z_before == z_after {
        z_stopcat == z_before
    } else {
        (z_before.min(z_after)..=z_before.max(z_after)).contains(&z_stopcat)
    };
    let pass = overlap >= 0.99 && mismatch.is_empty() && zombie_ok;
    write_result(
        "crosscheck_1_pids",
        pass,
        json!({
            "criterion": "안정 PID(수집 전·후 ps 모두에 있는 것) 중 stopcat에도 있는 비율 ≥ 0.99, 공통 PID의 ppid·pgid 불일치 0, ps STAT=Z 개수와 stopcat zombie 개수 같음",
            "ps_before": before.len(), "ps_after": after.len(), "stable": stable.len(), "stopcat_processes": s.processes.len(),
            "stable_in_stopcat": in_stopcat, "overlap": overlap, "stable_missing_in_stopcat_pids": missing,
            "ppid_pgid_compared": stable.len() - ps_changed - missing.len(), "ps_changed_between_runs": ps_changed,
            "ppid_pgid_mismatch": mismatch,
            "zombies": {"ps_before": z_before, "ps_after": z_after, "stopcat": z_stopcat, "ok": zombie_ok},
            "collection_error_stages": error_stages(&s),
        }),
    );
    assert!(
        pass,
        "overlap {overlap:.4}, mismatch {}, zombies ps {z_before}/{z_after} stopcat {z_stopcat}",
        mismatch.len()
    );
}

fn parse_top_mem(tok: &str) -> Option<(u64, u64)> {
    let t = tok.trim_end_matches(['+', '-']);
    let (num, unit) = t.split_at(t.find(|c: char| c.is_ascii_alphabetic())?);
    let n: f64 = num.parse().ok()?;
    let mult: u64 = match unit {
        "B" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return None,
    };
    Some(((n * mult as f64) as u64, mult / 2))
}

#[test]
#[ignore]
fn crosscheck_2_footprint() {
    let s = snapshot();
    let top_out = run(
        "/usr/bin/top",
        &["-l", "1", "-o", "mem", "-stats", "pid,mem", "-n", "100"],
    );
    let mut top: HashMap<i32, (u64, u64)> = HashMap::new();
    let mut in_table = false;
    for line in top_out.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("PID"), Some("MEM")) => in_table = true,
            (Some(pid), Some(mem)) if in_table => {
                if let (Ok(pid), Some(v)) = (pid.parse::<i32>(), parse_top_mem(mem)) {
                    top.insert(pid, v);
                }
            }
            _ => {}
        }
    }
    let mut ours: Vec<(i32, u64)> = s
        .processes
        .iter()
        .filter_map(|p| p.footprint_bytes.map(|f| (p.pid, f)))
        .collect();
    ours.sort_by_key(|a| std::cmp::Reverse(a.1));
    ours.truncate(20);
    let mut rows = Vec::new();
    let mut fails = 0usize;
    for (pid, fp) in &ours {
        match top.get(pid) {
            Some(&(t, half)) => {
                let tol = ((t as f64) * 0.10).max(half as f64);
                let diff = (*fp as f64 - t as f64).abs();
                let ok = diff <= tol;
                if !ok {
                    fails += 1;
                }
                rows.push(json!({"pid": pid, "stopcat_bytes": fp, "top_bytes": t, "diff_ratio": diff / (t.max(1) as f64), "ok": ok}));
            }
            None => {
                fails += 1;
                rows.push(json!({"pid": pid, "stopcat_bytes": fp, "top_bytes": null, "ok": false, "why": "top 상위 100에 없음"}));
            }
        }
    }
    let footprint_none = s
        .processes
        .iter()
        .filter(|p| p.footprint_bytes.is_none() && p.status != ProcStatus::Zombie)
        .count();
    let pass = rows.len() == 20 && fails == 0;
    write_result(
        "crosscheck_2_footprint",
        pass,
        json!({
            "criterion": "stopcat footprint 상위 20개가 top -l 1 -o mem MEM과 ±10% 이내(단위 반올림 반폭 허용: G 0.5GiB, M 0.5MiB, K 0.5KiB)",
            "compared": rows.len(), "fails": fails, "rows": rows,
            "top_rows_parsed": top.len(), "stopcat_footprint_none_non_zombie": footprint_none,
        }),
    );
    assert!(pass, "footprint 비교 실패 {fails}건 / {}", rows.len());
}

fn lsof_listen(uid: u32) -> HashSet<(i32, u16)> {
    let uid = uid.to_string();
    let out = run(
        "/usr/sbin/lsof",
        &["-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-u", &uid, "-Fpn"],
    );
    let mut set = HashSet::new();
    let mut pid = 0;
    for line in out.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse().unwrap_or(0);
        } else if let Some(n) = line.strip_prefix('n')
            && let Some(port) = n.rsplit(':').next().and_then(|p| p.parse::<u16>().ok())
        {
            set.insert((pid, port));
        }
    }
    set
}

#[test]
#[ignore]
fn crosscheck_3_listeners() {
    // SAFETY: getuid는 항상 성공한다.
    let uid = unsafe { libc::getuid() };
    let before = lsof_listen(uid);
    let s = snapshot();
    let after = lsof_listen(uid);
    let own: HashSet<i32> = s
        .processes
        .iter()
        .filter(|p| p.uid == s.self_uid)
        .map(|p| p.pid)
        .collect();
    let stopcat: HashSet<(i32, u16)> = s
        .listeners
        .iter()
        .filter(|l| own.contains(&l.pid))
        .map(|l| (l.pid, l.port))
        .collect();
    let union: HashSet<(i32, u16)> = before.union(&after).copied().collect();
    let stable: HashSet<(i32, u16)> = before.intersection(&after).copied().collect();
    let changed: HashSet<(i32, u16)> = before.symmetric_difference(&after).copied().collect();
    let stopcat_only: Vec<(i32, u16)> = stopcat.difference(&union).copied().collect();
    let lsof_only: Vec<(i32, u16)> = stable.difference(&stopcat).copied().collect();
    let explained: Vec<Value> = changed
        .iter()
        .map(|k| json!({"pid": k.0, "port": k.1, "in_stopcat": stopcat.contains(k), "why": if before.contains(k) { "수집 전 lsof에만 있음(그 사이 사라짐)" } else { "수집 후 lsof에만 있음(그 사이 생김)" }}))
        .collect();
    let pass = stopcat_only.is_empty() && lsof_only.is_empty();
    write_result(
        "crosscheck_3_listeners",
        pass,
        json!({
            "criterion": "자기 uid (pid, port) 집합이 lsof -nP -iTCP -sTCP:LISTEN 과 같음. 수집 전·후 lsof 중 한쪽에만 있는 것은 이유와 함께 따로 표시하고, 설명 없는 불일치가 0이면 PASS",
            "stopcat_pairs": stopcat.len(), "lsof_before": before.len(), "lsof_after": after.len(), "lsof_stable": stable.len(),
            "unexplained_stopcat_only": stopcat_only, "unexplained_lsof_only": lsof_only, "explained_changes": explained,
            "stopcat_listener_sockets_total": s.listeners.len(),
        }),
    );
    assert!(
        pass,
        "설명 없는 불일치: stopcat에만 {}, lsof에만 {}",
        stopcat_only.len(),
        lsof_only.len()
    );
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn run_bytes(cmd: &str, args: &[&str]) -> Vec<u8> {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| o.stdout)
        .unwrap_or_default()
}

/// macOS `ps -o command`의 표시 규칙(이 맥에서 합성 인자로 확인): 탭 → `\011`, 개행 → `\012`,
/// 그 밖의 제어 문자 → `^X`, DEL → `^?`. 역슬래시와 UTF-8 바이트는 그대로.
fn ps_vis(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(b.len());
    for &c in b {
        match c {
            b'\t' => o.extend_from_slice(b"\\011"),
            b'\n' => o.extend_from_slice(b"\\012"),
            0..=0x1f => o.extend_from_slice(&[b'^', c + 0x40]),
            0x7f => o.extend_from_slice(b"^?"),
            _ => o.push(c),
        }
    }
    o
}

/// ps 출력 끝의 개행 하나만 뗀다(다른 공백은 그대로 비교한다).
fn strip_nl(mut v: Vec<u8>) -> Vec<u8> {
    if v.last() == Some(&b'\n') {
        v.pop();
    }
    v
}

#[test]
fn ps_vis_rules() {
    assert_eq!(
        ps_vis(b"a\tb\nc\rd\x01e\x1bf\x7fg\\h"),
        b"a\\011b\\012c^Md^Ae^[f^?g\\h".to_vec()
    );
    assert_eq!(ps_vis("한글 ".as_bytes()), "한글 ".as_bytes().to_vec());
    assert_eq!(strip_nl(b"x  \n".to_vec()), b"x  ".to_vec());
}

#[test]
#[ignore]
fn crosscheck_4_cwd_argv() {
    let s = snapshot();
    let mut cands: Vec<&stopcat_model::Proc> = s
        .processes
        .iter()
        .filter(|p| {
            p.uid == s.self_uid
                && p.pid != s.self_pid
                && p.argv_readable
                && p.cwd.is_some()
                && p.status != ProcStatus::Zombie
        })
        .collect();
    cands.sort_by_key(|p| p.pid);
    let seed = s.taken_at_unix_ms | 1;
    let mut state = seed;
    let mut picked = HashSet::new();
    let mut rows = Vec::new();
    let mut unstable = 0usize;
    let mut excluded_empty_argv0 = 0usize;
    let mut excluded_non_utf8 = 0usize;
    let mut tries = 0usize;
    while rows.len() < 20 && tries < cands.len() * 4 && !cands.is_empty() {
        tries += 1;
        let p = cands[(xorshift(&mut state) % cands.len() as u64) as usize];
        if !picked.insert(p.pid) {
            continue;
        }
        // ps가 빈 argv[0]을 건너뛰고 env 문자열을 붙여 보여 주는 것을 확인했다(ps 쪽 한계). 비교에서 빼고 센다.
        if p.argv.first().is_some_and(|a| a.is_empty()) {
            excluded_empty_argv0 += 1;
            continue;
        }
        // stopcat argv는 계약상 String(손실 변환)이라 잘못된 UTF-8은 바이트 비교가 불가능하다. 빼고 센다.
        if p.argv.iter().any(|a| a.contains('\u{FFFD}')) {
            excluded_non_utf8 += 1;
            continue;
        }
        let pid = p.pid.to_string();
        let ps1 = run_bytes("/bin/ps", &["-ww", "-o", "command=", "-p", &pid]);
        let cwd1 = run("/usr/sbin/lsof", &["-a", "-d", "cwd", "-p", &pid, "-Fn"]);
        let ps2 = run_bytes("/bin/ps", &["-ww", "-o", "command=", "-p", &pid]);
        let cwd2 = run("/usr/sbin/lsof", &["-a", "-d", "cwd", "-p", &pid, "-Fn"]);
        let lsof_cwd = cwd1
            .lines()
            .find_map(|l| l.strip_prefix('n'))
            .map(str::to_string);
        if ps1.is_empty() || ps1 != ps2 || cwd1 != cwd2 || lsof_cwd.is_none() {
            unstable += 1;
            continue;
        }
        let expected = ps_vis(p.argv.join(" ").as_bytes());
        let ps_out = strip_nl(ps1);
        let argv_match = expected == ps_out;
        let cwd_match = p.cwd.as_deref() == lsof_cwd.as_deref();
        rows.push(json!({"pid": p.pid, "cwd_match": cwd_match, "argv_match": argv_match, "stopcat_bytes": expected.len(), "ps_bytes": ps_out.len()}));
    }
    let cwd_ok = rows.iter().filter(|r| r["cwd_match"] == true).count();
    let argv_ok = rows.iter().filter(|r| r["argv_match"] == true).count();
    let pass = rows.len() == 20 && cwd_ok == 20 && argv_ok == 20;
    write_result(
        "crosscheck_4_cwd_argv",
        pass,
        json!({
            "criterion": "시드 고정 무작위 자기 프로세스 20개: cwd = lsof -a -d cwd -p (문자열 완전 일치), argv = ps -ww -o command= (stopcat argv를 공백으로 잇고 ps 표시 규칙을 적용한 바이트가 ps 출력(끝 개행 1개 제외)과 완전 일치). 같은 pid의 ps·lsof를 두 번 읽어 다르거나 그 사이 종료되면 unstable로 빼고 다른 프로세스를 뽑는다",
            "ps_display_rule": "탭→\\011, 개행→\\012, 그 밖의 제어 문자→^X, DEL→^?, 역슬래시·UTF-8은 그대로",
            "seed": seed, "candidates": cands.len(), "compared": rows.len(), "cwd_match": cwd_ok, "argv_match": argv_ok,
            "unstable_skipped": unstable, "excluded_empty_argv0": excluded_empty_argv0, "excluded_non_utf8": excluded_non_utf8,
            "unit": "bytes", "rows": rows,
        }),
    );
    assert!(pass, "비교 {} · cwd {cwd_ok} · argv {argv_ok}", rows.len());
}

#[test]
#[ignore]
fn crosscheck_5_memory() {
    let s = snapshot();
    let pressure: u32 = run(
        "/usr/sbin/sysctl",
        &["-n", "kern.memorystatus_vm_pressure_level"],
    )
    .trim()
    .parse()
    .expect("pressure");
    let swap_txt = run("/usr/sbin/sysctl", &["vm.swapusage"]);
    let used_m: f64 = swap_txt
        .split("used = ")
        .nth(1)
        .and_then(|r| r.split('M').next())
        .and_then(|v| v.trim().parse().ok())
        .expect("swap used");
    let swap_sysctl = used_m * 1024.0 * 1024.0;
    let vm = run("/usr/bin/vm_stat", &[]);
    let comp_pages: f64 = vm
        .lines()
        .find(|l| l.starts_with("Pages occupied by compressor:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().trim_end_matches('.').parse().ok())
        .expect("compressor pages");
    let stopcat_comp_pages = s.memory.compressor_bytes as f64 / s.memory.page_size.max(1) as f64;
    let swap_diff = if swap_sysctl > 0.0 {
        (s.memory.swap_used_bytes as f64 - swap_sysctl).abs() / swap_sysctl
    } else {
        s.memory.swap_used_bytes as f64
    };
    let comp_diff = if comp_pages > 0.0 {
        (stopcat_comp_pages - comp_pages).abs() / comp_pages
    } else {
        stopcat_comp_pages
    };
    let pressure_ok = pressure == s.memory.pressure_level;
    let swap_ok = swap_diff <= 0.01;
    let comp_ok = comp_diff <= 0.02;
    let pass = pressure_ok && swap_ok && comp_ok;
    write_result(
        "crosscheck_5_memory",
        pass,
        json!({
            "criterion": "압력 레벨 = sysctl -n kern.memorystatus_vm_pressure_level, swap 사용량이 sysctl vm.swapusage 와 1% 이내, 압축 페이지가 vm_stat 'Pages occupied by compressor' 와 2% 이내",
            "pressure": {"stopcat": s.memory.pressure_level, "sysctl": pressure, "ok": pressure_ok},
            "swap_used": {"stopcat_bytes": s.memory.swap_used_bytes, "sysctl_bytes": swap_sysctl, "diff_ratio": swap_diff, "ok": swap_ok},
            "compressor_pages": {"stopcat": stopcat_comp_pages, "vm_stat": comp_pages, "diff_ratio": comp_diff, "ok": comp_ok},
            "page_size": s.memory.page_size,
        }),
    );
    assert!(
        pass,
        "pressure {pressure_ok} swap {swap_diff:.4} comp {comp_diff:.4}"
    );
}

fn lsof_established(uid: u32) -> HashMap<i32, usize> {
    let uid = uid.to_string();
    let out = run(
        "/usr/sbin/lsof",
        &[
            "-nP",
            "-iTCP",
            "-sTCP:ESTABLISHED",
            "-a",
            "-u",
            &uid,
            "-Fpf",
        ],
    );
    let mut m = HashMap::new();
    let mut pid = 0;
    for line in out.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse().unwrap_or(0);
        } else if line.starts_with('f') {
            *m.entry(pid).or_insert(0) += 1;
        }
    }
    m
}

#[test]
#[ignore]
fn crosscheck_6_established() {
    // SAFETY: getuid는 항상 성공한다.
    let uid = unsafe { libc::getuid() };
    let before = lsof_established(uid);
    let s = snapshot();
    let after = lsof_established(uid);
    let mut compared = 0usize;
    let mut unstable = 0usize;
    let mut unknown = 0usize;
    let mut mismatch = Vec::new();
    for p in s
        .processes
        .iter()
        .filter(|p| p.uid == s.self_uid && p.pid != s.self_pid)
    {
        let b = before.get(&p.pid).copied().unwrap_or(0);
        let a = after.get(&p.pid).copied().unwrap_or(0);
        if a != b {
            unstable += 1;
            continue;
        }
        let Some(t) = &p.tcp else {
            if p.status != ProcStatus::Zombie {
                unknown += 1;
            }
            continue;
        };
        compared += 1;
        if t.established as usize != b {
            mismatch.push(json!({"pid": p.pid, "stopcat": t.established, "lsof": b}));
        }
    }
    let total: u64 = s
        .processes
        .iter()
        .filter_map(|p| p.tcp.as_ref())
        .map(|t| u64::from(t.established))
        .sum();
    let resolved: u64 = s
        .processes
        .iter()
        .filter_map(|p| p.tcp.as_ref())
        .map(|t| u64::from(t.loopback - t.unresolved))
        .sum();
    let pass = mismatch.is_empty();
    write_result(
        "crosscheck_6_established",
        pass,
        json!({
            "criterion": "자기 uid 프로세스마다 ESTABLISHED TCP 수가 lsof -nP -iTCP -sTCP:ESTABLISHED (fd 수)와 같음. 수집 전·후 lsof 수가 다른 pid는 unstable로 빼고 센다. 설명 없는 불일치 0이면 PASS",
            "compared_pids": compared, "unstable_skipped": unstable, "tcp_unknown": unknown,
            "mismatch": mismatch, "stopcat_established_total": total, "stopcat_loopback_resolved_total": resolved,
            "sockets_ms": s.timings_ms.sockets_ms, "total_ms": s.timings_ms.total_ms,
        }),
    );
    assert!(pass, "불일치 {}건", mismatch.len());
}
