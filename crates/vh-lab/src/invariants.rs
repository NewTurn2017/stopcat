//! N1~N5(W4 불변식: 쓰고 있는 것은 건드리지 않는다). 지킴이 9칸을 한 감독 안에서 돈다.
//! 시간표·칸 배치는 RUN-READY에 그대로 적는다(PM 판정 Q1·Q2·Q6 보정·2단계 추가 절).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::json;
use vh_model::{AutoLevel, GuardEventKind, HealthLevel, ProcRef, Section, UsageReason};

use crate::cell::{Cell, dir_markers, level_name};
use crate::lab::{Lab, Meta};
use crate::run::{KernelRec, sample_kernel};
use crate::spec::{self, ExecSpec, Role};
use crate::util::{new_run_id, now_ms, sha256_file, write_json, write_jsonl};
use crate::verdict::{Item, Verdict};
use crate::verdict_w4::{self as w4, N4Input, N5Input};
use crate::vhjson::{self, JsonProbe};

pub const N5_BATCH_MS: [u64; 3] = [0, 90_000, 180_000];
pub const SPIN_END_MS: u64 = 14 * 60_000;
pub const NOTIFY_SWITCH_MS: u64 = 11 * 60_000;
pub const N5_FALLBACK_SWITCH_MS: u64 = 13 * 60_000;
pub const N5_AFTER_SWITCH_MS: u64 = 5 * 60_000;
pub const END_MS: u64 = 21 * 60_000 + 30_000;
pub const N4_HOLD_SECS: u64 = 660;
pub const SPIN_SECS: u64 = 900;
pub const MAX_SECS: u64 = 1_500;
pub const PROBES_MS: [u64; 5] = [300_000, 630_000, 720_000, 960_000, 1_260_000];
const KERNEL_EVERY_MS: u64 = 2_000;

const LEVELS: [AutoLevel; 3] = [
    AutoLevel::NotifyOnly,
    AutoLevel::Safe,
    AutoLevel::Aggressive,
];
const VITE: &[&str] = &["node_modules/.bin/vite"];
const NEXT_DEV: &[&str] = &["node_modules/.bin/next", "dev"];
const MCP: &[&str] = &["node_modules/chrome-devtools-mcp/build/src/index.js"];

pub struct VhCopy<'a> {
    pub path: &'a Path,
    pub sha256: &'a str,
}

struct Pair {
    server: ProcRef,
    client: ProcRef,
    port: u16,
}

fn node(
    lab: &Lab,
    dir: &Path,
    script: &[&str],
    role: Role,
    tag: &str,
    extra: &[(&str, String)],
) -> ExecSpec {
    let mut argv = vec!["node".to_string()];
    argv.extend(script.iter().map(|s| {
        if s.starts_with("node_modules") {
            dir.join(s).to_string_lossy().into_owned()
        } else {
            s.to_string()
        }
    }));
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut s = lab.exec_spec("node", role, &a, Some(tag), extra, MAX_SECS);
    s.cwd = dir.to_string_lossy().into_owned();
    s
}

fn project(lab: &Lab, d: &str) -> io::Result<PathBuf> {
    let p = lab.dir(d)?;
    std::fs::write(
        p.join("package.json"),
        format!("{{\"name\":\"lab-{d}\"}}\n"),
    )?;
    Ok(p)
}

fn wait_port(dir: &Path) -> io::Result<u16> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        if let Ok(s) = std::fs::read_to_string(dir.join(spec::PORT_FILE))
            && let Ok(p) = s.trim().parse::<u16>()
        {
            return Ok(p);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::other("서버 포트 파일이 10초 안에 안 생김"))
}

/// 주인 끝난 HTTP 서버(ppid 1) + 감독 직속 클라이언트(연결을 `hold_secs` 쥐고 스스로 끝남).
fn spawn_pair(
    lab: &mut Lab,
    sub: &str,
    dir: &str,
    hold_secs: u64,
    marks: &mut BTreeMap<ProcRef, Vec<String>>,
) -> io::Result<Pair> {
    let tag = lab.tag(sub);
    let d = project(lab, dir)?;
    let dead = lab.dead_pid()?;
    let s = node(
        lab,
        &d,
        NEXT_DEV,
        Role::Serve,
        &tag,
        &[("CLAUDE_PID", dead.to_string())],
    );
    let server = lab.spawn_orphans(vec![(Meta::new(sub, &format!("{dir}-server")), s)])?[0];
    let port = wait_port(&d)?;
    let c = lab.exec_spec(
        "lab-client",
        Role::Client,
        &["lab-client"],
        Some(&tag),
        &[
            (spec::CONNECT_PORT, port.to_string()),
            (spec::HOLD_SECS, hold_secs.to_string()),
        ],
        MAX_SECS,
    );
    let (client, _) = lab.spawn_direct(Meta::new(sub, &format!("{dir}-client")), c, vec![])?;
    dir_markers(marks, server, dir);
    Ok(Pair {
        server,
        client,
        port,
    })
}

struct Shared {
    n1_owner: ProcRef,
    n1: ProcRef,
    n2: Pair,
    n3: ProcRef,
}

fn spawn_shared(lab: &mut Lab, marks: &mut BTreeMap<ProcRef, Vec<String>>) -> io::Result<Shared> {
    let tag = lab.tag("NS");
    let d1 = project(lab, "n1")?;
    let owner = lab.exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], MAX_SECS);
    let work = node(
        lab,
        &d1,
        VITE,
        Role::Spin,
        &tag,
        &[
            ("CLAUDE_PID", spec::PARENT_PID_TOKEN.to_string()),
            (spec::SPIN_THREADS, "2".into()),
            (spec::SPIN_SECS, SPIN_SECS.to_string()),
        ],
    );
    let (n1_owner, kids) = lab.spawn_direct(
        Meta::new("NS", "N1-owner"),
        owner,
        vec![(Meta::new("NS", "N1"), work)],
    )?;
    let n1 = *kids
        .first()
        .ok_or_else(|| io::Error::other("N1 작업 생성 실패"))?;
    dir_markers(marks, n1, "n1");
    let n2 = spawn_pair(lab, "NS", "n2", MAX_SECS, marks)?;
    let d3 = project(lab, "n3")?;
    let dead = lab.dead_pid()?;
    let s3 = node(
        lab,
        &d3,
        VITE,
        Role::Spin,
        &tag,
        &[
            ("CLAUDE_PID", dead.to_string()),
            (spec::SPIN_THREADS, "1".into()),
            (spec::SPIN_SECS, SPIN_SECS.to_string()),
        ],
    );
    let n3 = lab.spawn_orphans(vec![(Meta::new("NS", "N3"), s3)])?[0];
    dir_markers(marks, n3, "n3");
    Ok(Shared {
        n1_owner,
        n1,
        n2,
        n3,
    })
}

fn spawn_n5(
    lab: &mut Lab,
    lvl: &str,
    i: usize,
    marks: &mut BTreeMap<ProcRef, Vec<String>>,
) -> io::Result<ProcRef> {
    let sub = format!("N5-{lvl}");
    let tag = lab.tag(&sub);
    let dir = format!("n5-{lvl}-{i}");
    let d = project(lab, &dir)?;
    let dead = lab.dead_pid()?;
    let s = node(
        lab,
        &d,
        MCP,
        Role::Idle,
        &tag,
        &[("CLAUDE_PID", dead.to_string())],
    );
    let r = lab.spawn_orphans(vec![(Meta::new(&sub, &format!("N5-{i}")), s)])?[0];
    dir_markers(marks, r, &dir);
    Ok(r)
}

pub fn run(out: &Path, vh: Option<VhCopy<'_>>) -> io::Result<bool> {
    if let Some(v) = &vh
        && sha256_file(v.path)? != v.sha256
    {
        return Err(io::Error::other("측정 대상 sha256 불일치"));
    }
    std::fs::create_dir_all(out)?;
    let run_id = new_run_id()?;
    let mut lab = Lab::create(&run_id)?;
    let res = drive(&mut lab, out, vh.as_ref());
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let (items, iso_ok, timeline) = res?;
    let all_pass = items.iter().all(|i| i.verdict == Verdict::Pass);
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "vh-lab/invariants/v1",
            "run_id": run_id,
            "items": items,
            "isolation_ok": iso_ok,
            "timeline": timeline,
            "strings": crate::strings::table(),
            "leftover_processes": cleanup.leftover_processes,
            "all_pass": all_pass,
        }),
    )?;
    Ok(iso_ok && cleanup.leftover_processes == 0)
}

fn first_gone(kernel: &[KernelRec], r: ProcRef) -> Option<u64> {
    let mut seen = false;
    for k in kernel.iter().filter(|k| k.r == r) {
        if k.alive {
            seen = true;
        } else if seen {
            return Some(k.at_ms);
        }
    }
    None
}

type Driven = (Vec<Item>, bool, serde_json::Value);

fn drive(lab: &mut Lab, out: &Path, vh: Option<&VhCopy<'_>>) -> io::Result<Driven> {
    let t0 = Instant::now();
    let t0_ms = now_ms();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    let mut marks: BTreeMap<ProcRef, Vec<String>> = BTreeMap::new();

    let sh = spawn_shared(lab, &mut marks)?;
    let n4s = spawn_pair(lab, "N4S", "n4s", N4_HOLD_SECS, &mut marks)?;
    let n4f_safe = spawn_pair(lab, "N4F-safe", "n4f-safe", N4_HOLD_SECS, &mut marks)?;
    let n4f_aggr = spawn_pair(
        lab,
        "N4F-aggressive",
        "n4f-aggressive",
        N4_HOLD_SECS,
        &mut marks,
    )?;
    let mut n5: BTreeMap<&'static str, Vec<ProcRef>> = BTreeMap::new();
    for l in LEVELS {
        n5.insert(
            level_name(l),
            vec![spawn_n5(lab, level_name(l), 0, &mut marks)?],
        );
    }

    let mut cells: Vec<Cell> = Vec::new();
    for l in LEVELS {
        cells.push(Cell::new(
            &format!("n-{}", level_name(l)),
            l,
            None,
            &["NS", "N4S"],
        ));
    }
    cells.push(Cell::new(
        "f-notify",
        AutoLevel::NotifyOnly,
        Some(w4::FORCED),
        &["NS", "N4S"],
    ));
    cells.push(Cell::new(
        "f-safe",
        AutoLevel::Safe,
        Some(w4::FORCED),
        &["NS", "N4F-safe"],
    ));
    cells.push(Cell::new(
        "f-aggressive",
        AutoLevel::Aggressive,
        Some(w4::FORCED),
        &["NS", "N4F-aggressive"],
    ));
    for c in cells.iter_mut() {
        c.start(lab, out)?;
    }
    for l in LEVELS {
        let sub = format!("N5-{}", level_name(l));
        cells.push(Cell::new(
            &format!("t-{}", level_name(l)),
            l,
            Some(w4::FORCED),
            &["NS", &sub],
        ));
    }

    let mut watch: BTreeSet<ProcRef> = lab.registry.all_refs();
    let mut kernel: Vec<KernelRec> = Vec::new();
    let mut probes: Vec<JsonProbe> = Vec::new();
    let mut probe_i = 0;
    let mut last_k = Instant::now() - Duration::from_secs(10);
    let mut batch = 1;
    let mut n5_started = false;
    let mut spin_ended_ms: Option<u64> = None;
    let mut switch_ms: BTreeMap<String, u64> = BTreeMap::new();
    let mut t_end: BTreeMap<String, Instant> = BTreeMap::new();
    let json_state = out.join("vhjson-state");
    let mut lab_calls = Vec::new();

    loop {
        let now = Instant::now();
        if now >= at(END_MS) {
            break;
        }
        if batch < N5_BATCH_MS.len() && now >= at(N5_BATCH_MS[batch]) {
            for l in LEVELS {
                let r = spawn_n5(lab, level_name(l), batch, &mut marks)?;
                n5.entry(level_name(l)).or_default().push(r);
            }
            batch += 1;
            watch = lab.registry.all_refs();
        }
        if !n5_started && batch == N5_BATCH_MS.len() {
            for c in cells.iter_mut().filter(|c| c.name.starts_with("t-")) {
                c.start(lab, out)?;
            }
            n5_started = true;
        }
        if spin_ended_ms.is_none() && now >= at(SPIN_END_MS) {
            lab_calls.extend(lab.signal(sh.n1, libc::SIGTERM).1);
            lab_calls.extend(lab.signal(sh.n3, libc::SIGTERM).1);
            spin_ended_ms = Some(now_ms());
        }
        lab.reap_exited();
        if last_k.elapsed() >= Duration::from_millis(KERNEL_EVERY_MS) {
            kernel.extend(sample_kernel(&watch));
            last_k = Instant::now();
        }
        if let Some(v) = vh
            && probe_i < PROBES_MS.len()
            && now >= at(PROBES_MS[probe_i])
        {
            let refs = lab.registry.all_refs();
            probes.push(vhjson::probe(
                v.path,
                &json_state,
                &format!("T+{}s", PROBES_MS[probe_i] / 1000),
                &refs,
            ));
            probe_i += 1;
        }
        for c in cells.iter_mut().filter(|c| c.guard.is_some() && !c.done) {
            c.pump();
            if !c.name.starts_with("t-") {
                continue;
            }
            let lvl = c.name.trim_start_matches("t-");
            let cands = n5.get(lvl).cloned().unwrap_or_default();
            if !switch_ms.contains_key(&c.name) {
                let killed = c.guard.as_ref().is_some_and(|g| {
                    g.scans.iter().flat_map(|s| s.events.iter()).any(|e| {
                        e.kind == GuardEventKind::AutoTerminated
                            && e.target.is_some_and(|t| cands.contains(&t))
                    })
                });
                let by_time = if c.level == AutoLevel::NotifyOnly {
                    now >= at(NOTIFY_SWITCH_MS)
                } else {
                    now >= at(N5_FALLBACK_SWITCH_MS)
                };
                if killed || by_time {
                    let ms = now_ms();
                    c.forced.set(None, ms);
                    switch_ms.insert(c.name.clone(), ms);
                    t_end.insert(
                        c.name.clone(),
                        Instant::now() + Duration::from_millis(N5_AFTER_SWITCH_MS),
                    );
                }
            }
            if t_end.get(&c.name).is_some_and(|e| Instant::now() >= *e) {
                c.finish()?;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for c in cells.iter_mut() {
        c.finish()?;
    }
    for _ in 0..10 {
        kernel.extend(sample_kernel(&watch));
        std::thread::sleep(Duration::from_millis(500));
    }
    let end_ms = now_ms();
    write_jsonl(&out.join("kernel.jsonl"), &kernel)?;
    write_jsonl(&out.join("vhjson.jsonl"), &probes)?;
    write_json(&out.join("registry.json"), &lab.registry)?;
    write_json(&out.join("lab_signals.json"), &lab_calls)?;

    let disc = |p: &Pair| first_gone(&kernel, p.client);
    let spin_end = spin_ended_ms.unwrap_or(t0_ms + SPIN_END_MS);
    let mut items = Vec::new();
    let mut iso_ok = true;
    let mut iso = Vec::new();
    for c in &cells {
        let (ok, v) = c.isolation();
        iso_ok &= ok;
        iso.push(v);
        let Some(rec) = c.records(&kernel, &marks) else {
            continue;
        };
        let start = c.started_ms.unwrap_or(t0_ms);
        items.push(w4::invariant_untouched(
            "N1",
            &c.name,
            &rec,
            sh.n1,
            (start, spin_end),
            &[Section::Working],
            &[UsageReason::OwnerAlive, UsageReason::CpuActive],
        ));
        items.push(w4::invariant_untouched(
            "N2",
            &c.name,
            &rec,
            sh.n2.server,
            (start, end_ms),
            &[Section::Check],
            &[UsageReason::PeerOutsideSubtree],
        ));
        items.push(w4::invariant_untouched(
            "N3",
            &c.name,
            &rec,
            sh.n3,
            (start, spin_end),
            &[Section::Check],
            &[UsageReason::CpuActive],
        ));
        let n4_pair = match c.name.as_str() {
            "f-safe" => Some((&n4f_safe, true)),
            "f-aggressive" => Some((&n4f_aggr, true)),
            n if n.starts_with("n-") || n == "f-notify" => Some((&n4s, false)),
            _ => None,
        };
        if let Some((p, allowed)) = n4_pair {
            items.push(w4::n4(
                &c.name,
                &rec,
                &N4Input {
                    server: p.server,
                    disconnect_ms: disc(p),
                    forced: c.is_forced(),
                    term_allowed: allowed,
                    end_ms,
                },
            ));
        }
        if let Some(lvl) = c.name.strip_prefix("t-") {
            items.push(w4::n5(
                &c.name,
                &rec,
                &N5Input {
                    candidates: n5.get(lvl).cloned().unwrap_or_default(),
                    switch_ms: switch_ms.get(&c.name).copied(),
                    expect_pre_term: c.level != AutoLevel::NotifyOnly,
                    end_ms,
                },
            ));
        }
    }
    items.extend(json_items(&probes, &sh, &n4s, disc(&n4s), spin_end));
    for it in &mut items {
        it.repro = "VH_STATE_DIR=<임시> VH_NOTIFY=off nice -n 19 <vh-lab> invariants --out <폴더> --vh <복사본> --vh-sha256 <값>".into();
        it.evidence = vec![
            out.join("kernel.jsonl").to_string_lossy().into_owned(),
            out.join("vhjson.jsonl").to_string_lossy().into_owned(),
        ];
    }
    write_json(&out.join("isolation.json"), &iso)?;
    let timeline = json!({
        "t0_ms": t0_ms,
        "end_ms": end_ms,
        "spin_end_ms": spin_end,
        "n4_disconnect_ms": {"n4s": disc(&n4s), "n4f-safe": disc(&n4f_safe), "n4f-aggressive": disc(&n4f_aggr)},
        "n4_ports": [n4s.port, n4f_safe.port, n4f_aggr.port, sh.n2.port],
        "n5_switch_ms": switch_ms,
        "n5_candidates": n5,
        "cells_started_ms": cells.iter().map(|c| (c.name.clone(), c.started_ms)).collect::<BTreeMap<_, _>>(),
        "n1_owner": sh.n1_owner,
        "forced_level": HealthLevel::Watch,
    });
    Ok((items, iso_ok, timeline))
}

fn json_item(id: &str, checks: Vec<(&str, Option<bool>)>, obs: serde_json::Value) -> Item {
    let missing = checks.iter().any(|(_, v)| v.is_none());
    let pass = checks.iter().all(|(_, v)| *v == Some(true));
    Item {
        id: id.to_string(),
        expected: "vh --json(측정 바이너리) 구역이 기대와 같음".into(),
        observed: obs,
        verdict: if pass {
            Verdict::Pass
        } else if missing {
            Verdict::Inconclusive
        } else {
            Verdict::Fail
        },
        evidence: Vec::new(),
        suspected_owner: if pass || missing { "none" } else { "CORE" }.into(),
        severity: "medium".into(),
        repro: String::new(),
        checks: checks
            .into_iter()
            .map(|(k, v)| (k.to_string(), v == Some(true)))
            .collect(),
    }
}

/// vh --json 검사점: 발견이 없으면 Working으로 본다(보고에 안 나옴).
fn section_is(p: &JsonProbe, t: ProcRef, want: &str) -> Option<bool> {
    if p.error.is_some() || !p.schema_ok {
        return None;
    }
    Some(match p.section_of(t) {
        Some(s) => s == want,
        None => want == "working",
    })
}

fn json_items(
    probes: &[JsonProbe],
    sh: &Shared,
    n4s: &Pair,
    disc: Option<u64>,
    spin_end: u64,
) -> Vec<Item> {
    if probes.is_empty() {
        return Vec::new();
    }
    let during = |p: &&JsonProbe| p.at_ms < spin_end;
    let mut out = Vec::new();
    for (id, t, want, use_spin) in [
        ("N1/vhjson", sh.n1, "working", true),
        ("N2/vhjson", sh.n2.server, "check", false),
        ("N3/vhjson", sh.n3, "check", true),
    ] {
        let ps: Vec<&JsonProbe> = probes.iter().filter(|p| !use_spin || during(p)).collect();
        let checks: Vec<(&str, Option<bool>)> = ps
            .iter()
            .map(|p| (p.label.as_str(), section_is(p, t, want)))
            .collect();
        let obs = json!(ps.iter().map(|p| json!({"label": p.label, "section": p.section_of(t), "reasons": p.reasons_of(t), "error": p.error, "wall_ms": p.wall_ms})).collect::<Vec<_>>());
        out.push(json_item(id, checks, obs));
    }
    let after: Vec<&JsonProbe> = probes
        .iter()
        .filter(|p| disc.is_some_and(|d| p.at_ms > d + 30_000))
        .collect();
    let before: Vec<&JsonProbe> = probes
        .iter()
        .filter(|p| disc.is_some_and(|d| p.at_ms < d))
        .collect();
    let mut checks: Vec<(&str, Option<bool>)> = before
        .iter()
        .map(|p| (p.label.as_str(), section_is(p, n4s.server, "check")))
        .collect();
    checks.extend(
        after
            .iter()
            .map(|p| (p.label.as_str(), section_is(p, n4s.server, "unneeded"))),
    );
    if disc.is_none() {
        checks.push(("disconnect_observed", None));
    }
    out.push(json_item(
        "N4/vhjson",
        checks,
        json!({"before": before.iter().map(|p| p.section_of(n4s.server)).collect::<Vec<_>>(), "after": after.iter().map(|p| p.section_of(n4s.server)).collect::<Vec<_>>()}),
    ));
    out
}
