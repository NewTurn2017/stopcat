//! 시나리오 S1~S12(실제 시계). 하위 실행 A(S1·S2·S4~S11 + 미끼 D1·D2), B(S12), C(S3)를 동시에 돈다.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;
use vh_model::{AutoLevel, GuardEventKind, GuardPolicy, ProcRef};

use crate::kernel::task_priority;
use crate::lab::{Lab, Meta};
use crate::run::{GuardRun, KernelRec, sample_kernel};
use crate::scope::LabScope;
use crate::spec::{self, ExecSpec, Role};
use crate::util::{new_run_id, write_json, write_jsonl};
use crate::verdict::{self, Item, Records, Verdict};

pub const A_END_MS: u64 = 13 * 60_000;
pub const B_END_MS: u64 = 11 * 60_000 + 30_000;
pub const C_MAX_MS: u64 = 4 * 60_000;
pub const S11_DELAY_MS: u64 = 60_000;
const KERNEL_EVERY_MS: u64 = 2_000;

struct Sub {
    name: &'static str,
    guard: Option<GuardRun>,
    end_at: Option<Instant>,
    done: bool,
}

fn node_spec(
    lab: &Lab,
    dir: &Path,
    script: &[&str],
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
    let r: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut s = lab.exec_spec("node", Role::Idle, &r, Some(tag), extra, 1_500);
    s.cwd = dir.to_string_lossy().into_owned();
    s
}

const MCP: &[&str] = &["node_modules/chrome-devtools-mcp/build/src/index.js"];
/// S10·S11은 S1과 다른 MCP 이름을 쓴다(알림 줄을 이름으로 구분할 수 있게).
const MCP_FS: &[&str] = &["node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"];
const MCP_MEMORY: &[&str] = &["node_modules/@modelcontextprotocol/server-memory/dist/index.js"];
const NEXT_DEV: &[&str] = &["node_modules/.bin/next", "dev"];

pub fn run(out: &Path, only: &BTreeSet<String>) -> io::Result<bool> {
    let run_id = new_run_id()?;
    std::fs::create_dir_all(out)?;
    let mut lab = Lab::create(&run_id)?;
    let res = drive(&mut lab, out, only);
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let (mut items, iso_ok) = res?;
    for it in &mut items {
        it.repro = format!(
            "VH_STATE_DIR=<임시> VH_NOTIFY=off nice -n 19 <vh-lab> scenarios --out <폴더> --only {}",
            sub_of(&it.id)
        );
    }
    let all_pass = items.iter().all(|i| i.verdict == Verdict::Pass);
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "vh-lab/scenarios/v1",
            "run_id": run_id,
            "subs": only,
            "items": items,
            "isolation_ok": iso_ok,
            "leftover_processes": cleanup.leftover_processes,
            "all_pass": all_pass,
        }),
    )?;
    Ok(iso_ok && cleanup.leftover_processes == 0)
}

fn sub_of(id: &str) -> &'static str {
    match id {
        "S12" => "B",
        "S3" => "C",
        _ => "A",
    }
}

#[allow(clippy::type_complexity)]
fn drive(lab: &mut Lab, out: &Path, only: &BTreeSet<String>) -> io::Result<(Vec<Item>, bool)> {
    let t0 = Instant::now();
    let want = |s: &str| only.is_empty() || only.contains(s);
    let mut refs: BTreeMap<&'static str, Vec<ProcRef>> = BTreeMap::new();
    let mut c_base_prio = None;
    let mut s2_port: Option<u16> = None;
    let mut subs: Vec<Sub> = Vec::new();

    if want("A") {
        let tag = lab.tag("A");
        let owner = lab.exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], 1_500);
        let s6_dir = lab.dir("s6")?;
        let s7_dir = lab.dir("s7")?;
        let s6 = node_spec(lab, &s6_dir, NEXT_DEV, &tag, &[]);
        let s7 = node_spec(lab, &s7_dir, &["node_modules/.bin/vite"], &tag, &[]);
        let (owner_ref, kids) = lab.spawn_direct(
            Meta::new("A", "OWNER"),
            owner,
            vec![
                (Meta::new("A", "S6"), s6),
                (Meta::new("A", "S7"), ExecSpec { count: 2, ..s7 }),
            ],
        )?;
        refs.insert("OWNER", vec![owner_ref]);
        refs.insert("S6", vec![kids[0]]);
        refs.insert("S7", vec![kids[1], kids[2]]);

        let mut orphans: Vec<(Meta, ExecSpec, &'static str)> = Vec::new();
        for (sc, dir_name, script, listen) in [
            ("S1", "s1", MCP, false),
            ("S2", "s2", NEXT_DEV, true),
            ("S10", "s10", MCP_FS, false),
        ] {
            let d = lab.dir(dir_name)?;
            std::fs::write(
                d.join("package.json"),
                format!("{{\"name\":\"lab-{dir_name}\"}}\n"),
            )?;
            let owner_pid = if sc == "S10" {
                owner_ref.pid
            } else {
                lab.dead_pid()?
            };
            let mut extra = vec![("CLAUDE_PID", owner_pid.to_string())];
            if listen {
                extra.push((spec::LISTEN, "1".into()));
            }
            orphans.push((
                Meta::new("A", sc),
                node_spec(lab, &d, script, &tag, &extra),
                sc,
            ));
        }
        let dead8 = lab.dead_pid()?;
        let mut s8 = lab.exec_spec(
            "qemu-system-aarch64",
            Role::Idle,
            &["qemu-system-aarch64", "-avd", "lab_pixel"],
            Some(&tag),
            &[("CLAUDE_PID", dead8.to_string())],
            1_500,
        );
        s8.cwd = lab.dir("s8")?.to_string_lossy().into_owned();
        orphans.push((Meta::new("A", "S8"), s8, "S8"));
        let mut s9 = lab.exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], 1_500);
        s9.cwd = lab.dir("s9")?.to_string_lossy().into_owned();
        orphans.push((Meta::new("A", "S9"), s9, "S9"));
        for (d, decoy_tag) in [
            ("d1", None),
            ("d2", Some(format!("lab-{}-decoy", lab.run_id))),
        ] {
            let dir = lab.dir(d)?;
            let dead = lab.dead_pid()?;
            let mut s = node_spec(lab, &dir, MCP, &tag, &[("CLAUDE_PID", dead.to_string())]);
            match decoy_tag {
                Some(t) => {
                    s.env.insert(spec::TAG.into(), t);
                }
                None => {
                    s.env.remove(spec::TAG);
                }
            }
            let sc = if d == "d1" { "D1" } else { "D2" };
            orphans.push((Meta::decoy("A", sc), s, sc));
        }
        let names: Vec<&'static str> = orphans.iter().map(|o| o.2).collect();
        let made = lab.spawn_orphans(orphans.into_iter().map(|(m, s, _)| (m, s)).collect())?;
        for (n, r) in names.into_iter().zip(made) {
            refs.insert(n, vec![r]);
        }
        let mem = lab.exec_spec(
            "lab-mem",
            Role::Mem,
            &["lab-mem"],
            Some(&tag),
            &[
                (spec::MEM_KB_PER_SEC, "853".into()),
                (spec::MEM_MAX_MB, "400".into()),
            ],
            1_500,
        );
        let (s4, _) = lab.spawn_direct(Meta::new("A", "S4"), mem, vec![])?;
        refs.insert("S4", vec![s4]);
        let z = lab.exec_spec(
            "lab-zombie",
            Role::Zombie,
            &["lab-zombie"],
            Some(&tag),
            &[],
            1_500,
        );
        let (s5, zk) = lab.spawn_direct(Meta::new("A", "S5"), z, vec![])?;
        refs.insert("S5", vec![s5]);
        refs.insert("S5Z", zk);
        lab.signal(refs["S6"][0], libc::SIGSTOP);
        subs.push(Sub {
            name: "A",
            guard: None,
            end_at: None,
            done: false,
        });
    }

    if want("B") {
        let tag = lab.tag("B");
        let mut items = Vec::new();
        for i in 0..7 {
            let d = lab.dir(&format!("s12-{i}"))?;
            std::fs::write(
                d.join("package.json"),
                format!("{{\"name\":\"lab-s12-{i}\"}}\n"),
            )?;
            let dead = lab.dead_pid()?;
            let script = if i < 4 { MCP } else { NEXT_DEV };
            items.push((
                Meta::new("B", "S12"),
                node_spec(lab, &d, script, &tag, &[("CLAUDE_PID", dead.to_string())]),
            ));
        }
        let made = lab.spawn_orphans(items)?;
        refs.insert("S12", made);
        lab.registry.freeze("B");
        let g = start_guard(lab, out, "B")?;
        subs.push(Sub {
            name: "B",
            guard: Some(g),
            end_at: Some(t0 + Duration::from_millis(B_END_MS)),
            done: false,
        });
    }

    if want("C") {
        let tag = lab.tag("C");
        let mut spin = lab.exec_spec(
            "lab-spin",
            Role::Spin,
            &["lab-spin"],
            Some(&tag),
            &[
                (spec::SPIN_THREADS, "2".into()),
                (spec::SPIN_SECS, "120".into()),
                (spec::SPIN_STOP_ON_DEMOTE, "1".into()),
            ],
            600,
        );
        spin.cwd = lab.dir("s3")?.to_string_lossy().into_owned();
        let (s3, _) = lab.spawn_direct(Meta::new("C", "S3"), spin, vec![])?;
        refs.insert("S3", vec![s3]);
        std::thread::sleep(Duration::from_millis(300));
        c_base_prio = task_priority(s3.pid);
        lab.registry.freeze("C");
        let g = start_guard(lab, out, "C")?;
        subs.push(Sub {
            name: "C",
            guard: Some(g),
            end_at: Some(t0 + Duration::from_millis(C_MAX_MS)),
            done: false,
        });
    }

    let watch: BTreeSet<ProcRef> = lab.registry.all_refs();
    let mut kernel: Vec<KernelRec> = Vec::new();
    let mut last_k = Instant::now() - Duration::from_secs(10);
    let mut a_started = false;
    let mut c_demoted_at: Option<Instant> = None;
    while subs.iter().any(|s| !s.done) {
        if want("A") && !a_started && t0.elapsed() >= Duration::from_millis(S11_DELAY_MS) {
            let tag = lab.tag("A");
            let d = lab.dir("s11")?;
            let dead = lab.dead_pid()?;
            let s11 = node_spec(
                lab,
                &d,
                MCP_MEMORY,
                &tag,
                &[("CLAUDE_PID", dead.to_string())],
            );
            let made = lab.spawn_orphans(vec![(Meta::new("A", "S11"), s11)])?;
            refs.insert("S11", made);
            lab.registry.freeze("A");
            let g = start_guard(lab, out, "A")?;
            if let Some(a) = subs.iter_mut().find(|s| s.name == "A") {
                a.guard = Some(g);
                a.end_at = Some(t0 + Duration::from_millis(A_END_MS));
            }
            a_started = true;
        }
        let watch_now: BTreeSet<ProcRef> = lab.registry.all_refs().union(&watch).copied().collect();
        if last_k.elapsed() >= Duration::from_millis(KERNEL_EVERY_MS) {
            kernel.extend(sample_kernel(&watch_now));
            last_k = Instant::now();
        }
        for s in subs.iter_mut().filter(|s| !s.done) {
            let Some(g) = s.guard.as_mut() else { continue };
            g.pump();
            if s.name == "A" && s2_port.is_none() {
                let s2 = refs.get("S2").and_then(|v| v.first()).copied();
                s2_port = g
                    .scans
                    .iter()
                    .flat_map(|sc| sc.listeners.iter())
                    .find(|l| Some(l.r) == s2)
                    .map(|l| l.port);
            }
            if s.name == "C" && c_demoted_at.is_none() {
                let s3 = refs["S3"][0];
                if g.scans
                    .iter()
                    .flat_map(|x| x.events.iter())
                    .any(|e| e.kind == GuardEventKind::Demoted && e.target == Some(s3))
                {
                    c_demoted_at = Some(Instant::now());
                }
            }
            let c_early = s.name == "C"
                && c_demoted_at.is_some_and(|t| t.elapsed() >= Duration::from_secs(30));
            if c_early || s.end_at.is_some_and(|e| Instant::now() >= e) {
                g.shutdown();
                g.write()?;
                s.done = true;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for _ in 0..10 {
        kernel.extend(sample_kernel(&watch));
        std::thread::sleep(Duration::from_millis(500));
    }
    write_jsonl(&out.join("kernel.jsonl"), &kernel)?;
    write_json(&out.join("registry.json"), &lab.registry)?;
    let s2_refused = s2_port.map(|p| {
        TcpStream::connect_timeout(&([127, 0, 0, 1], p).into(), Duration::from_millis(500)).is_err()
    });

    let mut items = Vec::new();
    let mut iso_ok = true;
    let mut iso = serde_json::Map::new();
    for s in &subs {
        let Some(g) = &s.guard else { continue };
        let reg = lab.registry.scope_refs(s.name);
        let inv = g.isolation_check(&reg);
        iso_ok &= inv.holds(false);
        iso.insert(
            s.name.into(),
            json!({"invariants": inv, "scan_seq_gaps": g.seq_gaps}),
        );
        let rec = Records {
            scans: g.scans.clone(),
            kernel: kernel.clone(),
            signals: g.signal_calls(),
            notes: g.notifications(),
            audit: g.audit_lines(),
            undemoted: g
                .shutdown
                .as_ref()
                .map(|x| x.undemoted.clone())
                .unwrap_or_default(),
            markers: markers(&refs),
        };
        let ev = |id: &str| {
            vec![
                g.dir.join("scans.jsonl").to_string_lossy().into_owned(),
                out.join("kernel.jsonl").to_string_lossy().into_owned(),
                format!("sub {} / {id}", s.name),
            ]
        };
        let one = |k: &str| refs.get(k).and_then(|v| v.first()).copied();
        match s.name {
            "A" => {
                let mut push = |mut it: Item| {
                    it.evidence = ev(&it.id);
                    items.push(it);
                };
                if let Some(t) = one("S1") {
                    push(verdict::auto_terminated("S1", &rec, t, None));
                }
                if let Some(t) = one("S2") {
                    let mut it = verdict::auto_terminated("S2", &rec, t, None);
                    let listened = s2_port.is_some();
                    it.checks.insert("listener_seen".into(), listened);
                    it.checks
                        .insert("connection_refused_after".into(), s2_refused == Some(true));
                    if !it.checks.values().all(|v| *v) {
                        it.verdict = Verdict::Fail;
                    }
                    push(it);
                }
                if let Some(t) = one("S4") {
                    push(verdict::memory_grower(&rec, t));
                }
                if let (Some(p), Some(z)) = (one("S5"), one("S5Z")) {
                    push(verdict::zombie(&rec, p, z));
                }
                if let Some(t) = one("S6") {
                    push(verdict::stopped(&rec, t));
                }
                if let (Some(a), Some(b)) = (
                    one("S7"),
                    refs.get("S7").and_then(|v| v.get(1)).copied().or(one("S7")),
                ) {
                    push(verdict::duplicate(&rec, a, b));
                }
                if let Some(t) = one("S8") {
                    push(verdict::notify_only(&rec, t));
                }
                if let Some(t) = one("S9") {
                    push(verdict::never_touched(
                        "S9",
                        "어떤 조치·알림도 없음",
                        &rec,
                        t,
                        None,
                    ));
                }
                if let Some(t) = one("S10") {
                    push(verdict::never_touched(
                        "S10",
                        "주인 생존(owner_alive=true), 자동 종료 없음",
                        &rec,
                        t,
                        Some(true),
                    ));
                }
                if let Some(t) = one("S11") {
                    let mut it = verdict::auto_terminated("S11", &rec, t, None);
                    let s1_at = one("S1").and_then(|s1| {
                        rec.events(GuardEventKind::AutoTerminated, s1)
                            .first()
                            .map(|e| e.at_unix_ms)
                    });
                    let (vis, obs) = s1_at
                        .map(|at| verdict::young_pending_visible(&rec, t, at))
                        .unwrap_or((false, json!({"s1_not_terminated": true})));
                    it.checks.insert("pending_visible_while_9min".into(), vis);
                    it.observed["young"] = obs;
                    if !vis {
                        it.verdict = Verdict::Fail;
                        if it.suspected_owner == "none" {
                            it.suspected_owner = "CORE".into();
                            it.severity = "medium".into();
                        }
                    }
                    push(it);
                }
                let decoys: Vec<ProcRef> = ["D1", "D2"].iter().filter_map(|k| one(k)).collect();
                let filter = g
                    .scope_log
                    .lock()
                    .map(|l| l.scans.clone())
                    .unwrap_or_default();
                let decoy_seen = decoys.iter().any(|d| {
                    filter.iter().any(|f| f.stats.kept_refs.contains(d))
                        || rec.any_event_on(*d) > 0
                        || rec.signals_to(d.pid) > 0
                });
                let control = filter
                    .iter()
                    .filter_map(|f| f.shadow.as_ref())
                    .filter(|sh| {
                        decoys.iter().any(|d| {
                            sh.watched_in_terminate.contains(d) || sh.watched_in_pending.contains(d)
                        })
                    })
                    .count();
                iso.insert("A_decoys".into(), json!({"decoys": decoys, "seen_by_guard": decoy_seen, "alive_at_end": decoys.iter().all(|d| rec.alive_at_end(*d)), "control_shadow_scans_candidate_or_pending": control}));
                iso_ok &= !decoy_seen;
            }
            "B" => {
                let mut it =
                    verdict::circuit(&rec, refs.get("S12").map(Vec::as_slice).unwrap_or(&[]));
                it.evidence = ev("S12");
                items.push(it);
            }
            "C" => {
                if let Some(t) = one("S3") {
                    let mut it = verdict::demoted_and_restored(&rec, t, c_base_prio);
                    it.evidence = ev("S3");
                    items.push(it);
                }
            }
            _ => {}
        }
    }
    write_json(&out.join("isolation.json"), &iso)?;
    items.sort_by_key(|i| i.id.trim_start_matches('S').parse::<u32>().unwrap_or(99));
    Ok((items, iso_ok))
}

/// 알림 줄 귀속용 표지: 폴더가 있는 시나리오는 폴더 이름과 package.json 이름(`lab-<폴더>`).
fn markers(refs: &BTreeMap<&'static str, Vec<ProcRef>>) -> BTreeMap<ProcRef, Vec<String>> {
    let mut m = BTreeMap::new();
    for (name, rs) in refs {
        let dir = name.to_lowercase();
        let with_dir = matches!(
            *name,
            "S1" | "S2" | "S10" | "S11" | "S3" | "S6" | "S7" | "S8" | "S9"
        );
        for (i, r) in rs.iter().enumerate() {
            let mut v = Vec::new();
            if with_dir {
                v.push(dir.clone());
                v.push(format!("lab-{dir}"));
            } else if *name == "S12" {
                v.push(format!("s12-{i}"));
                v.push(format!("lab-s12-{i}"));
            }
            m.insert(*r, v);
        }
    }
    m
}

fn start_guard(lab: &Lab, out: &Path, sub: &str) -> io::Result<GuardRun> {
    let scope = LabScope {
        tag: lab.tag(sub),
        refs: lab.registry.scope_refs(sub),
    };
    GuardRun::start(
        &out.join(sub),
        sub,
        scope,
        lab.registry.lock_pids(sub),
        lab.registry.decoys(),
        GuardPolicy::for_level(AutoLevel::Safe),
    )
}
