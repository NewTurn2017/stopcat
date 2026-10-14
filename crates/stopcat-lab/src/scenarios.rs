//! 시나리오 S1~S12(실제 시계, W4). 안전 자동 × 정상·강제 불안정(watch). 칸:
//! A(정상: S1·S2·S4~S11 + 미끼 D1·D2), AF(강제: S1·S4~S10 + 미끼), AF2(강제: S2), AF3(강제: S11),
//! B·BF(S12), C·CF(S3). 강제 쪽 파괴 대상은 칸을 나눠 정착 시간이 W3 나이 창 검사에 끼지 않게 한다(PM Q3).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;
use stopcat_model::{AutoLevel, GuardEventKind, ProcRef, Section};

use crate::cell::{Cell, dir_markers};
use crate::invariants::StopcatCopy;
use crate::lab::{Lab, Meta};
use crate::run::{KernelRec, sample_kernel};
use crate::spec::{self, ExecSpec, Role};
use crate::util::{new_run_id, sha256_file, write_json, write_jsonl};
use crate::verdict::{self, Item, Records, Verdict};
use crate::verdict_w4::{self as w4};
use crate::stopcatjson::{self, JsonProbe};

pub const A_END_MS: u64 = 13 * 60_000;
/// S12 자격 ≈ T+12:00(young 10분 + idle_confirm 120초) 뒤 2분을 더 본다(PM 판정표 보정 2: 13분 30초 이상).
pub const B_END_MS: u64 = 14 * 60_000;
pub const C_END_MS: u64 = 3 * 60_000;
pub const S11_DELAY_MS: u64 = 60_000;
pub const PROBES_MS: [u64; 4] = [120_000, 540_000, 660_000, 750_000];
const KERNEL_EVERY_MS: u64 = 2_000;
const MAX_SECS: u64 = 1_500;

const MCP: &[&str] = &["node_modules/chrome-devtools-mcp/build/src/index.js"];
const MCP_FS: &[&str] = &["node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"];
const MCP_MEMORY: &[&str] = &["node_modules/@modelcontextprotocol/server-memory/dist/index.js"];
const NEXT_DEV: &[&str] = &["node_modules/.bin/next", "dev"];

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
    let mut s = lab.exec_spec("node", Role::Idle, &r, Some(tag), extra, MAX_SECS);
    s.cwd = dir.to_string_lossy().into_owned();
    s
}

#[derive(Default)]
struct Set {
    refs: BTreeMap<&'static str, Vec<ProcRef>>,
}

impl Set {
    fn one(&self, k: &str) -> Option<ProcRef> {
        self.refs.get(k).and_then(|v| v.first()).copied()
    }
}

#[derive(Default)]
struct Orphan {
    owner: Option<i32>,
    listen: bool,
    /// Some(None) = 태그 없는 미끼, Some(Some(t)) = 다른 태그 미끼.
    decoy: Option<Option<String>>,
}

struct Ctx<'a> {
    lab: &'a mut Lab,
    marks: BTreeMap<ProcRef, Vec<String>>,
}

impl Ctx<'_> {
    fn project(&mut self, d: &str) -> io::Result<std::path::PathBuf> {
        let p = self.lab.dir(d)?;
        std::fs::write(
            p.join("package.json"),
            format!("{{\"name\":\"lab-{d}\"}}\n"),
        )?;
        Ok(p)
    }

    fn orphan(
        &mut self,
        sub: &str,
        sc: &str,
        dir: &str,
        script: &[&str],
        o: Orphan,
    ) -> io::Result<ProcRef> {
        let Orphan {
            owner,
            listen,
            decoy,
        } = o;
        let tag = self.lab.tag(sub);
        let d = self.project(dir)?;
        let owner_pid = match owner {
            Some(p) => p,
            None => self.lab.dead_pid()?,
        };
        let mut extra = vec![("CLAUDE_PID", owner_pid.to_string())];
        if listen {
            extra.push((spec::LISTEN, "1".into()));
        }
        let mut s = node_spec(self.lab, &d, script, &tag, &extra);
        let meta = match &decoy {
            Some(t) => {
                match t {
                    Some(t) => {
                        s.env.insert(spec::TAG.into(), t.clone());
                    }
                    None => {
                        s.env.remove(spec::TAG);
                    }
                }
                Meta::decoy(sub, sc)
            }
            None => Meta::new(sub, sc),
        };
        let r = self.lab.spawn_orphans(vec![(meta, s)])?[0];
        dir_markers(&mut self.marks, r, dir);
        Ok(r)
    }

    /// W3 하위 실행 A와 같은 모양(S2·S11 제외 여부는 인자). `sfx`는 폴더 이름 뒤에 붙여 칸끼리 구분한다.
    fn a_set(&mut self, sub: &str, sfx: &str, with_s2: bool) -> io::Result<Set> {
        let mut set = Set::default();
        let tag = self.lab.tag(sub);
        let owner =
            self.lab
                .exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], MAX_SECS);
        let s6_dir = self.lab.dir(&format!("s6{sfx}"))?;
        let s7_dir = self.lab.dir(&format!("s7{sfx}"))?;
        let s6 = node_spec(self.lab, &s6_dir, NEXT_DEV, &tag, &[]);
        let s7 = node_spec(self.lab, &s7_dir, &["node_modules/.bin/vite"], &tag, &[]);
        let (owner_ref, kids) = self.lab.spawn_direct(
            Meta::new(sub, "OWNER"),
            owner,
            vec![
                (Meta::new(sub, "S6"), s6),
                (Meta::new(sub, "S7"), ExecSpec { count: 2, ..s7 }),
            ],
        )?;
        set.refs.insert("OWNER", vec![owner_ref]);
        set.refs.insert("S6", vec![kids[0]]);
        set.refs.insert("S7", vec![kids[1], kids[2]]);
        dir_markers(&mut self.marks, kids[0], &format!("s6{sfx}"));
        let s1 = self.orphan(sub, "S1", &format!("s1{sfx}"), MCP, Orphan::default())?;
        set.refs.insert("S1", vec![s1]);
        if with_s2 {
            let s2 = self.orphan(
                sub,
                "S2",
                &format!("s2{sfx}"),
                NEXT_DEV,
                Orphan {
                    listen: true,
                    ..Default::default()
                },
            )?;
            set.refs.insert("S2", vec![s2]);
        }
        let s10 = self.orphan(
            sub,
            "S10",
            &format!("s10{sfx}"),
            MCP_FS,
            Orphan {
                owner: Some(owner_ref.pid),
                ..Default::default()
            },
        )?;
        set.refs.insert("S10", vec![s10]);
        let dead8 = self.lab.dead_pid()?;
        let mut s8 = self.lab.exec_spec(
            "qemu-system-aarch64",
            Role::Idle,
            &["qemu-system-aarch64", "-avd", "lab_pixel"],
            Some(&tag),
            &[("CLAUDE_PID", dead8.to_string())],
            MAX_SECS,
        );
        s8.cwd = self
            .lab
            .dir(&format!("s8{sfx}"))?
            .to_string_lossy()
            .into_owned();
        let mut s9 =
            self.lab
                .exec_spec("claude", Role::Idle, &["claude"], Some(&tag), &[], MAX_SECS);
        s9.cwd = self
            .lab
            .dir(&format!("s9{sfx}"))?
            .to_string_lossy()
            .into_owned();
        let made = self
            .lab
            .spawn_orphans(vec![(Meta::new(sub, "S8"), s8), (Meta::new(sub, "S9"), s9)])?;
        set.refs.insert("S8", vec![made[0]]);
        set.refs.insert("S9", vec![made[1]]);
        dir_markers(&mut self.marks, made[0], &format!("s8{sfx}"));
        dir_markers(&mut self.marks, made[1], &format!("s9{sfx}"));
        let d1 = self.orphan(
            sub,
            "D1",
            &format!("d1{sfx}"),
            MCP,
            Orphan {
                decoy: Some(None),
                ..Default::default()
            },
        )?;
        let d2_tag = format!("lab-{}-decoy{sfx}", self.lab.run_id);
        let d2 = self.orphan(
            sub,
            "D2",
            &format!("d2{sfx}"),
            MCP,
            Orphan {
                decoy: Some(Some(d2_tag)),
                ..Default::default()
            },
        )?;
        set.refs.insert("D1", vec![d1]);
        set.refs.insert("D2", vec![d2]);
        let mem = self.lab.exec_spec(
            "lab-mem",
            Role::Mem,
            &["lab-mem"],
            Some(&tag),
            &[
                (spec::MEM_KB_PER_SEC, "853".into()),
                (spec::MEM_MAX_MB, "400".into()),
            ],
            MAX_SECS,
        );
        let (s4, _) = self.lab.spawn_direct(Meta::new(sub, "S4"), mem, vec![])?;
        set.refs.insert("S4", vec![s4]);
        let z = self.lab.exec_spec(
            "lab-zombie",
            Role::Zombie,
            &["lab-zombie"],
            Some(&tag),
            &[],
            MAX_SECS,
        );
        let (s5, zk) = self.lab.spawn_direct(Meta::new(sub, "S5"), z, vec![])?;
        set.refs.insert("S5", vec![s5]);
        set.refs.insert("S5Z", zk);
        Ok(set)
    }

    fn s12_set(&mut self, sub: &str, sfx: &str) -> io::Result<Vec<ProcRef>> {
        let tag = self.lab.tag(sub);
        let mut items = Vec::new();
        let mut dirs = Vec::new();
        for i in 0..7 {
            let dir = format!("s12{sfx}-{i}");
            let d = self.project(&dir)?;
            let dead = self.lab.dead_pid()?;
            let script = if i < 4 { MCP } else { NEXT_DEV };
            items.push((
                Meta::new(sub, "S12"),
                node_spec(
                    self.lab,
                    &d,
                    script,
                    &tag,
                    &[("CLAUDE_PID", dead.to_string())],
                ),
            ));
            dirs.push(dir);
        }
        let made = self.lab.spawn_orphans(items)?;
        for (r, d) in made.iter().zip(dirs) {
            dir_markers(&mut self.marks, *r, &d);
        }
        Ok(made)
    }

    fn spinner(&mut self, sub: &str, dir: &str) -> io::Result<ProcRef> {
        let tag = self.lab.tag(sub);
        let mut spin = self.lab.exec_spec(
            "lab-spin",
            Role::Spin,
            &["lab-spin"],
            Some(&tag),
            &[
                (spec::SPIN_THREADS, "2".into()),
                (spec::SPIN_SECS, (C_END_MS / 1000 + 30).to_string()),
                (spec::SPIN_STOP_ON_DEMOTE, "1".into()),
            ],
            600,
        );
        spin.cwd = self.lab.dir(dir)?.to_string_lossy().into_owned();
        let (r, _) = self.lab.spawn_direct(Meta::new(sub, "S3"), spin, vec![])?;
        dir_markers(&mut self.marks, r, dir);
        Ok(r)
    }
}

pub fn run(out: &Path, only: &BTreeSet<String>, stopcat: Option<StopcatCopy<'_>>) -> io::Result<bool> {
    if let Some(v) = &stopcat
        && sha256_file(v.path)? != v.sha256
    {
        return Err(io::Error::other("측정 대상 sha256 불일치"));
    }
    let run_id = new_run_id()?;
    std::fs::create_dir_all(out)?;
    let mut lab = Lab::create(&run_id)?;
    let res = drive(&mut lab, out, only, stopcat.as_ref());
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let (mut items, iso_ok) = res?;
    for it in &mut items {
        it.repro = "STOPCAT_STATE_DIR=<임시> STOPCAT_NOTIFY=off nice -n 19 <stopcat-lab> scenarios --out <폴더> --stopcat <복사본> --stopcat-sha256 <값>".into();
    }
    let all_pass = items.iter().all(|i| i.verdict == Verdict::Pass);
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "stopcat-lab/scenarios/v2",
            "run_id": run_id,
            "subs": only,
            "items": items,
            "isolation_ok": iso_ok,
            "strings": crate::strings::table(),
            "leftover_processes": cleanup.leftover_processes,
            "all_pass": all_pass,
        }),
    )?;
    Ok(iso_ok && cleanup.leftover_processes == 0)
}

struct Planned {
    cell: Cell,
    start_ms: u64,
    end_ms: u64,
}

fn drive(
    lab: &mut Lab,
    out: &Path,
    only: &BTreeSet<String>,
    stopcat: Option<&StopcatCopy<'_>>,
) -> io::Result<(Vec<Item>, bool)> {
    let t0 = Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    let want = |s: &str| only.is_empty() || only.contains(s);
    let mut cx = Ctx {
        lab,
        marks: BTreeMap::new(),
    };
    let mut sets: BTreeMap<&'static str, Set> = BTreeMap::new();
    let mut s12: BTreeMap<&'static str, Vec<ProcRef>> = BTreeMap::new();
    let mut s3: BTreeMap<&'static str, ProcRef> = BTreeMap::new();
    let mut lab_calls = Vec::new();
    let forced = Some(w4::FORCED);
    let mut plan: Vec<Planned> = Vec::new();

    if want("A") {
        let set = cx.a_set("A", "", true)?;
        lab_calls.extend(cx.lab.signal(set.refs["S6"][0], libc::SIGSTOP).1);
        sets.insert("A", set);
        plan.push(Planned {
            cell: Cell::new("A", AutoLevel::Safe, None, &["A"]),
            start_ms: S11_DELAY_MS,
            end_ms: A_END_MS,
        });
    }
    if want("AF") {
        let set = cx.a_set("AF", "f", false)?;
        lab_calls.extend(cx.lab.signal(set.refs["S6"][0], libc::SIGSTOP).1);
        sets.insert("AF", set);
        plan.push(Planned {
            cell: Cell::new("AF", AutoLevel::Safe, forced, &["AF"]),
            start_ms: S11_DELAY_MS,
            end_ms: A_END_MS,
        });
        let s2 = cx.orphan(
            "AF2",
            "S2",
            "s2f",
            NEXT_DEV,
            Orphan {
                listen: true,
                ..Default::default()
            },
        )?;
        sets.insert(
            "AF2",
            Set {
                refs: [("S2", vec![s2])].into(),
            },
        );
        plan.push(Planned {
            cell: Cell::new("AF2", AutoLevel::Safe, forced, &["AF2"]),
            start_ms: S11_DELAY_MS,
            end_ms: A_END_MS,
        });
    }
    if want("B") {
        s12.insert("B", cx.s12_set("B", "")?);
        plan.push(Planned {
            cell: Cell::new("B", AutoLevel::Safe, None, &["B"]),
            start_ms: 0,
            end_ms: B_END_MS,
        });
    }
    if want("BF") {
        s12.insert("BF", cx.s12_set("BF", "f")?);
        plan.push(Planned {
            cell: Cell::new("BF", AutoLevel::Safe, forced, &["BF"]),
            start_ms: 0,
            end_ms: B_END_MS,
        });
    }
    if want("C") {
        s3.insert("C", cx.spinner("C", "s3")?);
        plan.push(Planned {
            cell: Cell::new("C", AutoLevel::Safe, None, &["C"]),
            start_ms: 0,
            end_ms: C_END_MS,
        });
    }
    if want("CF") {
        s3.insert("CF", cx.spinner("CF", "s3f")?);
        plan.push(Planned {
            cell: Cell::new("CF", AutoLevel::Safe, forced, &["CF"]),
            start_ms: 0,
            end_ms: C_END_MS,
        });
    }
    if want("AF") {
        plan.push(Planned {
            cell: Cell::new("AF3", AutoLevel::Safe, forced, &["AF3"]),
            start_ms: S11_DELAY_MS,
            end_ms: A_END_MS,
        });
    }
    std::thread::sleep(Duration::from_millis(300));
    let base: BTreeMap<&'static str, (Option<i32>, Option<i32>)> = s3
        .iter()
        .map(|(k, r)| {
            (
                *k,
                (
                    crate::kernel::task_priority(r.pid),
                    crate::kernel::nice_of(r.pid),
                ),
            )
        })
        .collect();

    let mut s11_spawned = false;
    let mut kernel: Vec<KernelRec> = Vec::new();
    let mut probes: Vec<JsonProbe> = Vec::new();
    let mut probe_i = 0;
    let mut last_k = Instant::now() - Duration::from_secs(10);
    let json_state = out.join("stopcatjson-state");
    loop {
        let now = Instant::now();
        if !s11_spawned && now >= at(S11_DELAY_MS) {
            if want("A") {
                let r = cx.orphan("A", "S11", "s11", MCP_MEMORY, Orphan::default())?;
                sets.entry("A").or_default().refs.insert("S11", vec![r]);
            }
            if want("AF") {
                let r = cx.orphan("AF3", "S11", "s11f", MCP_MEMORY, Orphan::default())?;
                sets.insert(
                    "AF3",
                    Set {
                        refs: [("S11", vec![r])].into(),
                    },
                );
            }
            s11_spawned = true;
        }
        for p in plan.iter_mut() {
            if p.cell.guard.is_none() && now >= at(p.start_ms) && (p.start_ms == 0 || s11_spawned) {
                p.cell.start(cx.lab, out)?;
            }
            p.cell.pump();
            if p.cell.guard.is_some() && !p.cell.done && now >= at(p.end_ms) {
                p.cell.finish()?;
            }
        }
        let watch = cx.lab.registry.all_refs();
        if last_k.elapsed() >= Duration::from_millis(KERNEL_EVERY_MS) {
            kernel.extend(sample_kernel(&watch));
            last_k = Instant::now();
        }
        if let Some(v) = stopcat
            && probe_i < PROBES_MS.len()
            && now >= at(PROBES_MS[probe_i])
        {
            probes.push(stopcatjson::probe(
                v.path,
                &json_state,
                &format!("T+{}s", PROBES_MS[probe_i] / 1000),
                &watch,
            ));
            probe_i += 1;
        }
        if plan.iter().all(|p| p.cell.done) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let watch = cx.lab.registry.all_refs();
    for _ in 0..10 {
        kernel.extend(sample_kernel(&watch));
        std::thread::sleep(Duration::from_millis(500));
    }
    write_jsonl(&out.join("kernel.jsonl"), &kernel)?;
    write_jsonl(&out.join("stopcatjson.jsonl"), &probes)?;
    write_json(&out.join("registry.json"), &cx.lab.registry)?;
    write_json(&out.join("lab_signals.json"), &lab_calls)?;
    let marks = cx.marks.clone();

    let mut items = Vec::new();
    let mut iso_ok = true;
    let mut iso = Vec::new();
    let recs: BTreeMap<String, Records> = plan
        .iter()
        .filter_map(|p| {
            p.cell
                .records(&kernel, &marks)
                .map(|r| (p.cell.name.clone(), r))
        })
        .collect();
    for p in &plan {
        let (ok, v) = p.cell.isolation();
        iso_ok &= ok;
        iso.push(v);
    }
    let s1f_at = recs.get("AF").and_then(|r| {
        sets.get("AF").and_then(|s| s.one("S1")).and_then(|s1| {
            r.events(GuardEventKind::AutoTerminated, s1)
                .first()
                .map(|e| e.at_unix_ms)
        })
    });
    for p in &plan {
        let name = p.cell.name.as_str();
        let Some(rec) = recs.get(name) else { continue };
        let ev = |id: &str| {
            vec![
                out.join(name)
                    .join("scans.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                out.join("kernel.jsonl").to_string_lossy().into_owned(),
                format!("cell {name} / {id}"),
            ]
        };
        let mode = if p.cell.is_forced() {
            "forced"
        } else {
            "normal"
        };
        let mut cell_items: Vec<Item> = Vec::new();
        match name {
            "A" | "AF" => {
                let set = &sets[name];
                let forced = name == "AF";
                let end = rec.scans.last().map_or(0, |s| s.taken_at_ms + 1);
                if let Some(t) = set.one("S1") {
                    let mut it = if forced {
                        w4::forced_auto_terminated("S1", rec, t)
                    } else {
                        w4::report_only(
                            "S1",
                            rec,
                            t,
                            t.start_time_unix_ms + verdict::MIN_AGE_MS + 30_000,
                            end,
                        )
                    };
                    if !forced {
                        json_check(&mut it, &probes, 660_000, t, Want::Section("unneeded"));
                    }
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S2") {
                    let mut it = w4::report_only(
                        "S2",
                        rec,
                        t,
                        t.start_time_unix_ms + verdict::MIN_AGE_MS + 30_000,
                        end,
                    );
                    let port = listener_port(rec, t);
                    it.checks.insert("listener_seen".into(), port.is_some());
                    it.checks
                        .insert("connect_ok_at_end".into(), port.is_some_and(connects));
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S4") {
                    cell_items.push(verdict::memory_grower(rec, t));
                }
                if let (Some(pp), Some(z)) = (set.one("S5"), set.one("S5Z")) {
                    let mut it = verdict::zombie(rec, pp, z);
                    let (ok, v) = w4::sections_ok(rec, z, 0, end, &[Section::Manual]);
                    it.checks.insert("section_manual".into(), ok);
                    it.observed["sections"] = v;
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S6") {
                    cell_items.push(verdict::stopped(rec, t));
                }
                if let (Some(a), Some(b)) = (
                    set.one("S7"),
                    set.refs.get("S7").and_then(|v| v.get(1)).copied(),
                ) {
                    cell_items.push(verdict::duplicate(rec, a, b));
                }
                if let Some(t) = set.one("S8") {
                    let mut it = w4::emulator(rec, t, forced);
                    if !forced {
                        json_check(&mut it, &probes, 540_000, t, Want::Section("check"));
                    }
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S9") {
                    let mut it = verdict::never_touched(
                        "S9",
                        "어떤 조치·알림도 없음, 구역 working",
                        rec,
                        t,
                        None,
                    );
                    let (ok, v) = w4::sections_ok(rec, t, 0, end, &[Section::Working]);
                    it.checks.insert("section_working".into(), ok);
                    it.observed["sections"] = v;
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S10") {
                    let mut it = verdict::never_touched(
                        "S10",
                        "주인 생존(owner_alive=true), 자동 종료 없음, 구역 working 또는 check",
                        rec,
                        t,
                        Some(true),
                    );
                    let (ok, v) =
                        w4::sections_ok(rec, t, 0, end, &[Section::Working, Section::Check]);
                    it.checks.insert("section_working_or_check".into(), ok);
                    it.observed["sections"] = v;
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
                if let Some(t) = set.one("S11") {
                    let mut it = w4::young_normal(rec, t, end);
                    json_check(&mut it, &probes, 540_000, t, Want::Reason("young"));
                    json_check(&mut it, &probes, 750_000, t, Want::Section("unneeded"));
                    cell_items.push(it);
                }
                let (d_ok, d) = decoys(p, rec, set, forced);
                iso_ok &= d_ok;
                iso.push(d);
            }
            "AF2" => {
                if let Some(t) = sets[name].one("S2") {
                    let mut it = w4::forced_auto_terminated("S2", rec, t);
                    let port = listener_port(rec, t);
                    it.checks.insert("listener_seen".into(), port.is_some());
                    it.checks.insert(
                        "connection_refused_after".into(),
                        port.is_some_and(|p| !connects(p)),
                    );
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
            }
            "AF3" => {
                if let Some(t) = sets.get(name).and_then(|s| s.one("S11")) {
                    let mut it = w4::forced_auto_terminated("S11", rec, t);
                    let at9 = s1f_at.unwrap_or(t.start_time_unix_ms + 540_000);
                    let (vis, obs) = verdict::young_pending_visible(rec, t, at9);
                    it.checks.insert("pending_visible_while_9min".into(), vis);
                    it.observed["young"] = obs;
                    fail_if_unchecked(&mut it);
                    cell_items.push(it);
                }
            }
            "B" => cell_items.push(w4::no_circuit(rec, &s12["B"])),
            "BF" => cell_items.push(w4::forced_circuit(rec, &s12["BF"])),
            "C" | "CF" => {
                let t = s3[name];
                let mut it = w4::no_priority_change(rec, t, name == "CF");
                if let Some((p0, n0)) = base.get(name) {
                    it.observed["priority_base"] = json!(p0);
                    it.observed["nice_base"] = json!(n0);
                }
                if name == "C" {
                    json_check(&mut it, &probes, 120_000, t, Want::Section("check"));
                }
                cell_items.push(it);
            }
            _ => {}
        }
        for mut it in cell_items {
            it.evidence = ev(&it.id);
            it.id = format!("{}/{mode}", it.id);
            it.observed["cell"] = json!(name);
            items.push(it);
        }
    }
    write_json(&out.join("isolation.json"), &iso)?;
    items.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((items, iso_ok))
}

fn listener_port(rec: &Records, t: ProcRef) -> Option<u16> {
    rec.scans
        .iter()
        .flat_map(|s| s.listeners.iter())
        .find(|l| l.r == t)
        .map(|l| l.port)
}

fn connects(port: u16) -> bool {
    TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500)).is_ok()
}

/// 덧붙인 검사가 하나라도 거짓이면 PASS를 FAIL로(이미 FAIL·INCONCLUSIVE면 그대로).
fn fail_if_unchecked(it: &mut Item) {
    if it.verdict == Verdict::Pass && !it.checks.values().all(|v| *v) {
        it.verdict = Verdict::Fail;
        if it.suspected_owner == "none" {
            it.suspected_owner = "CORE".into();
            it.severity = "medium".into();
        }
    }
}

enum Want {
    Section(&'static str),
    Reason(&'static str),
}

/// stopcat --json 검사점 하나를 항목에 더한다. 검사점이 없거나 실패했으면 관찰값만 남긴다.
fn json_check(it: &mut Item, probes: &[JsonProbe], at_ms_rel: u64, t: ProcRef, want: Want) {
    let label = format!("T+{}s", at_ms_rel / 1000);
    let Some(p) = probes.iter().find(|p| p.label == label) else {
        it.observed[format!("stopcatjson_{label}")] = json!("검사점 없음(--stopcat 없이 실행)");
        return;
    };
    if p.error.is_some() || !p.schema_ok {
        it.observed[format!("stopcatjson_{label}")] =
            json!({"error": p.error, "schema_version": p.schema_version});
        return;
    }
    let (key, ok) = match want {
        Want::Section(s) => (
            format!("stopcatjson_{label}_section_{s}"),
            p.section_of(t) == Some(s),
        ),
        Want::Reason(r) => (
            format!("stopcatjson_{label}_reason_{r}"),
            p.reasons_of(t).is_some_and(|v| v.iter().any(|x| x == r)),
        ),
    };
    it.checks.insert(key, ok);
    it.observed[format!("stopcatjson_{label}")] =
        json!({"section": p.section_of(t), "reasons": p.reasons_of(t)});
    fail_if_unchecked(it);
}

fn decoys(p: &Planned, rec: &Records, set: &Set, forced: bool) -> (bool, serde_json::Value) {
    let ds: Vec<ProcRef> = ["D1", "D2"].iter().filter_map(|k| set.one(k)).collect();
    let Some(g) = &p.cell.guard else {
        return (false, json!({"cell": p.cell.name, "started": false}));
    };
    let filter = g
        .scope_log
        .lock()
        .map(|l| l.scans.clone())
        .unwrap_or_default();
    let seen = ds.iter().any(|d| {
        filter.iter().any(|f| f.stats.kept_refs.contains(d))
            || rec.any_event_on(*d) > 0
            || rec.signals_to(d.pid) > 0
    });
    let control = filter
        .iter()
        .filter_map(|f| f.shadow.as_ref())
        .filter(|sh| {
            ds.iter()
                .any(|d| sh.watched_in_terminate.contains(d) || sh.watched_in_pending.contains(d))
        })
        .count();
    let control_ko = if forced && control == 0 {
        "강제 대조군이 미끼를 후보로 한 번도 못 봄: 격리 증명만 INCONCLUSIVE(격리 실패 아님)"
    } else if forced {
        "강제 대조군이 미끼를 후보·대기로 봄 → 필터가 실제로 막음"
    } else {
        "정상 건강에서는 대조군 후보 0이 정상. 필터 증명은 kept_refs"
    };
    (
        !seen,
        json!({"cell": p.cell.name, "decoys": ds, "seen_by_guard": seen, "alive_at_end": ds.iter().all(|d| rec.alive_at_end(*d)), "control_shadow_scans_candidate_or_pending": control, "control_ko": control_ko}),
    )
}
