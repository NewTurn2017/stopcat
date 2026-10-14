//! 경계: 이상한 argv(E1~E4), 스캔 중 종료(E5), 작은 창·창 크기 바꾸기(E6·E7, 측정 대상 vh를 pty로), 빈 상태(E8).

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use vh_model::{AutoLevel, GuardEventKind, GuardPolicy};

use crate::lab::{Lab, Meta};
use crate::pty::{PtyVh, forced_env, notify_only_env, write_config};
use crate::run::GuardRun;
use crate::scope::LabScope;
use crate::spec::{self, ExecSpec, Role, encode_hex};
use crate::util::{display_width, new_run_id, sha256_file, sha256_hex, write_json};
use crate::verdict::{Item, Verdict};

fn it(
    id: &str,
    expected: &str,
    checks: &[(&str, bool)],
    observed: serde_json::Value,
    owner: &str,
) -> Item {
    let pass = checks.iter().all(|c| c.1);
    Item {
        id: id.into(),
        expected: expected.into(),
        observed,
        verdict: if pass { Verdict::Pass } else { Verdict::Fail },
        evidence: Vec::new(),
        suspected_owner: if pass { "none".into() } else { owner.into() },
        severity: if pass { "low".into() } else { "medium".into() },
        repro: "VH_STATE_DIR=<임시> VH_NOTIFY=off nice -n 19 <vh-lab> edge --vh <복사본> --vh-sha256 <값> --out <폴더>".into(),
        checks: checks.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
    }
}

pub struct WhyCheck {
    pub json_exit: Option<i32>,
    pub json_ok: bool,
    pub text_exit: Option<i32>,
    pub max_width: usize,
    pub lines: usize,
}

fn vh_why(vh: &Path, state: &Path, pid: i32) -> WhyCheck {
    let run = |json: bool| {
        let mut c = Command::new(vh);
        c.arg("why").arg(pid.to_string());
        if json {
            c.arg("--json");
        }
        c.env_clear()
            .envs(notify_only_env(state))
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
    };
    let j = run(true).ok();
    let t = run(false).ok();
    let text = t
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    WhyCheck {
        json_exit: j.as_ref().and_then(|o| o.status.code()),
        json_ok: j
            .as_ref()
            .is_some_and(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).is_ok()),
        text_exit: t.as_ref().and_then(|o| o.status.code()),
        max_width: text.lines().map(display_width).max().unwrap_or(0),
        lines: text.lines().count(),
    }
}

pub fn run(vh: &Path, sha: &str, out: &Path) -> io::Result<bool> {
    if sha256_file(vh)? != sha {
        return Err(io::Error::other("측정 대상 sha256 불일치"));
    }
    std::fs::create_dir_all(out)?;
    let mut lab = Lab::create(&new_run_id()?)?;
    let res = drive(&mut lab, vh, out);
    let cleanup = lab.cleanup();
    write_json(&out.join("cleanup.json"), &cleanup)?;
    let mut items = res?;
    let ui = ui_checks(vh, out)?;
    items.extend(ui);
    let all = items.iter().all(|i| i.verdict == Verdict::Pass);
    write_json(
        &out.join("result.json"),
        &json!({"schema": "vh-lab/edge/v1", "items": items, "leftover_processes": cleanup.leftover_processes, "all_pass": all}),
    )?;
    Ok(cleanup.leftover_processes == 0)
}

fn drive(lab: &mut Lab, vh: &Path, out: &Path) -> io::Result<Vec<Item>> {
    let tag = lab.tag("E");
    let big = "x".repeat(100 * 1024);
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("E1", vec![b"lab-idle".to_vec(), b"a\nb".to_vec()]),
        (
            "E2",
            vec![
                b"lab-idle".to_vec(),
                "\u{1F431} e\u{301} 한글 \u{1F468}\u{200D}\u{1F469}"
                    .as_bytes()
                    .to_vec(),
            ],
        ),
        ("E3", vec![b"lab-idle".to_vec(), big.as_bytes().to_vec()]),
        ("E4", vec![b"lab-idle".to_vec(), vec![0xff, 0xfe, b'z']]),
    ];
    let mut refs = Vec::new();
    for (id, argv) in &cases {
        let mut s: ExecSpec =
            lab.exec_spec("lab-idle", Role::Idle, &["lab-idle"], Some(&tag), &[], 600);
        s.argv_hex = Some(argv.iter().map(|a| encode_hex(a)).collect());
        s.cwd = lab.dir(&id.to_lowercase())?.to_string_lossy().into_owned();
        let (r, _) = lab.spawn_direct(Meta::new("E", id), s, vec![])?;
        refs.push((*id, r, argv.clone()));
    }
    let flick = lab.exec_spec(
        "lab-flicker",
        Role::Flicker,
        &["lab-flicker"],
        Some(&tag),
        &[
            (spec::FLICKER_MAX, "50".into()),
            (spec::FLICKER_SECS, "30".into()),
        ],
        90,
    );
    lab.spawn_direct(Meta::new("E", "E5"), flick, vec![])?;
    let scope = LabScope {
        tag: tag.clone(),
        refs: lab.registry.scope_refs("E"),
    };
    let mut g = GuardRun::start(
        &out.join("E"),
        "E",
        scope,
        lab.registry.lock_pids("E"),
        BTreeSet::new(),
        GuardPolicy::for_level(AutoLevel::Safe),
    )?;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(40) {
        g.pump();
        std::thread::sleep(Duration::from_millis(250));
    }
    let state = out.join("why-state");
    std::fs::create_dir_all(&state)?;
    let mut items = Vec::new();
    for (id, r, argv) in &refs {
        let joined: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let expect = joined.join("\u{0}");
        let seen = g
            .scans
            .iter()
            .rev()
            .find_map(|s| s.procs.iter().find(|p| p.r == *r).cloned());
        let argv_match = seen
            .as_ref()
            .is_some_and(|p| p.argv_sha256 == sha256_hex(expect.as_bytes()));
        let w = vh_why(vh, &state, r.pid);
        let mut checks = vec![
            ("collected", seen.is_some()),
            ("argv_bytes_preserved", argv_match),
            ("why_json_exit_0", w.json_exit == Some(0)),
            ("why_json_parses", w.json_ok),
            ("why_text_exit_0", w.text_exit == Some(0)),
            ("why_lines_le_80_cols", w.max_width <= 80),
        ];
        if *id == "E4" {
            checks[1] = (
                "argv_lossy_replacement",
                seen.as_ref().is_some_and(|p| {
                    p.argv
                        .as_ref()
                        .is_some_and(|a| a.iter().any(|s| s.contains('\u{FFFD}')))
                }) || argv_match,
            );
        }
        let owner = if !checks[0].1 || !checks[1].1 {
            "CORE"
        } else {
            "TUI"
        };
        items.push(it(
            id,
            "수집·표시 패닉 없음, argv 그대로(잘못된 UTF-8은 대체 문자), vh why --json 파싱, 텍스트 줄 80칸 이하",
            &checks,
            json!({"argv_len": seen.as_ref().map(|p| p.argv_len), "why_max_width": w.max_width, "why_lines": w.lines, "scan_ms_max": g.scans.iter().map(|s| s.status.last_scan_ms).fold(0.0, f64::max)}),
            owner,
        ));
    }
    g.shutdown();
    g.write()?;
    let scan_errors = g
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.kind == GuardEventKind::ScanError)
        .count();
    let coll_max = g
        .scans
        .iter()
        .map(|s| s.collection_errors)
        .max()
        .unwrap_or(0);
    let unreg = g
        .scope_log
        .lock()
        .map(|l| {
            l.scans
                .iter()
                .map(|s| s.stats.unregistered_tagged)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0);
    items.push(it(
        "E5",
        "스캔 중 끝나는 프로세스(깜빡이 50개, 30초): ScanError 0, 지킴이 패닉 0",
        &[("scan_errors_zero", scan_errors == 0), ("guard_scanned", g.scans.len() >= 3)],
        json!({"scans": g.scans.len(), "collection_errors_max": coll_max, "transient_tagged_seen_max": unreg, "signal_calls": g.signal_calls().len()}),
        "GUARD",
    ));

    let mut z = GuardRun::start(
        &out.join("Z"),
        "Z",
        LabScope {
            tag: lab.tag("Z"),
            refs: BTreeSet::new(),
        },
        BTreeSet::new(),
        BTreeSet::new(),
        GuardPolicy::for_level(AutoLevel::Safe),
    )?;
    let t = Instant::now();
    while z.scans.len() < 3 && t.elapsed() < Duration::from_secs(20) {
        z.pump();
        std::thread::sleep(Duration::from_millis(250));
    }
    z.shutdown();
    z.write()?;
    let targeted = z
        .scans
        .iter()
        .flat_map(|s| s.findings.iter())
        .filter(|f| !f.targets.is_empty())
        .count();
    let events = z.scans.iter().map(|s| s.events.len()).sum::<usize>();
    let errs = z
        .scans
        .iter()
        .flat_map(|s| s.events.iter())
        .filter(|e| e.kind == GuardEventKind::ScanError)
        .count();
    items.push(it(
        "E8",
        "빈 상태(실험실 0개, 범위 지킴이로만 확인): 대상 있는 발견 0, 이벤트 0, ScanError 0",
        &[("scans_ge_3", z.scans.len() >= 3), ("targeted_findings_zero", targeted == 0), ("events_zero", events == 0), ("scan_errors_zero", errs == 0)],
        json!({"scans": z.scans.len(), "note_ko": "vh 화면은 실기기라 빈 상태를 만들 수 없어 범위 지킴이로만 확인"}),
        "GUARD",
    ));
    Ok(items)
}

/// 관찰이 비었거나 판정에 필요한 값을 못 얻었으면 FAIL이 아니라 INCONCLUSIVE(도구 쪽 공백).
pub fn inconclusive_if(mut item: Item, missing: bool) -> Item {
    let empty = item.observed.as_object().is_some_and(|o| o.is_empty());
    if (missing || empty) && item.verdict == Verdict::Fail {
        item.verdict = Verdict::Inconclusive;
        item.suspected_owner = "LAB".into();
        item.severity = "low".into();
    }
    item
}

pub const TOO_SMALL_KO: &str = crate::strings::TOO_SMALL;

/// 마지막이 80×24가 아니어야 끝의 80×24가 실제 크기 변화가 된다(PM 4단계 추가 절).
pub const RESIZE_ORDER: [(u16, u16); 3] = [(120, 40), (60, 20), (80, 24)];
pub const RESIZES: usize = 20;

fn ui_checks(vh: &Path, out: &Path) -> io::Result<Vec<Item>> {
    let controls = crate::ttycheck::controls(&out.join("termios-controls"))?;
    let state = out.join("ui-state");
    write_config(&state, None)?;
    let mut p = PtyVh::spawn(vh, &state, 60, 20)?;
    let small_after = p.wait_for(TOO_SMALL_KO, Duration::from_secs(10));
    let small_bytes = p.mark();
    let small_rows = p.nonblank_rows();
    let alive_small = p.alive();
    let mut last = (60u16, 20u16);
    for i in 0..RESIZES {
        last = RESIZE_ORDER[i % RESIZE_ORDER.len()];
        p.resize(last.0, last.1);
        std::thread::sleep(Duration::from_millis(500));
    }
    let mark = p.mark();
    let final_changes_size = last != (80, 24);
    p.resize(80, 24);
    let redraw_after = p.wait_for(crate::strings::REDRAW_MARK, Duration::from_secs(10));
    let redraw_bytes = p.bytes_since(mark);
    let alive_after = p.alive();
    let exit = p.quit(Duration::from_secs(10));
    let restored = p.termios_restored();
    let rep = p.report();
    let e6 = it(
        "E6",
        "60×20 창: '창을 조금 키워 주세요', 크래시 없음",
        &[
            ("small_window_message", small_after.is_some()),
            ("alive", alive_small),
        ],
        json!({
            "screen_bytes": small_bytes,
            "screen_nonblank_rows": small_rows,
            "message_seen_after_ms": small_after.map(|d| d.as_millis() as u64),
            "how_ko": "화면 격자(screen.rs)에서 찾음. 화면 내용은 저장하지 않음",
        }),
        "TUI",
    );
    let e7 = it(
        "E7",
        "창 크기 20번 바꾸기(10초, 마지막은 80×24가 아님) 뒤 생존, 80×24로 바꾸면 다시 그림, q로 exit 0, 터미널 모드 복구",
        &[
            ("alive_after_resizes", alive_after),
            ("final_resize_changes_size", final_changes_size),
            (
                "redrawn_at_80x24",
                redraw_after.is_some() && redraw_bytes > 0,
            ),
            ("exit_0", exit.is_some_and(|e| e.success())),
            ("termios_restored", restored == Some(true)),
        ],
        json!({
            "exit_code": exit.and_then(|e| e.code()),
            "redraw_bytes": redraw_bytes,
            "redraw_seen_after_ms": redraw_after.map(|d| d.as_millis() as u64),
            "termios_restored": restored,
            "termios_controls": controls.json,
            "shim_report": rep,
        }),
        "TUI",
    );
    let h1 = h1(vh, out)?;
    Ok(vec![
        inconclusive_if(e6, small_bytes == 0),
        inconclusive_if(e7, restored.is_none() || !controls.ok),
        h1,
    ])
}

struct H1Case {
    unstable_after_ms: Option<u64>,
    normal_after_ms: Option<u64>,
    screen_bytes: u64,
    exit_0: bool,
}

fn h1_case(vh: &Path, state: &Path, env: Vec<(String, String)>) -> io::Result<H1Case> {
    use crate::strings::{STATE_NORMAL, STATE_UNSTABLE_NOTIFY};
    write_config(state, None)?;
    let mut p = PtyVh::spawn_env(vh, state, 100, 30, env)?;
    let t = Instant::now();
    let (mut unstable, mut normal) = (None, None);
    while t.elapsed() < Duration::from_secs(15) && unstable.is_none() && normal.is_none() {
        if p.contains(STATE_UNSTABLE_NOTIFY) {
            unstable = Some(t.elapsed().as_millis() as u64);
        } else if p.contains(STATE_NORMAL) {
            normal = Some(t.elapsed().as_millis() as u64);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let bytes = p.mark();
    let exit = p.quit(Duration::from_secs(10));
    Ok(H1Case {
        unstable_after_ms: unstable,
        normal_after_ms: normal,
        screen_bytes: bytes,
        exit_0: exit.is_some_and(|e| e.success()),
    })
}

/// H1: env 훅 경로(`VH_E2E_FORCE_HEALTH`)를 vh 바이너리로 확인. (a) 잠금 있음 → 불안정 표시,
/// (b) 잠금 없음 → 무시(평소 표시), (c) 강제 없음 대조. 셋 다 알림만·알림 끔·임시 상태 폴더.
fn h1(vh: &Path, out: &Path) -> io::Result<Item> {
    let a = h1_case(
        vh,
        &out.join("h1-forced"),
        forced_env(&out.join("h1-forced"), true),
    )?;
    let b = h1_case(
        vh,
        &out.join("h1-ungated"),
        forced_env(&out.join("h1-ungated"), false),
    )?;
    let c = h1_case(
        vh,
        &out.join("h1-control"),
        notify_only_env(&out.join("h1-control")),
    )?;
    let real_normal = c.normal_after_ms.is_some();
    let mut item = it(
        "H1",
        "강제 env 화면: (a) VH_E2E_FORCE_HEALTH=watch + VH_E2E_ALLOW_PIDS → 불안정 표시, (b) ALLOW_PIDS 없음 → 무시, (c) 대조는 평소 표시, 모두 q로 exit 0",
        &[
            ("forced_shows_unstable", a.unstable_after_ms.is_some()),
            ("ungated_ignored", b.normal_after_ms.is_some()),
            ("control_normal", real_normal),
            ("all_exit_0", a.exit_0 && b.exit_0 && c.exit_0),
        ],
        json!({
            "strings": {"unstable": crate::strings::STATE_UNSTABLE_NOTIFY, "normal": crate::strings::STATE_NORMAL},
            "a": {"unstable_after_ms": a.unstable_after_ms, "normal_after_ms": a.normal_after_ms, "screen_bytes": a.screen_bytes},
            "b": {"unstable_after_ms": b.unstable_after_ms, "normal_after_ms": b.normal_after_ms, "screen_bytes": b.screen_bytes},
            "c": {"unstable_after_ms": c.unstable_after_ms, "normal_after_ms": c.normal_after_ms, "screen_bytes": c.screen_bytes},
            "how_ko": "화면 격자에서 문구만 찾음. 화면 내용은 저장하지 않음",
        }),
        "GUARD",
    );
    if !real_normal && c.unstable_after_ms.is_some() && item.verdict == Verdict::Fail {
        item.verdict = Verdict::Inconclusive;
        item.suspected_owner = "none".into();
        item.observed["inconclusive_reason"] = json!("real_mac_not_normal(대조군이 불안정 표시)");
    }
    Ok(inconclusive_if(
        item,
        a.screen_bytes == 0 || b.screen_bytes == 0 || c.screen_bytes == 0,
    ))
}
