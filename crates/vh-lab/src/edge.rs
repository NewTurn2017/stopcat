//! 경계: 이상한 argv(E1~E4), 스캔 중 종료(E5), 작은 창·창 크기 바꾸기(E6·E7, 측정 대상 vh를 pty로), 빈 상태(E8).

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use vh_model::{AutoLevel, GuardEventKind, GuardPolicy};

use crate::lab::{Lab, Meta};
use crate::pty::{PtyVh, notify_only_env, write_config};
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

fn ui_checks(vh: &Path, out: &Path) -> io::Result<Vec<Item>> {
    let state = out.join("ui-state");
    write_config(&state, None)?;
    let mut p = PtyVh::spawn(vh, &state, 60, 20)?;
    std::thread::sleep(Duration::from_secs(3));
    let small = p.contains("창을 조금 키워 주세요", 0);
    let alive_small = p.alive();
    let sizes = [(80u16, 24u16), (120, 40), (60, 20)];
    for i in 0..19 {
        let (c, r) = sizes[i % 3];
        p.resize(c, r);
        std::thread::sleep(Duration::from_millis(500));
    }
    let mark = p.mark();
    p.resize(80, 24);
    std::thread::sleep(Duration::from_secs(3));
    let alive_after = p.alive();
    let redrawn = p.contains("지킴이", mark);
    let exit = p.quit(Duration::from_secs(10));
    let restored = p.termios_restored();
    Ok(vec![
        it(
            "E6",
            "60×20 창: '창을 조금 키워 주세요', 크래시 없음",
            &[("small_window_message", small), ("alive", alive_small)],
            json!({}),
            "TUI",
        ),
        it(
            "E7",
            "창 크기 20번 바꾸기(10초) 뒤 생존, 80×24에서 다시 그림, q로 exit 0, 터미널 모드 복구",
            &[
                ("alive_after_resizes", alive_after),
                ("redrawn_at_80x24", redrawn),
                ("exit_0", exit.is_some_and(|e| e.success())),
                ("termios_restored", restored),
            ],
            json!({"exit_code": exit.and_then(|e| e.code())}),
            "TUI",
        ),
    ])
}
