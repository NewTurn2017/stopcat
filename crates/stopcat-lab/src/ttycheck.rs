//! 터미널 모드 복구 검사 방법 자체의 검증(PM 4단계 지시 3). 같은 pty·shim 방식으로 대조군을 먼저 돌린다:
//! 아무것도 안 바꾸는 `true`(복구 true여야 함), 바꾸고 안 되돌리는 `stty raw -echo`(false여야 함),
//! 잘 알려진 TUI `less`(true여야 함). 대조군이 맞을 때만 stopcat 결과(T1)를 판정한다.

use std::io;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::pty::{PtyVh, ShimReport, base_env, write_config};
use crate::util::{sha256_file, write_json};
use crate::verdict::{Item, Verdict};

pub struct Case {
    pub id: &'static str,
    pub expect_restored: Option<bool>,
    pub report: Option<ShimReport>,
    pub exit_code: Option<i32>,
    pub old_method_errno: Option<i32>,
    pub screen_bytes: u64,
    pub ready: bool,
}

impl Case {
    pub fn restored(&self) -> Option<bool> {
        self.report
            .as_ref()
            .filter(|r| r.finished)
            .and_then(|r| r.flags_restored)
    }

    fn stty_agrees(&self) -> bool {
        self.report
            .as_ref()
            .is_some_and(|r| r.stty_restored.is_some() && r.stty_restored == r.flags_restored)
    }

    fn json(&self) -> Value {
        json!({
            "id": self.id,
            "expect_restored": self.expect_restored,
            "restored": self.restored(),
            "stty_agrees_with_tcgetattr": self.stty_agrees(),
            "exit_code": self.exit_code,
            "screen_ready": self.ready,
            "screen_bytes": self.screen_bytes,
            "old_method_slave_fd_errno_after_exit": self.old_method_errno,
            "shim_report": self.report,
        })
    }
}

/// 대조군 판정: 세 대조군이 기대대로이고 `stty -g` 비교가 tcgetattr 비교와 같으면 방법이 맞다.
pub fn method_item(cases: &[Case]) -> Item {
    let ctrl: Vec<&Case> = cases
        .iter()
        .filter(|c| c.expect_restored.is_some())
        .collect();
    let mut checks = std::collections::BTreeMap::new();
    for c in &ctrl {
        checks.insert(
            format!("{}_as_expected", c.id.replace('-', "_")),
            c.restored() == c.expect_restored,
        );
        checks.insert(
            format!("{}_stty_agrees", c.id.replace('-', "_")),
            c.stty_agrees(),
        );
    }
    let old_broken = cases
        .iter()
        .filter(|c| c.old_method_errno == Some(libc::ENOTTY))
        .count();
    let pass = !ctrl.is_empty() && checks.values().all(|v| *v);
    Item {
        id: "TERMIOS-METHOD".into(),
        expected: "대조군: true → 복구 true, stty raw -echo → false, less → true. stty -g 전후 비교가 tcgetattr 비교와 같음".into(),
        observed: json!({
            "controls": ctrl.iter().map(|c| json!({"id": c.id, "expect": c.expect_restored, "restored": c.restored(), "stty_agrees": c.stty_agrees()})).collect::<Vec<_>>(),
            "old_method_enotty_cases": old_broken,
            "old_method_ko": "이전 방식(실험실이 든 slave fd로 대상 종료 뒤 tcgetattr)은 세션 리더 종료로 터미널이 revoke돼 ENOTTY → 언제나 false였다",
        }),
        verdict: if pass { Verdict::Pass } else { Verdict::Fail },
        evidence: Vec::new(),
        suspected_owner: if pass { "none".into() } else { "LAB".into() },
        severity: if pass { "low".into() } else { "high".into() },
        repro: "nice -n 19 <stopcat-lab> termios-check --out <폴더> [--stopcat <복사본> --stopcat-sha256 <값>]".into(),
        checks,
    }
}

/// T1: stopcat이 q로 끝난 뒤 터미널 모드 복구. 방법 검증이 실패했거나 보고서가 없으면 INCONCLUSIVE.
pub fn stopcat_item(stopcat: &Case, method_ok: bool) -> Item {
    let restored = stopcat.restored();
    let checks: std::collections::BTreeMap<String, bool> = [
        ("exit_0".to_string(), stopcat.exit_code == Some(0)),
        ("termios_restored".to_string(), restored == Some(true)),
        (
            "stty_restored".to_string(),
            stopcat.report.as_ref().and_then(|r| r.stty_restored) == Some(true),
        ),
    ]
    .into_iter()
    .collect();
    let verdict = if !method_ok || restored.is_none() || !stopcat.ready {
        Verdict::Inconclusive
    } else if checks.values().all(|v| *v) {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    Item {
        id: "T1".into(),
        expected:
            "pty stopcat이 q로 끝난 뒤(세션 리더 셸 역할 shim 아래) 터미널 모드·stty -g가 시작 때와 같음"
                .into(),
        observed: stopcat.json(),
        verdict,
        evidence: Vec::new(),
        suspected_owner: if verdict == Verdict::Fail {
            "TUI".into()
        } else {
            "none".into()
        },
        severity: if verdict == Verdict::Fail {
            "medium".into()
        } else {
            "low".into()
        },
        repro: "nice -n 19 <stopcat-lab> termios-check --out <폴더> --stopcat <복사본> --stopcat-sha256 <값>"
            .into(),
        checks,
    }
}

fn run_case(
    id: &'static str,
    expect: Option<bool>,
    prog: &Path,
    args: &[String],
    env: Vec<(String, String)>,
    out: &Path,
    ready_text: Option<&str>,
) -> io::Result<Case> {
    let shim = std::env::current_exe()?;
    let mut p = PtyVh::spawn_program(
        &shim,
        prog,
        args,
        env,
        &out.join(format!("{id}.shim.json")),
        80,
        24,
    )?;
    let ready = match ready_text {
        Some(t) => p.wait_for(t, Duration::from_secs(15)).is_some(),
        None => true,
    };
    let exit = if ready_text.is_some() {
        p.quit(Duration::from_secs(10))
    } else {
        let t = std::time::Instant::now();
        while p.alive() && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        p.quit(Duration::from_millis(100))
    };
    Ok(Case {
        id,
        expect_restored: expect,
        report: p.report(),
        exit_code: exit.and_then(|e| e.code()),
        old_method_errno: p.old_method_errno(),
        screen_bytes: p.mark(),
        ready,
    })
}

/// 매 pty 측정 전에 같이 돌리는 대조군(`true` → 복구, `stty raw -echo` → 미복구). 방법이 실패를 잡는지 확인.
pub struct Controls {
    pub ok: bool,
    pub json: Value,
}

fn control_cases(out: &Path) -> io::Result<Vec<Case>> {
    Ok(vec![
        run_case(
            "true",
            Some(true),
            Path::new("/usr/bin/true"),
            &[],
            base_env(),
            out,
            None,
        )?,
        run_case(
            "stty-raw",
            Some(false),
            Path::new("/bin/stty"),
            &["raw".into(), "-echo".into()],
            base_env(),
            out,
            None,
        )?,
    ])
}

pub fn controls(out: &Path) -> io::Result<Controls> {
    std::fs::create_dir_all(out)?;
    let cases = control_cases(out)?;
    let item = method_item(&cases);
    Ok(Controls {
        ok: item.verdict == Verdict::Pass,
        json: json!({"ok": item.verdict == Verdict::Pass, "checks": item.checks, "cases": cases.iter().map(Case::json).collect::<Vec<_>>()}),
    })
}

pub fn run(out: &Path, stopcat: Option<(&Path, &str)>) -> io::Result<bool> {
    std::fs::create_dir_all(out)?;
    let text = out.join("less-input.txt");
    let lines: Vec<String> = (1..=200).map(|i| format!("stopcat-lab line {i}")).collect();
    std::fs::write(&text, lines.join("\n"))?;
    let mut less_env = base_env();
    less_env.push(("LESSHISTFILE".into(), "-".into()));
    let mut cases = control_cases(out)?;
    cases.push(run_case(
        "less",
        Some(true),
        Path::new("/usr/bin/less"),
        &[text.to_string_lossy().into_owned()],
        less_env,
        out,
        Some("stopcat-lab line 1"),
    )?);
    let method = method_item(&cases);
    let method_ok = method.verdict == Verdict::Pass;
    let mut items = vec![method];
    if let Some((stopcat, sha)) = stopcat {
        if sha256_file(stopcat)? != sha {
            return Err(io::Error::other("측정 대상 sha256 불일치"));
        }
        let state = out.join("stopcat-state");
        write_config(&state, None)?;
        let mut p = PtyVh::spawn(stopcat, &state, 80, 24)?;
        let ready = p
            .wait_for(crate::strings::REDRAW_MARK, Duration::from_secs(15))
            .is_some();
        let exit = p.quit(Duration::from_secs(10));
        let c = Case {
            id: "stopcat",
            expect_restored: None,
            report: p.report(),
            exit_code: exit.and_then(|e| e.code()),
            old_method_errno: p.old_method_errno(),
            screen_bytes: p.mark(),
            ready,
        };
        items.push(stopcat_item(&c, method_ok));
        cases.push(c);
    }
    let all_pass = items.iter().all(|i| i.verdict == Verdict::Pass);
    write_json(
        &out.join("result.json"),
        &json!({
            "schema": "stopcat-lab/termios-check/v1",
            "cases": cases.iter().map(Case::json).collect::<Vec<_>>(),
            "items": items,
            "all_pass": all_pass,
        }),
    )?;
    Ok(method_ok)
}
