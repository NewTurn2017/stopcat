use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const USAGE: &str = "사용법: stopcat-lab <명령> [옵션]
  preflight --out <파일> [--stopcat <원본> --stopcat-copy <복사본> --stopcat-sha256 <값>] [--wait-normal-secs 600]
  isolation-check --out <폴더> --report <파일>
  prepare-stopcat --src <원본> --dest <복사본> --sha256 <값>
  scenarios --out <폴더> [--only A,AF,B,BF,C,CF] [--stopcat <복사본> --stopcat-sha256 <값>]
  invariants --out <폴더> [--stopcat <복사본> --stopcat-sha256 <값>]
  soak --stopcat <복사본> --stopcat-sha256 <값> --minutes <분> --sample-secs <초> --out <폴더>
  interval-ab --stopcat <복사본> --stopcat-sha256 <값> --minutes 15 --intervals 5000,30000 --out <폴더>
  stress --max-procs <≤300> --storm-secs <≤60> --out <폴더>
  edge --stopcat <복사본> --stopcat-sha256 <값> --out <폴더>
  termios-check --out <폴더> [--stopcat <복사본> --stopcat-sha256 <값>]
  findings --run-dir <폴더> --out <파일> --repo <작업트리> --lab-build-sha <sha> --stopcat-sha256 <값> [--isolation <파일>]
  privacy-check --dir <폴더> --out <파일> [--allow <접두사>]...";

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], name: &str) -> Result<PathBuf, String> {
    opt(args, name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} 필요\n{USAGE}"))
}

fn num(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match opt(args, name) {
        Some(v) => v.parse().map_err(|_| format!("{name} 숫자 필요")),
        None => Ok(default),
    }
}

fn stopcat_pair(args: &[String]) -> Result<Option<(PathBuf, String)>, String> {
    match (opt(args, "--stopcat"), opt(args, "--stopcat-sha256")) {
        (Some(a), Some(b)) => Ok(Some((PathBuf::from(a), b))),
        (None, None) => Ok(None),
        _ => Err("--stopcat과 --stopcat-sha256는 함께 필요".into()),
    }
}

fn supervised(cmd: &str) -> bool {
    matches!(
        cmd,
        "preflight"
            | "isolation-check"
            | "kill-probe-lab"
            | "scenarios"
            | "invariants"
            | "soak"
            | "interval-ab"
            | "stress"
            | "edge"
            | "termios-check"
    )
}

/// 실험실을 띄우는 명령은 setsid로 새 세션(제어 터미널 없음)에서 자기 자신을 다시 실행해 돌린다.
fn reexec_supervised(args: &[String]) -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    let mut cmd = Command::new(exe);
    cmd.arg("__supervise").args(args);
    // SAFETY: fork 뒤 exec 전 setsid만 부른다(async-signal-safe).
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("감독 실행 실패: {e}");
            1
        }
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args[1.min(args.len())..];
    let io = |e: std::io::Error| e.to_string();
    match cmd {
        "preflight" => {
            let out = need(rest, "--out")?;
            let stopcat = match (
                opt(rest, "--stopcat"),
                opt(rest, "--stopcat-copy"),
                opt(rest, "--stopcat-sha256"),
            ) {
                (Some(a), Some(b), Some(c)) => Some((PathBuf::from(a), PathBuf::from(b), c)),
                _ => None,
            };
            stopcat_lab::preflight::run(
                &out,
                stopcat.as_ref()
                    .map(|(a, b, c)| (a.as_path(), b.as_path(), c.as_str())),
                num(rest, "--wait-normal-secs", 0)?,
            )
            .map_err(io)
        }
        "isolation-check" => {
            let out = need(rest, "--out")?;
            let report = need(rest, "--report")?;
            stopcat_lab::iso::run_isolation(&out, &report).map_err(io)
        }
        "kill-probe-lab" => {
            let out = need(rest, "--out")?;
            stopcat_lab::iso::kill_probe_lab(&out).map(|_| true).map_err(io)
        }
        "prepare-stopcat" => {
            let c = stopcat_lab::preflight::copy_stopcat(
                &need(rest, "--src")?,
                &need(rest, "--dest")?,
                &opt(rest, "--sha256").ok_or("--sha256 필요")?,
            )
            .map_err(io)?;
            println!("{}", serde_json::to_string_pretty(&c).unwrap_or_default());
            Ok(c.matches)
        }
        "scenarios" => {
            let only = opt(rest, "--only")
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default();
            let stopcat = stopcat_pair(rest)?;
            stopcat_lab::scenarios::run(
                &need(rest, "--out")?,
                &only,
                stopcat.as_ref().map(|(p, s)| stopcat_lab::invariants::StopcatCopy {
                    path: p.as_path(),
                    sha256: s.as_str(),
                }),
            )
            .map_err(io)
        }
        "invariants" => {
            let stopcat = stopcat_pair(rest)?;
            stopcat_lab::invariants::run(
                &need(rest, "--out")?,
                stopcat.as_ref().map(|(p, s)| stopcat_lab::invariants::StopcatCopy {
                    path: p.as_path(),
                    sha256: s.as_str(),
                }),
            )
            .map_err(io)
        }
        "soak" => stopcat_lab::soak::soak(
            &need(rest, "--stopcat")?,
            &opt(rest, "--stopcat-sha256").ok_or("--stopcat-sha256 필요")?,
            num(rest, "--minutes", 60)?,
            num(rest, "--sample-secs", 5)?,
            &need(rest, "--out")?,
        )
        .map_err(io),
        "interval-ab" => {
            let ivs: Vec<u32> = opt(rest, "--intervals")
                .unwrap_or_else(|| "5000,30000".into())
                .split(',')
                .filter_map(|x| x.trim().parse().ok())
                .collect();
            stopcat_lab::soak::interval_ab(
                &need(rest, "--stopcat")?,
                &opt(rest, "--stopcat-sha256").ok_or("--stopcat-sha256 필요")?,
                num(rest, "--minutes", 15)?,
                &ivs,
                &need(rest, "--out")?,
            )
            .map_err(io)
        }
        "stress" => stopcat_lab::stress::run(
            num(rest, "--max-procs", 300)? as usize,
            num(rest, "--storm-secs", 60)?,
            &need(rest, "--out")?,
        )
        .map_err(io),
        "edge" => stopcat_lab::edge::run(
            &need(rest, "--stopcat")?,
            &opt(rest, "--stopcat-sha256").ok_or("--stopcat-sha256 필요")?,
            &need(rest, "--out")?,
        )
        .map_err(io),
        "termios-check" => {
            let stopcat = match (opt(rest, "--stopcat"), opt(rest, "--stopcat-sha256")) {
                (Some(a), Some(b)) => Some((PathBuf::from(a), b)),
                (None, None) => None,
                _ => return Err("--stopcat과 --stopcat-sha256는 함께 필요".into()),
            };
            stopcat_lab::ttycheck::run(
                &need(rest, "--out")?,
                stopcat.as_ref().map(|(a, b)| (a.as_path(), b.as_str())),
            )
            .map_err(io)
        }
        "findings" => {
            let iso = opt(rest, "--isolation").map(PathBuf::from);
            let lab_sha = opt(rest, "--lab-build-sha").ok_or("--lab-build-sha 필요")?;
            let stopcat_sha = opt(rest, "--stopcat-sha256").ok_or("--stopcat-sha256 필요")?;
            let run_dir = need(rest, "--run-dir")?;
            let out = need(rest, "--out")?;
            let repo = need(rest, "--repo")?;
            stopcat_lab::findings::write_findings(&stopcat_lab::findings::Inputs {
                run_dir: &run_dir,
                out: &out,
                repo: &repo,
                lab_build_sha: &lab_sha,
                stopcat_sha256: &stopcat_sha,
                isolation: iso.as_deref(),
            })
            .map(|_| true)
            .map_err(io)
        }
        "privacy-check" => {
            let extra: Vec<String> = rest
                .windows(2)
                .filter(|w| w[0] == "--allow")
                .map(|w| w[1].clone())
                .collect();
            let allowed = stopcat_lab::findings::default_allowed(&extra);
            let v = stopcat_lab::findings::privacy_check(&need(rest, "--dir")?, &allowed).map_err(io)?;
            let out = need(rest, "--out")?;
            stopcat_lab::util::write_json(&out, &v).map_err(io)?;
            Ok(v["foreign_path_tokens"].as_u64() == Some(0))
        }
        _ => Err(USAGE.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some(stopcat_lab::pty::SHIM_CMD) => stopcat_lab::pty::shim_main(&args[1..]),
        Some("__supervise") => match run(&args[1..]) {
            Ok(true) => 0,
            Ok(false) => 2,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Some(c) if supervised(c) => reexec_supervised(&args),
        _ => match run(&args) {
            Ok(true) => 0,
            Ok(false) => 2,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
    };
    std::process::exit(code);
}
