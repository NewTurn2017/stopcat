use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const USAGE: &str = "사용법: vh-lab <명령> [옵션]
  preflight --out <파일> [--vh <원본> --vh-copy <복사본> --vh-sha256 <값>]
  isolation-check --out <폴더> --report <파일>
  prepare-vh --src <원본> --dest <복사본> --sha256 <값>
  scenarios --out <폴더> [--only A,B,C]
  soak --vh <복사본> --vh-sha256 <값> --minutes <분> --sample-secs <초> --out <폴더>
  interval-ab --vh <복사본> --vh-sha256 <값> --minutes 15 --intervals 5000,30000 --out <폴더>
  stress --max-procs <≤300> --storm-secs <≤60> --out <폴더>
  edge --vh <복사본> --vh-sha256 <값> --out <폴더>
  termios-check --out <폴더> [--vh <복사본> --vh-sha256 <값>]
  findings --run-dir <폴더> --out <파일> --repo <작업트리> --lab-build-sha <sha> --vh-sha256 <값> [--isolation <파일>]
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

fn supervised(cmd: &str) -> bool {
    matches!(
        cmd,
        "preflight"
            | "isolation-check"
            | "kill-probe-lab"
            | "scenarios"
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
            let vh = match (
                opt(rest, "--vh"),
                opt(rest, "--vh-copy"),
                opt(rest, "--vh-sha256"),
            ) {
                (Some(a), Some(b), Some(c)) => Some((PathBuf::from(a), PathBuf::from(b), c)),
                _ => None,
            };
            vh_lab::preflight::run(
                &out,
                vh.as_ref()
                    .map(|(a, b, c)| (a.as_path(), b.as_path(), c.as_str())),
            )
            .map_err(io)
        }
        "isolation-check" => {
            let out = need(rest, "--out")?;
            let report = need(rest, "--report")?;
            vh_lab::iso::run_isolation(&out, &report).map_err(io)
        }
        "kill-probe-lab" => {
            let out = need(rest, "--out")?;
            vh_lab::iso::kill_probe_lab(&out).map(|_| true).map_err(io)
        }
        "prepare-vh" => {
            let c = vh_lab::preflight::copy_vh(
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
            vh_lab::scenarios::run(&need(rest, "--out")?, &only).map_err(io)
        }
        "soak" => vh_lab::soak::soak(
            &need(rest, "--vh")?,
            &opt(rest, "--vh-sha256").ok_or("--vh-sha256 필요")?,
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
            vh_lab::soak::interval_ab(
                &need(rest, "--vh")?,
                &opt(rest, "--vh-sha256").ok_or("--vh-sha256 필요")?,
                num(rest, "--minutes", 15)?,
                &ivs,
                &need(rest, "--out")?,
            )
            .map_err(io)
        }
        "stress" => vh_lab::stress::run(
            num(rest, "--max-procs", 300)? as usize,
            num(rest, "--storm-secs", 60)?,
            &need(rest, "--out")?,
        )
        .map_err(io),
        "edge" => vh_lab::edge::run(
            &need(rest, "--vh")?,
            &opt(rest, "--vh-sha256").ok_or("--vh-sha256 필요")?,
            &need(rest, "--out")?,
        )
        .map_err(io),
        "termios-check" => {
            let vh = match (opt(rest, "--vh"), opt(rest, "--vh-sha256")) {
                (Some(a), Some(b)) => Some((PathBuf::from(a), b)),
                (None, None) => None,
                _ => return Err("--vh와 --vh-sha256는 함께 필요".into()),
            };
            vh_lab::ttycheck::run(
                &need(rest, "--out")?,
                vh.as_ref().map(|(a, b)| (a.as_path(), b.as_str())),
            )
            .map_err(io)
        }
        "findings" => {
            let iso = opt(rest, "--isolation").map(PathBuf::from);
            let lab_sha = opt(rest, "--lab-build-sha").ok_or("--lab-build-sha 필요")?;
            let vh_sha = opt(rest, "--vh-sha256").ok_or("--vh-sha256 필요")?;
            let run_dir = need(rest, "--run-dir")?;
            let out = need(rest, "--out")?;
            let repo = need(rest, "--repo")?;
            vh_lab::findings::write_findings(&vh_lab::findings::Inputs {
                run_dir: &run_dir,
                out: &out,
                repo: &repo,
                lab_build_sha: &lab_sha,
                vh_sha256: &vh_sha,
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
            let allowed = vh_lab::findings::default_allowed(&extra);
            let v = vh_lab::findings::privacy_check(&need(rest, "--dir")?, &allowed).map_err(io)?;
            let out = need(rest, "--out")?;
            vh_lab::util::write_json(&out, &v).map_err(io)?;
            Ok(v["foreign_path_tokens"].as_u64() == Some(0))
        }
        _ => Err(USAGE.to_string()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some(vh_lab::pty::SHIM_CMD) => vh_lab::pty::shim_main(&args[1..]),
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
