use vh_model::{ExeOrigin, Proc, exe_origin};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Interp {
    Node,
    Bun,
    Deno,
    Python,
    Ruby,
    Java,
    Uv,
    Php,
}

impl Interp {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Interp::Node => "node",
            Interp::Bun => "bun",
            Interp::Deno => "deno",
            Interp::Python => "python",
            Interp::Ruby => "ruby",
            Interp::Java => "java",
            Interp::Uv => "uv",
            Interp::Php => "php",
        }
    }

    fn from_base(base: &str) -> Option<Interp> {
        Some(match base {
            "node" => Interp::Node,
            "bun" => Interp::Bun,
            "deno" => Interp::Deno,
            "ruby" => Interp::Ruby,
            "java" => Interp::Java,
            "uv" | "uvx" => Interp::Uv,
            "php" => Interp::Php,
            b if b == "Python" || b.starts_with("python") => Interp::Python,
            _ => return None,
        })
    }
}

/// 프로세스마다 한 번 계산하는 분류용 값. 원자 조건은 이 값만 본다.
#[derive(Debug, Clone)]
pub(crate) struct Feat {
    pub origin: ExeOrigin,
    pub exe_path: String,
    pub exe_base: String,
    pub app: Option<String>,
    pub app_count: usize,
    pub bundle_main: bool,
    pub interp: Option<Interp>,
    pub entry: Option<String>,
    pub entry_base: Option<String>,
    pub module: Option<String>,
    pub subcommand: Option<String>,
    pub tokens: Vec<String>,
    pub title: String,
}

impl Feat {
    pub(crate) fn name_base(&self) -> &str {
        match (&self.interp, &self.entry_base) {
            (Some(_), Some(e)) => e,
            _ => &self.exe_base,
        }
    }
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn strip_version(t: &str) -> &str {
    let base_start = t.rfind('/').map_or(0, |i| i + 1);
    match t[base_start..].rfind('@') {
        Some(i) if i > 0 => &t[..base_start + i],
        _ => t,
    }
}

const GENERIC_ENTRY: &[&str] = &["cli", "index", "main", "bin", "entry", "run"];

fn entry_base_of(entry: &str) -> String {
    let base = basename(entry);
    let stem = [".js", ".cjs", ".mjs", ".ts", ".py"]
        .iter()
        .find_map(|ext| base.strip_suffix(ext))
        .unwrap_or(base);
    if GENERIC_ENTRY.contains(&stem)
        && let Some(i) = entry.rfind("node_modules/")
    {
        let rest = &entry[i + "node_modules/".len()..];
        let mut parts = rest.split('/');
        let first = parts.next().unwrap_or("");
        let pkg = if first.starts_with('@') {
            parts.next().unwrap_or(first)
        } else {
            first
        };
        if !pkg.is_empty() && pkg != ".bin" {
            return pkg.to_string();
        }
    }
    stem.to_string()
}

const OPTS_WITH_VALUE: &[&str] = &[
    "-X",
    "-W",
    "-r",
    "--require",
    "--loader",
    "--import",
    "--experimental-loader",
    "--cwd",
    "--config",
    "--from",
    "--with",
    "--python",
];
const STOP_OPTS: &[&str] = &["-c", "-e", "--eval", "-p", "--print"];
const BUN_UV_VERBS: &[&str] = &["run", "x", "exec", "tool"];

pub(crate) fn effective_argv(p: &Proc) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(first) = p.argv.first() {
        if first.contains(char::is_whitespace) && !first.starts_with('/') {
            out.extend(first.split_whitespace().map(str::to_string));
        } else {
            out.push(first.clone());
        }
    }
    out.extend(p.argv.iter().skip(1).filter(|a| !a.is_empty()).cloned());
    out
}

pub(crate) fn features(p: &Proc) -> Feat {
    let argv = effective_argv(p);
    let exe_path = match (&p.exe, p.argv.first()) {
        (Some(e), _) if !e.is_empty() => e.clone(),
        (_, Some(a0)) if a0.starts_with('/') => a0.clone(),
        _ => argv.first().cloned().unwrap_or_else(|| p.name.clone()),
    };
    let exe_base = basename(&exe_path).to_string();
    let origin = exe_origin(p.exe.as_deref());

    let comps: Vec<&str> = exe_path.split('/').filter(|c| !c.is_empty()).collect();
    let app_positions: Vec<usize> = comps
        .iter()
        .enumerate()
        .filter(|(_, c)| c.ends_with(".app"))
        .map(|(i, _)| i)
        .collect();
    let app = app_positions
        .first()
        .map(|&i| comps[i].trim_end_matches(".app").to_string());
    let bundle_main = app_positions.len() == 1 && {
        let i = app_positions[0];
        comps.len() == i + 4 && comps[i + 1] == "Contents" && comps[i + 2] == "MacOS"
    };

    let interp = Interp::from_base(&exe_base)
        .or_else(|| argv.first().and_then(|a0| Interp::from_base(basename(a0))));

    let mut entry = None;
    let mut module = None;
    let mut subcommand = None;
    let mut i = 1;
    if interp.is_some() {
        while i < argv.len() {
            let a = argv[i].as_str();
            if a == "-m" {
                module = argv.get(i + 1).cloned();
                i += 2;
                break;
            }
            if STOP_OPTS.contains(&a) {
                i = argv.len();
                break;
            }
            if OPTS_WITH_VALUE.contains(&a) {
                i += 2;
                continue;
            }
            if a.starts_with('-') {
                i += 1;
                continue;
            }
            if matches!(interp, Some(Interp::Bun) | Some(Interp::Uv)) && BUN_UV_VERBS.contains(&a) {
                i += 1;
                continue;
            }
            entry = Some(a.to_string());
            i += 1;
            break;
        }
    }
    while i < argv.len() {
        let a = argv[i].as_str();
        if !a.starts_with('-') {
            subcommand = Some(a.to_string());
            break;
        }
        i += 1;
    }
    let entry_base = entry.as_deref().map(entry_base_of);

    let tokens = argv.iter().map(|t| strip_version(t).to_string()).collect();

    Feat {
        origin,
        exe_path,
        exe_base,
        app,
        app_count: app_positions.len(),
        bundle_main,
        interp,
        entry,
        entry_base,
        module,
        subcommand,
        tokens,
        title: p.argv.first().cloned().unwrap_or_default(),
    }
}

pub(crate) fn token_base(t: &str) -> &str {
    basename(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vh_model::ProcStatus;

    fn proc(exe: &str, argv: &[&str]) -> Proc {
        Proc {
            pid: 10,
            ppid: 1,
            pgid: 10,
            uid: 501,
            start_time_unix_ms: 0,
            name: String::new(),
            exe: Some(exe.to_string()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            argv_readable: true,
            env: BTreeMap::new(),
            env_readable: true,
            cwd: None,
            status: ProcStatus::Sleeping,
            has_tty: false,
            footprint_bytes: None,
            rss_bytes: None,
            cpu_time_ns: None,
            cpu_pct: None,
            threads: None,
            nice: None,
            translated: false,
            tcp: None,
            disk_read_bytes: None,
            disk_written_bytes: None,
            disk_io_delta_bytes: None,
        }
    }

    #[test]
    fn interpreter_entry_and_module() {
        let f = features(&proc(
            "/opt/homebrew/bin/node",
            &[
                "node",
                "--max-old-space-size=4096",
                "/w/node_modules/.bin/next",
                "dev",
            ],
        ));
        assert_eq!(f.interp, Some(Interp::Node));
        assert_eq!(f.entry_base.as_deref(), Some("next"));
        assert_eq!(f.subcommand.as_deref(), Some("dev"));

        let f = features(&proc(
            "/usr/local/bin/python3.13",
            &["python3", "-u", "-m", "uvicorn", "app:app"],
        ));
        assert_eq!(f.module.as_deref(), Some("uvicorn"));
        assert_eq!(f.subcommand.as_deref(), Some("app:app"));
    }

    #[test]
    fn package_name_for_generic_entry() {
        let f = features(&proc(
            "/Users/demo/.bun/bin/bun",
            &[
                "bun",
                "/Users/demo/.bun/install/global/node_modules/@demo/senpi/dist/bundle/cli.js",
            ],
        ));
        assert_eq!(f.entry_base.as_deref(), Some("senpi"));
    }

    #[test]
    fn rewritten_title_is_split() {
        let f = features(&proc(
            "/opt/homebrew/bin/node",
            &["npm exec chrome-devtools-mcp@1.9.0"],
        ));
        assert!(f.tokens.iter().any(|t| t == "chrome-devtools-mcp"));
    }

    #[test]
    fn bundle_main_detection() {
        let f = features(&proc(
            "/Applications/OrbStack.app/Contents/MacOS/OrbStack",
            &["/Applications/OrbStack.app/Contents/MacOS/OrbStack"],
        ));
        assert!(f.bundle_main);
        assert_eq!(f.app.as_deref(), Some("OrbStack"));
        let f = features(&proc(
            "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper",
            &["x", "vmgr"],
        ));
        assert!(!f.bundle_main);
    }
}
