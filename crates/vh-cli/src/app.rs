//! 명령 실행: 파싱 → 수집·분석 → 화면 또는 JSON → 종료 코드(0 정상, 1 사용법·내부 오류).

use std::io::{BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use vh_act::{
    DirectTarget, ExecEnv, PlanOrigin, Policy, RealProber, RealSignaler, Selection, Signaler,
};
use vh_model::{ActionPlan, Confidence, Explanation, ProcRef, Report, Snapshot};
use vh_sample::CollectOptions;

use crate::cli::{self, Cli, Command, GlobalOpts, ParseFailure};
use crate::color;
use crate::flow::{self, Executed};
use crate::guard;
use crate::json;
use crate::render;
use crate::target::{self, TARGET_HINT, Target};

/// 표준 입출력과 터미널 여부. 테스트는 버퍼와 원하는 TTY 값을 넣는다.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub input: &'a mut dyn BufRead,
    pub stdin_tty: bool,
    pub stdout_tty: bool,
    pub stderr_tty: bool,
    pub no_color_env: bool,
}

impl Io<'_> {
    /// 사람에게 y/N을 물을 수 있는지: JSON이 아니고 stdin·stderr가 모두 터미널.
    pub fn interactive(&self, json: bool) -> bool {
        !json && self.stdin_tty && self.stderr_tty
    }
}

/// 수집·분석·조치 연결. 실제 구현은 [`RealBackend`], 테스트는 합성 데이터와 가짜 신호기.
pub trait Backend {
    fn collect(&self, opts: &CollectOptions) -> Snapshot;
    fn analyze(&self, s: &Snapshot) -> Report;
    fn explain_pid(&self, s: &Snapshot, r: &Report, pid: i32) -> Option<Explanation>;
    fn explain_port(&self, s: &Snapshot, r: &Report, port: u16) -> Vec<Explanation>;
    fn plan(&self, s: &Snapshot, r: &Report, sel: &Selection, policy: &Policy) -> ActionPlan {
        vh_act::plan(s, r, sel, policy)
    }
    fn execute(&self, plan: &ActionPlan, s: &Snapshot) -> anyhow::Result<Executed>;
}

pub struct RealBackend;

impl Backend for RealBackend {
    fn collect(&self, opts: &CollectOptions) -> Snapshot {
        vh_sample::collect(opts)
    }

    fn analyze(&self, s: &Snapshot) -> Report {
        vh_analyze::analyze(s)
    }

    fn explain_pid(&self, s: &Snapshot, r: &Report, pid: i32) -> Option<Explanation> {
        vh_analyze::explain_pid(s, r, pid)
    }

    fn explain_port(&self, s: &Snapshot, r: &Report, port: u16) -> Vec<Explanation> {
        vh_analyze::explain_port(s, r, port)
    }

    fn execute(&self, plan: &ActionPlan, s: &Snapshot) -> anyhow::Result<Executed> {
        let state_dir = vh_act::state_dir()
            .map_err(|e| anyhow::anyhow!("상태 폴더를 준비하지 못했어요: {e}"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let allow = std::env::var(guard::ENV)
            .ok()
            .map(|v| guard::parse_allow(&v));
        let guarded;
        let signaler: &dyn Signaler = match &allow {
            Some(pids) => {
                eprintln!("vh: {} 잠금 사용 중 — 허용 pid {pids:?}", guard::ENV);
                guarded = guard::AllowListSignaler::new(&RealSignaler, pids.clone(), true);
                &guarded
            }
            None => &RealSignaler,
        };
        let env = ExecEnv {
            signaler,
            prober: &RealProber,
            state_dir: state_dir.clone(),
            snapshot: s,
            run_id: format!("{now}-{}", std::process::id()),
        };
        Ok(Executed {
            outcomes: vh_act::execute(plan, &env),
            state_dir,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Usage,
    NotFound,
    Internal,
    /// 읽는 쪽이 먼저 닫힘(`vh | head`). 조용히 끝낸다.
    BrokenPipe,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Usage => "usage",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Internal | ErrorCode::BrokenPipe => "internal",
        }
    }
}

#[derive(Debug)]
pub struct CliError {
    pub code: ErrorCode,
    pub message: String,
    pub hint: Option<String>,
}

pub const USAGE_HINT: &str = "도움말: vh --help";
pub const INTERNAL_HINT: &str =
    "다시 해 보고, 계속되면 vh snapshot --json 결과를 함께 알려 주세요.";

impl CliError {
    pub fn usage(message: impl Into<String>, hint: &str) -> Self {
        CliError {
            code: ErrorCode::Usage,
            message: message.into(),
            hint: Some(hint.to_string()),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        CliError {
            code: ErrorCode::NotFound,
            message: message.into(),
            hint: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        CliError {
            code: ErrorCode::Internal,
            message: message.into(),
            hint: Some(INTERNAL_HINT.to_string()),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return CliError {
                code: ErrorCode::BrokenPipe,
                message: String::new(),
                hint: None,
            };
        }
        CliError::internal(format!("입출력 중 문제가 생겼어요: {e}"))
    }
}

/// `vh`를 전체 화면으로 띄울지, W1 글자·JSON 경로로 보낼지.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Tui(TuiOpts),
    Cli,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuiOpts {
    pub no_color: bool,
}

/// stdin·stdout이 모두 터미널이고, TERM이 화면 제어를 할 수 있고(`dumb`·없음 제외),
/// 하위 명령·`--json`·`--plain`이 없을 때만 전체 화면. 파싱 오류는 [`run`]이 W1처럼 알린다.
pub fn route(
    args: &[String],
    stdin_tty: bool,
    stdout_tty: bool,
    term: Option<&str>,
    no_color_env: bool,
) -> Route {
    if !stdin_tty || !stdout_tty {
        return Route::Cli;
    }
    match term {
        Some(t) if !t.is_empty() && t != "dumb" => {}
        _ => return Route::Cli,
    }
    let Ok(c) = cli::parse(args) else {
        return Route::Cli;
    };
    if c.command.is_some() || c.global.json || c.global.plain {
        return Route::Cli;
    }
    Route::Tui(TuiOpts {
        no_color: c.global.no_color || no_color_env,
    })
}

/// 명령줄 전체를 실행하고 종료 코드를 돌려준다.
pub fn run(args: &[String], io: &mut Io<'_>, be: &dyn Backend) -> i32 {
    let json_hint = args.iter().skip(1).any(|a| a == "--json");
    let parsed = match cli::parse(args) {
        Ok(c) => c,
        Err(ParseFailure::Display(text)) => {
            let _ = io.out.write_all(text.as_bytes());
            let _ = io.out.flush();
            return 0;
        }
        Err(ParseFailure::Usage(msg)) => {
            return report(io, json_hint, CliError::usage(msg, USAGE_HINT));
        }
    };
    let json = parsed.global.json || matches!(parsed.command, Some(Command::Snapshot));
    let result = dispatch(&parsed, io, be);
    let flushed = io.out.flush();
    match result.and(flushed.map_err(CliError::from)) {
        Ok(()) => 0,
        Err(e) => report(io, json, e),
    }
}

fn report(io: &mut Io<'_>, json: bool, e: CliError) -> i32 {
    if e.code == ErrorCode::BrokenPipe {
        return 0;
    }
    if json {
        let _ = writeln!(io.out, "{}", json::error(e.code.as_str(), &e.message));
        let _ = io.out.flush();
    } else {
        let _ = writeln!(io.err, "vh: {}", e.message);
        if let Some(h) = &e.hint {
            let _ = writeln!(io.err, "    {h}");
        }
    }
    1
}

fn collect_opts(g: &GlobalOpts) -> CollectOptions {
    CollectOptions {
        cpu_interval_ms: if g.no_cpu { None } else { Some(g.interval_ms) },
        ..CollectOptions::default()
    }
}

fn parse_target(raw: &str) -> Result<Target, CliError> {
    target::parse(raw).map_err(|m| CliError::usage(m, TARGET_HINT))
}

fn write_json(io: &mut Io<'_>, v: &impl serde::Serialize) -> Result<(), CliError> {
    let s = serde_json::to_string(v)
        .map_err(|e| CliError::internal(format!("JSON을 만들지 못했어요: {e}")))?;
    writeln!(io.out, "{s}")?;
    Ok(())
}

fn pid_missing(pid: i32) -> CliError {
    CliError::not_found(format!("{pid}번 프로세스가 없어요. 이미 끝났을 수 있어요."))
}

fn port_missing(port: u16) -> CliError {
    CliError::not_found(format!(":{port} 포트에서 기다리는 프로그램이 없어요."))
}

/// `vh kill` 대상 → 스냅샷의 ProcRef(포트면 그 포트를 기다리는 프로세스 전부).
fn resolve_direct(s: &Snapshot, t: Target) -> Result<Vec<ProcRef>, CliError> {
    match t {
        Target::Pid(pid) => s
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| {
                vec![ProcRef {
                    pid,
                    start_time_unix_ms: p.start_time_unix_ms,
                }]
            })
            .ok_or_else(|| pid_missing(pid)),
        Target::Port(port) => {
            let mut refs: Vec<ProcRef> = Vec::new();
            for l in s.listeners.iter().filter(|l| l.port == port) {
                let r = ProcRef {
                    pid: l.pid,
                    start_time_unix_ms: l.start_time_unix_ms,
                };
                if !refs.contains(&r) {
                    refs.push(r);
                }
            }
            if refs.is_empty() {
                Err(port_missing(port))
            } else {
                Ok(refs)
            }
        }
    }
}

fn dispatch(c: &Cli, io: &mut Io<'_>, be: &dyn Backend) -> Result<(), CliError> {
    let g = &c.global;
    let color = color::enabled(g.no_color, io.no_color_env, io.stdout_tty, g.json);
    let cmd = c.command.as_ref().unwrap_or(&Command::Status);
    match cmd {
        Command::Status => {
            let s = be.collect(&collect_opts(g));
            let r = be.analyze(&s);
            if g.json {
                write_json(io, &json::status(&s, &r))
            } else {
                io.out
                    .write_all(render::status::render(&s, &r, color).as_bytes())?;
                Ok(())
            }
        }
        Command::Why { target } => {
            let t = parse_target(target)?;
            let s = be.collect(&collect_opts(g));
            let r = be.analyze(&s);
            let exps = match t {
                Target::Pid(pid) => {
                    if !s.processes.iter().any(|p| p.pid == pid) {
                        return Err(pid_missing(pid));
                    }
                    be.explain_pid(&s, &r, pid).into_iter().collect::<Vec<_>>()
                }
                Target::Port(port) => {
                    if !s.listeners.iter().any(|l| l.port == port) {
                        return Err(port_missing(port));
                    }
                    be.explain_port(&s, &r, port)
                }
            };
            if exps.is_empty() {
                return Err(CliError::internal(format!(
                    "{} 의 설명을 만들지 못했어요",
                    t.display()
                )));
            }
            if g.json {
                write_json(io, &json::why(&s, t, &exps))
            } else {
                io.out
                    .write_all(render::why::render(&s, &r, t, &exps, color).as_bytes())?;
                Ok(())
            }
        }
        Command::Ports => {
            let s = be.collect(&collect_opts(g));
            let r = be.analyze(&s);
            if g.json {
                write_json(io, &json::ports(&s, &r))
            } else {
                io.out
                    .write_all(render::ports::render(&s, &r, color).as_bytes())?;
                Ok(())
            }
        }
        Command::Snapshot => {
            let s = be.collect(&collect_opts(g));
            write_json(io, &json::snapshot(&s))
        }
        Command::Fix {
            yes,
            only,
            min_confidence,
        } => {
            let s = be.collect(&collect_opts(g));
            let r = be.analyze(&s);
            let explicit = min_confidence.map(|m| m.to_model());
            let (conf, basis) = flow::min_confidence(explicit, !only.is_empty(), *yes);
            let finding_ids = if only.is_empty() {
                render::section::bulk_ids(&r.findings)
            } else {
                Vec::new()
            };
            let plan = if only.is_empty() && finding_ids.is_empty() {
                ActionPlan {
                    created_at_unix_ms: s.taken_at_unix_ms,
                    total_deadline_ms: Policy::default().total_deadline_ms,
                    items: Vec::new(),
                    refused: Vec::new(),
                }
            } else {
                let sel = Selection {
                    finding_ids,
                    pids: only.clone(),
                    min_confidence: conf,
                    direct: Vec::new(),
                };
                let origin = if only.is_empty() {
                    PlanOrigin::Bulk
                } else {
                    PlanOrigin::Pointed
                };
                let policy = Policy {
                    origin,
                    ..Policy::default()
                };
                be.plan(&s, &r, &sel, &policy)
            };
            let note = basis == flow::Basis::Confirm
                && plan.items.iter().any(|i| {
                    r.findings
                        .iter()
                        .find(|f| f.id == i.finding_id)
                        .is_some_and(|f| f.confidence != Confidence::Confirmed)
                });
            let req = flow::Request {
                s: &s,
                r: &r,
                plan: &plan,
                kind: flow::Kind::Fix {
                    basis: flow::basis_ko(basis, conf),
                    only,
                    yes_only_confirmed_note: note,
                },
                yes: *yes,
                json: g.json,
                color,
            };
            flow::run(&req, io, &mut |p| be.execute(p, &s)).map(|_| ())
        }
        Command::Kill { target, yes, tree } => {
            let t = parse_target(target)?;
            let s = be.collect(&collect_opts(g));
            let r = be.analyze(&s);
            let refs = resolve_direct(&s, t)?;
            let sel = Selection {
                direct: refs
                    .into_iter()
                    .map(|target| DirectTarget {
                        target,
                        include_descendants: *tree,
                    })
                    .collect(),
                ..Selection::default()
            };
            let policy = Policy {
                origin: PlanOrigin::Pointed,
                ..Policy::default()
            };
            let plan = be.plan(&s, &r, &sel, &policy);
            let req = flow::Request {
                s: &s,
                r: &r,
                plan: &plan,
                kind: flow::Kind::Kill { target: t },
                yes: *yes,
                json: g.json,
                color,
            };
            flow::run(&req, io, &mut |p| be.execute(p, &s)).map(|_| ())
        }
    }
}
