//! clap 명령 정의와 clap 오류의 한국어 문구.

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use vh_model::Confidence;

const HELP_TEMPLATE: &str = "{about}\n\n사용법: {usage}\n\n{all-args}";

/// 맨 위 도움말(`vh --help`)만 쓰는 틀: 첫 줄에 화면 사용법을 먼저 알린다.
const TOP_HELP_TEMPLATE: &str = "vh 만 치면 됩니다. 화면에서 방향키로 고르고 Enter로 정리해요.\n\n{about}\n\n사용법: {usage}\n\n{all-args}";

#[derive(Debug, Parser)]
#[command(
    name = "vh",
    version,
    about = "vh(Vibe Health) — 맥을 프로젝트·AI 세션 단위로 보고, 끄기 전에 누가 왜 띄웠는지 설명해요",
    override_usage = "vh [명령] [옵션]",
    help_template = TOP_HELP_TEMPLATE,
    subcommand_help_heading = "스크립트·AI용 명령",
    subcommand_value_name = "명령",
    next_help_heading = "옵션",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub global: GlobalOpts,

    #[arg(short = 'h', long = "help", action = ArgAction::Help, global = true, help = "도움말 보기")]
    help: Option<bool>,

    #[arg(short = 'V', long = "version", action = ArgAction::Version, help = "버전 보기")]
    version: Option<bool>,
}

#[derive(Debug, Args)]
pub struct GlobalOpts {
    #[arg(long, global = true, help = "사람용 화면 대신 JSON 한 줄로 출력")]
    pub json: bool,

    #[arg(
        long,
        global = true,
        help = "전체 화면 대신 맥 상태를 글자로 한 화면(스크립트·AI용)"
    )]
    pub plain: bool,

    #[arg(
        long,
        global = true,
        help = "CPU 사용률을 재지 않음(한 번만 읽어서 더 빠름)"
    )]
    pub no_cpu: bool,

    #[arg(
        long,
        global = true,
        value_name = "밀리초",
        default_value_t = 250,
        hide_default_value = true,
        value_parser = clap::value_parser!(u32).range(50..=5000),
        help = "CPU 사용률을 잴 때 두 번 읽는 간격(기본 250, 50~5000)"
    )]
    pub interval_ms: u32,

    #[arg(
        long,
        global = true,
        help = "색 없이 출력(NO_COLOR가 있거나 터미널이 아니면 자동으로 색 없음)"
    )]
    pub no_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinConfidence {
    Confirmed,
    Likely,
}

impl MinConfidence {
    pub fn to_model(self) -> Confidence {
        match self {
            MinConfidence::Confirmed => Confidence::Confirmed,
            MinConfidence::Likely => Confidence::Likely,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 맥 상태를 글자로 한 화면(= vh --plain)
    #[command(override_usage = "vh status [옵션]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Status,

    /// 이 프로세스·포트를 누가 왜 띄웠는지 설명
    #[command(override_usage = "vh why <대상> [옵션]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Why {
        #[arg(
            value_name = "대상",
            allow_hyphen_values = true,
            help = "프로세스 번호(예: 4821) 또는 콜론 붙인 포트(예: :5000)"
        )]
        target: String,
    },

    /// 기다리는 포트와 그 프로그램·프로젝트, 외부 노출·충돌
    #[command(override_usage = "vh ports [옵션]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Ports,

    /// 정리 미리보기, 확인하면 단계적으로 종료
    #[command(override_usage = "vh fix [--yes] [--only <번호>]… [옵션]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Fix {
        #[arg(
            short = 'y',
            long,
            help = "묻지 않고 바로 정리(기본 기준: 확실한 것만)"
        )]
        yes: bool,

        #[arg(
            long = "only",
            value_name = "번호",
            value_parser = clap::value_parser!(i32).range(1..),
            help = "이 프로세스만 정리(여러 번 쓸 수 있음)"
        )]
        only: Vec<i32>,

        #[arg(
            long,
            value_enum,
            value_name = "기준",
            hide_possible_values = true,
            help = "이 신뢰도 이상만 정리: confirmed(확실) 또는 likely(확실 + 가능성 높음)"
        )]
        min_confidence: Option<MinConfidence>,
    },

    /// 한 대상을 미리보기 후 단계적으로 끄기
    #[command(override_usage = "vh kill <대상> [--yes] [--tree] [옵션]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Kill {
        #[arg(
            value_name = "대상",
            allow_hyphen_values = true,
            help = "프로세스 번호(예: 4821) 또는 콜론 붙인 포트(예: :5000)"
        )]
        target: String,

        #[arg(short = 'y', long, help = "묻지 않고 바로 끄기")]
        yes: bool,

        #[arg(long, help = "자식 프로세스도 함께(자식부터) 끄기")]
        tree: bool,
    },

    /// 수집 원본을 JSON으로 출력(인자 가림·허용된 환경변수만). 버그 보고용
    #[command(override_usage = "vh snapshot [--json]", help_template = HELP_TEMPLATE, next_help_heading = "옵션")]
    Snapshot,
}

#[derive(Debug)]
pub enum ParseFailure {
    /// `--help`·`--version`: 이 글을 표준출력에 찍고 exit 0.
    Display(String),
    /// 사용법 오류: 한국어 문구, exit 1.
    Usage(String),
}

pub fn parse(args: &[String]) -> Result<Cli, ParseFailure> {
    Cli::try_parse_from(args).map_err(|e| match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ParseFailure::Display(e.to_string()),
        _ => ParseFailure::Usage(usage_message(&e)),
    })
}

fn ctx(e: &clap::Error, k: ContextKind) -> String {
    match e.get(k) {
        Some(ContextValue::String(s)) => s.clone(),
        Some(ContextValue::Strings(v)) => v.join(", "),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn usage_message(e: &clap::Error) -> String {
    let arg = ctx(e, ContextKind::InvalidArg);
    match e.kind() {
        ErrorKind::UnknownArgument => format!("알 수 없는 옵션이에요: {arg}"),
        ErrorKind::InvalidSubcommand => format!(
            "알 수 없는 명령이에요: {} (쓸 수 있는 명령: status, why, ports, fix, kill, snapshot)",
            ctx(e, ContextKind::InvalidSubcommand)
        ),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let val = ctx(e, ContextKind::InvalidValue);
            if arg.contains("interval-ms") {
                format!("'--interval-ms' 값은 50~5000 사이 숫자여야 해요: {val}")
            } else if arg.contains("only") {
                format!("'--only' 값은 프로세스 번호(1 이상 숫자)여야 해요: {val}")
            } else if arg.contains("min-confidence") {
                format!("'--min-confidence' 값은 confirmed 또는 likely 여야 해요: {val}")
            } else {
                format!("'{arg}' 값이 올바르지 않아요: {val}")
            }
        }
        ErrorKind::MissingRequiredArgument => {
            "대상을 넣어 주세요(예: vh why :5000, vh kill 4821)".to_string()
        }
        ErrorKind::ArgumentConflict => format!("같이 쓸 수 없는 옵션이에요: {arg}"),
        _ => "명령을 이해하지 못했어요.".to_string(),
    }
}
