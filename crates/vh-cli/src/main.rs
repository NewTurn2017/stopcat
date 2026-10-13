//! vh: Vibe Health 명령줄 도구 (CLI 소유).

use std::io::{self, IsTerminal};

fn main() {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    let mut input = io::stdin().lock();
    let mut vio = vh_cli::app::Io {
        stdin_tty: io::stdin().is_terminal(),
        stdout_tty: io::stdout().is_terminal(),
        stderr_tty: io::stderr().is_terminal(),
        no_color_env: std::env::var_os("NO_COLOR").is_some(),
        out: &mut out,
        err: &mut err,
        input: &mut input,
    };
    let code = vh_cli::app::run(&args, &mut vio, &vh_cli::app::RealBackend);
    std::process::exit(code);
}
