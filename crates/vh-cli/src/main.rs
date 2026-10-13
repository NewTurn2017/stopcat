//! vh: Vibe Health 명령줄 도구 (TUI 레인 소유).

use std::io::{self, IsTerminal};

fn main() {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let stdin_tty = io::stdin().is_terminal();
    let stdout_tty = io::stdout().is_terminal();
    let no_color_env = std::env::var_os("NO_COLOR").is_some();
    let term = std::env::var("TERM").ok();
    if let vh_cli::app::Route::Tui(opts) =
        vh_cli::app::route(&args, stdin_tty, stdout_tty, term.as_deref(), no_color_env)
    {
        std::process::exit(vh_cli::tui::run(opts));
    }
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    let mut input = io::stdin().lock();
    let mut vio = vh_cli::app::Io {
        stdin_tty,
        stdout_tty,
        stderr_tty: io::stderr().is_terminal(),
        no_color_env,
        out: &mut out,
        err: &mut err,
        input: &mut input,
    };
    let code = vh_cli::app::run(&args, &mut vio, &vh_cli::app::RealBackend);
    std::process::exit(code);
}
