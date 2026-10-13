//! 색 출력(ANSI 직접). 켜는 조건은 [`enabled`] 한 곳에서 정한다.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Red,
    Yellow,
    Green,
    Bold,
}

/// `--no-color`가 없고, `NO_COLOR` 환경변수가 없고, 표준출력이 터미널이고, JSON이 아닐 때만 색을 쓴다.
pub fn enabled(no_color_flag: bool, no_color_env: bool, stdout_tty: bool, json: bool) -> bool {
    !no_color_flag && !no_color_env && stdout_tty && !json
}

/// `on`이면 ANSI로 감싼다.
pub fn paint(c: Color, s: &str, on: bool) -> String {
    if !on {
        return s.to_string();
    }
    let code = match c {
        Color::Red => "31",
        Color::Yellow => "33",
        Color::Green => "32",
        Color::Bold => "1",
    };
    format!("\x1b[{code}m{s}\x1b[0m")
}
