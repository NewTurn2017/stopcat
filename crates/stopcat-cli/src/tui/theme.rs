//! 전체 화면 색. 색 모드(트루컬러·256색·없음)와 쓰임새별 스타일을 이곳에서만 정한다.
//!
//! 색은 어두운 배경과 밝은 배경(Terminal.app 기본) 모두에서 읽히는 중간 밝기로 고른다.
//! 배경색을 칠하는 곳은 글자색도 함께 정해 터미널 배경과 상관없이 같은 모양이 나오게 한다.
//! 색이 없을 때는 굵게·반전·흐리게만 쓴다.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    None,
    Ansi256,
    TrueColor,
}

impl ColorMode {
    /// `--no-color`·`NO_COLOR`면 없음, `COLORTERM`이 truecolor·24bit면 트루컬러, 아니면 256색.
    pub fn detect(no_color: bool, colorterm: Option<&str>) -> ColorMode {
        if no_color {
            return ColorMode::None;
        }
        match colorterm.map(str::to_ascii_lowercase).as_deref() {
            Some("truecolor" | "24bit") => ColorMode::TrueColor,
            _ => ColorMode::Ansi256,
        }
    }
}

/// 쓰임새별 색 이름.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// 상표·'필요 없음'(멈출 것).
    Brand,
    /// 로고 그라데이션 끝.
    BrandEnd,
    /// 정상·일하는 중.
    Ok,
    /// 주의·확인 필요.
    Warn,
    /// 위험·불안정·노출.
    Danger,
    Info,
    /// 지킴이·직접 하면 확보.
    Violet,
    Muted,
    /// 상태 막대 바탕과 그 위 글자.
    Surface,
    OnSurface,
    /// 커서 줄 바탕과 그 위 글자.
    Selection,
    OnSelection,
    /// 색 칩 위 글자.
    OnChip,
    Border,
    Shadow,
    /// 대화상자 뒤를 어둡게 할 때의 글자색.
    Backdrop,
}

impl Tone {
    pub const fn rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Brand => (255, 77, 109),
            Tone::BrandEnd => (255, 159, 67),
            Tone::Ok => (47, 191, 113),
            Tone::Warn => (240, 160, 32),
            Tone::Danger => (240, 62, 62),
            Tone::Info => (77, 171, 247),
            Tone::Violet => (151, 117, 250),
            Tone::Muted => (134, 142, 150),
            Tone::Surface => (37, 41, 50),
            Tone::OnSurface => (222, 226, 230),
            Tone::Selection => (54, 79, 199),
            Tone::OnSelection => (255, 255, 255),
            Tone::OnChip => (20, 20, 24),
            Tone::Border => (88, 96, 105),
            Tone::Shadow => (12, 12, 16),
            Tone::Backdrop => (92, 98, 106),
        }
    }
}

/// RGB → xterm 256색 번호(6×6×6 정육면체와 회색 띠 중 가까운 쪽).
pub fn ansi256(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let q = |v: u8| -> usize {
        match v {
            0..=47 => 0,
            48..=114 => 1,
            _ => usize::from((v - 35) / 40),
        }
    };
    let (qr, qg, qb) = (q(r), q(g), q(b));
    let dist = |a: (i32, i32, i32)| {
        let (dr, dg, db) = (a.0 - i32::from(r), a.1 - i32::from(g), a.2 - i32::from(b));
        dr * dr + dg * dg + db * db
    };
    let cube = (LEVELS[qr], LEVELS[qg], LEVELS[qb]);
    let avg = (i32::from(r) + i32::from(g) + i32::from(b)) / 3;
    let gi = ((avg - 8).max(0) / 10).min(23);
    let gv = 8 + 10 * gi;
    if dist((gv, gv, gv)) < dist(cube) {
        (232 + gi) as u8
    } else {
        (16 + 36 * qr + 6 * qg + qb) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub mode: ColorMode,
}

impl Theme {
    pub const fn new(mode: ColorMode) -> Theme {
        Theme { mode }
    }

    pub fn colored(self) -> bool {
        self.mode != ColorMode::None
    }

    fn rgb_color(self, (r, g, b): (u8, u8, u8)) -> Option<Color> {
        match self.mode {
            ColorMode::None => None,
            ColorMode::Ansi256 => Some(Color::Indexed(ansi256(r, g, b))),
            ColorMode::TrueColor => Some(Color::Rgb(r, g, b)),
        }
    }

    pub fn color(self, t: Tone) -> Option<Color> {
        self.rgb_color(t.rgb())
    }

    /// 글자색만.
    pub fn fg(self, t: Tone) -> Style {
        match self.color(t) {
            Some(c) => Style::new().fg(c),
            None => Style::new(),
        }
    }

    pub fn bold(self, t: Tone) -> Style {
        self.fg(t).add_modifier(Modifier::BOLD)
    }

    /// 보조 글(근거·나이·설명). 색이 없으면 흐리게.
    pub fn muted(self) -> Style {
        match self.color(Tone::Muted) {
            Some(c) => Style::new().fg(c),
            None => Style::new().add_modifier(Modifier::DIM),
        }
    }

    /// 색 칩(구역 머리·고른 탭·상태 구간). 색이 없으면 반전.
    pub fn chip(self, t: Tone) -> Style {
        match (self.color(t), self.color(Tone::OnChip)) {
            (Some(bg), Some(fg)) => Style::new().bg(bg).fg(fg).add_modifier(Modifier::BOLD),
            _ => Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }

    /// 밝은 글자를 얹는 칩(보라·파랑처럼 어두운 바탕).
    pub fn chip_light(self, t: Tone) -> Style {
        match (self.color(t), self.color(Tone::OnSelection)) {
            (Some(bg), Some(fg)) => Style::new().bg(bg).fg(fg).add_modifier(Modifier::BOLD),
            _ => Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
        }
    }

    /// 커서 줄. 색이 없으면 반전.
    pub fn selection(self) -> Style {
        match (self.color(Tone::Selection), self.color(Tone::OnSelection)) {
            (Some(bg), Some(fg)) => Style::new().bg(bg).fg(fg),
            _ => Style::new().add_modifier(Modifier::REVERSED),
        }
    }

    /// 상태 막대 바탕.
    pub fn bar(self) -> Style {
        match (self.color(Tone::Surface), self.color(Tone::OnSurface)) {
            (Some(bg), Some(fg)) => Style::new().bg(bg).fg(fg),
            _ => Style::new(),
        }
    }

    pub fn border(self) -> Style {
        self.fg(Tone::Border)
    }

    /// 키 안내의 키 글자.
    pub fn key(self) -> Style {
        self.bold(Tone::Info)
    }

    /// 로고 그라데이션: `i`번째 칸(전체 `n`칸)의 색.
    pub fn gradient(self, i: usize, n: usize) -> Style {
        let (a, b) = (Tone::Brand.rgb(), Tone::BrandEnd.rgb());
        let t = if n <= 1 {
            0.0
        } else {
            i as f32 / (n - 1) as f32
        };
        let mix = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
        match self.rgb_color((mix(a.0, b.0), mix(a.1, b.1), mix(a.2, b.2))) {
            Some(c) => Style::new().fg(c).add_modifier(Modifier::BOLD),
            None => Style::new().add_modifier(Modifier::BOLD),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_modes() {
        assert_eq!(ColorMode::detect(true, Some("truecolor")), ColorMode::None);
        assert_eq!(
            ColorMode::detect(false, Some("truecolor")),
            ColorMode::TrueColor
        );
        assert_eq!(
            ColorMode::detect(false, Some("24bit")),
            ColorMode::TrueColor
        );
        assert_eq!(ColorMode::detect(false, None), ColorMode::Ansi256);
        assert_eq!(ColorMode::detect(false, Some("")), ColorMode::Ansi256);
    }

    #[test]
    fn ansi256_nearest() {
        assert_eq!(ansi256(0, 0, 0), 16);
        assert_eq!(ansi256(255, 255, 255), 231);
        assert_eq!(ansi256(255, 0, 0), 196);
        assert_eq!(ansi256(128, 128, 128), 244);
        assert_eq!(ansi256(255, 95, 135), 204);
    }

    #[test]
    fn no_color_uses_modifiers_only() {
        let t = Theme::new(ColorMode::None);
        assert_eq!(t.fg(Tone::Brand), Style::new());
        assert!(t.selection().add_modifier.contains(Modifier::REVERSED));
        assert!(t.muted().add_modifier.contains(Modifier::DIM));
        assert_eq!(t.bar(), Style::new());
    }
}
