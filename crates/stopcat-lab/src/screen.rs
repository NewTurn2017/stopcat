//! pty 출력 바이트를 화면 격자에 적용하는 작은 VT 해석기(검사 전용, 메모리에만 둔다).
//!
//! ratatui(crossterm)는 넓은 글자(한글) 다음 칸마다 커서 이동(CSI H)을 끼워 쓰므로, 바이트 흐름에서
//! 글자를 그대로 찾으면 "알림만"·"창을 조금 키워 주세요" 같은 한글 문구를 절대 찾지 못한다.
//! 그래서 커서 이동·지우기만 적용한 격자에서 찾는다. 색·속성은 무시한다.

use crate::util::display_width;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Blank,
    Ch(char),
    /// 넓은 글자의 오른쪽 반.
    Cont,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Ground,
    Esc,
    EscSkip,
    Csi,
    Osc,
    OscEsc,
}

#[derive(Debug, Clone)]
pub struct Screen {
    cols: usize,
    rows: usize,
    cells: Vec<Vec<Cell>>,
    row: usize,
    col: usize,
    st: St,
    params: Vec<u8>,
    utf8: Vec<u8>,
}

impl Screen {
    pub fn new(cols: u16, rows: u16) -> Screen {
        let (cols, rows) = (usize::from(cols.max(1)), usize::from(rows.max(1)));
        Screen {
            cols,
            rows,
            cells: vec![vec![Cell::Blank; cols]; rows],
            row: 0,
            col: 0,
            st: St::Ground,
            params: Vec::new(),
            utf8: Vec::new(),
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = (usize::from(cols.max(1)), usize::from(rows.max(1)));
        self.cells.resize(rows, vec![Cell::Blank; cols]);
        for r in &mut self.cells {
            r.resize(cols, Cell::Blank);
        }
        self.cols = cols;
        self.rows = rows;
        self.row = self.row.min(rows - 1);
        self.col = self.col.min(cols - 1);
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.byte(b);
        }
    }

    /// 줄마다 끝 공백을 뺀 화면 글자(넓은 글자는 한 글자로).
    pub fn text(&self) -> String {
        self.cells
            .iter()
            .map(|r| {
                let s: String = r
                    .iter()
                    .filter_map(|c| match c {
                        Cell::Blank => Some(' '),
                        Cell::Ch(ch) => Some(*ch),
                        Cell::Cont => None,
                    })
                    .collect();
                s.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.text().contains(needle)
    }

    pub fn nonblank_rows(&self) -> usize {
        self.cells
            .iter()
            .filter(|r| r.iter().any(|c| *c != Cell::Blank))
            .count()
    }

    fn byte(&mut self, b: u8) {
        match self.st {
            St::Ground => self.ground(b),
            St::Esc => {
                self.st = match b {
                    b'[' => {
                        self.params.clear();
                        St::Csi
                    }
                    b']' => St::Osc,
                    b'(' | b')' | b'*' | b'+' | b'#' | b'%' => St::EscSkip,
                    _ => St::Ground,
                }
            }
            St::EscSkip => self.st = St::Ground,
            St::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    self.csi(b);
                    self.st = St::Ground;
                } else if (0x20..=0x3f).contains(&b) {
                    self.params.push(b);
                } else if b == 0x1b {
                    self.st = St::Esc;
                }
            }
            St::Osc => match b {
                0x07 => self.st = St::Ground,
                0x1b => self.st = St::OscEsc,
                _ => {}
            },
            St::OscEsc => self.st = if b == b'\\' { St::Ground } else { St::Osc },
        }
    }

    fn ground(&mut self, b: u8) {
        if b >= 0x80 || !self.utf8.is_empty() {
            self.utf8.push(b);
            match std::str::from_utf8(&self.utf8) {
                Ok(s) => {
                    let chars: Vec<char> = s.chars().collect();
                    self.utf8.clear();
                    for c in chars {
                        self.put(c);
                    }
                }
                Err(e) if e.error_len().is_some() || self.utf8.len() >= 4 => {
                    self.utf8.clear();
                    self.put('\u{FFFD}');
                }
                Err(_) => {}
            }
            return;
        }
        match b {
            0x1b => self.st = St::Esc,
            b'\r' => self.col = 0,
            b'\n' | 0x0b | 0x0c => self.line_feed(),
            0x08 => self.col = self.col.saturating_sub(1),
            b'\t' => self.col = ((self.col / 8 + 1) * 8).min(self.cols - 1),
            0x20..=0x7e => self.put(b as char),
            _ => {}
        }
    }

    fn line_feed(&mut self) {
        if self.row + 1 >= self.rows {
            self.cells.remove(0);
            self.cells.push(vec![Cell::Blank; self.cols]);
        } else {
            self.row += 1;
        }
    }

    fn put(&mut self, c: char) {
        let w = display_width(&c.to_string());
        if w == 0 {
            return;
        }
        if self.col + w > self.cols {
            self.col = 0;
            self.line_feed();
        }
        let (r, x) = (self.row, self.col);
        for p in x..(x + w).min(self.cols) {
            self.break_wide_pair(r, p);
        }
        self.cells[r][x] = Cell::Ch(c);
        if w == 2 && x + 1 < self.cols {
            self.cells[r][x + 1] = Cell::Cont;
        }
        self.col = (x + w).min(self.cols);
    }

    /// 칸 `p`를 덮기 전에, 그 칸이 넓은 글자의 한쪽 반이면 짝 칸을 비운다(진짜 터미널과 같은 동작).
    /// 비우지 않으면 남은 Cont가 `text()`에서 빠져 공백이 사라진다.
    fn break_wide_pair(&mut self, r: usize, p: usize) {
        match self.cells[r][p] {
            Cell::Cont if p > 0 => self.cells[r][p - 1] = Cell::Blank,
            Cell::Ch(old)
                if display_width(&old.to_string()) == 2
                    && p + 1 < self.cols
                    && self.cells[r][p + 1] == Cell::Cont =>
            {
                self.cells[r][p + 1] = Cell::Blank;
            }
            _ => {}
        }
    }

    fn nums(&self) -> Vec<usize> {
        String::from_utf8_lossy(&self.params)
            .trim_start_matches(['?', '>', '<', '='])
            .split(';')
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    }

    fn clear_row(&mut self, r: usize, from: usize, to: usize) {
        let to = to.min(self.cols);
        for c in &mut self.cells[r][from.min(to)..to] {
            *c = Cell::Blank;
        }
    }

    fn clear_all(&mut self) {
        for r in 0..self.rows {
            self.clear_row(r, 0, self.cols);
        }
    }

    fn csi(&mut self, fin: u8) {
        let private = self.params.first() == Some(&b'?');
        let n = self.nums();
        let p = |i: usize| n.get(i).copied().unwrap_or(0);
        let one = |i: usize| p(i).max(1);
        let (cols, rows) = (self.cols, self.rows);
        if private {
            if matches!(fin, b'h' | b'l') && n.iter().any(|v| matches!(v, 47 | 1047 | 1049)) {
                self.clear_all();
            }
            return;
        }
        match fin {
            b'H' | b'f' => {
                self.row = (one(0) - 1).min(rows - 1);
                self.col = (one(1) - 1).min(cols - 1);
            }
            b'A' => self.row = self.row.saturating_sub(one(0)),
            b'B' => self.row = (self.row + one(0)).min(rows - 1),
            b'C' => self.col = (self.col + one(0)).min(cols - 1),
            b'D' => self.col = self.col.saturating_sub(one(0)),
            b'E' => {
                self.row = (self.row + one(0)).min(rows - 1);
                self.col = 0;
            }
            b'F' => {
                self.row = self.row.saturating_sub(one(0));
                self.col = 0;
            }
            b'G' | b'`' => self.col = (one(0) - 1).min(cols - 1),
            b'd' => self.row = (one(0) - 1).min(rows - 1),
            b'J' => match p(0) {
                0 => {
                    self.clear_row(self.row, self.col, cols);
                    for r in self.row + 1..rows {
                        self.clear_row(r, 0, cols);
                    }
                }
                1 => {
                    for r in 0..self.row {
                        self.clear_row(r, 0, cols);
                    }
                    self.clear_row(self.row, 0, self.col + 1);
                }
                _ => self.clear_all(),
            },
            b'K' => match p(0) {
                0 => self.clear_row(self.row, self.col, cols),
                1 => self.clear_row(self.row, 0, self.col + 1),
                _ => self.clear_row(self.row, 0, cols),
            },
            b'X' => self.clear_row(self.row, self.col, self.col + one(0)),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// crossterm가 넓은 글자마다 커서 이동을 끼워 쓰는 모양.
    fn ratatui_like(row: u16, col: u16, s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut x = col;
        for c in s.chars() {
            out.extend_from_slice(format!("\x1b[{};{}H\x1b[38;5;2m", row + 1, x + 1).as_bytes());
            out.extend_from_slice(c.to_string().as_bytes());
            x += display_width(&c.to_string()) as u16;
        }
        out
    }

    #[test]
    fn finds_korean_text_written_with_cursor_moves_between_cells() {
        let mut s = Screen::new(60, 20);
        let bytes = ratatui_like(9, 3, "창을 조금 키워 주세요.");
        assert!(!String::from_utf8_lossy(&bytes).contains("창을 조금 키워 주세요"));
        s.feed(b"\x1b[?1049h\x1b[2J");
        s.feed(&bytes);
        assert!(s.contains("창을 조금 키워 주세요."));
        assert_eq!(s.nonblank_rows(), 1);
    }

    #[test]
    fn utf8_split_across_feeds_and_clears() {
        let mut s = Screen::new(20, 3);
        let b = "지킴이: 알림만".as_bytes();
        s.feed(&b[..4]);
        s.feed(&b[4..]);
        assert!(s.contains("지킴이: 알림만"));
        s.feed(b"\x1b[1;1H\x1b[2K");
        assert!(!s.contains("지킴이"));
        s.feed("가나\r\n다".as_bytes());
        assert_eq!(s.text().lines().take(2).collect::<Vec<_>>(), ["가나", "다"]);
        s.feed(b"\x1b]0;title\x07\x1b[2J");
        assert_eq!(s.nonblank_rows(), 0);
    }

    #[test]
    fn resize_keeps_grid_consistent_and_wraps() {
        let mut s = Screen::new(4, 2);
        s.feed("ab가나".as_bytes());
        assert_eq!(s.text(), "ab가\n나");
        s.resize(80, 24);
        s.feed(b"\x1b[24;79Hxyz");
        assert!(s.text().ends_with("z"));
    }

    /// ratatui 버퍼 칸: 넓은 글자는 [글자, " "](뒤 반은 공백 칸으로 둔다).
    fn cells_of(s: &str) -> Vec<(String, bool)> {
        let mut v = Vec::new();
        for c in s.chars() {
            v.push((c.to_string(), false));
            if display_width(&c.to_string()) == 2 {
                v.push((" ".to_string(), true));
            }
        }
        v
    }

    /// ratatui 차분 그리기: 앞 화면과 다른 칸만, 넓은 글자의 뒤 반은 건너뛰고 커서 이동과 함께 쓴다.
    fn ratatui_diff(row: u16, old: &str, new: &str) -> Vec<u8> {
        let (o, n) = (cells_of(old), cells_of(new));
        let blank = (" ".to_string(), false);
        let mut out = Vec::new();
        for i in 0..o.len().max(n.len()) {
            let nc = n.get(i).unwrap_or(&blank);
            let oc = o.get(i).unwrap_or(&blank);
            if nc.1 || nc.0 == oc.0 {
                continue;
            }
            out.extend_from_slice(format!("\x1b[{};{}H", row + 1, i + 1).as_bytes());
            out.extend_from_slice(nc.0.as_bytes());
        }
        out
    }

    #[test]
    fn narrow_over_wide_half_leaves_space() {
        let mut s = Screen::new(20, 2);
        s.feed("가나다".as_bytes());
        s.feed(b"\x1b[1;1Ha\x1b[1;3Hb");
        assert_eq!(s.text().lines().next(), Some("a b 다"));
        s.feed("\x1b[2;1Hxy\x1b[2;2H가".as_bytes());
        assert_eq!(s.text().lines().nth(1), Some("x가"));
        s.feed("\x1b[2;1H나\x1b[2;2H다".as_bytes());
        assert_eq!(s.text().lines().nth(1), Some(" 다"));
        s.feed("\x1b[2;3H라".as_bytes());
        assert_eq!(s.text().lines().nth(1), Some("  라"));
    }

    #[test]
    fn h1_guard_line_diff_redraw_keeps_spaces() {
        let old =
            "─ 지킴이 보고만(STOPCAT_GUARD_LEVEL 고정) · 켜짐 · 첫 확인 중 · STOPCAT_E2E_ALLOW_PIDS 잠금 ─";
        let new = "─ 지킴이 보고만(STOPCAT_GUARD_LEVEL 고정) · 불안정 — 보고만(자동 정리 안 함) · 자동 종료 0/5(10분) ─";
        assert!(display_width(old) <= 100 && display_width(new) <= 100);
        let mut s = Screen::new(100, 30);
        s.feed(&ratatui_like(28, 0, old));
        s.feed(&ratatui_diff(28, old, new));
        let row = s.text().lines().nth(28).unwrap_or_default().to_string();
        assert_eq!(row, new);
        assert!(s.contains("불안정 — 보고만(자동 정리 안 함)"));
    }
}
