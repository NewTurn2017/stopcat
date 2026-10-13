//! 화면 문자열 도구: 크기·기간 표기, 표시 폭(한글 2칸), 자르기·줄 바꿈.

/// 화면 한 줄의 최대 표시 폭.
pub const WIDTH: usize = 80;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// 바이트 → "41GB"(10GB 이상 정수), "7.5GB", "412MB", "96KB", "12B".
pub fn bytes(b: u64) -> String {
    if b >= GIB {
        let v = b as f64 / GIB as f64;
        if v >= 10.0 {
            format!("{}GB", v.round() as u64)
        } else {
            format!("{v:.1}GB")
        }
    } else if b >= MIB {
        format!("{}MB", (b as f64 / MIB as f64).round() as u64)
    } else if b >= KIB {
        format!("{}KB", (b as f64 / KIB as f64).round() as u64)
    } else {
        format!("{b}B")
    }
}

/// 경과 시간(밀리초) → "방금", "12분", "7시간", "3일 4시간", "5일".
pub fn duration(ms: u64) -> String {
    let mins = ms / 60_000;
    if mins < 1 {
        return "방금".to_string();
    }
    if mins < 60 {
        return format!("{mins}분");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}시간");
    }
    let days = hours / 24;
    let rest = hours % 24;
    if rest == 0 {
        format!("{days}일")
    } else {
        format!("{days}일 {rest}시간")
    }
}

/// 밀리초 → "3초", "1.5초".
pub fn secs(ms: u32) -> String {
    if ms.is_multiple_of(1000) {
        format!("{}초", ms / 1000)
    } else {
        format!("{:.1}초", f64::from(ms) / 1000.0)
    }
}

/// 글자 한 개의 표시 폭. 한글·한자·가나·전각은 2칸, 제어 문자는 0칸, 그 밖 1칸.
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    if u < 0x20 || (0x7f..0xa0).contains(&u) {
        return 0;
    }
    let wide = matches!(
        u,
        0x1100..=0x115F
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA000..=0xA4CF
            | 0xA960..=0xA97F
            | 0xAC00..=0xD7A3
            | 0xD7B0..=0xD7FF
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F900..=0x1F9FF
            | 0x20000..=0x3FFFD
    );
    if wide { 2 } else { 1 }
}

pub fn width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// 표시 폭이 `max`를 넘으면 잘라 끝에 "…"를 붙인다.
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw + 1 > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// 오른쪽을 공백으로 채워 표시 폭 `w`로 맞춘다(넘으면 그대로).
pub fn pad(s: &str, w: usize) -> String {
    let cur = width(s);
    if cur >= w {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(w - cur))
    }
}

/// 왼쪽을 공백으로 채워 표시 폭 `w`로 맞춘다.
pub fn lpad(s: &str, w: usize) -> String {
    let cur = width(s);
    if cur >= w {
        s.to_string()
    } else {
        format!("{}{s}", " ".repeat(w - cur))
    }
}

/// 공백 기준 줄 바꿈. 첫 줄은 `first`, 다음 줄은 `cont`로 시작하고 모든 줄 폭 ≤ `max`.
pub fn wrap(text: &str, max: usize, first: &str, cont: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = first.to_string();
    let mut has_word = false;
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let sep = usize::from(has_word);
        if width(&cur) + sep + width(word) <= max {
            if has_word {
                cur.push(' ');
            }
            cur.push_str(word);
            has_word = true;
            continue;
        }
        if has_word {
            lines.push(std::mem::replace(&mut cur, cont.to_string()));
        }
        // 빈 줄에도 안 들어가는 긴 낱말은 글자 단위로 나눈다.
        for c in word.chars() {
            if width(&cur) + char_width(c) > max {
                lines.push(std::mem::replace(&mut cur, cont.to_string()));
            }
            cur.push(c);
        }
        has_word = true;
    }
    if has_word || lines.is_empty() {
        lines.push(cur);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(bytes(0), "0B");
        assert_eq!(bytes(96 * KIB), "96KB");
        assert_eq!(bytes(412 * MIB), "412MB");
        assert_eq!(bytes(GIB), "1.0GB");
        assert_eq!(bytes(7 * GIB + GIB / 2), "7.5GB");
        assert_eq!(bytes(41 * GIB), "41GB");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(59_000), "방금");
        assert_eq!(duration(12 * 60_000), "12분");
        assert_eq!(duration(7 * 3_600_000), "7시간");
        assert_eq!(duration((3 * 24 + 4) * 3_600_000), "3일 4시간");
        assert_eq!(duration(5 * 24 * 3_600_000), "5일");
        assert_eq!(secs(3000), "3초");
        assert_eq!(secs(1500), "1.5초");
    }

    #[test]
    fn widths_and_wrap() {
        assert_eq!(width("메모리 정상"), 11);
        assert_eq!(truncate("가나다라마", 7), "가나다…");
        for l in wrap(
            "아주 긴 문장을 여러 줄로 나눠 봅니다 정말로",
            12,
            "> ",
            "  ",
        ) {
            assert!(width(&l) <= 12, "{l}");
        }
        assert_eq!(wrap("", 10, "a", "b"), vec!["a".to_string()]);
    }
}
