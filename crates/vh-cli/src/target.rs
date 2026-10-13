//! `vh why`·`vh kill` 대상 해석: `:5000`은 포트, 숫자만이면 프로세스 번호.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Pid(i32),
    Port(u16),
}

impl Target {
    /// 화면 표기: ":5000" 또는 "4821".
    pub fn display(&self) -> String {
        match self {
            Target::Pid(p) => p.to_string(),
            Target::Port(p) => format!(":{p}"),
        }
    }
}

/// 대상 문자열을 해석한다. 실패하면 사용법 오류 문구(한국어)를 돌려준다.
pub fn parse(raw: &str) -> Result<Target, String> {
    let s = raw.trim();
    let bad = || format!("대상을 알아볼 수 없어요: '{raw}'");
    if let Some(port) = s.strip_prefix(':') {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        return match port.parse::<u32>() {
            Ok(p) if (1..=65535).contains(&p) => Ok(Target::Port(p as u16)),
            _ => Err(format!("포트 번호는 1~65535 사이여야 해요: '{raw}'")),
        };
    }
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    match s.parse::<i64>() {
        Ok(p) if (1..=i64::from(i32::MAX)).contains(&p) => Ok(Target::Pid(p as i32)),
        _ => Err(format!("프로세스 번호는 1 이상이어야 해요: '{raw}'")),
    }
}

/// 대상 형식 오류 때 덧붙이는 안내.
pub const TARGET_HINT: &str =
    "프로세스 번호(예: 4821)나 콜론을 붙인 포트(예: :5000)를 넣어 주세요.";
