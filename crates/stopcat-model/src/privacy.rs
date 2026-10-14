//! 개인정보: env 허용 목록, argv 마스킹, 표시용 경로.
//!
//! `redact_argv` 규칙(키 이름은 남기고 값만 `<가림>`으로 바꾼다):
//! 1. 민감 키 판정(단어 단위): 키를 `_` `-` `.` 와 camelCase·숫자 경계로 나눈 조각 중 하나가
//!    key, keys, apikey, token, tokens, secret, secrets, auth, authorization, bearer, cookie, cookies 이거나
//!    passw 로 시작하면 민감 키다(대소문자 무시).
//! 2. `KEY=VALUE`, `--opt=VALUE` 에서 키가 민감하면 값을 가린다.
//! 3. `--opt VALUE` 에서 플래그가 민감하면 다음 인자 전체를 가린다.
//! 4. URL 쿼리 파라미터 이름이 민감하면 값만 가린다.
//! 5. `Bearer` 뒤 값을 가린다.
//! 6. 인자 안 어디서든 sk- 키, GitHub·Slack 토큰, AWS 키 ID, JWT, URL userinfo 부분만 가린다.
//!
//! 계약 v1.1 보강:
//! 1'. 민감 키 판정 확장: 조각이 credential, credentials, pass 이거나 조각에 passw가 들어 있거나,
//!     구분자를 뺀 키 전체(소문자)가 password, passwd, token, secret, apikey, pwd 로 끝나면 민감
//!     (키 전체가 pwd·oldpwd이면 아님).
//! 7. 인자 안에 박힌 대입 `<민감 키>=<값>`: 값(따옴표로 감쌌으면 따옴표 포함)을 가린다.
//! 8. JSON·사전 모양 `"<민감 키>": "<값>"`, `'<민감 키>': '<값>'`: 따옴표 안 값을 가린다.

/// 수집 단계에서 이 키만 값과 함께 남긴다. 나머지 키와 값은 읽는 즉시 버린다.
pub const ENV_ALLOWLIST: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_PID",
    "CMUX_CLAUDE_PID",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_ENTRYPOINT",
    "CMUX_WORKSPACE_ID",
    "CMUX_SURFACE_ID",
    "CMUX_PANEL_ID",
    "CMUX_TAB_ID",
    "TERM_PROGRAM",
    "PI_SESSION_ID",
    "PI_CODING_AGENT",
    "SENPI_PY_KERNEL_PARENT_PID",
    "npm_lifecycle_event",
    "npm_package_name",
    "INIT_CWD",
    "VSCODE_PID",
    "CURSOR_TRACE_ID",
    "VIRTUAL_ENV",
    "STOPCAT_TAG",
];

/// 가린 값 자리에 들어가는 표시.
pub const REDACTED: &str = "<가림>";

const SENSITIVE_WORDS: &[&str] = &[
    "key",
    "keys",
    "apikey",
    "token",
    "tokens",
    "secret",
    "secrets",
    "auth",
    "authorization",
    "bearer",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "pass",
];

/// 구분자를 뺀 키 전체가 이것으로 끝나면 민감하다(규칙 1').
const SENSITIVE_SUFFIXES: &[&str] = &["password", "passwd", "token", "secret", "apikey", "pwd"];

/// 작업 폴더 변수라서 민감하지 않은 키(규칙 1' 예외).
const NOT_SENSITIVE_KEYS: &[&str] = &["pwd", "oldpwd"];

/// 표시·JSON 출력용 argv 마스킹. 원소 수는 그대로 유지한다.
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut mask_next = false;
    for arg in argv {
        if mask_next {
            mask_next = false;
            out.push(REDACTED.to_string());
            continue;
        }
        if is_sensitive_flag(arg) {
            mask_next = true;
            out.push(arg.clone());
            continue;
        }
        out.push(redact_one(arg));
    }
    out
}

/// 홈 디렉터리를 `~`로 바꾼 표시용 경로.
pub fn display_path(path: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path.to_string();
    }
    if path == home {
        return "~".to_string();
    }
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

/// 키 이름을 단어 조각으로 나눈다(소문자).
fn split_words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' || c == '.' {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if !cur.is_empty() {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let boundary = (prev.is_lowercase() && c.is_uppercase())
                || (prev.is_ascii_digit() != c.is_ascii_digit())
                || (prev.is_uppercase() && c.is_uppercase() && next_lower);
            if boundary {
                words.push(std::mem::take(&mut cur));
            }
        }
        cur.push(c);
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words.into_iter().map(|w| w.to_lowercase()).collect()
}

fn is_sensitive_name(name: &str) -> bool {
    let joined: String = name
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .collect::<String>()
        .to_lowercase();
    if NOT_SENSITIVE_KEYS.contains(&joined.as_str()) {
        return false;
    }
    SENSITIVE_SUFFIXES.iter().any(|s| joined.ends_with(s))
        || split_words(name)
            .iter()
            .any(|w| SENSITIVE_WORDS.contains(&w.as_str()) || w.contains("passw"))
}

/// 따옴표로 시작하는 값의 끝(닫는 따옴표 다음 위치). `"`는 역슬래시 이스케이프를 건너뛴다.
/// 닫는 따옴표가 없으면 문자열 끝.
fn quoted_end(b: &[u8], open: usize) -> usize {
    let q = b[open];
    let mut j = open + 1;
    while j < b.len() {
        if q == b'"' && b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == q {
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

fn is_ident(name: &str) -> bool {
    let mut it = name.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    it.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// 앞의 `-`·`--`를 뗀 이름.
fn strip_dashes(s: &str) -> &str {
    s.strip_prefix("--")
        .or_else(|| s.strip_prefix('-'))
        .unwrap_or(s)
}

fn is_sensitive_flag(arg: &str) -> bool {
    if !arg.starts_with('-') || arg.contains('=') {
        return false;
    }
    let name = strip_dashes(arg);
    is_ident(name) && is_sensitive_name(name)
}

fn redact_one(arg: &str) -> String {
    if let Some(eq) = arg.find('=') {
        let key = &arg[..eq];
        let value = &arg[eq + 1..];
        let name = strip_dashes(key);
        if !value.is_empty() && is_ident(name) && is_sensitive_name(name) {
            return format!("{key}={REDACTED}");
        }
    }
    mask_spans(arg)
}

fn is_tok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn run_end(b: &[u8], from: usize, pred: impl Fn(u8) -> bool) -> usize {
    let mut j = from;
    while j < b.len() && pred(b[j]) {
        j += 1;
    }
    j
}

fn value_byte(b: u8) -> bool {
    !b.is_ascii_whitespace() && b != b'"' && b != b'\''
}

/// 인자 안의 비밀 부분을 찾아 `<가림>`으로 바꾼다. 모든 경계는 ASCII 바이트 위치다.
fn mask_spans(s: &str) -> String {
    let b = s.as_bytes();
    let n = b.len();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let not_redacted = |a: usize, e: usize| a < e && &s[a..e] != REDACTED;

    for i in 0..n {
        let rest = &b[i..];
        let boundary_before = i == 0 || !b[i - 1].is_ascii_alphanumeric();

        // sk- 키: 앞이 영숫자가 아니고 뒤가 [A-Za-z0-9_-] 20자 이상
        if boundary_before && rest.starts_with(b"sk-") {
            let j = run_end(b, i + 3, is_tok);
            if j - (i + 3) >= 20 {
                spans.push((i, j));
            }
        }
        // GitHub 토큰: gh[pousr]_ + 영숫자 20자 이상
        if rest.len() >= 4
            && rest[0] == b'g'
            && rest[1] == b'h'
            && b"pousr".contains(&rest[2])
            && rest[3] == b'_'
        {
            let j = run_end(b, i + 4, |c| c.is_ascii_alphanumeric());
            if j - (i + 4) >= 20 {
                spans.push((i, j));
            }
        }
        // Slack 토큰: xox[abpr]-…
        if rest.len() >= 5
            && rest.starts_with(b"xox")
            && b"abpr".contains(&rest[3])
            && rest[4] == b'-'
        {
            let j = run_end(b, i + 5, |c| c.is_ascii_alphanumeric() || c == b'-');
            if j > i + 5 {
                spans.push((i, j));
            }
        }
        // AWS 키 ID: AKIA + 대문자·숫자 16자
        if rest.starts_with(b"AKIA") {
            let j = run_end(b, i + 4, |c| c.is_ascii_uppercase() || c.is_ascii_digit());
            if j - (i + 4) >= 16 {
                spans.push((i, j));
            }
        }
        // JWT: eyJ… . … . …
        if rest.starts_with(b"eyJ") {
            let j1 = run_end(b, i + 3, is_tok);
            if j1 > i + 3 && j1 < n && b[j1] == b'.' {
                let j2 = run_end(b, j1 + 1, is_tok);
                if j2 > j1 + 1 && j2 < n && b[j2] == b'.' {
                    let j3 = run_end(b, j2 + 1, is_tok);
                    spans.push((i, j3));
                }
            }
        }
        // URL userinfo: scheme://userinfo@host
        if rest.starts_with(b"://") && i > 0 {
            let mut k = i;
            while k > 0
                && (b[k - 1].is_ascii_alphanumeric() || matches!(b[k - 1], b'+' | b'.' | b'-'))
            {
                k -= 1;
            }
            if k < i && b[k].is_ascii_alphabetic() {
                let start = i + 3;
                let j = run_end(b, start, |c| {
                    !c.is_ascii_whitespace() && !matches!(c, b'@' | b'/' | b'?' | b'#')
                });
                if j < n && b[j] == b'@' && not_redacted(start, j) {
                    spans.push((start, j));
                }
            }
        }
        // URL 쿼리: ?name=value 또는 &name=value 에서 name이 민감
        if b[i] == b'?' || b[i] == b'&' {
            let name_end = run_end(b, i + 1, |c| {
                c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')
            });
            if name_end > i + 1 && name_end < n && b[name_end] == b'=' {
                let vstart = name_end + 1;
                let vend = run_end(b, vstart, |c| value_byte(c) && c != b'&' && c != b'#');
                if is_sensitive_name(&s[i + 1..name_end]) && not_redacted(vstart, vend) {
                    spans.push((vstart, vend));
                }
            }
        }
        // Bearer <값>
        if boundary_before && rest.len() > 6 && rest[..6].eq_ignore_ascii_case(b"bearer") {
            let vstart = run_end(b, i + 6, |c| c == b' ');
            if vstart > i + 6 {
                let vend = run_end(b, vstart, value_byte);
                if not_redacted(vstart, vend) {
                    spans.push((vstart, vend));
                }
            }
        }
        // 7. 박힌 대입: 앞이 영숫자·_가 아닌 위치에서 시작하는 <민감 키>=<값>
        let key_start = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if key_start && (b[i].is_ascii_alphabetic() || b[i] == b'_') {
            let kend = run_end(b, i, |c| c.is_ascii_alphanumeric() || c == b'_');
            if kend < n && b[kend] == b'=' && is_sensitive_name(&s[i..kend]) {
                let v = kend + 1;
                let vend = match b.get(v) {
                    Some(b'\'' | b'"') => quoted_end(b, v),
                    _ => run_end(b, v, |c| {
                        !(c.is_ascii_whitespace() || matches!(c, b';' | b'&' | b'|' | b')'))
                    }),
                };
                // 이미 가린 값(<가림>으로 시작)은 다시 가리지 않는다(멱등).
                if v < vend && !s[v..vend].starts_with(REDACTED) {
                    spans.push((v, vend));
                }
            }
        }
        // 8. JSON·사전 모양: "<민감 키>" : "<값>" 또는 '<민감 키>' : '<값>'
        if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i];
            let ks = i + 1;
            let ke = run_end(b, ks, |c| {
                c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
            });
            if ke > ks && ke < n && b[ke] == q {
                let colon = run_end(b, ke + 1, |c| c == b' ' || c == b'\t');
                if colon < n && b[colon] == b':' {
                    let open = run_end(b, colon + 1, |c| c == b' ' || c == b'\t');
                    if open < n && b[open] == q && is_sensitive_name(&s[ks..ke]) {
                        let close = quoted_end(b, open);
                        let vend = if close > open + 1 && b[close - 1] == q {
                            close - 1
                        } else {
                            close
                        };
                        if not_redacted(open + 1, vend) {
                            spans.push((open + 1, vend));
                        }
                    }
                }
            }
        }
    }

    if spans.is_empty() {
        return s.to_string();
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (a, e) in spans {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((a, e)),
        }
    }
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    for (a, e) in merged {
        out.push_str(&s[pos..a]);
        out.push_str(REDACTED);
        pos = e;
    }
    out.push_str(&s[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_words_handles_camel_acronym_and_digits() {
        assert_eq!(split_words("APIKey"), ["api", "key"]);
        assert_eq!(split_words("sessionToken"), ["session", "token"]);
        assert_eq!(split_words("OAuth2Token"), ["o", "auth", "2", "token"]);
        assert_eq!(split_words("KEYBOARD_LAYOUT"), ["keyboard", "layout"]);
    }
}
