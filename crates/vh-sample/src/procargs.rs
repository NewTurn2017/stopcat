//! KERN_PROCARGS2 읽기와 해석.
//!
//! 형식: [i32 argc][exec_path\0][\0 패딩][argv × argc, 각 \0][env 문자열…][\0][apple 문자열…].
//! 패딩은 문자열 영역(오프셋 4)부터 센 exec_path 길이(NUL 포함)를 8바이트 경계로 맞추는 만큼이다
//! (이 맥 자기 프로세스 1,581개 전부에서 확인). NUL을 모두 건너뛰면 빈 argv[0]이 사라지고
//! env 첫 문자열이 argv로 밀려 들어오므로, 정확히 패딩만큼만 건너뛴다.
//! env는 `ENV_ALLOWLIST` 키만 값과 함께 남긴다. 나머지 키의 값은 문자열로 만들지 않는다.

use std::collections::BTreeMap;
use std::ptr::null_mut;

use libc::c_int;
use vh_model::ENV_ALLOWLIST;

use crate::ffi;

/// argc가 이보다 크면 깨진 버퍼로 본다.
const MAX_ARGC: i32 = 1 << 16;

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ParsedArgs {
    pub argv: Vec<String>,
    pub argv_readable: bool,
    pub env: BTreeMap<String, String>,
    pub env_readable: bool,
}

/// kern.argmax (KERN_PROCARGS2 버퍼 크기). 실패하면 1 MiB.
pub(crate) fn argmax() -> usize {
    let mut mib: [c_int; 2] = [libc::CTL_KERN, ffi::KERN_ARGMAX];
    let mut v: c_int = 0;
    let mut len = std::mem::size_of::<c_int>();
    // SAFETY: v는 c_int 크기.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut v as *mut c_int).cast(),
            &mut len,
            null_mut(),
            0,
        )
    };
    if rc == 0 && v > 0 {
        v as usize
    } else {
        1 << 20
    }
}

/// 버퍼에 KERN_PROCARGS2를 읽고 쓴 바이트 수를 돌려준다.
pub(crate) fn read(pid: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let mut mib: [c_int; 3] = [libc::CTL_KERN, ffi::KERN_PROCARGS2, pid];
    let mut len = buf.len();
    // SAFETY: buf는 len 바이트다.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            null_mut(),
            0,
        )
    };
    if rc == 0 {
        Ok(len.min(buf.len()))
    } else {
        Err(ffi::errno())
    }
}

fn next_str(data: &[u8], pos: usize) -> Option<(&[u8], usize, bool)> {
    let rest = data.get(pos..)?;
    if rest.is_empty() {
        return None;
    }
    match rest.iter().position(|&c| c == 0) {
        Some(e) => Some((&rest[..e], pos + e + 1, true)),
        None => Some((rest, data.len(), false)),
    }
}

fn env_key(entry: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = entry.iter().position(|&c| c == b'=')?;
    let key = &entry[..eq];
    if key.is_empty() || !key.iter().all(|&c| (0x21..=0x7e).contains(&c)) {
        return None;
    }
    Some((key, &entry[eq + 1..]))
}

/// exec_path(NUL 포함 `len` 바이트) 뒤 8바이트 정렬 패딩 길이.
pub(crate) fn exec_path_padding(len: usize) -> usize {
    (8 - len % 8) % 8
}

/// 순수 해석 함수. 패닉하지 않는다.
pub(crate) fn parse(data: &[u8]) -> ParsedArgs {
    let mut out = ParsedArgs::default();
    if data.len() < 4 {
        return out;
    }
    let argc = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if argc <= 0 || argc > MAX_ARGC {
        return out;
    }
    // exec_path
    let Some((_, mut pos, terminated)) = next_str(data, 4) else {
        return out;
    };
    if !terminated {
        return out;
    }
    let pad = exec_path_padding(pos - 4);
    match data.get(pos..pos + pad) {
        Some(p) if p.iter().all(|&c| c == 0) => pos += pad,
        // 배치가 예상과 다르면 argv 시작을 추측하지 않는다(env가 argv로 섞이는 것을 막는다).
        _ => return out,
    }
    let mut complete = true;
    for _ in 0..argc {
        match next_str(data, pos) {
            Some((s, next, terminated)) => {
                out.argv.push(String::from_utf8_lossy(s).into_owned());
                pos = next;
                if !terminated {
                    complete = false;
                    break;
                }
            }
            None => {
                complete = false;
                break;
            }
        }
    }
    out.argv_readable = complete;
    if !complete {
        return out;
    }
    let mut env_count = 0usize;
    while let Some((entry, next, _)) = next_str(data, pos) {
        if entry.is_empty() {
            break;
        }
        let Some((key, value)) = env_key(entry) else {
            break;
        };
        env_count += 1;
        if ENV_ALLOWLIST.iter().any(|k| k.as_bytes() == key) {
            out.env.insert(
                String::from_utf8_lossy(key).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
        pos = next;
    }
    out.env_readable = env_count > 0;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(argc: i32, parts: &[&[u8]]) -> Vec<u8> {
        let mut v = argc.to_ne_bytes().to_vec();
        for p in parts {
            v.extend_from_slice(p);
        }
        v
    }

    /// 커널과 같은 배치: argc, exec_path\0, 8바이트 정렬 패딩, argv, 나머지.
    fn layout(exec: &[u8], argv: &[&[u8]], rest: &[u8]) -> Vec<u8> {
        let mut v = (argv.len() as i32).to_ne_bytes().to_vec();
        v.extend_from_slice(exec);
        v.push(0);
        v.extend(std::iter::repeat_n(0u8, exec_path_padding(exec.len() + 1)));
        for a in argv {
            v.extend_from_slice(a);
            v.push(0);
        }
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn exec_path_padding_aligns_to_8() {
        assert_eq!(exec_path_padding(8), 0);
        assert_eq!(exec_path_padding(7), 1);
        assert_eq!(exec_path_padding(9), 7);
        assert_eq!(exec_path_padding(23), 1);
    }

    #[test]
    fn procargs_normal() {
        let data = layout(
            b"/opt/homebrew/bin/node",
            &[b"node", b"server.js", b"--port"],
            b"CLAUDE_PID=4242\0HOME_LIKE=/Users/demo\0VH_TAG=shop\0OTHER_VAR=x\0\0executable_path=/opt/homebrew/bin/node\0ptr_munge=\0",
        );
        let p = parse(&data);
        assert_eq!(p.argv, ["node", "server.js", "--port"]);
        assert!(p.argv_readable);
        assert!(p.env_readable);
        let keys: Vec<&str> = p.env.keys().map(String::as_str).collect();
        assert_eq!(keys, ["CLAUDE_PID", "VH_TAG"]);
        assert_eq!(p.env["CLAUDE_PID"], "4242");
    }

    #[test]
    fn procargs_empty_argv0_preserved() {
        // exec_path 길이별로 패딩 0~7을 모두 확인한다. env 문자열이 argv로 밀려 들어오면 안 된다.
        for n in 1..=8 {
            let exec = format!("/bin/{}", "s".repeat(n));
            let data = layout(
                exec.as_bytes(),
                &[b"", b"-c", b"", b"end"],
                b"VH_TAG=a\0OTHER_VAR=b\0\0",
            );
            let p = parse(&data);
            assert_eq!(p.argv, ["", "-c", "", "end"], "exec 길이 {}", exec.len());
            assert!(p.argv_readable);
            assert_eq!(p.env.len(), 1);
            assert!(p.env_readable);
        }
    }

    #[test]
    fn procargs_zero_padding() {
        let data = layout(b"/bin/sh", &[b"sh", b"-c"], b"VH_TAG=a\0");
        assert_eq!(exec_path_padding(b"/bin/sh".len() + 1), 0);
        assert_eq!(parse(&data).argv, ["sh", "-c"]);
    }

    #[test]
    fn procargs_unexpected_padding_is_unreadable() {
        // 패딩 자리(1바이트)에 NUL이 아닌 값이 있으면 argv 시작을 추측하지 않는다.
        let data = buf(1, &[b"/bin/x\0", b"Zarg\0VH_TAG=a\0"]);
        let p = parse(&data);
        assert!(!p.argv_readable);
        assert!(p.argv.is_empty() && p.env.is_empty());
        // 패딩이 버퍼 끝을 넘는 경우.
        assert!(!parse(&buf(1, &[b"/bin/x\0"])).argv_readable);
    }

    #[test]
    fn procargs_control_chars_and_utf8_kept_raw() {
        let data = layout(
            b"/bin/x",
            &["a\tb\nc".as_bytes(), "한글 인자".as_bytes()],
            b"",
        );
        let p = parse(&data);
        assert_eq!(p.argv, ["a\tb\nc", "한글 인자"]);
    }

    #[test]
    fn procargs_title_rewritten() {
        let mut tail = b"npm exec demo-mcp".to_vec();
        tail.extend(std::iter::repeat_n(0u8, 300));
        let data = buf(3, &[b"/opt/homebrew/bin/node\0\0", &tail]);
        let p = parse(&data);
        assert_eq!(p.argv, ["npm exec demo-mcp", "", ""]);
        assert!(p.argv_readable);
        assert!(p.env.is_empty());
        assert!(!p.env_readable);
    }

    #[test]
    fn procargs_garbage_env() {
        let data = buf(
            1,
            &[b"/bin/x\0\0", b"x\0", b"garbage-without-eq\0CLAUDE_PID=1\0"],
        );
        let p = parse(&data);
        assert!(p.argv_readable);
        assert!(!p.env_readable);
        assert!(p.env.is_empty());
    }

    #[test]
    fn procargs_truncated() {
        let data = buf(5, &[b"/bin/x\0\0", b"a\0bb"]);
        let p = parse(&data);
        assert_eq!(p.argv, ["a", "bb"]);
        assert!(!p.argv_readable);
        assert!(!p.env_readable);
    }

    #[test]
    fn procargs_bad_argc() {
        for argc in [-1, 0, 100_000] {
            let p = parse(&buf(argc, &[b"/bin/x\0\0a\0"]));
            assert!(!p.argv_readable, "argc {argc}");
            assert!(p.argv.is_empty());
        }
        assert_eq!(parse(&[1, 0]), ParsedArgs::default());
        assert_eq!(parse(&buf(1, &[b"/no/terminator"])), ParsedArgs::default());
    }

    #[test]
    fn procargs_non_utf8() {
        let data = buf(1, &[b"/bin/x\0\0", b"a\xff\xfeb\0"]);
        let p = parse(&data);
        assert!(p.argv_readable);
        assert_eq!(p.argv.len(), 1);
        assert!(p.argv[0].starts_with('a') && p.argv[0].ends_with('b'));
    }

    #[test]
    fn procargs_drops_non_allowlisted() {
        let marker = "zq-value-that-must-not-survive";
        let entry = format!("SECRET_THING{}{marker}\0", '=');
        let data = buf(1, &[b"/bin/x\0\0", b"x\0", entry.as_bytes(), b"VH_TAG=a\0"]);
        let p = parse(&data);
        assert!(p.env_readable);
        assert_eq!(p.env.len(), 1);
        assert!(!format!("{p:?}").contains(marker));
    }
}
