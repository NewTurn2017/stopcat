//! KERN_PROCARGS2 읽기와 해석.
//!
//! 형식: [i32 argc][exec_path\0][\0 패딩…][argv × argc, 각 \0][env 문자열…][\0][apple 문자열…].
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
    while data.get(pos) == Some(&0) {
        pos += 1;
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

    #[test]
    fn procargs_normal() {
        let data = buf(
            3,
            &[
                b"/opt/homebrew/bin/node\0\0\0\0",
                b"node\0server.js\0--port\0",
                b"CLAUDE_PID=4242\0HOME_LIKE=/Users/demo\0VH_TAG=shop\0OTHER_VAR=x\0",
                b"\0",
                b"executable_path=/opt/homebrew/bin/node\0ptr_munge=\0",
            ],
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
