//! 감독 ↔ 도우미 약속(env 이름, 실행 명세). 도우미 env는 모두 `env_clear()` 뒤 이것만 받는다.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const ROLE: &str = "VH_LAB_ROLE";
pub const SUPERVISOR: &str = "VH_LAB_SUPERVISOR";
pub const MAX_SECS: &str = "VH_LAB_MAX_SECS";
pub const LOG: &str = "VH_LAB_LOG";
pub const SPIN_THREADS: &str = "VH_LAB_SPIN_THREADS";
pub const SPIN_SECS: &str = "VH_LAB_SPIN_SECS";
pub const SPIN_STOP_ON_DEMOTE: &str = "VH_LAB_SPIN_STOP_ON_DEMOTE";
pub const MEM_KB_PER_SEC: &str = "VH_LAB_MEM_KB_PER_SEC";
pub const MEM_MAX_MB: &str = "VH_LAB_MEM_MAX_MB";
pub const LISTEN: &str = "VH_LAB_LISTEN";
pub const SPAWN: &str = "VH_LAB_SPAWN";
pub const FANOUT: &str = "VH_LAB_FANOUT";
pub const FLICKER_MAX: &str = "VH_LAB_FLICKER_MAX";
pub const FLICKER_SECS: &str = "VH_LAB_FLICKER_SECS";
pub const TAG: &str = "VH_TAG";

/// 도우미 복사본 이름(전부 같은 바이너리).
pub const HELPER_NAMES: &[&str] = &[
    "node",
    "qemu-system-aarch64",
    "claude",
    "lab-anchor",
    "lab-idle",
    "lab-spin",
    "lab-mem",
    "lab-zombie",
    "lab-fanout",
    "lab-exit",
    "lab-flicker",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Idle,
    Spin,
    Mem,
    Zombie,
    Fanout,
    Exit,
    Flicker,
    Blip,
    Selftest,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Idle => "idle",
            Role::Spin => "spin",
            Role::Mem => "mem",
            Role::Zombie => "zombie",
            Role::Fanout => "fanout",
            Role::Exit => "exit",
            Role::Flicker => "flicker",
            Role::Blip => "blip",
            Role::Selftest => "selftest",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "idle" => Role::Idle,
            "spin" => Role::Spin,
            "mem" => Role::Mem,
            "zombie" => Role::Zombie,
            "fanout" => Role::Fanout,
            "exit" => Role::Exit,
            "flicker" => Role::Flicker,
            "blip" => Role::Blip,
            "selftest" => Role::Selftest,
            _ => return None,
        })
    }
}

/// 도우미가 자식으로 띄울(SPAWN) 또는 fork+exec로 ppid 1에 놓을(FANOUT) 프로세스 하나.
/// `count > 1`이면 argv·cwd의 `{i}`를 0..count로 바꾼다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecSpec {
    pub exe: String,
    pub argv: Vec<String>,
    /// 있으면 argv 대신 이 16진 바이트열을 쓴다(잘못된 UTF-8 인자 시험).
    #[serde(default)]
    pub argv_hex: Option<Vec<String>>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
    #[serde(default = "one")]
    pub count: u32,
}

fn one() -> u32 {
    1
}

impl ExecSpec {
    pub fn expand(&self) -> Vec<ExecSpec> {
        if self.count <= 1 {
            return vec![ExecSpec {
                count: 1,
                ..self.clone()
            }];
        }
        (0..self.count)
            .map(|i| {
                let sub = |s: &String| s.replace("{i}", &i.to_string());
                ExecSpec {
                    exe: self.exe.clone(),
                    argv: self.argv.iter().map(sub).collect(),
                    argv_hex: self.argv_hex.clone(),
                    cwd: sub(&self.cwd),
                    env: self.env.iter().map(|(k, v)| (k.clone(), sub(v))).collect(),
                    count: 1,
                }
            })
            .collect()
    }

    pub fn argv_bytes(&self) -> Vec<Vec<u8>> {
        match &self.argv_hex {
            Some(hex) => hex.iter().map(|h| decode_hex(h)).collect(),
            None => self.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        }
    }
}

pub fn encode_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn decode_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .filter_map(|c| u8::from_str_radix(c, 16).ok())
        .collect()
}

/// "pid:start_ms".
pub fn parse_proc_ref(s: &str) -> Option<vh_model::ProcRef> {
    let (p, st) = s.split_once(':')?;
    Some(vh_model::ProcRef {
        pid: p.parse().ok()?,
        start_time_unix_ms: st.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_substitutes_index() {
        let s = ExecSpec {
            exe: "/x/node".into(),
            argv: vec!["node".into(), "/w/{i}/index.js".into()],
            argv_hex: None,
            cwd: "/w/{i}".into(),
            env: BTreeMap::from([("CLAUDE_PID".into(), "9{i}".into())]),
            count: 3,
        };
        let e = s.expand();
        assert_eq!(e.len(), 3);
        assert_eq!(e[2].argv[1], "/w/2/index.js");
        assert_eq!(e[1].cwd, "/w/1");
        assert_eq!(e[0].env["CLAUDE_PID"], "90");
    }

    #[test]
    fn hex_roundtrip_keeps_invalid_utf8() {
        let raw = [0xffu8, 0xfe, b'a'];
        assert_eq!(decode_hex(&encode_hex(&raw)), raw);
    }
}
