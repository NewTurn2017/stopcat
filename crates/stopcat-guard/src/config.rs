//! `<state_dir>/config.json` 읽기·쓰기와 효력 수준(`STOPCAT_GUARD_LEVEL` > 설정 > Safe).

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use stopcat_model::{AutoLevel, StopcatConfig};

pub fn config_path(state_dir: &Path) -> PathBuf {
    state_dir.join("config.json")
}

/// 없으면 `Ok(None)`(처음 실행). 깨진 JSON은 `InvalidData`.
pub fn load(state_dir: &Path) -> io::Result<Option<StopcatConfig>> {
    let text = match fs::read_to_string(config_path(state_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 폴더 0700, 임시 파일 0600에 쓰고 fsync 뒤 rename(원자적).
pub fn save(state_dir: &Path, config: &StopcatConfig) -> io::Result<()> {
    if !state_dir.is_dir() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
    }
    let fin = config_path(state_dir);
    let tmp = state_dir.join(format!(".tmp-config-{}.json", std::process::id()));
    let body = serde_json::to_vec_pretty(config).map_err(io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &fin)
}

/// 효력 수준.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLevel {
    pub level: AutoLevel,
    /// `STOPCAT_GUARD_LEVEL`로 고정(화면에서 못 바꿈).
    pub locked_by_env: bool,
    /// 이상한 env 값이면 경고 문구(수준은 NotifyOnly로 내려간다).
    pub warning_ko: Option<String>,
}

/// `env_value`(비어 있지 않은 `STOPCAT_GUARD_LEVEL`) > `config.auto_level` > Safe.
/// env 값을 모르면 NotifyOnly(닫힌 쪽) + 경고.
pub fn effective_level(env_value: Option<&str>, config: Option<&StopcatConfig>) -> EffectiveLevel {
    match env_value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => match AutoLevel::from_env_value(v) {
            Some(level) => EffectiveLevel {
                level,
                locked_by_env: true,
                warning_ko: None,
            },
            None => EffectiveLevel {
                level: AutoLevel::NotifyOnly,
                locked_by_env: true,
                warning_ko: Some(format!(
                    "STOPCAT_GUARD_LEVEL 값 '{v}'을(를) 모르겠어요. notify|safe|aggressive 중 하나여야 해요. 알림만으로 둡니다"
                )),
            },
        },
        None => EffectiveLevel {
            level: config.map(|c| c.auto_level).unwrap_or(AutoLevel::Safe),
            locked_by_env: false,
            warning_ko: None,
        },
    }
}
