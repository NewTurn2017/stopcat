//! 상태 폴더: 감사 로그(audit.jsonl)와 부활 기록(revive/*.json). 파일 0600, 폴더 0700.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use vh_model::ReviveRecord;

use crate::{AuditEntry, audit_log_path, revive_dir};

const STATE_ENV: &str = "VH_STATE_DIR";

/// `VH_STATE_DIR`(비어 있지 않으면, 상대 경로는 cwd 기준) → `$HOME/Library/Application Support/vibe-health`.
pub(crate) fn resolve_state_dir(
    vh_state_dir: Option<OsString>,
    home: Option<OsString>,
    cwd: &Path,
) -> io::Result<PathBuf> {
    if let Some(v) = vh_state_dir.filter(|v| !v.is_empty()) {
        let p = PathBuf::from(v);
        return Ok(if p.is_absolute() { p } else { cwd.join(p) });
    }
    match home.filter(|h| !h.is_empty()) {
        Some(h) => Ok(PathBuf::from(h).join("Library/Application Support/vibe-health")),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "VH_STATE_DIR과 HOME이 모두 없어 상태 폴더를 정할 수 없습니다",
        )),
    }
}

pub(crate) fn ensure_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

pub(crate) fn state_dir() -> io::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    let dir = resolve_state_dir(std::env::var_os(STATE_ENV), std::env::var_os("HOME"), &cwd)?;
    ensure_dir(&dir)?;
    Ok(dir)
}

fn force_0600(f: &fs::File) -> io::Result<()> {
    if f.metadata()?.permissions().mode() & 0o777 != 0o600 {
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// 한 줄을 O_APPEND로 한 번에 쓴다.
pub(crate) fn append_audit(state: &Path, entry: &AuditEntry) -> io::Result<()> {
    ensure_dir(state)?;
    let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(audit_log_path(state))?;
    force_0600(&f)?;
    f.write_all(&line)?;
    f.flush()
}

/// 임시 파일(0600)에 쓰고 fsync 뒤 rename. 같은 ProcRef는 덮어쓴다.
pub(crate) fn write_revive(state: &Path, rec: &ReviveRecord, self_pid: i32) -> io::Result<PathBuf> {
    let dir = revive_dir(state);
    ensure_dir(&dir)?;
    let name = format!("{}-{}.json", rec.target.pid, rec.target.start_time_unix_ms);
    let tmp = dir.join(format!(".tmp-{self_pid}-{name}"));
    let fin = dir.join(name);
    let body = serde_json::to_vec_pretty(rec).map_err(io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        force_0600(&f)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &fin)?;
    Ok(fin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vh_state_dir_wins_over_home() {
        let cwd = Path::new("/work");
        let got =
            resolve_state_dir(Some("/tmp/vh-x".into()), Some("/Users/demo".into()), cwd).unwrap();
        assert_eq!(got, PathBuf::from("/tmp/vh-x"));
    }

    #[test]
    fn relative_vh_state_dir_is_cwd_based() {
        let got = resolve_state_dir(
            Some("state".into()),
            Some("/Users/demo".into()),
            Path::new("/work"),
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/work/state"));
    }

    #[test]
    fn empty_vh_state_dir_falls_back_to_home() {
        let got = resolve_state_dir(Some("".into()), Some("/Users/demo".into()), Path::new("/w"))
            .unwrap();
        assert_eq!(
            got,
            PathBuf::from("/Users/demo/Library/Application Support/vibe-health")
        );
    }

    #[test]
    fn no_env_no_home_is_error() {
        assert!(resolve_state_dir(None, None, Path::new("/w")).is_err());
    }
}
