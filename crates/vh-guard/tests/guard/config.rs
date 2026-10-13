//! 설정 파일과 효력 수준(Q3 A).

use std::os::unix::fs::PermissionsExt;

use vh_guard::config::{config_path, effective_level, load, save};
use vh_guard::{AutoLevel, VhConfig};

#[test]
fn roundtrip_creates_dir_0700_and_file_0600() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    assert_eq!(load(&state).unwrap(), None, "없으면 None(처음 실행)");
    let c = VhConfig {
        schema_version: 1,
        auto_level: AutoLevel::NotifyOnly,
        first_run_done: true,
        scan_interval_ms: Some(10_000),
    };
    save(&state, &c).unwrap();
    assert_eq!(load(&state).unwrap(), Some(c));
    let dmode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
    let fmode = std::fs::metadata(config_path(&state))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!((dmode, fmode), (0o700, 0o600));
    assert!(
        std::fs::read_dir(&state).unwrap().count() == 1,
        "임시 파일이 남지 않는다"
    );
}

#[test]
fn broken_json_is_invalid_data() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(config_path(dir.path()), "{").unwrap();
    let e = load(dir.path()).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn env_wins_unknown_env_is_notify_only_with_warning() {
    let cfg = VhConfig {
        auto_level: AutoLevel::Aggressive,
        ..VhConfig::default()
    };
    let e = effective_level(Some("notify"), Some(&cfg));
    assert_eq!(
        (e.level, e.locked_by_env, e.warning_ko),
        (AutoLevel::NotifyOnly, true, None)
    );
    let e = effective_level(Some(" SAFE "), Some(&cfg));
    assert_eq!((e.level, e.locked_by_env), (AutoLevel::Safe, true));
    let e = effective_level(Some("yolo"), Some(&cfg));
    assert_eq!((e.level, e.locked_by_env), (AutoLevel::NotifyOnly, true));
    assert!(e.warning_ko.unwrap().contains("yolo"));
    let e = effective_level(Some(""), Some(&cfg));
    assert_eq!(
        (e.level, e.locked_by_env),
        (AutoLevel::Aggressive, false),
        "빈 값은 없는 것"
    );
    let e = effective_level(None, Some(&cfg));
    assert_eq!((e.level, e.locked_by_env), (AutoLevel::Aggressive, false));
    let e = effective_level(None, None);
    assert_eq!(
        (e.level, e.locked_by_env),
        (AutoLevel::Safe, false),
        "설정 없으면 Safe"
    );
}
