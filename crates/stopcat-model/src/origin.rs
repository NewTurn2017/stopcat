//! 실행 파일 출처 판정 (stopcat-analyze와 stopcat-act가 같이 쓴다).

use serde::{Deserialize, Serialize};

/// 실행 파일이 어디서 왔는지.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExeOrigin {
    System,
    Platform,
    AppBundle,
    DevToolBundle,
    User,
    Unknown,
}

const SYSTEM_PREFIXES: &[&str] = &[
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/sbin/",
    "/Library/Apple/",
];
const APP_PREFIXES: &[&str] = &["/Applications/", "/System/Applications/", "/Library/"];
const PLATFORM_PREFIXES: &[&str] = &["/usr/bin/", "/bin/"];

/// 위에서부터 처음 맞는 규칙(경로 문자열 그대로, 심볼릭 링크 해석 없음).
pub fn exe_origin(exe: Option<&str>) -> ExeOrigin {
    let path = match exe {
        Some(p) if !p.is_empty() => p,
        _ => return ExeOrigin::Unknown,
    };
    if SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return ExeOrigin::System;
    }
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let parents = &components[..components.len().saturating_sub(1)];
    if parents
        .iter()
        .any(|c| c.ends_with(".xpc") || c.ends_with(".appex"))
    {
        return ExeOrigin::AppBundle;
    }
    if path.contains("/Contents/Developer/") {
        return ExeOrigin::DevToolBundle;
    }
    let apps: Vec<&&str> = components.iter().filter(|c| c.ends_with(".app")).collect();
    if apps.len() == 1 && *apps[0] == "Python.app" && path.ends_with("Contents/MacOS/Python") {
        return ExeOrigin::DevToolBundle;
    }
    if !apps.is_empty()
        && (APP_PREFIXES.iter().any(|p| path.starts_with(p)) || in_user_applications(path))
    {
        return ExeOrigin::AppBundle;
    }
    if PLATFORM_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return ExeOrigin::Platform;
    }
    ExeOrigin::User
}

/// `/Users/<이름>/Applications/` 로 시작하는지.
fn in_user_applications(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/Users/") else {
        return false;
    };
    match rest.split_once('/') {
        Some((name, tail)) => !name.is_empty() && tail.starts_with("Applications/"),
        None => false,
    }
}
