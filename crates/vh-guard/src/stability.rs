//! 지킴이의 '불안정' 판정 입력. W4 커밋 A: 시험용 강제 건강 값 해석.

use vh_model::HealthLevel;

/// `VH_E2E_FORCE_HEALTH` 해석. `VH_E2E_ALLOW_PIDS`가 있을 때만(값이 비어 있어도 '있음') 읽는다.
/// 값은 `watch`·`critical`(대소문자·앞뒤 공백 무시)만 받고, 그 밖(ok·빈 값·모르는 값)은 None.
pub fn forced_health_from(force: Option<&str>, allow_pids: Option<&str>) -> Option<HealthLevel> {
    allow_pids?;
    match force?.trim().to_ascii_lowercase().as_str() {
        "watch" => Some(HealthLevel::Watch),
        "critical" => Some(HealthLevel::Critical),
        _ => None,
    }
}
