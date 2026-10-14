//! 보호 규칙 id (`Refusal.rule`과 감사 로그에 그대로 쓰인다).

pub const R01_PID_LE_1: &str = "R01_pid_le_1";
pub const R02_SELF: &str = "R02_self";
pub const R03_SELF_ANCESTOR: &str = "R03_self_ancestor";
pub const R04_OTHER_UID: &str = "R04_other_uid";
pub const R05_SYSTEM_PATH: &str = "R05_system_path";
pub const R06_XPC_APPEX: &str = "R06_xpc_appex";
pub const R07_APP_BUNDLE: &str = "R07_app_bundle";
pub const R08_KIND_PROTECTED: &str = "R08_kind_protected";
pub const R09_PROTECTED_IN_SUBTREE: &str = "R09_protected_in_subtree";
pub const R10_ZOMBIE: &str = "R10_zombie";
pub const R11_SUGGESTION_NOT_ACTIONABLE: &str = "R11_suggestion_not_actionable";
pub const R12_DEMOTE_DISABLED: &str = "R12_demote_disabled";
pub const R13_BELOW_CONFIDENCE: &str = "R13_below_confidence";
pub const R14_START_TIME_MISMATCH: &str = "R14_start_time_mismatch";
pub const R15_RUNTIME_CHILD_GUARD: &str = "R15_runtime_child_guard";
pub const R16_MAX_ACTIONS: &str = "R16_max_actions";
/// `plan_priority`에 Demote·Undemote가 아닌 단계를 넣었다(W2).
pub const R17_PRIORITY_STEP_ONLY: &str = "R17_priority_step_only";
/// 자동·일괄(`PlanOrigin::Auto`·`Bulk`) 종료 계획에서 대상이나 자손이 쓰고 있음(`Usage::in_use()`, 분류 없음 포함)(W4).
pub const R18_IN_USE: &str = "R18_in_use";
/// 자동(`PlanOrigin::Auto`) 계획의 우선순위 낮추기(W4).
pub const R19_AUTO_DEMOTE_OFF: &str = "R19_auto_demote_off";
