//! 화면·알림 문구 검사에 쓰는 값. 출처는 `TUI/PLAN.json` `.strings`(잠정)와 GUARD PLAN 알림 문구이고,
//! TUI가 `TUI/STRINGS.json`을 커밋하면 그 값으로 맞춘다. 결과 파일에 [`table`]을 증거로 첨부한다.

use serde_json::{Value, json};

/// E6: 60×20 작은 창(`strings.too_small`).
pub const TOO_SMALL: &str = "창을 조금 키워 주세요";
/// E7·T1·termios-check: 다시 그림·화면 준비 표지(`strings.guard_line.format`의 머리).
pub const REDRAW_MARK: &str = "지킴이";
/// soak: 알림만 수준 이름(`strings.level_names.notify_only`).
pub const LEVEL_NOTIFY: &str = "보고만";
/// H1(a): 강제 불안정 + 알림만 수준(`strings.guard_line.state_unstable_notify`).
pub const STATE_UNSTABLE_NOTIFY: &str = "불안정 — 보고만(자동 정리 안 함)";
/// H1(b)(c): 평소 상태(`strings.guard_line.state_normal`).
pub const STATE_NORMAL: &str = "평소 보고만";
/// GUARD 불안정 전환 알림의 머리(GUARD PLAN `notifications.unstable_transition_ko`).
pub const UNSTABLE_NOTE: &str = "맥이 불안정해요";
/// GUARD 강제 불안정 알림 앞 표지.
pub const FORCED_NOTE_PREFIX: &str = "[시험]";
/// GUARD 차단기 알림(W3와 같음).
pub const CIRCUIT_NOTE: &str = "자동 종료를 멈췄어요";

pub fn table() -> Value {
    json!({
        "source_ko": "TUI/PLAN.json .strings(잠정, TUI/STRINGS.json 커밋 뒤 갱신) · GUARD/PLAN.json policy_design.notifications",
        "E6": TOO_SMALL,
        "E7_T1_termios_check": REDRAW_MARK,
        "soak_level": LEVEL_NOTIFY,
        "H1_forced": STATE_UNSTABLE_NOTIFY,
        "H1_normal": STATE_NORMAL,
        "unstable_notification": UNSTABLE_NOTE,
        "forced_prefix": FORCED_NOTE_PREFIX,
        "S12_circuit_notification": CIRCUIT_NOTE,
    })
}
