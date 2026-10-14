//! stopcat-model: stopcat 레인들이 함께 쓰는 타입 계약(v2, W4 계약 커밋 뒤 동결).
//!
//! 계약 원문: `inputs/CONTRACT.md` v1(W1)과 W2 추가분(`guard`, `Step::Undemote`).
//! W4(v2, 동결 해제는 PM 판정): 사용 판정(`Usage`)·구역(`Section`)·연결 요약(`TcpSummary`)·디스크·지킴이 안정화 필드.
//! 필드 이름·타입·순서를 바꾸려면 PM 판정이 필요하다.

pub mod action;
pub mod guard;
pub mod origin;
pub mod privacy;
pub mod report;
pub mod snapshot;

pub use action::*;
pub use guard::*;
pub use origin::*;
pub use privacy::*;
pub use report::*;
pub use snapshot::*;

/// 스냅샷·리포트 JSON 형식 버전.
pub const SCHEMA_VERSION: u32 = 2;
