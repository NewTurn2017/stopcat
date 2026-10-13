//! vh 실전 테스트 실험실(개발 전용, vh 바이너리에 들어가지 않음)
//!
//! 두 겹 격리: [`scope::ScopedBackend`](스냅샷을 실험실 것만 남김) + [`signal::RecordingSignaler`]
//! (vh-guard `AllowListSignaler` 바깥 기록). 실험실 자체 신호는 [`cleanup::LabReaper`]만 보낸다.

pub mod cleanup;
pub mod edge;
pub mod findings;
pub mod helper;
pub mod iso;
pub mod kernel;
pub mod lab;
pub mod notify;
pub mod preflight;
pub mod pty;
pub mod registry;
pub mod run;
pub mod scenarios;
pub mod scope;
pub mod screen;
pub mod signal;
pub mod soak;
pub mod spec;
pub mod stress;
pub mod ttycheck;
pub mod util;
pub mod verdict;
