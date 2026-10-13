//! vh-analyze: 스냅샷 분석과 도감 (ANALYZE 소유).
//!
//! `Snapshot`만 읽는 순수 함수다. 파일 시스템·프로세스·네트워크에 접근하지 않는다.

use vh_model::{Explanation, Health, HealthLevel, Report, SCHEMA_VERSION, Snapshot, Totals};

/// 스냅샷을 분석해 화면·조치에 쓸 Report를 만든다.
pub fn analyze(s: &Snapshot) -> Report {
    Report {
        schema_version: SCHEMA_VERSION,
        taken_at_unix_ms: s.taken_at_unix_ms,
        health: Health {
            level: HealthLevel::Ok,
            headline_ko: String::new(),
            reasons_ko: Vec::new(),
        },
        classified: Vec::new(),
        groups: Vec::new(),
        findings: Vec::new(),
        listeners: Vec::new(),
        totals: Totals {
            reclaimable_confirmed_bytes: 0,
            reclaimable_likely_bytes: 0,
        },
    }
}

/// `vh why <pid>`: 계보·종류·주인·관련 발견·한국어 요약. 스냅샷에 없는 pid면 `None`.
pub fn explain_pid(s: &Snapshot, r: &Report, pid: i32) -> Option<Explanation> {
    let _ = (s, r, pid);
    None
}

/// `vh why :<port>`: 그 포트에서 대기 중인 프로세스마다 설명 하나. 없으면 빈 Vec.
pub fn explain_port(s: &Snapshot, r: &Report, port: u16) -> Vec<Explanation> {
    let _ = (s, r, port);
    Vec::new()
}
