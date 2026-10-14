//! 측정 vh 복사본의 `vh --json`(잠금 env) 검사점. 실기기 전체가 나오므로 원문은 저장하지 않고,
//! 실험실 ProcRef(pid + 시작 시각)에 해당하는 분류·발견만 줄여 남긴다.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vh_model::ProcRef;

use crate::pty::notify_only_env;
use crate::util::now_ms;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonCls {
    pub target: ProcRef,
    pub kind: String,
    pub usage_state: String,
    pub owner: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonFinding {
    pub kind: String,
    pub section: String,
    pub confidence: String,
    pub targets: Vec<ProcRef>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonProbe {
    pub label: String,
    pub at_ms: u64,
    pub exit_code: Option<i32>,
    pub wall_ms: u64,
    pub schema_version: Option<u64>,
    pub schema_ok: bool,
    pub classified: Vec<JsonCls>,
    pub findings: Vec<JsonFinding>,
    pub error: Option<String>,
}

impl JsonProbe {
    pub fn section_of(&self, t: ProcRef) -> Option<&str> {
        self.findings
            .iter()
            .find(|f| f.targets.contains(&t))
            .map(|f| f.section.as_str())
    }

    pub fn reasons_of(&self, t: ProcRef) -> Option<&[String]> {
        self.classified
            .iter()
            .find(|c| c.target == t)
            .map(|c| c.reasons.as_slice())
    }
}

fn pref(v: &Value) -> Option<ProcRef> {
    serde_json::from_value(v.clone()).ok()
}

fn s(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_default()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(s).collect())
        .unwrap_or_default()
}

/// `vh --json` 출력(`{"schema_version", "report": {...}}`)에서 실험실 대상만 고른다.
pub fn extract(label: &str, out: &Value, lab: &BTreeSet<ProcRef>) -> JsonProbe {
    let schema = out["schema_version"].as_u64();
    let rep = &out["report"];
    let classified = rep["classified"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let t = pref(&c["target"])?;
            lab.contains(&t).then(|| JsonCls {
                target: t,
                kind: s(&c["kind"]),
                usage_state: s(&c["usage"]["state"]),
                owner: s(&c["usage"]["owner"]),
                reasons: strs(&c["usage"]["reasons"]),
            })
        })
        .collect();
    let findings = rep["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let ts: Vec<ProcRef> = f["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(pref)
                .filter(|t| lab.contains(t))
                .collect();
            (!ts.is_empty()).then(|| JsonFinding {
                kind: s(&f["kind"]),
                section: s(&f["section"]),
                confidence: s(&f["confidence"]),
                targets: ts,
                reason_codes: strs(&f["reason_codes"]),
            })
        })
        .collect();
    JsonProbe {
        label: label.to_string(),
        at_ms: now_ms(),
        exit_code: None,
        wall_ms: 0,
        schema_version: schema,
        schema_ok: schema == Some(u64::from(vh_model::SCHEMA_VERSION)),
        classified,
        findings,
        error: None,
    }
}

/// 잠금 env(`VH_GUARD_LEVEL=notify VH_NOTIFY=off VH_STATE_DIR=<state> VH_E2E_ALLOW_PIDS=`)로 한 번 실행.
pub fn probe(vh: &Path, state: &Path, label: &str, lab: &BTreeSet<ProcRef>) -> JsonProbe {
    let t = Instant::now();
    let fail = |e: String, code: Option<i32>| JsonProbe {
        label: label.to_string(),
        at_ms: now_ms(),
        exit_code: code,
        wall_ms: t.elapsed().as_millis() as u64,
        schema_version: None,
        schema_ok: false,
        classified: Vec::new(),
        findings: Vec::new(),
        error: Some(e),
    };
    if let Err(e) = std::fs::create_dir_all(state) {
        return fail(e.to_string(), None);
    }
    let child = Command::new(vh)
        .arg("--json")
        .env_clear()
        .envs(notify_only_env(state))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let out = match child.and_then(|c| wait_output(c, Duration::from_secs(30))) {
        Ok(o) => o,
        Err(e) => return fail(e.to_string(), None),
    };
    let code = out.status.code();
    match serde_json::from_slice::<Value>(&out.stdout) {
        Ok(v) => JsonProbe {
            exit_code: code,
            wall_ms: t.elapsed().as_millis() as u64,
            ..extract(label, &v, lab)
        },
        Err(e) => fail(format!("JSON 해석 실패: {e}"), code),
    }
}

fn wait_output(mut c: std::process::Child, limit: Duration) -> io::Result<std::process::Output> {
    let t = Instant::now();
    let mut stdout = c.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(o) = stdout.as_mut() {
            let _ = io::Read::read_to_end(o, &mut buf);
        }
        buf
    });
    loop {
        if let Some(status) = c.try_wait()? {
            let stdout = reader.join().unwrap_or_default();
            return Ok(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            });
        }
        if t.elapsed() >= limit {
            let _ = c.kill();
            let _ = c.wait();
            return Err(io::Error::other("vh --json 시간 초과"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_lab_targets() {
        let lab_t = ProcRef {
            pid: 10,
            start_time_unix_ms: 5,
        };
        let other = ProcRef {
            pid: 10,
            start_time_unix_ms: 6,
        };
        let v = serde_json::json!({
            "schema_version": 2,
            "report": {
                "classified": [
                    {"target": lab_t, "kind": "dev_server", "usage": {"state": "active", "owner": "ended", "reasons": ["peer_outside_subtree"]}},
                    {"target": other, "kind": "gui_app", "usage": {"state": "active", "owner": "user", "reasons": []}}
                ],
                "findings": [
                    {"kind": "orphan", "section": "check", "confidence": "confirmed", "targets": [lab_t, other], "reason_codes": ["owner_dead"]},
                    {"kind": "high_cpu", "section": "working", "confidence": "likely", "targets": [other], "reason_codes": []}
                ]
            }
        });
        let lab: BTreeSet<ProcRef> = [lab_t].into();
        let p = extract("t", &v, &lab);
        assert!(p.schema_ok);
        assert_eq!(p.classified.len(), 1);
        assert_eq!(p.findings.len(), 1);
        assert_eq!(p.findings[0].targets, vec![lab_t]);
        assert_eq!(p.section_of(lab_t), Some("check"));
        assert_eq!(
            p.reasons_of(lab_t),
            Some(&["peer_outside_subtree".to_string()][..])
        );
        let old = extract("t", &serde_json::json!({"schema_version": 1}), &lab);
        assert!(!old.schema_ok);
    }
}
