//! `--json` 출력 모양. 원문 argv와 허용 목록 밖 env는 어떤 출력에도 나가지 않는다.

use std::path::Path;

use serde_json::{Map, Value, json};
use vh_model::{
    ActionOutcome, ActionPlan, ENV_ALLOWLIST, Explanation, FindingKind, Report, SCHEMA_VERSION,
    Snapshot, redact_argv,
};

use crate::target::Target;

pub fn status(s: &Snapshot, r: &Report) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "report": r,
        "host": s.host,
        "memory": s.memory,
        "limits": s.limits,
        "timings_ms": s.timings_ms,
    })
}

pub fn why(s: &Snapshot, t: Target, exps: &[Explanation]) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "taken_at_unix_ms": s.taken_at_unix_ms,
        "query": t,
        "explanations": exps,
    })
}

pub fn ports(s: &Snapshot, r: &Report) -> Value {
    let findings: Vec<_> = r
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::ExposedListener | FindingKind::KnownPortConflict
            )
        })
        .collect();
    json!({
        "schema_version": SCHEMA_VERSION,
        "taken_at_unix_ms": s.taken_at_unix_ms,
        "listeners": r.listeners,
        "findings": findings,
    })
}

/// `vh fix`(target 없음)·`vh kill`(target 있음).
pub fn action(
    s: &Snapshot,
    target: Option<Target>,
    mode: &str,
    plan: &ActionPlan,
    outcomes: &[ActionOutcome],
    state_dir: Option<&Path>,
) -> Value {
    let mut m = Map::new();
    m.insert("schema_version".into(), json!(SCHEMA_VERSION));
    m.insert("taken_at_unix_ms".into(), json!(s.taken_at_unix_ms));
    if let Some(t) = target {
        m.insert("target".into(), json!(t));
    }
    m.insert("mode".into(), json!(mode));
    m.insert("plan".into(), json!(plan));
    m.insert("outcomes".into(), json!(outcomes));
    m.insert(
        "audit_log".into(),
        json!(state_dir.map(|d| vh_act::audit_log_path(d).to_string_lossy().into_owned())),
    );
    m.insert(
        "state_dir".into(),
        json!(state_dir.map(|d| d.to_string_lossy().into_owned())),
    );
    Value::Object(m)
}

/// `vh snapshot`: argv는 `redact_argv`를 거치고 env는 허용 목록 키만 남긴 복사본.
pub fn snapshot(s: &Snapshot) -> Snapshot {
    let mut out = s.clone();
    for p in &mut out.processes {
        p.argv = redact_argv(&p.argv);
        p.env.retain(|k, _| ENV_ALLOWLIST.contains(&k.as_str()));
    }
    out
}

pub fn error(code: &str, message_ko: &str) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "error": { "code": code, "message_ko": message_ko },
    })
}
