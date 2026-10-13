//! 명령별 JSON 최상위 키와 가림(argv·env).

mod common;

use std::collections::BTreeSet;

use common::*;

fn keys(out: &str) -> BTreeSet<String> {
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("한 줄 JSON");
    v.as_object().unwrap().keys().cloned().collect()
}

fn set(ks: &[&str]) -> BTreeSet<String> {
    ks.iter().map(|k| k.to_string()).collect()
}

#[test]
fn top_level_keys() {
    let be = Synth::new();
    let cases: Vec<(Vec<&str>, Vec<&str>)> = vec![
        (
            vec!["--json"],
            vec![
                "schema_version",
                "report",
                "host",
                "memory",
                "limits",
                "timings_ms",
            ],
        ),
        (
            vec!["why", "51234", "--json"],
            vec![
                "schema_version",
                "taken_at_unix_ms",
                "query",
                "explanations",
            ],
        ),
        (
            vec!["why", ":4723", "--json"],
            vec![
                "schema_version",
                "taken_at_unix_ms",
                "query",
                "explanations",
            ],
        ),
        (
            vec!["ports", "--json"],
            vec![
                "schema_version",
                "taken_at_unix_ms",
                "listeners",
                "findings",
            ],
        ),
        (
            vec!["fix", "--json"],
            vec![
                "schema_version",
                "taken_at_unix_ms",
                "mode",
                "plan",
                "outcomes",
                "audit_log",
                "state_dir",
            ],
        ),
        (
            vec!["kill", ":18788", "--json"],
            vec![
                "schema_version",
                "taken_at_unix_ms",
                "target",
                "mode",
                "plan",
                "outcomes",
                "audit_log",
                "state_dir",
            ],
        ),
        (
            vec!["why", "abc", "--json"],
            vec!["schema_version", "error"],
        ),
    ];
    for (args, want) in cases {
        let ran = run(&be, &args, false, "");
        assert_eq!(keys(&ran.out), set(&want), "{args:?}");
    }
    let snapshot_keys = set(&[
        "schema_version",
        "taken_at_unix_ms",
        "host",
        "memory",
        "limits",
        "processes",
        "listeners",
        "launchd_job_pids",
        "launchd_job_labels",
        "project_roots",
        "self_pid",
        "self_uid",
        "cpu_sample_interval_ms",
        "collection_errors",
        "timings_ms",
    ]);
    assert_eq!(
        keys(&run(&be, &["snapshot", "--json"], false, "").out),
        snapshot_keys
    );
    assert_eq!(keys(&run(&be, &["snapshot"], false, "").out), snapshot_keys);
    assert_eq!(be.exec_calls.get(), 0);
}

#[test]
fn snapshot_hides_secrets_and_unlisted_env() {
    let mut be = Synth::new();
    let openai = format!("{}{}", "sk", "-".to_string() + &"Ab3".repeat(9));
    let github = format!("{}{}", "gh", "p_".to_string() + &"Zx9".repeat(8));
    let p = be
        .snap
        .processes
        .iter_mut()
        .find(|p| p.pid == 40112)
        .unwrap();
    p.argv = vec![
        "node".into(),
        format!("--api-{}={openai}", "key"),
        "--token".into(),
        github.clone(),
    ];
    p.env
        .insert("AWS_SECRET_ACCESS_KEY".into(), "should-not-leak".into());
    p.env.insert("CLAUDE_PID".into(), "33298".into());
    let out = run(&be, &["snapshot", "--json"], false, "").out;
    assert!(!out.contains(&openai));
    assert!(!out.contains(&github));
    assert!(!out.contains("AWS_SECRET_ACCESS_KEY"));
    assert!(!out.contains("should-not-leak"));
    assert!(out.contains("<가림>"));
    assert!(out.contains("CLAUDE_PID"));
    for args in [vec!["--json"], vec!["ports", "--json"]] {
        let o = run(&be, &args, false, "").out;
        assert!(!o.contains(&openai) && !o.contains(&github), "{args:?}");
    }
}
