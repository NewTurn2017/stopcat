//! 인자 해석·사용법 오류·종료 코드·신뢰도 기본값 매핑.

mod common;

use common::*;
use vh_cli::flow::{Basis, min_confidence};
use vh_cli::target::{Target, parse};
use vh_model::Confidence;

#[test]
fn target_parsing() {
    assert_eq!(parse(":4723"), Ok(Target::Port(4723)));
    assert_eq!(parse("4723"), Ok(Target::Pid(4723)));
    assert_eq!(parse(" 51234 "), Ok(Target::Pid(51234)));
    for bad in [
        ":0",
        ":70000",
        ":",
        "abc",
        "-1",
        "0",
        "localhost:5000",
        "99999999999",
        "",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn exit_codes() {
    let be = Synth::new();
    let help = run(&be, &["--help"], false, "");
    assert_eq!(help.code, 0);
    assert!(
        help.out.contains("사용법: vh [명령] [옵션]"),
        "{}",
        help.out
    );
    assert_eq!(run(&be, &["-V"], false, "").code, 0);
    assert_eq!(run(&be, &["fix", "--help"], false, "").code, 0);
    for bad in [
        vec!["--bogus"],
        vec!["why"],
        vec!["why", "abc"],
        vec!["why", "4821"],
        vec!["why", ":5001"],
        vec!["kill", ":0"],
        vec!["--interval-ms", "3"],
        vec!["fix", "--only", "0"],
        vec!["fix", "--min-confidence", "maybe"],
        vec!["frobnicate"],
    ] {
        let ran = run(&be, &bad, false, "");
        assert_eq!(ran.code, 1, "{bad:?}: {}", ran.err);
        assert!(ran.err.starts_with("vh: "), "{bad:?}: {}", ran.err);
    }
    assert_eq!(be.exec_calls.get(), 0);
}

#[test]
fn bare_vh_is_status() {
    let be = Synth::new();
    let a = run(&be, &[], false, "");
    let b = run(&be, &["status"], false, "");
    assert_eq!(a.code, 0);
    assert_eq!(a.out, b.out);
    assert!(a.out.starts_with("메모리 정상"));
}

#[test]
fn json_usage_error_goes_to_stdout() {
    let be = Synth::new();
    let ran = run(&be, &["--json", "kill", ":0"], false, "");
    assert_eq!(ran.code, 1);
    let v: serde_json::Value = serde_json::from_str(ran.out.trim()).unwrap();
    assert_eq!(v["error"]["code"], "usage");
    assert_eq!(v["schema_version"], 1);
}

#[test]
fn confidence_defaults() {
    assert_eq!(
        min_confidence(None, false, false),
        (Confidence::Likely, Basis::Confirm)
    );
    assert_eq!(
        min_confidence(None, false, true),
        (Confidence::Confirmed, Basis::Yes)
    );
    assert_eq!(
        min_confidence(None, true, false),
        (Confidence::Possible, Basis::Only)
    );
    assert_eq!(
        min_confidence(None, true, true),
        (Confidence::Possible, Basis::Only)
    );
    assert_eq!(
        min_confidence(Some(Confidence::Likely), true, true),
        (Confidence::Likely, Basis::Explicit)
    );
    assert_eq!(
        min_confidence(Some(Confidence::Confirmed), false, false),
        (Confidence::Confirmed, Basis::Explicit)
    );
}

#[test]
fn route_table() {
    use vh_cli::app::{Route, TuiOpts, route};
    let a = |xs: &[&str]| {
        let mut v = vec!["vh".to_string()];
        v.extend(xs.iter().map(|s| s.to_string()));
        v
    };
    let term = Some("xterm-ghostty");
    let tui = Route::Tui(TuiOpts { no_color: false });
    assert_eq!(route(&a(&[]), true, true, term, false), tui);
    assert_eq!(
        route(&a(&["--no-color"]), true, true, term, false),
        Route::Tui(TuiOpts { no_color: true })
    );
    assert_eq!(
        route(&a(&[]), true, true, term, true),
        Route::Tui(TuiOpts { no_color: true })
    );
    assert_eq!(route(&a(&["--no-cpu"]), true, true, term, false), tui);
    assert_eq!(route(&a(&[]), false, true, term, false), Route::Cli);
    assert_eq!(route(&a(&[]), true, false, term, false), Route::Cli);
    for args in [
        &["--json"][..],
        &["--plain"],
        &["status"],
        &["ports"],
        &["why", ":5000"],
        &["--help"],
        &["--bogus"],
    ] {
        assert_eq!(
            route(&a(args), true, true, term, false),
            Route::Cli,
            "{args:?}"
        );
    }
    assert_eq!(route(&a(&[]), true, true, Some("dumb"), false), Route::Cli);
    assert_eq!(route(&a(&[]), true, true, None, false), Route::Cli);
    assert_eq!(route(&a(&[]), true, true, Some(""), false), Route::Cli);
}

#[test]
fn plain_is_w1_status_and_help_starts_with_vh_only() {
    let be = Synth::new();
    let plain = run(&be, &["--plain"], true, "");
    let status = run(&be, &[], true, "");
    assert_eq!(plain.code, 0);
    assert_eq!(plain.out, status.out);
    let help = run(&be, &["--help"], false, "");
    assert!(
        help.out
            .starts_with("vh 만 치면 됩니다. 화면에서 방향키로 고르고 Enter로 정리해요."),
        "{}",
        help.out
    );
    assert!(help.out.contains("스크립트·AI용 명령"));
    assert!(help.out.contains("--plain"));
}
