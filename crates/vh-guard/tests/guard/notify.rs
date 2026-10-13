//! GUARD_6 알림: argv 전달(이스케이프 없음), 묶기, 30초 제한. 실제 osascript 0회.

use vh_guard::notify::{Notifier, NotifyBatcher, NullNotifier, TITLE_KO, osascript_argv};

#[test]
fn osascript_argv_is_exact_and_passes_quotes_verbatim() {
    let body = "MCP 서버 'chrome' \"끔\" \\ ; rm -rf $(x) `y`";
    let argv = osascript_argv(body, "vh 지킴이");
    assert_eq!(
        argv,
        [
            "-e".to_string(),
            "on run argv".to_string(),
            "-e".to_string(),
            "display notification (item 1 of argv) with title (item 2 of argv)".to_string(),
            "-e".to_string(),
            "end run".to_string(),
            body.to_string(),
            "vh 지킴이".to_string(),
        ]
    );
    assert!(
        !argv[3].contains(body),
        "문구가 스크립트 문자열에 끼어들지 않는다"
    );
}

#[test]
fn one_scan_many_lines_one_notification() {
    let mut b = NotifyBatcher::new(30_000);
    b.push("a 종료");
    b.push("b 종료");
    b.push("c 우선순위 낮춤");
    b.push("a 종료");
    assert_eq!(b.queued(), 3, "같은 줄은 한 번");
    let mut sent = Vec::new();
    let mut send = |t: &str, body: &str| {
        sent.push((t.to_string(), body.to_string()));
        Ok(())
    };
    let (body, res) = b.flush(1_000, &mut send).expect("보냄");
    assert!(res.is_ok());
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, TITLE_KO);
    assert_eq!(body, "a 종료 · b 종료 · c 우선순위 낮춤");
    assert_eq!(b.queued(), 0);
}

#[test]
fn thirty_second_limit_queues_then_merges() {
    let mut b = NotifyBatcher::new(30_000);
    let mut n = 0;
    let mut send = |_: &str, _: &str| {
        n += 1;
        Ok(())
    };
    b.push("1");
    assert!(b.flush(0, &mut send).is_some());
    b.push("2");
    assert!(b.flush(10_000, &mut send).is_none());
    assert_eq!(b.queued(), 1);
    b.push("3");
    assert!(b.flush(29_999, &mut send).is_none());
    let (body, _) = b.flush(30_000, &mut send).unwrap();
    assert_eq!(body, "2 · 3");
    assert_eq!(n, 2);
}

#[test]
fn truncates_lines_and_chars() {
    let mut b = NotifyBatcher::new(0);
    for i in 0..25 {
        b.push(format!("줄{i}"));
    }
    let mut send = |_: &str, _: &str| Ok(());
    let (body, _) = b.flush(0, &mut send).unwrap();
    assert!(body.ends_with(" 외 5건"), "{body}");
    assert_eq!(body.matches('줄').count(), 20);

    let mut b = NotifyBatcher::new(0);
    b.push("가".repeat(500));
    let (body, _) = b.flush(0, &mut send).unwrap();
    assert_eq!(body.chars().count(), 240);
    assert!(body.ends_with('…'));
}

#[test]
fn send_failure_is_returned_and_queue_is_cleared() {
    let mut b = NotifyBatcher::new(0);
    b.push("x");
    let mut send = |_: &str, _: &str| Err("안 됨".to_string());
    let (_, res) = b.flush(0, &mut send).unwrap();
    assert_eq!(res, Err("안 됨".to_string()));
    assert_eq!(b.queued(), 0);
}

#[test]
fn null_notifier_sends_nothing() {
    assert_eq!(NullNotifier.notify("t", "b"), Ok(()));
}
