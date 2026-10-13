//! macOS 알림. 문구는 `osascript`에 argv로만 넘긴다(스크립트 문자열에 끼워 넣지 않는다 → 따옴표 주입 없음).
//! 한 스캔의 여러 처리는 한 알림으로 묶고, 30초(정책 `notify_min_interval_ms`)에 1번 이하.

use std::process::{Child, Command, Stdio};

/// 알림 보내기. 스레드로 옮겨지므로 Send.
pub trait Notifier: Send {
    fn notify(&mut self, title: &str, body: &str) -> Result<(), String>;
}

/// 아무것도 보내지 않는다(`VH_NOTIFY=off`, 테스트).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullNotifier;

impl Notifier for NullNotifier {
    fn notify(&mut self, _title: &str, _body: &str) -> Result<(), String> {
        Ok(())
    }
}

/// 알림 제목.
pub const TITLE_KO: &str = "vh 지킴이";

/// `osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title (item 2 of argv)' -e 'end run' <body> <title>`
pub fn osascript_argv(body: &str, title: &str) -> [String; 8] {
    [
        "-e".to_string(),
        "on run argv".to_string(),
        "-e".to_string(),
        "display notification (item 1 of argv) with title (item 2 of argv)".to_string(),
        "-e".to_string(),
        "end run".to_string(),
        body.to_string(),
        title.to_string(),
    ]
}

/// 진짜 `osascript`. 셸을 거치지 않고 argv로 실행한다. 자식은 다음 호출·Drop에서 회수한다(좀비 방지).
#[derive(Debug, Default)]
pub struct OsascriptNotifier {
    children: Vec<Child>,
}

impl OsascriptNotifier {
    fn reap(&mut self) {
        self.children
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        while self.children.len() > 2 {
            let mut c = self.children.remove(0);
            let _ = c.wait();
        }
    }
}

impl Notifier for OsascriptNotifier {
    fn notify(&mut self, title: &str, body: &str) -> Result<(), String> {
        self.reap();
        let child = Command::new("osascript")
            .args(osascript_argv(body, title))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("osascript 실행 실패: {e}"))?;
        self.children.push(child);
        Ok(())
    }
}

impl Drop for OsascriptNotifier {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.wait();
        }
    }
}

/// 알림 줄의 대상 이름(구분 정보 포함) 상한(글자). 넘으면 이름 쪽을 줄이고 구분 정보는 남긴다.
pub const MAX_NOTIFY_NAME_CHARS: usize = 60;
/// 구분 정보 상한(글자).
pub const MAX_NOTIFY_TAG_CHARS: usize = 24;

/// 알림 줄의 대상 이름: `이름 (프로젝트 폴더 이름)`, 프로젝트가 없으면 `이름 (pid N)`.
/// 같은 이름이 여러 개여도 무엇에 대한 알림인지 구분되게 한다.
pub fn notify_name(label_ko: &str, project: Option<&str>, pid: i32) -> String {
    let last = project
        .map(|p| p.trim_end_matches('/'))
        .and_then(|p| p.rsplit('/').next())
        .filter(|s| !s.is_empty());
    let tag = match last {
        Some(name) => clip(name, MAX_NOTIFY_TAG_CHARS),
        None => format!("pid {pid}"),
    };
    let room = MAX_NOTIFY_NAME_CHARS.saturating_sub(tag.chars().count() + 3);
    format!("{} ({tag})", clip(label_ko, room))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// 큐에 두는 서로 다른 줄의 상한. 넘친 줄은 버리고 수만 세어 본문 끝 '외 N건'에 넣는다.
pub const MAX_QUEUED_LINES: usize = 100;

/// 묶음과 속도 제한. 못 보낸 줄은 큐에 모였다가 다음 허용 시점에 한 번에 나간다(버리지 않는다).
#[derive(Debug, Clone, PartialEq)]
pub struct NotifyBatcher {
    min_interval_ms: u64,
    last_sent_at_unix_ms: Option<u64>,
    queued: Vec<String>,
    overflow: usize,
    max_lines: usize,
    max_body_chars: usize,
}

impl NotifyBatcher {
    pub fn new(min_interval_ms: u64) -> Self {
        NotifyBatcher {
            min_interval_ms,
            last_sent_at_unix_ms: None,
            queued: Vec::new(),
            overflow: 0,
            max_lines: 20,
            max_body_chars: 240,
        }
    }

    pub fn set_min_interval_ms(&mut self, ms: u64) {
        self.min_interval_ms = ms;
    }

    pub fn push(&mut self, line: impl Into<String>) {
        let line = line.into();
        if line.is_empty() || self.queued.contains(&line) {
            return;
        }
        if self.queued.len() >= MAX_QUEUED_LINES {
            self.overflow += 1;
            return;
        }
        self.queued.push(line);
    }

    pub fn queued(&self) -> usize {
        self.queued.len()
    }

    pub fn ready(&self, now_ms: u64) -> bool {
        !self.queued.is_empty()
            && self
                .last_sent_at_unix_ms
                .is_none_or(|t| now_ms.saturating_sub(t) >= self.min_interval_ms)
    }

    /// 큐를 한 알림으로 합쳐 보낸다. 보냈으면 본문과 전송 결과를 돌려준다.
    pub fn flush(
        &mut self,
        now_ms: u64,
        send: &mut dyn FnMut(&str, &str) -> Result<(), String>,
    ) -> Option<(String, Result<(), String>)> {
        if !self.ready(now_ms) {
            return None;
        }
        let body = self.compose();
        let res = send(TITLE_KO, &body);
        self.last_sent_at_unix_ms = Some(now_ms);
        self.queued.clear();
        self.overflow = 0;
        Some((body, res))
    }

    fn compose(&self) -> String {
        let mut lines: Vec<&str> = self.queued.iter().map(String::as_str).collect();
        let extra = lines.len().saturating_sub(self.max_lines) + self.overflow;
        lines.truncate(self.max_lines);
        let mut body = lines.join(" · ");
        if extra > 0 {
            body.push_str(&format!(" 외 {extra}건"));
        }
        if body.chars().count() > self.max_body_chars {
            body = body.chars().take(self.max_body_chars - 1).collect();
            body.push('…');
        }
        body
    }
}
