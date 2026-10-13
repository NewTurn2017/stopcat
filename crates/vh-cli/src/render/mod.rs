//! 사람용 한국어 화면. 모든 줄은 [`Out`]을 거쳐 80칸 안으로 들어간다.

pub mod action;
pub mod ports;
pub mod status;
pub mod why;

use std::collections::HashMap;

use vh_model::{
    Classified, Confidence, Finding, FindingKind, Listener, Proc, ProcRef, Report, Snapshot,
    display_path,
};

use crate::color::{Color, paint};
use crate::fmt::{self, WIDTH};

pub(crate) struct Out {
    lines: Vec<String>,
    color: bool,
}

impl Out {
    pub(crate) fn new(color: bool) -> Self {
        Out {
            lines: Vec::new(),
            color,
        }
    }

    pub(crate) fn line(&mut self, s: &str) {
        self.lines.push(fmt::truncate(s, WIDTH));
    }

    pub(crate) fn colored(&mut self, s: &str, c: Color) {
        let t = fmt::truncate(s, WIDTH);
        self.lines.push(paint(c, &t, self.color));
    }

    /// `tag`(예: "주의")만 색칠하고 `"{tag}  {rest}"`를 한 줄로.
    pub(crate) fn tagged(&mut self, tag: &str, c: Color, rest: &str) {
        let t = fmt::truncate(&format!("{tag}  {rest}"), WIDTH);
        match t.strip_prefix(tag) {
            Some(tail) if self.color => self.lines.push(format!("{}{tail}", paint(c, tag, true))),
            _ => self.lines.push(t),
        }
    }

    pub(crate) fn wrap(&mut self, first: &str, cont: &str, text: &str) {
        self.lines.extend(fmt::wrap(text, WIDTH, first, cont));
    }

    pub(crate) fn blank(&mut self) {
        self.lines.push(String::new());
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub(crate) fn finish(self) -> String {
        let mut s = self.lines.join("\n");
        s.push('\n');
        s
    }
}

/// 스냅샷·리포트에서 ProcRef로 이름·크기·나이를 찾는 색인.
pub(crate) struct Lookup<'a> {
    pub(crate) s: &'a Snapshot,
    pub(crate) r: &'a Report,
    classified: HashMap<ProcRef, &'a Classified>,
    procs: HashMap<i32, &'a Proc>,
    findings: HashMap<&'a str, &'a Finding>,
}

impl<'a> Lookup<'a> {
    pub(crate) fn new(s: &'a Snapshot, r: &'a Report) -> Self {
        Lookup {
            s,
            r,
            classified: r.classified.iter().map(|c| (c.target, c)).collect(),
            procs: s.processes.iter().map(|p| (p.pid, p)).collect(),
            findings: r.findings.iter().map(|f| (f.id.as_str(), f)).collect(),
        }
    }

    pub(crate) fn classified(&self, t: ProcRef) -> Option<&'a Classified> {
        self.classified.get(&t).copied()
    }

    /// 같은 pid·start_time의 스냅샷 프로세스.
    pub(crate) fn proc(&self, t: ProcRef) -> Option<&'a Proc> {
        self.procs
            .get(&t.pid)
            .copied()
            .filter(|p| p.start_time_unix_ms == t.start_time_unix_ms)
    }

    pub(crate) fn finding(&self, id: &str) -> Option<&'a Finding> {
        self.findings.get(id).copied()
    }

    pub(crate) fn label(&self, t: ProcRef) -> String {
        if let Some(c) = self.classified(t).filter(|c| !c.label_ko.is_empty()) {
            return c.label_ko.clone();
        }
        match self.proc(t) {
            Some(p) => p.name.clone(),
            None => format!("{}번 프로세스", t.pid),
        }
    }

    pub(crate) fn age(&self, t: ProcRef) -> Option<String> {
        self.proc(t)
            .map(|p| fmt::duration(self.s.taken_at_unix_ms.saturating_sub(p.start_time_unix_ms)))
    }

    pub(crate) fn path(&self, p: &str) -> String {
        display_path(p, &self.s.host.home_dir)
    }

    /// 스냅샷 기준 자손(대상 제외) 수와 footprint 합.
    pub(crate) fn descendants(&self, pid: i32) -> (u32, u64) {
        let mut count = 0u32;
        let mut bytes = 0u64;
        let mut stack = vec![pid];
        let mut seen = std::collections::HashSet::from([pid]);
        while let Some(cur) = stack.pop() {
            for p in self
                .s
                .processes
                .iter()
                .filter(|p| p.ppid == cur && p.pid != cur)
            {
                if seen.insert(p.pid) {
                    count += 1;
                    bytes += p.footprint_bytes.unwrap_or(0);
                    stack.push(p.pid);
                }
            }
        }
        (count, bytes)
    }
}

pub fn confidence_ko(c: Confidence) -> &'static str {
    match c {
        Confidence::Confirmed => "확실",
        Confidence::Likely => "가능성 높음",
        Confidence::Possible => "가능성 있음",
    }
}

pub(crate) fn finding_kind_ko(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Orphan => "고아",
        FindingKind::LogicalOrphan => "고아(띄운 세션 종료)",
        FindingKind::Duplicate => "중복",
        FindingKind::Zombie => "좀비",
        FindingKind::Stopped => "멈춤",
        FindingKind::Runaway => "CPU 폭주",
        FindingKind::HeavyProcess => "무거움",
        FindingKind::HeavyAgentSession => "무거운 AI 세션",
        FindingKind::HeadlessBrowserLeftover => "남은 테스트 브라우저",
        FindingKind::ExposedListener => "노출",
        FindingKind::KnownPortConflict => "포트 충돌",
        FindingKind::LimitNearing => "한도 근접",
        FindingKind::MemoryPressure => "메모리 압력",
    }
}

/// 대기 소켓이 열린 범위: "모든 네트워크" / "이 맥만" / 주소.
pub(crate) fn scope_ko(ls: &[&Listener]) -> String {
    if ls.iter().any(|l| l.all_interfaces) {
        "모든 네트워크".to_string()
    } else if !ls.is_empty() && ls.iter().all(|l| l.loopback) {
        "이 맥만".to_string()
    } else {
        ls.first().map(|l| l.local_addr.clone()).unwrap_or_default()
    }
}
