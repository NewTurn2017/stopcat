use std::collections::{BTreeSet, HashMap};

use stopcat_model::{
    ChainNode, Classified, Confidence, Explanation, Finding, Kind, ProcRef, Report, Snapshot,
    Suggestion,
};

use crate::fmt::{age, size};

const MAX_CHAIN: usize = 64;

fn conf_word(c: Confidence) -> &'static str {
    match c {
        Confidence::Confirmed => "확실",
        Confidence::Likely => "가능성 높음",
        Confidence::Possible => "가능성 있음",
    }
}

fn owner_ko(c: &Classified) -> Option<String> {
    let label = c
        .owner_label_ko
        .clone()
        .unwrap_or_else(|| "세션".to_string());
    let who = match c.owner_pid {
        Some(pid) => format!("{label}(pid {pid})"),
        None => label,
    };
    match (c.owner_alive, c.owner_source.as_deref()) {
        (None, _) => None,
        (Some(true), _) => Some(format!("{who}이 띄웠고 지금도 실행 중")),
        (Some(false), Some("tmp_cwd")) => Some(format!(
            "{who}의 임시 폴더에서 실행 중인데 그 세션은 종료됨"
        )),
        (Some(false), source) => {
            let how = match source {
                Some(s) if s.starts_with("env:") => format!(" (환경변수 {} 기준)", &s[4..]),
                Some("argv:spawned_by") => " (--spawned-by 인자 기준)".to_string(),
                Some("argv:parent_pid") => " (--parent-pid 인자 기준)".to_string(),
                _ => String::new(),
            };
            Some(format!("{who}이 띄웠고 그 세션은 종료됨{how}"))
        }
    }
}

fn next_step(f: &Finding, pid: i32) -> String {
    match &f.suggestion {
        Suggestion::Terminate {
            include_descendants,
        } => {
            if *include_descendants && f.descendant_count > 0 {
                "`stopcat fix`로 자식까지 정리할 수 있어요.".to_string()
            } else {
                format!("`stopcat kill {pid}`로 정리할 수 있어요.")
            }
        }
        Suggestion::Demote => "`stopcat fix`로 우선순위를 낮출 수 있어요.".to_string(),
        Suggestion::Resume => "터미널에서 `fg`로 이어서 실행하거나 정리하세요.".to_string(),
        Suggestion::RestartParent { parent } => {
            format!("부모(pid {})를 재시작해야 사라져요.", parent.pid)
        }
        Suggestion::HandoffThenRestart => "핸드오프를 저장한 뒤 재시작하세요.".to_string(),
        Suggestion::Review => "확신할 수 없어 사람이 판단할 일이에요.".to_string(),
        Suggestion::None => String::new(),
    }
}

fn is_terminating(s: &Suggestion) -> bool {
    matches!(s, Suggestion::Terminate { .. } | Suggestion::Resume)
}

pub(crate) fn explain(s: &Snapshot, r: &Report, pid: i32) -> Option<Explanation> {
    let by_pid: HashMap<i32, usize> = s
        .processes
        .iter()
        .enumerate()
        .map(|(i, p)| (p.pid, i))
        .collect();
    let cls: HashMap<ProcRef, &Classified> = r.classified.iter().map(|c| (c.target, c)).collect();
    let &i = by_pid.get(&pid)?;
    let p = &s.processes[i];
    let target = ProcRef {
        pid: p.pid,
        start_time_unix_ms: p.start_time_unix_ms,
    };
    let me = cls.get(&target).copied();

    let mut chain = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cur = Some(i);
    while let Some(k) = cur {
        if chain.len() >= MAX_CHAIN || !seen.insert(k) {
            break;
        }
        let q = &s.processes[k];
        let qr = ProcRef {
            pid: q.pid,
            start_time_unix_ms: q.start_time_unix_ms,
        };
        chain.push(ChainNode {
            target: qr,
            name: q.name.clone(),
            label_ko: cls
                .get(&qr)
                .map(|c| c.label_ko.clone())
                .unwrap_or_else(|| q.name.clone()),
        });
        if q.pid == 1 {
            break;
        }
        cur = by_pid
            .get(&q.ppid)
            .copied()
            .filter(|&j| s.processes[j].start_time_unix_ms <= q.start_time_unix_ms && j != k);
        if cur.is_none() && q.ppid == 1 {
            chain.push(ChainNode {
                target: ProcRef {
                    pid: 1,
                    start_time_unix_ms: 0,
                },
                name: "launchd".to_string(),
                label_ko: "launchd(모든 프로세스의 뿌리)".to_string(),
            });
        }
    }

    let related: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| {
            f.targets.contains(&target)
                || matches!(&f.suggestion, Suggestion::RestartParent { parent } if *parent == target)
        })
        .collect();
    let listeners: Vec<_> = s
        .listeners
        .iter()
        .filter(|l| l.pid == target.pid && l.start_time_unix_ms == target.start_time_unix_ms)
        .cloned()
        .collect();

    let kind = me.map(|c| c.kind).unwrap_or(Kind::Other);
    let label = me
        .map(|c| c.label_ko.clone())
        .unwrap_or_else(|| p.name.clone());
    let project = me.and_then(|c| c.project.clone());
    let owner = me.and_then(owner_ko);

    let mut summary = format!("{label}입니다.");
    if let Some(proj) = &project {
        summary.push_str(&format!(" 프로젝트 {proj}."));
    }
    if let Some(o) = &owner {
        summary.push_str(&format!(" {o}."));
    }
    let main = related
        .iter()
        .find(|f| is_terminating(&f.suggestion))
        .or_else(|| related.first());
    if let Some(f) = main {
        let age_ms = s.taken_at_unix_ms.saturating_sub(p.start_time_unix_ms);
        summary.push_str(&format!(
            " {}({}). {}째 실행 중",
            f.title_ko,
            conf_word(f.confidence),
            age(age_ms)
        ));
        if f.reclaim_bytes > 0 {
            if f.descendant_count > 0 {
                summary.push_str(&format!(
                    "이고 자식 {}개와 함께 약 {}를 쓰고 있어요.",
                    f.descendant_count,
                    size(f.reclaim_bytes)
                ));
            } else {
                summary.push_str(&format!("이고 약 {}를 쓰고 있어요.", size(f.reclaim_bytes)));
            }
        } else {
            summary.push_str("이에요.");
        }
        let step = next_step(f, pid);
        if !step.is_empty() {
            summary.push(' ');
            summary.push_str(&step);
        }
        for extra in related.iter().filter(|x| x.id != f.id) {
            summary.push(' ');
            summary.push_str(&extra.title_ko);
            summary.push('.');
        }
        if f.suggestion == Suggestion::None {
            summary.push(' ');
            summary.push_str(&f.detail_ko);
        } else if kind == Kind::System {
            summary.push_str(" macOS 구성요소라 정리하지 않아요.");
        }
    } else if kind == Kind::System {
        summary.push_str(" macOS 구성요소라 정리하지 않아요.");
    } else {
        summary.push_str(" 지금은 특별히 문제가 보이지 않아요.");
    }

    Some(Explanation {
        target,
        chain,
        kind,
        label_ko: label,
        project,
        owner_ko: owner,
        finding_ids: related.iter().map(|f| f.id.clone()).collect(),
        listeners,
        summary_ko: summary,
    })
}

pub(crate) fn explain_port(s: &Snapshot, r: &Report, port: u16) -> Vec<Explanation> {
    let pids: BTreeSet<i32> = s
        .listeners
        .iter()
        .filter(|l| l.port == port)
        .map(|l| l.pid)
        .collect();
    pids.into_iter()
        .filter_map(|pid| explain(s, r, pid))
        .collect()
}
