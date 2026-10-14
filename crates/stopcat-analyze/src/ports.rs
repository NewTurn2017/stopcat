use std::collections::BTreeSet;

use stopcat_model::{
    Confidence, ExeOrigin, Family, Finding, FindingKind, Kind, Listener, ListenerView, Suggestion,
};

use crate::ctx::Ctx;
use crate::findings::{Draft, build, fid, review_note};

const AIRPLAY_PORTS: &[u16] = &[5000, 7000];

fn port_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        6333 | 6334 => "Qdrant",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        3306 => "MySQL",
        11434 => "Ollama",
        8888 => "Jupyter",
        4723 => "Appium",
        9222 => "Chrome 원격 디버깅",
        _ => return None,
    })
}

fn owner_index(c: &Ctx, l: &Listener) -> Option<usize> {
    let &j = c.idx.get(&l.pid)?;
    (c.procs[j].start_time_unix_ms == l.start_time_unix_ms && c.procs[j].uid == c.s.self_uid)
        .then_some(j)
}

fn addr_text(l: &Listener) -> String {
    match (l.family, l.all_interfaces) {
        (Family::V6, true) => format!("*:{}", l.port),
        (Family::V6, false) => format!("[{}]:{}", l.local_addr, l.port),
        (Family::V4, _) => format!("{}:{}", l.local_addr, l.port),
    }
}

fn is_airplay(c: &Ctx, j: usize, l: &Listener) -> bool {
    c.cls[j].sig == "sys_controlcenter" && AIRPLAY_PORTS.contains(&l.port)
}

fn airplay_text(port: u16) -> String {
    format!(
        "macOS 제어 센터의 AirPlay 수신이 {port}번을 써요. Flask 같은 개발 서버가 {port}번이 이미 사용 중이라고 하면 시스템 설정 → 일반 → AirDrop 및 Handoff에서 AirPlay 수신 모드를 끄거나 다른 포트(예: 5001)를 쓰세요."
    )
}

fn exposure_text(c: &Ctx, j: usize, l: &Listener) -> Option<String> {
    if is_airplay(c, j, l) {
        return Some(airplay_text(l.port));
    }
    if l.loopback {
        return None;
    }
    if l.all_interfaces {
        let both = if l.family == Family::V6 && l.dual_stack {
            " IPv4·IPv6 모두 열려 있어요."
        } else {
            ""
        };
        let hint = match (c.cls[j].kind, port_hint(l.port)) {
            (Kind::VirtualMachine, Some(h)) => format!(" 컨테이너 포트 전달이에요(보통 {h})."),
            _ => String::new(),
        };
        return Some(format!(
            "모든 네트워크에서 대기 중이라 같은 와이파이의 다른 기기에서도 접속할 수 있어요.{both}{hint}"
        ));
    }
    Some(format!(
        "이 Mac의 주소 {}로 다른 기기에서 접속할 수 있어요.",
        l.local_addr
    ))
}

pub(crate) fn listeners(c: &Ctx) -> (Vec<ListenerView>, Vec<Finding>) {
    let mut views = Vec::new();
    let mut findings = Vec::new();
    let mut seen_known: BTreeSet<u16> = BTreeSet::new();
    let mut seen_exposed: BTreeSet<(i32, u64, u16)> = BTreeSet::new();
    for l in &c.s.listeners {
        let Some(j) = owner_index(c, l) else { continue };
        let kind = c.cls[j].kind;
        let label = c.cls[j].label.clone();
        views.push(ListenerView {
            listener: l.clone(),
            kind,
            label_ko: label.clone(),
            project: c.project[j].clone(),
            exposure_ko: exposure_text(c, j, l),
        });
        if is_airplay(c, j, l) {
            if seen_known.insert(l.port) {
                findings.push(build(
                    c,
                    Draft {
                        id: format!("known_port_conflict:{}", l.port),
                        kind: FindingKind::KnownPortConflict,
                        confidence: Confidence::Confirmed,
                        targets: vec![j],
                        with_desc: false,
                        title: format!("포트 {}: 제어 센터(AirPlay 수신)", l.port),
                        short: format!("AirPlay :{}", l.port),
                        detail: format!("{} 시스템 구성요소라 끄지 않아요.", airplay_text(l.port)),
                        reasons: vec!["airplay_receiver_port".into()],
                        suggestion: Suggestion::None,
                    },
                ));
            }
            continue;
        }
        if !l.all_interfaces || kind == Kind::System || c.origin(j) == ExeOrigin::System {
            continue;
        }
        let r = c.pref(j);
        if !seen_exposed.insert((r.pid, r.start_time_unix_ms, l.port)) {
            continue;
        }
        let job_label =
            c.s.launchd_job_labels
                .get(&r.pid)
                .filter(|_| c.s.launchd_job_pids.contains(&r.pid));
        let conf = if matches!(kind, Kind::GuiApp | Kind::AppHelper) || job_label.is_some() {
            Confidence::Possible
        } else {
            Confidence::Confirmed
        };
        let mut reasons = vec!["listens_all_ifaces".to_string()];
        let service_note = match job_label {
            Some(lbl) => {
                reasons.push("launchd_service".into());
                format!(" LaunchAgent 서비스({lbl})로 일부러 띄운 것이라 의도된 노출일 수 있어요.")
            }
            None => String::new(),
        };
        let name = match (kind, port_hint(l.port)) {
            (Kind::VirtualMachine, Some(h)) => format!("{h}({label})"),
            _ => label.clone(),
        };
        let addr = addr_text(l);
        findings.push(build(
            c,
            Draft {
                id: format!("{}:{}", fid(FindingKind::ExposedListener, r), l.port),
                kind: FindingKind::ExposedListener,
                confidence: conf,
                targets: vec![j],
                with_desc: false,
                title: format!("{name} 외부 노출 {addr}"),
                short: format!("{name} {addr}"),
                detail: format!(
                    "{}{service_note} 개발용이면 127.0.0.1로만 띄우는 게 안전해요.{}",
                    exposure_text(c, j, l).unwrap_or_default(),
                    review_note("다른 기기 접속을 일부러 연 것일 수 있음", r.pid)
                ),
                reasons,
                suggestion: Suggestion::Review,
            },
        ));
    }
    views.sort_by(|a, b| {
        (
            a.listener.port,
            a.listener.pid,
            a.listener.family == Family::V6,
        )
            .cmp(&(
                b.listener.port,
                b.listener.pid,
                b.listener.family == Family::V6,
            ))
            .then_with(|| a.listener.local_addr.cmp(&b.listener.local_addr))
    });
    (views, findings)
}
