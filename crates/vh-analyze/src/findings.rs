use std::collections::{BTreeMap, BTreeSet, HashMap};

use vh_model::{
    Confidence, ExeOrigin, Finding, FindingKind, Kind, ProcRef, ProcStatus, Section, Suggestion,
};

use crate::ctx::{Ctx, DeadWhy};
use crate::features::effective_argv;
use crate::fmt::{GIB, age, size};

const MIN_10: u64 = 10 * 60_000;
const HOUR: u64 = 60 * 60_000;
pub(crate) const HEAVY_PROCESS: u64 = 4 * GIB;
pub(crate) const HEAVY_SESSION: u64 = 8 * GIB;

pub(crate) fn kind_str(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Orphan => "orphan",
        FindingKind::LogicalOrphan => "logical_orphan",
        FindingKind::Duplicate => "duplicate",
        FindingKind::Zombie => "zombie",
        FindingKind::Stopped => "stopped",
        FindingKind::HighCpu => "runaway",
        FindingKind::HeavyProcess => "heavy_process",
        FindingKind::HeavyAgentSession => "heavy_agent_session",
        FindingKind::HeadlessBrowserLeftover => "headless_browser_leftover",
        FindingKind::ExposedListener => "exposed_listener",
        FindingKind::KnownPortConflict => "known_port_conflict",
        FindingKind::LimitNearing => "limit_nearing",
        FindingKind::MemoryPressure => "memory_pressure",
    }
}

pub(crate) fn kind_order(k: FindingKind) -> u8 {
    match k {
        FindingKind::MemoryPressure => 0,
        FindingKind::LimitNearing => 1,
        FindingKind::HeavyAgentSession => 2,
        FindingKind::LogicalOrphan => 3,
        FindingKind::Orphan => 4,
        FindingKind::HeadlessBrowserLeftover => 5,
        FindingKind::Duplicate => 6,
        FindingKind::Stopped => 7,
        FindingKind::Zombie => 8,
        FindingKind::HighCpu => 9,
        FindingKind::HeavyProcess => 10,
        FindingKind::ExposedListener => 11,
        FindingKind::KnownPortConflict => 12,
    }
}

pub(crate) fn fid(kind: FindingKind, r: ProcRef) -> String {
    format!("{}:{}:{}", kind_str(kind), r.pid, r.start_time_unix_ms)
}

/// Review 제안의 detail 끝에 붙인다. `vh fix --only`로 지목하면 실행될 수 있으므로 사람이 판단할 것임을 밝힌다.
pub(crate) fn review_note(why: &str, pid: i32) -> String {
    format!(
        " 확신할 수 없어 자동 정리 대상에서 뺐어요({why}). 사람이 직접 확인할 일이고, 정리하려면 `vh fix --only {pid}`로 지목하세요."
    )
}

fn downgrade(c: Confidence) -> Confidence {
    match c {
        Confidence::Confirmed => Confidence::Likely,
        _ => Confidence::Possible,
    }
}

pub(crate) struct Draft {
    pub id: String,
    pub kind: FindingKind,
    pub confidence: Confidence,
    pub targets: Vec<usize>,
    pub with_desc: bool,
    pub title: String,
    pub short: String,
    pub detail: String,
    pub reasons: Vec<String>,
    pub suggestion: Suggestion,
}

pub(crate) fn build(c: &Ctx, d: Draft) -> Finding {
    let mut seen = BTreeSet::new();
    let mut desc_count = 0u32;
    let mut reclaim = 0u64;
    for &t in &d.targets {
        if seen.insert(t) {
            reclaim += c.footprint(t);
        }
        if d.with_desc {
            for x in c.descendants(t) {
                if seen.insert(x) {
                    reclaim += c.footprint(x);
                    desc_count += 1;
                }
            }
        }
    }
    if matches!(
        d.kind,
        FindingKind::KnownPortConflict
            | FindingKind::ExposedListener
            | FindingKind::HighCpu
            | FindingKind::MemoryPressure
            | FindingKind::LimitNearing
    ) {
        reclaim = 0;
    }
    let mut targets: Vec<ProcRef> = d.targets.iter().map(|&t| c.pref(t)).collect();
    targets.sort();
    Finding {
        id: d.id,
        kind: d.kind,
        confidence: d.confidence,
        targets,
        title_ko: d.title,
        short_ko: d.short,
        detail_ko: d.detail,
        reason_codes: d.reasons,
        reclaim_bytes: reclaim,
        descendant_count: desc_count,
        suggestion: d.suggestion,
        section: Section::Check,
    }
}

pub(crate) struct Ports(HashMap<ProcRef, u16>);

impl Ports {
    pub(crate) fn new(c: &Ctx) -> Self {
        let mut m: HashMap<ProcRef, u16> = HashMap::new();
        for l in &c.s.listeners {
            let r = ProcRef {
                pid: l.pid,
                start_time_unix_ms: l.start_time_unix_ms,
            };
            m.entry(r)
                .and_modify(|p| *p = (*p).min(l.port))
                .or_insert(l.port);
        }
        Ports(m)
    }

    fn of(&self, c: &Ctx, i: usize) -> Option<u16> {
        self.0.get(&c.pref(i)).copied()
    }
}

fn short_for(c: &Ctx, ports: &Ports, i: usize, reclaim: u64, prefer_age: bool) -> String {
    let label = &c.cls[i].label;
    if let Some(port) = ports.of(c, i) {
        format!("{label} :{port}")
    } else if prefer_age {
        format!("{label} {}", age(c.age_ms(i)))
    } else if reclaim >= GIB {
        format!("{label} {}", size(reclaim))
    } else {
        format!("{label} {}", age(c.age_ms(i)))
    }
}

fn with_kids(nd: usize, fp: u64) -> String {
    if nd > 0 {
        format!("자식 {nd}개 포함 약 {}", size(fp))
    } else {
        format!("약 {}", size(fp))
    }
}

fn subtree_footprint(c: &Ctx, i: usize) -> (u64, usize) {
    let d = c.descendants(i);
    (
        c.footprint(i) + d.iter().map(|&x| c.footprint(x)).sum::<u64>(),
        d.len(),
    )
}

fn cover(c: &Ctx, covered: &mut [bool], i: usize) {
    covered[i] = true;
    for x in c.descendants(i) {
        covered[x] = true;
    }
}

fn argv_flag_value<'b>(argv: &'b [String], flag: &str) -> Option<&'b str> {
    let eq = format!("{flag}=");
    argv.iter().enumerate().find_map(|(i, a)| {
        if a == flag {
            argv.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix(eq.as_str())
        }
    })
}

const SERVICE_KINDS: &[Kind] = &[
    Kind::Database,
    Kind::VirtualMachine,
    Kind::LocalLlm,
    Kind::Tunnel,
];
const LEFTOVER_KINDS: &[Kind] = &[Kind::HeadlessBrowser, Kind::Emulator, Kind::TestTool];
const DEV_KINDS: &[Kind] = &[
    Kind::DevServer,
    Kind::BuildTool,
    Kind::Watcher,
    Kind::AgentHelper,
];
const STOPPED_DEV_KINDS: &[Kind] = &[
    Kind::DevServer,
    Kind::DevRuntime,
    Kind::BuildTool,
    Kind::TestTool,
    Kind::Watcher,
];

fn is_stdio(c: &Ctx, i: usize) -> bool {
    matches!(c.cls[i].kind, Kind::McpServer | Kind::LanguageServer)
        || matches!(c.cls[i].sig, "w_esbuild_service" | "agent_claude_bg")
}

fn owner_phrase(c: &Ctx, i: usize) -> String {
    let o = &c.owner[i];
    let label = o.label.clone().unwrap_or_else(|| "띄운 세션".to_string());
    match (o.pid, o.dead) {
        (Some(pid), Some(DeadWhy::PidReused)) => {
            format!("띄운 {label}(pid {pid})은 종료됐고 그 번호는 지금 다른 프로세스가 써요")
        }
        (Some(pid), Some(_)) => format!("띄운 {label}(pid {pid})은 이미 종료됐어요"),
        (None, Some(_)) => format!("띄운 {label}은 이미 종료됐어요(임시 폴더 기준)"),
        _ => format!("띄운 {label}이 아직 실행 중이에요"),
    }
}

pub(crate) fn process_findings(c: &Ctx, ports: &Ports) -> Vec<Finding> {
    let n = c.procs.len();
    let mut out = Vec::new();
    let mut covered = vec![false; n];
    let jobs: BTreeSet<i32> = c.s.launchd_job_pids.iter().copied().collect();

    for &i in &c.topo {
        if covered[i] || !c.is_mine(i) || !c.alive(i) {
            continue;
        }
        let p = &c.procs[i];
        let kind = c.cls[i].kind;
        let label = c.cls[i].label.clone();
        let r = c.pref(i);
        let age_ms = c.age_ms(i);

        if p.status == ProcStatus::Stopped && !c.excluded(i) {
            let dev = STOPPED_DEV_KINDS.contains(&kind);
            let (fp, _) = subtree_footprint(c, i);
            let (conf, sugg, mut reasons, detail) = if dev && p.ppid == 1 {
                (
                    Confidence::Confirmed,
                    Suggestion::Terminate {
                        include_descendants: true,
                    },
                    vec!["stopped", "ppid_launchd"],
                    format!(
                        "Ctrl+Z로 멈춘 채 터미널이 닫혀 되살릴 방법이 없어요. 다시 시작시킨 뒤(CONT) 정리하면 약 {} 회수됩니다.",
                        size(fp)
                    ),
                )
            } else if dev {
                (
                    Confidence::Confirmed,
                    Suggestion::Resume,
                    vec!["stopped"],
                    "Ctrl+Z로 일시정지된 상태예요. 띄운 터미널이 열려 있으면 `fg`로 이어서 실행하고, 필요 없으면 정리하세요.".to_string(),
                )
            } else {
                (
                    Confidence::Possible,
                    Suggestion::Review,
                    vec!["stopped", "unknown_purpose"],
                    format!(
                        "일시정지된 상태예요. 디버거가 세웠을 수도 있어요.{}",
                        review_note("누가 왜 멈췄는지 알 수 없음", p.pid)
                    ),
                )
            };
            if age_ms < MIN_10 {
                reasons.push("young");
            }
            let terminating = matches!(sugg, Suggestion::Terminate { .. });
            out.push(build(
                c,
                Draft {
                    id: fid(FindingKind::Stopped, r),
                    kind: FindingKind::Stopped,
                    confidence: conf,
                    targets: vec![i],
                    with_desc: terminating,
                    title: format!("{label} 일시정지됨"),
                    short: format!("{label} 정지"),
                    detail,
                    reasons: reasons.into_iter().map(str::to_string).collect(),
                    suggestion: sugg,
                },
            ));
            if terminating {
                cover(c, &mut covered, i);
            }
            continue;
        }

        let owner = &c.owner[i];
        if p.ppid != 1
            && c.parent[i].is_some()
            && kind != Kind::AgentCli
            && !c.excluded(i)
            && !c.daemon_by_design(i)
            && age_ms >= MIN_10
            && let Some(dead) = owner.dead
        {
            let mut ancestor_shares = false;
            let mut up = c.parent[i];
            while let Some(j) = up {
                if c.owner[j].dead.is_some()
                    && c.owner[j].pid == owner.pid
                    && c.owner[j].source == owner.source
                {
                    ancestor_shares = true;
                    break;
                }
                up = c.parent[j];
            }
            if !ancestor_shares {
                let mut conf = if dead == DeadWhy::TmpSessionGone {
                    Confidence::Likely
                } else {
                    Confidence::Confirmed
                };
                let mut reasons: Vec<String> = vec![dead.code().to_string()];
                if let Some(sc) = owner.source_code() {
                    reasons.push(sc.to_string());
                }
                if c.tmp_cwd[i] {
                    reasons.push("agent_tmp_cwd".into());
                }
                reasons.push("parent_alive".into());
                reasons.push("age_ge_10m".into());
                if p.has_tty {
                    conf = downgrade(conf);
                    reasons.push("has_tty".into());
                }
                let (fp, nd) = subtree_footprint(c, i);
                let sugg = if conf == Confidence::Possible {
                    Suggestion::Review
                } else {
                    Suggestion::Terminate {
                        include_descendants: true,
                    }
                };
                let mut detail = format!(
                    "{}. {}째 실행 중이고 {}를 쓰고 있어요. 바로 위 부모는 살아 있어서 PPID만 보면 고아로 안 보이는 경우예요.",
                    owner_phrase(c, i),
                    age(age_ms),
                    with_kids(nd, fp)
                );
                if sugg == Suggestion::Review {
                    detail.push_str(&review_note("터미널이 붙어 있어 사용 중일 수 있음", p.pid));
                }
                let terminating = matches!(sugg, Suggestion::Terminate { .. });
                out.push(build(
                    c,
                    Draft {
                        id: fid(FindingKind::LogicalOrphan, r),
                        kind: FindingKind::LogicalOrphan,
                        confidence: conf,
                        targets: vec![i],
                        with_desc: terminating,
                        title: format!(
                            "{label} — 띄운 {} 종료됨",
                            owner.label.as_deref().unwrap_or("세션")
                        ),
                        short: short_for(c, ports, i, fp, false),
                        detail,
                        reasons,
                        suggestion: sugg,
                    },
                ));
                if terminating {
                    cover(c, &mut covered, i);
                }
                continue;
            }
        }

        if p.ppid == 1
            && !jobs.contains(&p.pid)
            && !c.excluded(i)
            && !c.daemon_by_design(i)
            && let Some(f) = orphan_finding(c, ports, i)
        {
            let terminating = matches!(f.suggestion, Suggestion::Terminate { .. });
            out.push(f);
            if terminating {
                cover(c, &mut covered, i);
            }
        }
    }

    out.extend(zombies(c));
    out.extend(duplicates(c, &mut covered));
    out.extend(runaways(c));
    out.extend(heavy(c, &covered));
    out
}

fn orphan_finding(c: &Ctx, ports: &Ports, i: usize) -> Option<Finding> {
    let p = &c.procs[i];
    let kind = c.cls[i].kind;
    let sig = c.cls[i].sig;
    let label = c.cls[i].label.clone();
    let r = c.pref(i);
    let age_ms = c.age_ms(i);
    let owner = &c.owner[i];
    let mut reasons: Vec<String> = ["ppid_launchd", "not_launchd_job", "same_uid"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (fp, nd) = subtree_footprint(c, i);

    if kind == Kind::AgentCli {
        reasons.push("agent_cli_never_terminated".into());
        return Some(build(
            c,
            Draft {
                id: fid(FindingKind::Orphan, r),
                kind: FindingKind::Orphan,
                confidence: Confidence::Possible,
                targets: vec![i],
                with_desc: false,
                title: format!("{label} — 띄운 터미널이 사라짐"),
                short: short_for(c, ports, i, fp, false),
                detail: format!(
                    "대화형 에이전트 세션이라 vh는 정리하지 않아요. 대화 맥락이 사라지기 때문이에요. 쓰지 않는 세션이면 핸드오프를 저장하고 직접 종료하세요.{}",
                    review_note("에이전트 세션은 대화 맥락을 잃을 수 있음", p.pid)
                ),
                reasons,
                suggestion: Suggestion::Review,
            },
        ));
    }

    let (mut conf, why_review): (Confidence, &str);
    if sig == "agent_claude_daemon" {
        let transient = argv_flag_value(&p.argv, "--origin") == Some("transient");
        let spawner_dead = owner.dead.is_some();
        if transient {
            reasons.push("transient_origin".into());
        }
        if spawner_dead {
            reasons.push("spawner_dead".into());
            if let Some(sc) = owner.source_code() {
                reasons.push(sc.into());
            }
        }
        if transient && spawner_dead {
            conf = Confidence::Likely;
            why_review = "";
        } else {
            conf = Confidence::Possible;
            why_review = "띄운 쪽이 살아 있거나 일회용 데몬이 아님";
        }
    } else {
        let service = SERVICE_KINDS.contains(&kind);
        let dead = owner.dead;
        let owner_dead = dead.is_some_and(|d| d != DeadWhy::TmpSessionGone);
        let tmp_gone = c.tmp_cwd[i] && dead == Some(DeadWhy::TmpSessionGone);
        let stdio = is_stdio(c, i);
        if !service && age_ms >= MIN_10 && (stdio || owner_dead || tmp_gone) {
            conf = Confidence::Confirmed;
            why_review = "";
            if stdio {
                reasons.push("stdio_kind".into());
            }
            if let Some(d) = dead {
                if c.tmp_cwd[i] {
                    reasons.push("agent_tmp_cwd".into());
                }
                reasons.push(d.code().into());
                if let Some(sc) = owner.source_code() {
                    reasons.push(sc.into());
                }
            }
            reasons.push("age_ge_10m".into());
        } else if !service
            && age_ms >= HOUR
            && (LEFTOVER_KINDS.contains(&kind)
                || DEV_KINDS.contains(&kind)
                || c.project[i].is_some())
        {
            conf = Confidence::Likely;
            why_review = "";
            reasons.push(
                if LEFTOVER_KINDS.contains(&kind) {
                    "leftover_kind"
                } else if DEV_KINDS.contains(&kind) {
                    "dev_kind"
                } else {
                    "in_project"
                }
                .into(),
            );
            reasons.push("age_ge_1h".into());
        } else {
            conf = Confidence::Possible;
            let (code, why) = if service {
                ("service_kind", "일부러 띄워 두는 일이 많은 서비스")
            } else if age_ms < HOUR {
                ("young", "띄운 지 얼마 안 됨")
            } else {
                ("unknown_purpose", "무엇에 쓰는 프로세스인지 알 수 없음")
            };
            reasons.push(code.into());
            why_review = why;
        }
        if owner.alive == Some(true) && conf != Confidence::Possible {
            conf = Confidence::Possible;
            reasons.push("owner_alive".into());
        }
    }
    let mut why_review = why_review.to_string();
    if owner.alive == Some(true) && why_review.is_empty() {
        why_review = "띄운 세션이 아직 실행 중".into();
    }
    if p.has_tty {
        conf = downgrade(conf);
        reasons.push("has_tty".into());
        if conf == Confidence::Possible && why_review.is_empty() {
            why_review = "터미널이 붙어 있어 사용 중일 수 있음".into();
        }
    }
    if c.origin(i) == ExeOrigin::Unknown && conf != Confidence::Possible {
        conf = Confidence::Possible;
        reasons.push("exe_unknown".into());
        why_review = "실행 파일 경로를 읽지 못함".into();
    }

    let fk = if kind == Kind::HeadlessBrowser {
        FindingKind::HeadlessBrowserLeftover
    } else {
        FindingKind::Orphan
    };
    let sugg = if conf == Confidence::Possible {
        Suggestion::Review
    } else {
        Suggestion::Terminate {
            include_descendants: true,
        }
    };
    let cause = match owner.dead {
        Some(_) => format!("{}. ", owner_phrase(c, i)),
        None => "띄운 프로그램이 끝나 launchd 밑에 홀로 남았어요. ".to_string(),
    };
    let mut detail = format!(
        "{cause}{}째 실행 중이고 {}를 쓰고 있어요.",
        age(age_ms),
        with_kids(nd, fp)
    );
    if sugg == Suggestion::Review {
        detail.push_str(&review_note(&why_review, p.pid));
    }
    let title = if fk == FindingKind::HeadlessBrowserLeftover {
        format!("{label} 잔재 — {}째 실행 중", age(age_ms))
    } else {
        format!("{label} — 주인 없는 프로세스")
    };
    Some(build(
        c,
        Draft {
            id: fid(fk, r),
            kind: fk,
            confidence: conf,
            targets: vec![i],
            with_desc: sugg != Suggestion::Review,
            title,
            short: short_for(c, ports, i, fp, fk == FindingKind::HeadlessBrowserLeftover),
            detail,
            reasons,
            suggestion: sugg,
        },
    ))
}

fn zombies(c: &Ctx) -> Vec<Finding> {
    let mut by_parent: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..c.procs.len() {
        let p = &c.procs[i];
        if p.status != ProcStatus::Zombie || p.uid != c.s.self_uid || p.ppid <= 1 {
            continue;
        }
        if let Some(&j) = c.idx.get(&p.ppid)
            && c.procs[j].uid == c.s.self_uid
        {
            by_parent.entry(j).or_default().push(i);
        }
    }
    by_parent
        .into_iter()
        .map(|(j, zs)| {
            let pr = c.pref(j);
            let plabel = c.cls[j].label.clone();
            let n = zs.len();
            let restart = if c.cls[j].kind == Kind::AgentCli {
                "부모가 에이전트 세션이라 핸드오프를 저장한 뒤 재시작하면 사라져요."
            } else {
                "부모를 재시작하면 사라져요."
            };
            Finding {
                id: format!("zombie:{}:{}", pr.pid, pr.start_time_unix_ms),
                kind: FindingKind::Zombie,
                confidence: Confidence::Confirmed,
                targets: {
                    let mut t: Vec<ProcRef> = zs.iter().map(|&z| c.pref(z)).collect();
                    t.sort();
                    t
                },
                title_ko: format!("회수 안 된 좀비 {n}개 ({plabel})"),
                short_ko: format!("좀비 {n}개 ({plabel})"),
                detail_ko: format!(
                    "이미 끝난 프로세스의 빈 껍데기라 kill로는 지워지지 않아요. 부모 프로세스({plabel}, pid {})가 거둬 가야 하는데 안 하고 있어요. 메모리는 거의 안 쓰지만 프로세스 수 한도를 차지해요. {restart}",
                    pr.pid
                ),
                reason_codes: vec!["zombie".into(), "parent_not_reaping".into()],
                reclaim_bytes: 0,
                descendant_count: 0,
                suggestion: Suggestion::RestartParent { parent: pr },
                section: Section::Check,
            }
        })
        .collect()
}

fn is_uuid_like(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        }))
        || (b.len() >= 16 && b.iter().all(u8::is_ascii_hexdigit))
}

pub(crate) fn normalize_token(t: &str) -> String {
    if t.starts_with("/tmp/")
        || t.starts_with("/private/tmp/")
        || t.contains("/var/folders/")
        || t.ends_with(".sock")
    {
        return "*".to_string();
    }
    let segs: Vec<&str> = t.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(segs.len());
    for (k, seg) in segs.iter().enumerate() {
        let prev = if k > 0 { segs[k - 1] } else { "" };
        let prev2 = if k > 1 { segs[k - 2] } else { "" };
        let s = if prev == "_npx"
            || prev == "node-versions"
            || prev2 == "Cellar"
            || is_uuid_like(seg)
        {
            "*".to_string()
        } else if seg.len() >= 4 && seg.bytes().all(|b| b.is_ascii_digit()) {
            "#".to_string()
        } else {
            seg.to_string()
        };
        out.push(s);
    }
    out.join("/")
}

const SKIP_NEXT: &[&str] = &[
    "--port",
    "-p",
    "--session-id",
    "--settings",
    "--parent-pid",
    "--ppid",
    "--pid",
];
const SKIP_PREFIX: &[&str] = &[
    "--port=",
    "--parent-pid=",
    "--ppid=",
    "--pid=",
    "--inspect",
    "--user-data-dir=",
    "--session-id=",
    "PORT=",
];

pub(crate) fn normalize_argv(exe_base: &str, argv: &[String]) -> String {
    let mut parts = vec![exe_base.to_string()];
    let mut skip = false;
    for a in argv.iter().skip(1) {
        if skip {
            skip = false;
            continue;
        }
        if SKIP_NEXT.contains(&a.as_str()) {
            skip = true;
            continue;
        }
        if SKIP_PREFIX.iter().any(|p| a.starts_with(p)) {
            continue;
        }
        parts.push(normalize_token(a));
    }
    parts.join("\u{1f}")
}

fn duplicates(c: &Ctx, covered: &mut [bool]) -> Vec<Finding> {
    let n = c.procs.len();
    let mut keys: Vec<Option<String>> = vec![None; n];
    for i in 0..n {
        let p = &c.procs[i];
        let kind = c.cls[i].kind;
        if covered[i]
            || !c.is_mine(i)
            || !c.alive(i)
            || c.excluded(i)
            || matches!(
                kind,
                Kind::AgentCli | Kind::AgentHelper | Kind::LanguageServer
            )
            || !p.argv_readable
            || p.argv.is_empty()
        {
            continue;
        }
        let owner_key = match (c.owner[i].session, c.owner[i].pid) {
            (Some(s), _) => format!("{}:{}", s.pid, s.start_time_unix_ms),
            (None, Some(pid)) => pid.to_string(),
            _ if kind == Kind::McpServer => continue,
            _ => String::new(),
        };
        let norm = normalize_argv(&c.feats[i].exe_base, &effective_argv(p));
        keys[i] = Some(format!(
            "{}\u{1e}{norm}\u{1e}{owner_key}",
            p.cwd.as_deref().unwrap_or("")
        ));
    }
    let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let Some(k) = keys[i].as_deref() else {
            continue;
        };
        if c.parent[i].is_some_and(|j| keys[j].as_deref() == Some(k)) {
            continue;
        }
        groups.entry(k).or_default().push(i);
    }
    let mut out = Vec::new();
    for (_, members) in groups {
        let mut by_parent: BTreeMap<usize, usize> = BTreeMap::new();
        let mut units: Vec<usize> = Vec::new();
        for &i in &members {
            match c.parent[i] {
                Some(j) if c.procs[j].pid > 1 && c.cls[j].kind != Kind::AgentCli => {
                    let e = by_parent.entry(j).or_insert(i);
                    if c.procs[i].start_time_unix_ms < c.procs[*e].start_time_unix_ms {
                        *e = i;
                    }
                }
                _ => units.push(i),
            }
        }
        units.extend(by_parent.values().copied());
        if units.len() < 2 {
            continue;
        }
        units.sort_by_key(|&i| (c.procs[i].start_time_unix_ms, c.procs[i].pid));
        let keep = *units.last().unwrap_or(&units[0]);
        let targets: Vec<usize> = units[..units.len() - 1].to_vec();
        let mcp = c.cls[keep].kind == Kind::McpServer;
        let any_tty = targets.iter().any(|&t| c.procs[t].has_tty);
        let conf = if any_tty {
            Confidence::Possible
        } else {
            Confidence::Likely
        };
        let sugg = if any_tty {
            Suggestion::Review
        } else {
            Suggestion::Terminate {
                include_descendants: true,
            }
        };
        let label = c.cls[keep].label.clone();
        let mut reasons: Vec<String> = vec!["same_cwd".into(), "same_argv_normalized".into()];
        if mcp || c.owner[keep].pid.is_some() {
            reasons.push("same_owner_session".into());
        }
        if any_tty {
            reasons.push("has_tty".into());
        }
        let first = targets[0];
        let fp: u64 = targets.iter().map(|&t| subtree_footprint(c, t).0).sum();
        let place = c.procs[keep]
            .cwd
            .as_deref()
            .map(|x| vh_model::display_path(x, &c.s.host.home_dir))
            .unwrap_or_else(|| "알 수 없는 폴더".into());
        let scope = if mcp {
            "같은 에이전트 세션 안에서 같은 MCP 서버가"
        } else {
            "같은 폴더에서 같은 명령이"
        };
        let mut detail = format!(
            "{scope} {}개 떠 있어요({place}). 가장 최근에 시작한 pid {}만 남기고 나머지 {}개를 정리하면 약 {} 회수됩니다.",
            units.len(),
            c.procs[keep].pid,
            targets.len(),
            size(fp)
        );
        if sugg == Suggestion::Review {
            detail.push_str(&review_note(
                "터미널이 붙어 있어 사용 중일 수 있음",
                c.procs[first].pid,
            ));
        }
        let terminating = matches!(sugg, Suggestion::Terminate { .. });
        if terminating {
            for &t in &targets {
                cover(c, covered, t);
            }
        }
        out.push(build(
            c,
            Draft {
                id: fid(FindingKind::Duplicate, c.pref(first)),
                kind: FindingKind::Duplicate,
                confidence: conf,
                targets,
                with_desc: terminating,
                title: format!("{label} {}개 중복 실행", units.len()),
                short: format!("{label} {}개", units.len()),
                detail,
                reasons,
                suggestion: sugg,
            },
        ));
    }
    out
}

fn runaways(c: &Ctx) -> Vec<Finding> {
    if c.s.cpu_sample_interval_ms.is_none_or(|ms| ms < 200) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..c.procs.len() {
        let p = &c.procs[i];
        let Some(pct) = p.cpu_pct else { continue };
        if pct < 100.0
            || p.uid != c.s.self_uid
            || !c.alive(i)
            || c.cls[i].kind == Kind::System
            || c.origin(i) == ExeOrigin::System
        {
            continue;
        }
        let kind = c.cls[i].kind;
        let label = c.cls[i].label.clone();
        let review = matches!(kind, Kind::AgentCli | Kind::GuiApp | Kind::AppHelper);
        let mut detail = format!(
            "잰 순간(약 {}ms) CPU를 {:.0}% 썼어요(코어 1개 = 100%). 순간값이라 잠깐 바쁜 것일 수도 있어요.",
            c.s.cpu_sample_interval_ms.unwrap_or(0),
            pct
        );
        let sugg = if review {
            detail.push_str(&review_note(
                "앱·에이전트 세션은 우선순위를 낮추면 느려짐",
                p.pid,
            ));
            Suggestion::Review
        } else {
            detail.push_str(" 우선순위를 낮추면(demote) 다른 작업이 덜 느려져요.");
            Suggestion::Demote
        };
        out.push(build(
            c,
            Draft {
                id: fid(FindingKind::HighCpu, c.pref(i)),
                kind: FindingKind::HighCpu,
                confidence: Confidence::Possible,
                targets: vec![i],
                with_desc: false,
                title: format!("{label} CPU {pct:.0}%"),
                short: format!("{label} CPU {pct:.0}%"),
                detail,
                reasons: vec!["cpu_ge_100_instant".into()],
                suggestion: sugg,
            },
        ));
    }
    out
}

fn heavy(c: &Ctx, covered: &[bool]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, p) in c.procs.iter().enumerate() {
        let kind = c.cls[i].kind;
        if c.session_root[i] == Some(i) && p.uid == c.s.self_uid {
            let (fp, nd) = subtree_footprint(c, i);
            let root_fp = c.footprint(i);
            if root_fp >= HEAVY_SESSION || fp >= HEAVY_SESSION {
                let label = c.cls[i].label.clone();
                let code = if root_fp >= HEAVY_SESSION {
                    "session_root_ge_8g"
                } else {
                    "session_group_ge_8g"
                };
                let place = c.project[i]
                    .clone()
                    .or_else(|| {
                        p.cwd
                            .as_deref()
                            .map(|x| vh_model::display_path(x, &c.s.host.home_dir))
                    })
                    .unwrap_or_default();
                out.push(build(
                    c,
                    Draft {
                        id: fid(FindingKind::HeavyAgentSession, c.pref(i)),
                        kind: FindingKind::HeavyAgentSession,
                        confidence: Confidence::Confirmed,
                        targets: vec![i],
                        with_desc: true,
                        title: format!("{label} {}, {}째", size(fp), age(c.age_ms(i))),
                        short: format!("{label} {}", size(fp)),
                        detail: format!(
                            "{label}{}이 {}(본체 {})를 쓰고 있어요. {}째 실행 중이에요. 핸드오프를 저장한 뒤 재시작하는 걸 권해요. 강제로 끄면 대화 맥락이 사라져서 vh는 끄지 않아요.",
                            if place.is_empty() {
                                String::new()
                            } else {
                                format!("({place})")
                            },
                            with_kids(nd, fp),
                            size(root_fp),
                            age(c.age_ms(i))
                        ),
                        reasons: vec![code.into()],
                        suggestion: Suggestion::HandoffThenRestart,
                    },
                ));
            }
        }
        let fp = c.footprint(i);
        if fp < HEAVY_PROCESS
            || p.uid != c.s.self_uid
            || covered.get(i).copied().unwrap_or(false)
            || !c.alive(i)
            || matches!(kind, Kind::System | Kind::AgentCli)
        {
            continue;
        }
        let label = c.cls[i].label.clone();
        let mut reasons = vec!["footprint_ge_4g".to_string()];
        let note = match kind {
            Kind::VirtualMachine => {
                reasons.push("vm_expected_large".into());
                " 가상 머신은 원래 메모리를 크게 잡아요. 안 쓰는 컨테이너를 멈추는 편이 효과적이에요."
            }
            Kind::LocalLlm => {
                reasons.push("llm_model_loaded".into());
                " 로컬 LLM은 모델을 메모리에 올려 두기 때문에 커요. 안 쓰면 끄세요."
            }
            Kind::LanguageServer => {
                reasons.push("worktree_tsserver".into());
                " 편집기가 띄운 언어 서버예요. 안 쓰는 워크트리·창을 닫으면 줄어요."
            }
            _ => "",
        };
        out.push(build(
            c,
            Draft {
                id: fid(FindingKind::HeavyProcess, c.pref(i)),
                kind: FindingKind::HeavyProcess,
                confidence: Confidence::Confirmed,
                targets: vec![i],
                with_desc: false,
                title: format!("{label} {}", size(fp)),
                short: format!("{label} {}", size(fp)),
                detail: format!(
                    "메모리를 약 {} 쓰고 있어요(실제 점유 footprint 기준).{note}{}",
                    size(fp),
                    review_note("크다고 해서 필요 없는 프로세스라는 뜻은 아님", p.pid)
                ),
                reasons,
                suggestion: Suggestion::Review,
            },
        ));
    }
    out
}
