//! 보고 구역·근거 요약·확보량 문구. 화면·`--plain`·`stopcat fix`가 같이 쓴다.
//! 구역(`Finding.section`)과 사용 판정(`Classified.usage`)은 stopcat-analyze 값을 그대로 읽고 다시 계산하지 않는다.

use stopcat_model::{
    Classified, Finding, Kind, OwnerState, Section, Suggestion, Totals, Usage, UsageReason,
    UsageState,
};

use std::fmt::Write as _;

use crate::fmt;

/// 화면·`--plain`의 구역 순서.
pub const ORDER: [Section; 5] = [
    Section::Unneeded,
    Section::Check,
    Section::Working,
    Section::Manual,
    Section::Info,
];

pub fn rank(s: Section) -> usize {
    match s {
        Section::Unneeded => 0,
        Section::Check => 1,
        Section::Working => 2,
        Section::Manual => 3,
        Section::Info => 4,
    }
}

/// `--plain` 줄 머리(9칸으로 맞춰진 이름).
pub fn plain_tag(s: Section) -> &'static str {
    match s {
        Section::Unneeded => "필요 없음",
        Section::Check => "확인 필요",
        Section::Working => "일하는 중",
        Section::Manual => "직접 하면",
        Section::Info => "알아 둘 것",
    }
}

/// 구역 이름(미리보기·`stopcat why`).
pub fn name_ko(s: Section) -> &'static str {
    match s {
        Section::Unneeded => "필요 없음",
        Section::Check => "확인 필요",
        Section::Working => "일하는 중",
        Section::Manual => "직접 하면 확보",
        Section::Info => "알아 둘 것",
    }
}

/// 사용 판정 근거를 복사 가능한 작은 값으로(화면 갱신마다 할당을 늘리지 않는다).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UsageView {
    pub state: UsageState,
    pub owner: OwnerState,
    pub reasons: u32,
    pub cpu_pct: Option<f32>,
    pub peers: u32,
}

fn bit(r: UsageReason) -> u32 {
    1 << (r as u32)
}

impl UsageView {
    pub fn of(u: &Usage) -> UsageView {
        UsageView {
            state: u.state,
            owner: u.owner,
            reasons: u.reasons.iter().fold(0, |acc, r| acc | bit(*r)),
            cpu_pct: u.subtree_cpu_pct,
            peers: u.outside_peer_count,
        }
    }

    pub fn has(&self, r: UsageReason) -> bool {
        self.reasons & bit(r) != 0
    }
}

pub const OWNER_ALIVE: &str = "주인 있음";
pub const OWNER_GONE: &str = "주인 끝남";
pub const OWNER_UNKNOWN: &str = "주인 모름";
pub const OWNER_APP: &str = "앱";
pub const OWNER_USER: &str = "직접 실행";
pub const NOT_USING: &str = "안 쓰는 듯";

fn owner_token(u: &UsageView, kind: Option<Kind>) -> &'static str {
    match u.owner {
        OwnerState::Alive => OWNER_ALIVE,
        OwnerState::Ended => OWNER_GONE,
        OwnerState::Unknown => OWNER_UNKNOWN,
        OwnerState::User if matches!(kind, Some(Kind::GuiApp | Kind::AppHelper)) => OWNER_APP,
        OwnerState::User => OWNER_USER,
    }
}

fn push_cpu(out: &mut String, u: &UsageView, long: bool) {
    match u.cpu_pct {
        Some(p) if p >= 0.5 => {
            let _ = write!(out, "CPU {}%", p.round() as u64);
        }
        _ if long => out.push_str("CPU 0%"),
        _ => out.push_str("CPU 0"),
    }
}

/// 근거 토큰을 `sep`으로 이어 `out`에 쓴다(토큰마다 할당하지 않는다). `long`이면 기록용 근거까지.
fn write_tokens(
    out: &mut String,
    u: &UsageView,
    kind: Option<Kind>,
    age_ms: Option<u64>,
    long: bool,
    sep: &str,
) {
    use UsageReason::*;
    out.push_str(owner_token(u, kind));
    let tok = |out: &mut String, f: &dyn Fn(&mut String)| {
        out.push_str(sep);
        f(out);
    };
    if u.has(HasTty) {
        tok(out, &|o| o.push_str("터미널 붙음"));
    }
    if u.has(CpuActive) {
        tok(out, &|o| push_cpu(o, u, long));
    }
    if u.has(DiskActive) {
        tok(out, &|o| o.push_str("디스크 사용"));
    }
    if u.has(PeerOutsideSubtree) || u.has(PeerExternal) || u.has(PeerUnresolved) {
        tok(out, &|o| {
            if u.peers > 0 {
                let _ = write!(o, "연결 {}", u.peers);
            } else {
                o.push_str("연결 있음");
            }
        });
    }
    if u.has(Young) {
        let mins = age_ms.map(|a| a / 60_000).unwrap_or(0);
        tok(out, &|o| {
            let _ = write!(o, "생긴 지 {mins}분");
        });
    }
    let idle_alive = u.state == UsageState::Idle && u.owner == OwnerState::Alive;
    if idle_alive && !long {
        tok(out, &|o| o.push_str(NOT_USING));
        return;
    }
    if u.has(CpuIdle) {
        tok(out, &|o| push_cpu(o, u, long));
    }
    if u.has(NoPeers) || u.has(InfraPeersOnly) {
        tok(out, &|o| o.push_str("연결 0"));
    }
    if long && u.has(DiskIdle) {
        tok(out, &|o| o.push_str("디스크 0"));
    }
    if long && u.has(LifetimeCpuLow) {
        tok(out, &|o| o.push_str("평생 CPU 낮음"));
    }
    if u.has(CpuUnknown) {
        tok(out, &|o| o.push_str("CPU 모름"));
    }
    if u.has(PeersUnknown) {
        tok(out, &|o| o.push_str("연결 모름"));
    }
    if long && u.has(DiskUnknown) {
        tok(out, &|o| o.push_str("디스크 모름"));
    }
    if long && idle_alive {
        tok(out, &|o| o.push_str(NOT_USING));
    }
}

/// 목록 근거 칸: "주인 끝남·CPU 0·연결 0".
pub fn evidence_short(u: &UsageView, kind: Option<Kind>, age_ms: Option<u64>) -> String {
    let mut s = String::with_capacity(64);
    write_tokens(&mut s, u, kind, age_ms, false, "·");
    s
}

/// 자세히·미리보기 근거: "주인 끝남 · CPU 0% · 연결 0 · 평생 CPU 낮음".
pub fn evidence_long(u: &UsageView, kind: Option<Kind>, age_ms: Option<u64>) -> String {
    let mut s = String::with_capacity(128);
    write_tokens(&mut s, u, kind, age_ms, true, " · ");
    s
}

/// '직접 하면 확보' 줄의 짧은 방법.
pub fn manual_hint(f: &Finding, kind: Option<Kind>) -> &'static str {
    match (&f.suggestion, kind) {
        (Suggestion::HandoffThenRestart, _) => "핸드오프 저장 후 재시작",
        (Suggestion::RestartParent { .. }, _) => "띄운 앱 다시 시작",
        (_, Some(Kind::VirtualMachine)) => "앱에서 멈추기",
        (_, Some(Kind::LocalLlm)) => "모델 내리기·앱 종료",
        _ => "직접 끄기",
    }
}

/// 구역·사용 판정 → (목록 근거 칸, 자세히 근거). manual 목록 칸은 짧은 방법, info는 둘 다 빈 문자열.
pub fn evidence_pair(
    f: &Finding,
    kind: Option<Kind>,
    usage: Option<UsageView>,
    age_ms: Option<u64>,
) -> (String, String) {
    if f.section == Section::Info {
        return (String::new(), String::new());
    }
    let long = usage
        .map(|u| evidence_long(&u, kind, age_ms))
        .unwrap_or_default();
    if f.section == Section::Manual {
        return (manual_hint(f, kind).to_string(), long);
    }
    let short = usage
        .map(|u| evidence_short(&u, kind, age_ms))
        .unwrap_or_default();
    (short, long)
}

/// 분류 결과 하나로 근거 쌍을 만든다(`--plain`·`stopcat fix`·`stopcat why`).
pub fn evidence_for(f: &Finding, c: Option<&Classified>, now_unix_ms: u64) -> (String, String) {
    let age = c.map(|c| now_unix_ms.saturating_sub(c.target.start_time_unix_ms));
    evidence_pair(
        f,
        c.map(|c| c.kind),
        c.map(|c| UsageView::of(&c.usage)),
        age,
    )
}

/// 확보량 줄(들여쓰기 없음). 셋 다 0이면 `None`.
pub fn reclaim_text(t: &Totals) -> Option<String> {
    if t.unneeded_bytes == 0 && t.check_bytes == 0 && t.manual_bytes == 0 {
        return None;
    }
    let mut s = format!(
        "확보 가능 {}",
        if t.unneeded_bytes == 0 {
            "0".to_string()
        } else {
            fmt::bytes(t.unneeded_bytes)
        }
    );
    if t.check_bytes > 0 {
        s.push_str(&format!(" · 확인하면 +{}", fmt::bytes(t.check_bytes)));
    }
    if t.manual_bytes > 0 {
        s.push_str(&format!(" · 직접 하면 +{}", fmt::bytes(t.manual_bytes)));
    }
    Some(s)
}

pub const RECLAIM_NOTHING: &str = "지금 확보할 것이 없어요";

/// `c`·`stopcat fix` 기본 대상: 구역 unneeded이고 바로 끌 수 있는(Terminate) 발견만.
pub fn bulk_ids(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| {
            f.section == Section::Unneeded && matches!(f.suggestion, Suggestion::Terminate { .. })
        })
        .map(|f| f.id.clone())
        .collect()
}
