//! 보고 구역 배정(PLAN `section_map`). 분석이 끝난 Finding마다 한 번 돈다.
//!
//! 기본 대응표(주인 × 쓰고 있는지):
//! | | 주인 살아 있음·사용자 | 주인 끝남·모름 |
//! |---|---|---|
//! | 쓰고 있음(Active·Unknown) | working | check |
//! | 안 쓰고 있음(Idle) | check | unneeded |
//!
//! 제한: 신뢰도 Possible, 대상 종류가 에뮬레이터·VM·DB·로컬 LLM·터널이면 unneeded가 되지 않는다(check).
//! Terminate 제안은 unneeded 구역에만 남는다. 나머지는 Review로 바꾸고 근거 코드를 붙인다.

use stopcat_model::{
    Confidence, Finding, FindingKind, Kind, OwnerState, ProcRef, Section, Suggestion, Usage,
    UsageReason, UsageState,
};

use crate::ctx::Ctx;
use crate::findings::review_note;

/// 사용자가 보거나 상태·데이터를 쥔 종류. unneeded로 보고하지 않는다(지킴이 NOTIFY_KINDS와 같다).
pub(crate) const REPORT_ONLY_KINDS: &[Kind] = &[
    Kind::Emulator,
    Kind::VirtualMachine,
    Kind::Database,
    Kind::LocalLlm,
    Kind::Tunnel,
];

fn idx_of(c: &Ctx, r: ProcRef) -> Option<usize> {
    c.idx.get(&r.pid).copied().filter(|&i| c.pref(i) == r)
}

/// 여러 대상: 하나라도 Active면 Active, 아니면 하나라도 Unknown이면 Unknown, 전부 Idle이면 Idle.
fn combined(c: &Ctx, idxs: &[usize]) -> UsageState {
    if idxs.is_empty() {
        return UsageState::Unknown;
    }
    let states = idxs.iter().map(|&i| c.usage[i].state);
    if states.clone().any(|s| s == UsageState::Active) {
        UsageState::Active
    } else if states.clone().any(|s| s == UsageState::Unknown) {
        UsageState::Unknown
    } else {
        UsageState::Idle
    }
}

fn owned(o: OwnerState) -> bool {
    matches!(o, OwnerState::Alive | OwnerState::User)
}

/// 쓰고 있음·모름 근거를 한국어로(Review 문장용).
fn in_use_words(u: &Usage) -> String {
    let words: Vec<&str> = u
        .reasons
        .iter()
        .filter_map(|r| {
            Some(match r {
                UsageReason::HasTty => "터미널이 붙어 있음",
                UsageReason::PeerOutsideSubtree => "다른 프로그램과 연결돼 있음",
                UsageReason::PeerExternal => "외부와 연결돼 있음",
                UsageReason::PeerUnresolved => "상대를 알 수 없는 연결이 있음",
                UsageReason::CpuActive => "CPU를 쓰고 있음",
                UsageReason::DiskActive => "디스크를 쓰고 있음",
                UsageReason::Young => "생긴 지 10분이 안 됨",
                UsageReason::CpuUnknown => "CPU를 재지 못함",
                UsageReason::DiskUnknown => "디스크를 재지 못함",
                UsageReason::PeersUnknown => "연결을 읽지 못함",
                _ => return None,
            })
        })
        .collect();
    if words.is_empty() {
        "지금 쓰고 있을 수 있음".to_string()
    } else {
        format!("지금 쓰고 있을 수 있음: {}", words.join(", "))
    }
}

pub(crate) fn assign(c: &Ctx, f: &mut Finding) {
    let idxs: Vec<usize> = f.targets.iter().filter_map(|&r| idx_of(c, r)).collect();
    let first = idxs.first().copied();
    let owner = first.map_or(OwnerState::Unknown, |i| c.usage[i].owner);
    let terminating = matches!(f.suggestion, Suggestion::Terminate { .. });
    let table = |state: UsageState| -> (Section, bool) {
        let base = match (state == UsageState::Idle, owned(owner)) {
            (false, true) => Section::Working,
            (false, false) => Section::Check,
            (true, true) => Section::Check,
            (true, false) => Section::Unneeded,
        };
        let kind_cap = idxs
            .iter()
            .any(|&i| REPORT_ONLY_KINDS.contains(&c.cls[i].kind));
        if base == Section::Unneeded && (f.confidence == Confidence::Possible || kind_cap) {
            (Section::Check, kind_cap)
        } else {
            (base, false)
        }
    };
    let state = combined(c, &idxs);
    let (section, kind_capped) = match f.kind {
        FindingKind::MemoryPressure
        | FindingKind::LimitNearing
        | FindingKind::ExposedListener
        | FindingKind::KnownPortConflict => (Section::Info, false),
        FindingKind::HeavyAgentSession | FindingKind::HeavyProcess | FindingKind::Zombie => {
            (Section::Manual, false)
        }
        FindingKind::HighCpu => (
            if owned(owner) {
                Section::Working
            } else {
                Section::Check
            },
            false,
        ),
        FindingKind::Stopped if !terminating => (Section::Check, false),
        FindingKind::Orphan if first.is_some_and(|i| c.cls[i].kind == Kind::AgentCli) => {
            (Section::Working, false)
        }
        FindingKind::Stopped
        | FindingKind::Orphan
        | FindingKind::LogicalOrphan
        | FindingKind::HeadlessBrowserLeftover
        | FindingKind::Duplicate => table(state),
    };
    f.section = section;
    if section != Section::Unneeded && terminating {
        f.suggestion = Suggestion::Review;
        let pid = f.targets.first().map_or(0, |t| t.pid);
        if state != UsageState::Idle {
            f.reason_codes.push("usage_not_idle".into());
            let why = first.map_or_else(
                || "지금 쓰고 있을 수 있음".to_string(),
                |i| in_use_words(&c.usage[i]),
            );
            f.detail_ko.push_str(&review_note(&why, pid));
        } else if kind_capped {
            f.reason_codes.push("kind_report_only".into());
            f.detail_ko.push_str(&review_note(
                "사용자가 직접 띄워 쓰는 종류라 보고만 함",
                pid,
            ));
        } else {
            f.reason_codes.push("owner_present".into());
            f.detail_ko
                .push_str(&review_note("띄운 쪽이 아직 있음", pid));
        }
    }
}
