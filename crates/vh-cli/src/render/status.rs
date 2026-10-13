//! `vh` 상태 화면.

use vh_model::{Confidence, Finding, FindingKind, HealthLevel, Kind, Report, Snapshot, Suggestion};

use super::{Lookup, Out};
use crate::color::Color;
use crate::fmt::{self, WIDTH};

const MAX_LINES_PER_BUCKET: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Watch,
    Orphan,
    Leftover,
    Exposed,
    Conflict,
}

fn bucket(f: &Finding, target_kind: Option<Kind>) -> Option<Bucket> {
    use FindingKind::*;
    let leftover_kind = matches!(
        target_kind,
        Some(Kind::Emulator | Kind::TestTool | Kind::HeadlessBrowser)
    );
    match f.kind {
        HeavyAgentSession | HeavyProcess | Runaway | LimitNearing => Some(Bucket::Watch),
        MemoryPressure => None,
        Orphan | LogicalOrphan if leftover_kind => Some(Bucket::Leftover),
        Orphan | LogicalOrphan => Some(Bucket::Orphan),
        HeadlessBrowserLeftover | Duplicate | Stopped | Zombie => Some(Bucket::Leftover),
        ExposedListener => Some(Bucket::Exposed),
        KnownPortConflict => Some(Bucket::Conflict),
    }
}

fn hint(f: &Finding) -> &'static str {
    if f.title_ko.contains('→') {
        return "";
    }
    match f.suggestion {
        Suggestion::HandoffThenRestart => " → 핸드오프 후 재시작 권장",
        Suggestion::RestartParent { .. } => " → 부모 앱을 다시 시작해야 정리돼요",
        _ => "",
    }
}

/// `"{tag}  a · b · c"`를 80칸 안에 맞추고, 못 넣은 개수는 " 외 N건"으로 붙인다.
fn joined(o: &mut Out, tag: &str, c: Color, items: &[&Finding]) {
    if items.is_empty() {
        return;
    }
    let mut shown: Vec<&str> = Vec::new();
    for (i, f) in items.iter().enumerate() {
        let rest = items.len() - i - 1;
        let mut trial = shown.clone();
        trial.push(&f.short_ko);
        let suffix = if rest > 0 {
            format!(" 외 {rest}건")
        } else {
            String::new()
        };
        let line = format!("{tag}  {}{suffix}", trial.join(" · "));
        if fmt::width(&line) > WIDTH && !shown.is_empty() {
            break;
        }
        shown = trial;
    }
    let hidden = items.len() - shown.len();
    let suffix = if hidden > 0 {
        format!(" 외 {hidden}건")
    } else {
        String::new()
    };
    o.tagged(tag, c, &format!("{}{suffix}", shown.join(" · ")));
}

pub fn render(s: &Snapshot, r: &Report, color: bool) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);
    let level_color = match r.health.level {
        HealthLevel::Ok => Color::Green,
        HealthLevel::Watch => Color::Yellow,
        HealthLevel::Critical => Color::Red,
    };
    o.colored(&r.health.headline_ko, level_color);
    if r.health.level != HealthLevel::Ok {
        for reason in &r.health.reasons_ko {
            o.wrap("  ", "  ", reason);
        }
    }

    let mut by: [Vec<&Finding>; 5] = Default::default();
    for f in &r.findings {
        let kind = f
            .targets
            .first()
            .and_then(|t| lk.classified(*t))
            .map(|c| c.kind);
        let Some(b) = bucket(f, kind) else { continue };
        let needs_confidence = matches!(b, Bucket::Orphan | Bucket::Leftover);
        if needs_confidence && !f.confidence.meets(Confidence::Likely) {
            continue;
        }
        by[b as usize].push(f);
    }

    let mut hidden = 0usize;
    for (b, tag) in [(Bucket::Watch, "주의"), (Bucket::Orphan, "고아")] {
        let list = &by[b as usize];
        for f in list.iter().take(MAX_LINES_PER_BUCKET) {
            o.tagged(tag, Color::Yellow, &format!("{}{}", f.title_ko, hint(f)));
        }
        hidden += list.len().saturating_sub(MAX_LINES_PER_BUCKET);
    }
    joined(
        &mut o,
        "잔재",
        Color::Yellow,
        &by[Bucket::Leftover as usize],
    );
    joined(&mut o, "노출", Color::Red, &by[Bucket::Exposed as usize]);
    joined(
        &mut o,
        "충돌",
        Color::Yellow,
        &by[Bucket::Conflict as usize],
    );
    if hidden > 0 {
        o.line(&format!(
            "  … 외 {hidden}건은 vh fix 미리보기에서 볼 수 있어요"
        ));
    }

    let shown_any = by.iter().any(|v| !v.is_empty());
    let total = r.totals.reclaimable_confirmed_bytes + r.totals.reclaimable_likely_bytes;
    if total > 0 {
        o.line(&format!(
            "→ vh fix 로 최대 약 {} 회수 (미리보기 → 확인)",
            fmt::bytes(total)
        ));
    } else if !shown_any {
        o.line(if r.health.level == HealthLevel::Ok {
            "지금 정리할 것이 없어요. 맥 상태가 좋아요."
        } else {
            "지금 vh가 정리할 것은 없어요."
        });
    }
    let heavy_agent = by[Bucket::Watch as usize]
        .iter()
        .any(|f| f.kind == FindingKind::HeavyAgentSession);
    if r.health.level == HealthLevel::Critical && heavy_agent {
        o.line("  AI 에이전트 세션은 vh가 끄지 않아요. 대화를 저장한 뒤 직접 다시 켜세요.");
    }
    let unread = s
        .collection_errors
        .iter()
        .filter(|e| !e.message.contains("(정상)"))
        .count();
    if unread > 0 {
        o.line(&format!(
            "  일부 정보를 읽지 못했어요({unread}건). 자세히: vh snapshot --json"
        ));
    }
    o.finish()
}
