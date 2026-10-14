//! `vh` 상태 화면.

use vh_model::{Finding, FindingKind, HealthLevel, Report, Section, Snapshot};

use super::{Lookup, Out, section};
use crate::color::Color;
use crate::fmt::{self, WIDTH};

const MAX_LINES_PER_SECTION: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Exposed,
    Conflict,
}

/// `"{tag}  a · b ×2 · c"`를 80칸 안에 맞춘다. 짧은 이름이 같은 발견은 "×N"으로 묶고,
/// 안 들어가는 묶음은 건너뛰고 뒤의 짧은 것을 넣으며, 못 넣은 발견 수는 " 외 N건"으로 붙인다.
fn joined(o: &mut Out, tag: &str, c: Color, items: &[&Finding]) {
    let mut groups: Vec<(&str, usize)> = Vec::new();
    for f in items {
        match groups.iter_mut().find(|(name, _)| *name == f.short_ko) {
            Some(g) => g.1 += 1,
            None => groups.push((&f.short_ko, 1)),
        }
    }
    if groups.is_empty() {
        return;
    }
    let label = |(name, n): &(&str, usize)| {
        if *n > 1 {
            format!("{name} ×{n}")
        } else {
            name.to_string()
        }
    };
    let suffix = |hidden: usize| {
        if hidden > 0 {
            format!(" 외 {hidden}건")
        } else {
            String::new()
        }
    };
    let mut shown: Vec<String> = Vec::new();
    let mut covered = 0usize;
    for g in &groups {
        let mut trial = shown.clone();
        trial.push(label(g));
        let line = format!(
            "{tag}  {}{}",
            trial.join(" · "),
            suffix(items.len() - covered - g.1)
        );
        if fmt::width(&line) > WIDTH && !shown.is_empty() {
            continue;
        }
        shown = trial;
        covered += g.1;
    }
    o.tagged(
        tag,
        c,
        &format!("{}{}", shown.join(" · "), suffix(items.len() - covered)),
    );
}

pub const FOOTER_NOTHING_OK: &str = "지금 정리할 것이 없어요. 맥 상태가 좋아요.";
pub const FOOTER_NOTHING: &str = "지금 vh가 정리할 것은 없어요.";

fn section_line(lk: &Lookup<'_>, f: &Finding) -> String {
    let c = f.targets.first().and_then(|t| lk.classified(*t));
    let label = match c.filter(|c| !c.label_ko.is_empty()) {
        Some(c) if f.targets.len() == 1 => c.label_ko.clone(),
        _ if f.short_ko.is_empty() => f.title_ko.clone(),
        _ => f.short_ko.clone(),
    };
    let size = if f.reclaim_bytes > 0 {
        format!(" {}", fmt::bytes(f.reclaim_bytes))
    } else {
        String::new()
    };
    let (short, _) = section::evidence_for(f, c, lk.s.taken_at_unix_ms);
    match f.section {
        Section::Working => format!("{label} — {short} · 건드리지 않음"),
        _ if short.is_empty() => format!("{label}{size}"),
        _ => format!("{label}{size} — {short}"),
    }
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
    o.line(
        &section::reclaim_text(&r.totals).unwrap_or_else(|| section::RECLAIM_NOTHING.to_string()),
    );

    let mut shown_any = false;
    for sect in section::ORDER {
        let list: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.section == sect)
            .filter(|f| sect != Section::Info || f.kind == FindingKind::LimitNearing)
            .collect();
        let tag = section::plain_tag(sect);
        let c = match sect {
            Section::Unneeded | Section::Check => Color::Yellow,
            _ => Color::Bold,
        };
        for f in list.iter().take(MAX_LINES_PER_SECTION) {
            o.tagged(tag, c, &section_line(&lk, f));
        }
        if list.len() > MAX_LINES_PER_SECTION {
            o.line(&format!(
                "  … 외 {}건(전체: vh --json)",
                list.len() - MAX_LINES_PER_SECTION
            ));
        }
        shown_any |= !list.is_empty();
    }

    let mut by: [Vec<&Finding>; 2] = Default::default();
    for f in &r.findings {
        match f.kind {
            FindingKind::ExposedListener => by[Bucket::Exposed as usize].push(f),
            FindingKind::KnownPortConflict => by[Bucket::Conflict as usize].push(f),
            _ => {}
        }
    }
    joined(&mut o, "노출", Color::Red, &by[Bucket::Exposed as usize]);
    joined(
        &mut o,
        "충돌",
        Color::Yellow,
        &by[Bucket::Conflict as usize],
    );

    if r.totals.unneeded_bytes > 0 {
        o.line(&format!(
            "→ vh fix 로 '필요 없음' 약 {} 정리 (미리보기 → 확인)",
            fmt::bytes(r.totals.unneeded_bytes)
        ));
    } else if !shown_any {
        o.line(if r.health.level == HealthLevel::Ok {
            FOOTER_NOTHING_OK
        } else {
            FOOTER_NOTHING
        });
    }
    let unread = s
        .collection_errors
        .iter()
        .filter(|e| e.pid.is_none() && !e.message.contains("(정상)"))
        .count();
    if unread > 0 {
        o.line(&format!(
            "  일부 정보를 읽지 못했어요({unread}건). 자세히: vh snapshot --json"
        ));
    }
    o.finish()
}
