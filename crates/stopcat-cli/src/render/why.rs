//! `stopcat why <pid | :port>` 화면.

use stopcat_model::{Explanation, Report, Section, Snapshot};

use super::{Lookup, Out, confidence_ko, finding_kind_ko, scope_ko, section};
use crate::color::Color;
use crate::fmt;
use crate::target::Target;

const CHAIN_NAME_WIDTH: usize = 30;

pub fn render(s: &Snapshot, r: &Report, q: Target, exps: &[Explanation], color: bool) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);
    for (i, e) in exps.iter().enumerate() {
        if i > 0 {
            o.blank();
        }
        one(&mut o, &lk, q, e);
    }
    o.finish()
}

fn one(o: &mut Out, lk: &Lookup<'_>, q: Target, e: &Explanation) {
    let name = e
        .chain
        .first()
        .map(|n| n.name.clone())
        .or_else(|| lk.proc(e.target).map(|p| p.name.clone()))
        .unwrap_or_else(|| format!("{}번 프로세스", e.target.pid));
    let head = match q {
        Target::Port(p) => format!(":{p} — {}", e.label_ko),
        Target::Pid(_) => format!("{name} — {}", e.label_ko),
    };
    o.colored(&head, Color::Bold);

    let refs: Vec<_> = e
        .listeners
        .iter()
        .filter(|l| match q {
            Target::Port(p) => l.port == p,
            Target::Pid(_) => true,
        })
        .collect();
    if !refs.is_empty() {
        let mut addrs: Vec<String> = Vec::new();
        for l in &refs {
            let a = if l.all_interfaces {
                format!("*:{}", l.port)
            } else {
                format!("{}:{}", l.local_addr, l.port)
            };
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
        let mut text = format!("{}({})", scope_ko(&refs), addrs.join(", "));
        if refs.iter().any(|l| l.all_interfaces) {
            text.push_str(" — 같은 와이파이의 다른 기기도 접속 가능");
        }
        o.wrap("  열린 곳    ", "             ", &text);
    }
    if let Some(p) = &e.project {
        o.line(&format!("  프로젝트   {}", lk.path(p)));
    }
    if let Some(owner) = &e.owner_ko {
        o.wrap("  띄운 곳    ", "             ", owner);
    }
    if let Some(p) = lk.proc(e.target) {
        let mut mem = p
            .footprint_bytes
            .map(fmt::bytes)
            .unwrap_or_else(|| "?".into());
        let with_kids = e
            .finding_ids
            .iter()
            .filter_map(|id| lk.finding(id))
            .find(|f| f.descendant_count > 0 && f.targets.contains(&e.target));
        if let Some(f) = with_kids {
            mem = format!(
                "{} (자식 {}개 포함)",
                fmt::bytes(f.reclaim_bytes),
                f.descendant_count
            );
        }
        let age = lk.age(e.target).unwrap_or_default();
        o.line(&format!("  실행 시간  {age} · 메모리 {mem}"));
    }

    o.line("누가 띄웠나 (자신 → 부모 → … → 시스템)");
    for n in &e.chain {
        let nm = if n.label_ko.is_empty() || n.label_ko == n.name {
            n.name.clone()
        } else {
            format!("{} — {}", n.name, n.label_ko)
        };
        let nm = fmt::pad(&fmt::truncate(&nm, CHAIN_NAME_WIDTH), CHAIN_NAME_WIDTH);
        match lk.proc(n.target) {
            Some(p) if n.target.pid != 1 => {
                let mem = p.footprint_bytes.map(fmt::bytes).unwrap_or_default();
                let age = lk.age(n.target).unwrap_or_default();
                o.line(&format!(
                    "  {}  {nm} {}   {age}",
                    fmt::lpad(&n.target.pid.to_string(), 5),
                    fmt::lpad(&mem, 6)
                ));
            }
            _ => o.line(
                format!(
                    "  {}  {}",
                    fmt::lpad(&n.target.pid.to_string(), 5),
                    nm.trim_end()
                )
                .as_str(),
            ),
        }
    }

    let fs: Vec<_> = e
        .finding_ids
        .iter()
        .filter_map(|id| lk.finding(id))
        .collect();
    if !fs.is_empty() {
        o.line("발견");
        let w = fs
            .iter()
            .map(|f| fmt::width(finding_kind_ko(f.kind)))
            .max()
            .unwrap_or(0);
        for f in fs {
            o.line(&format!(
                "  {}  {} — {}",
                fmt::pad(finding_kind_ko(f.kind), w),
                confidence_ko(f.confidence),
                f.title_ko
            ));
        }
    }
    if let Some(f) = e
        .finding_ids
        .iter()
        .filter_map(|id| lk.finding(id))
        .filter(|f| f.section != Section::Info && f.targets.contains(&e.target))
        .min_by_key(|f| section::rank(f.section))
    {
        let (_, long) = section::evidence_for(f, lk.classified(e.target), lk.s.taken_at_unix_ms);
        let text = if long.is_empty() {
            section::name_ko(f.section).to_string()
        } else {
            format!("{} — {long}", section::name_ko(f.section))
        };
        o.wrap("구역: ", "      ", &text);
    }
    if !e.summary_ko.is_empty() {
        o.wrap("요약: ", "      ", &e.summary_ko);
    }
}
