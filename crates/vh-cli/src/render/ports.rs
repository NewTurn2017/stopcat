//! `vh ports` 화면.

use std::collections::BTreeMap;

use vh_model::{FindingKind, ListenerView, ProcRef, Report, Snapshot};

use super::{Lookup, Out, scope_ko};
use crate::color::Color;
use crate::fmt;

const COL_PORT: usize = 6;
const COL_SCOPE: usize = 14;
const COL_PROGRAM: usize = 24;

pub fn render(s: &Snapshot, r: &Report, color: bool) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);

    let mut rows: BTreeMap<(u16, i32, u64), Vec<&ListenerView>> = BTreeMap::new();
    for v in &r.listeners {
        let l = &v.listener;
        rows.entry((l.port, l.pid, l.start_time_unix_ms))
            .or_default()
            .push(v);
    }
    if rows.is_empty() {
        o.line("기다리는 포트가 없어요.");
        return o.finish();
    }

    let conflict_targets: Vec<ProcRef> = r
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::KnownPortConflict)
        .flat_map(|f| f.targets.iter().copied())
        .collect();
    let exposed = rows
        .values()
        .filter(|vs| vs.iter().any(|v| v.listener.all_interfaces))
        .count();
    let conflicts = rows
        .keys()
        .filter(|(_, pid, st)| {
            conflict_targets.contains(&ProcRef {
                pid: *pid,
                start_time_unix_ms: *st,
            })
        })
        .count();
    o.colored(
        &format!(
            "기다리는 포트 {}개 — 외부 노출 {exposed} · 알려진 충돌 {conflicts}",
            rows.len()
        ),
        Color::Bold,
    );
    o.line(&format!(
        "{} {} {} 프로젝트",
        fmt::pad("포트", COL_PORT),
        fmt::pad("열린 곳", COL_SCOPE),
        fmt::pad("프로그램", COL_PROGRAM)
    ));
    for ((port, _, _), vs) in &rows {
        let ls: Vec<_> = vs.iter().map(|v| &v.listener).collect();
        let first = vs[0];
        let project = first
            .project
            .as_deref()
            .map(|p| lk.path(p))
            .unwrap_or_else(|| "—".to_string());
        o.line(&format!(
            "{} {} {} {project}",
            fmt::pad(&port.to_string(), COL_PORT),
            fmt::pad(&scope_ko(&ls), COL_SCOPE),
            fmt::pad(&fmt::truncate(&first.label_ko, COL_PROGRAM), COL_PROGRAM)
        ));
        if let Some(e) = vs.iter().find_map(|v| v.exposure_ko.as_deref()) {
            o.wrap("       ! ", "         ", e);
        }
    }
    o.line("자세히 보려면: vh why :<포트>");
    o.finish()
}
