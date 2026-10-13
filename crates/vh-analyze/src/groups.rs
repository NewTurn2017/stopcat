use std::collections::BTreeMap;

use vh_model::{ExeOrigin, Group, GroupKind, Kind};

use crate::ctx::Ctx;

struct Acc {
    kind: GroupKind,
    title: String,
    root: Option<String>,
    members: Vec<usize>,
}

pub(crate) fn groups(c: &Ctx) -> Vec<Group> {
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    let home = c.s.host.home_dir.as_str();
    for i in 0..c.procs.len() {
        let (id, kind, title, root) = if let Some(r) = c.session_root[i] {
            let rp = &c.procs[r];
            let place = c.project[r]
                .as_deref()
                .or(rp.cwd.as_deref())
                .map(|x| x.rsplit('/').next().unwrap_or(x).to_string());
            let title = match place {
                Some(pl) if !pl.is_empty() => format!("{} ({pl})", c.cls[r].label),
                _ => c.cls[r].label.clone(),
            };
            (
                format!("session:{}:{}", rp.pid, rp.start_time_unix_ms),
                GroupKind::AgentSession,
                title,
                rp.cwd.as_deref().map(|x| vh_model::display_path(x, home)),
            )
        } else if let Some(proj) = &c.project[i] {
            let title = proj.rsplit('/').next().unwrap_or(proj).to_string();
            (
                format!("project:{proj}"),
                GroupKind::Project,
                title,
                Some(proj.clone()),
            )
        } else if c.feats[i].origin == ExeOrigin::AppBundle
            && let Some(app) = &c.feats[i].app
        {
            (format!("app:{app}"), GroupKind::App, app.clone(), None)
        } else if c.cls[i].kind == Kind::System
            || matches!(c.feats[i].origin, ExeOrigin::System)
            || c.cls[i].sig == "emu_sim_runtime"
        {
            (
                "system".to_string(),
                GroupKind::System,
                "macOS 시스템".to_string(),
                None,
            )
        } else {
            (
                "other".to_string(),
                GroupKind::Other,
                "기타".to_string(),
                None,
            )
        };
        acc.entry(id)
            .or_insert_with(|| Acc {
                kind,
                title,
                root,
                members: Vec::new(),
            })
            .members
            .push(i);
    }
    let mut out: Vec<Group> = acc
        .into_iter()
        .map(|(id, a)| {
            let mut members: Vec<_> = a.members.iter().map(|&i| c.pref(i)).collect();
            members.sort();
            let footprint_bytes = a.members.iter().map(|&i| c.footprint(i)).sum();
            let cpus: Vec<f32> = a
                .members
                .iter()
                .filter_map(|&i| c.procs[i].cpu_pct)
                .collect();
            let cpu_pct = if cpus.is_empty() {
                None
            } else {
                Some(cpus.iter().sum())
            };
            Group {
                id,
                kind: a.kind,
                title: a.title,
                root: a.root,
                members,
                footprint_bytes,
                cpu_pct,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.footprint_bytes
            .cmp(&a.footprint_bytes)
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}
