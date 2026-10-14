use std::collections::HashMap;

use stopcat_model::{ExeOrigin, Kind, Proc, ProcRef, ProcStatus, Snapshot, Usage, display_path};

use crate::features::{Feat, features};
use crate::signatures::{Class, classify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadWhy {
    OwnerDead,
    PidReused,
    SpawnerDead,
    ArgvParentDead,
    TmpSessionGone,
}

impl DeadWhy {
    pub(crate) fn code(self) -> &'static str {
        match self {
            DeadWhy::OwnerDead => "owner_dead",
            DeadWhy::PidReused => "owner_pid_reused",
            DeadWhy::SpawnerDead => "spawner_dead",
            DeadWhy::ArgvParentDead => "argv_parent_dead",
            DeadWhy::TmpSessionGone => "tmp_session_gone",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Owner {
    pub session: Option<ProcRef>,
    pub pid: Option<i32>,
    pub source: Option<&'static str>,
    pub label: Option<String>,
    pub alive: Option<bool>,
    pub dead: Option<DeadWhy>,
}

impl Owner {
    pub(crate) fn source_code(&self) -> Option<&'static str> {
        Some(match self.source? {
            "lineage" => "owner_from_lineage",
            "env:CLAUDE_PID" => "owner_from_env_claude_pid",
            "env:CMUX_CLAUDE_PID" => "owner_from_env_cmux_claude_pid",
            "env:SENPI_PY_KERNEL_PARENT_PID" => "owner_from_env_senpi_py_kernel_parent_pid",
            "argv:spawned_by" | "argv:parent_pid" => "owner_from_argv",
            "tmp_cwd" => "owner_from_tmp_cwd",
            _ => return None,
        })
    }
}

/// 분석 한 번에 쓰는 색인. 모든 표는 `procs`와 같은 순서(인덱스)다.
pub(crate) struct Ctx<'a> {
    pub s: &'a Snapshot,
    pub procs: &'a [Proc],
    pub idx: HashMap<i32, usize>,
    pub parent: Vec<Option<usize>>,
    pub children: Vec<Vec<usize>>,
    pub topo: Vec<usize>,
    pub feats: Vec<Feat>,
    pub cls: Vec<Class>,
    pub session_root: Vec<Option<usize>>,
    pub owner: Vec<Owner>,
    pub project: Vec<Option<String>>,
    pub tmp_cwd: Vec<bool>,
    /// 사용 판정(`crate::usage::compute`). 모든 표와 같은 인덱스.
    pub usage: Vec<Usage>,
}

const DAEMON_BY_DESIGN: &[&str] = &[
    "agent_omo_lsp_daemon",
    "android_adb_server",
    "ls_biome",
    "w_watchman",
    "w_turbo_daemon",
    "w_nx_daemon",
    "build_gradle_daemon",
    "build_kotlin_daemon",
];

const ENV_OWNER_KEYS: &[(&str, &str, &str)] = &[
    ("CLAUDE_PID", "env:CLAUDE_PID", "Claude 세션"),
    ("CMUX_CLAUDE_PID", "env:CMUX_CLAUDE_PID", "Claude 세션"),
    (
        "SENPI_PY_KERNEL_PARENT_PID",
        "env:SENPI_PY_KERNEL_PARENT_PID",
        "omo 세션",
    ),
];

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

pub(crate) fn agent_tmp_cwd(cwd: &str) -> bool {
    let tmp = cwd
        .strip_prefix("/private/tmp/")
        .or_else(|| cwd.strip_prefix("/tmp/"));
    let claude_tmp =
        tmp.is_some_and(|rest| rest.starts_with("claude-") || rest.starts_with("cc-daemon-"));
    claude_tmp || cwd.contains("/scratchpad/") || cwd.ends_with("/scratchpad")
}

fn tmp_session_id(cwd: &str) -> Option<&str> {
    cwd.split('/').find(|seg| is_uuid(seg))
}

fn argv_value<'b>(argv: &'b [String], flag: &str) -> Option<&'b str> {
    let eq = format!("{flag}=");
    argv.iter().enumerate().find_map(|(i, a)| {
        if a == flag {
            argv.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix(eq.as_str())
        }
    })
}

fn spawned_by(argv: &[String]) -> Option<(i32, Option<String>)> {
    let raw = argv_value(argv, "--spawned-by")?;
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let pid = i32::try_from(v.get("pid")?.as_i64()?).ok()?;
    let label = v.get("label").and_then(|l| l.as_str()).map(str::to_string);
    Some((pid, label))
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(s: &'a Snapshot) -> Self {
        let procs = s.processes.as_slice();
        let n = procs.len();
        let home = s.host.home_dir.as_str();
        let mut idx = HashMap::with_capacity(n);
        for (i, p) in procs.iter().enumerate() {
            idx.insert(p.pid, i);
        }
        let parent: Vec<Option<usize>> = procs
            .iter()
            .map(|p| {
                if p.ppid == p.pid {
                    return None;
                }
                idx.get(&p.ppid)
                    .copied()
                    .filter(|&j| procs[j].start_time_unix_ms <= p.start_time_unix_ms)
            })
            .collect();
        let mut children = vec![Vec::new(); n];
        for (i, par) in parent.iter().enumerate() {
            if let Some(j) = par {
                children[*j].push(i);
            }
        }
        let mut topo = Vec::with_capacity(n);
        let mut seen = vec![false; n];
        for root in (0..n).filter(|&i| parent[i].is_none()) {
            seen[root] = true;
            topo.push(root);
        }
        let mut head = 0;
        while head < topo.len() {
            let i = topo[head];
            head += 1;
            for &c in &children[i] {
                if !seen[c] {
                    seen[c] = true;
                    topo.push(c);
                }
            }
        }
        let mut parent = parent;
        for i in 0..n {
            if !seen[i] {
                parent[i] = None;
                topo.push(i);
            }
        }

        let feats: Vec<Feat> = procs.iter().map(features).collect();
        let cls: Vec<Class> = procs
            .iter()
            .zip(&feats)
            .map(|(p, f)| classify(p, f, home))
            .collect();

        let mut session_root = vec![None; n];
        for &i in &topo {
            session_root[i] = match parent[i].and_then(|j| session_root[j]) {
                Some(r) => Some(r),
                None if cls[i].kind == Kind::AgentCli => Some(i),
                None => None,
            };
        }

        let project = procs
            .iter()
            .map(|p| {
                p.cwd
                    .as_ref()
                    .and_then(|c| s.project_roots.get(c))
                    .map(|root| display_path(root, home))
            })
            .collect();
        let tmp_cwd = procs
            .iter()
            .map(|p| p.cwd.as_deref().is_some_and(agent_tmp_cwd))
            .collect();

        let mut ctx = Ctx {
            s,
            procs,
            idx,
            parent,
            children,
            topo,
            feats,
            cls,
            session_root,
            owner: Vec::new(),
            project,
            tmp_cwd,
            usage: Vec::new(),
        };
        ctx.owner = (0..n).map(|i| ctx.compute_owner(i)).collect();
        ctx.usage = crate::usage::compute(&ctx);
        ctx
    }

    pub(crate) fn pref(&self, i: usize) -> ProcRef {
        let p = &self.procs[i];
        ProcRef {
            pid: p.pid,
            start_time_unix_ms: p.start_time_unix_ms,
        }
    }

    pub(crate) fn age_ms(&self, i: usize) -> u64 {
        self.s
            .taken_at_unix_ms
            .saturating_sub(self.procs[i].start_time_unix_ms)
    }

    pub(crate) fn footprint(&self, i: usize) -> u64 {
        self.procs[i].footprint_bytes.unwrap_or(0)
    }

    pub(crate) fn descendants(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack: Vec<usize> = self.children[i].clone();
        while let Some(c) = stack.pop() {
            out.push(c);
            stack.extend_from_slice(&self.children[c]);
        }
        out
    }

    pub(crate) fn origin(&self, i: usize) -> ExeOrigin {
        self.feats[i].origin
    }

    pub(crate) fn is_mine(&self, i: usize) -> bool {
        let p = &self.procs[i];
        p.uid == self.s.self_uid && p.pid != self.s.self_pid && p.pid > 1
    }

    pub(crate) fn alive(&self, i: usize) -> bool {
        self.procs[i].status != ProcStatus::Zombie
    }

    /// 고아·중복 판정에서 빼는 출처와 종류(시스템·앱 번들·플랫폼, 시뮬레이터 런타임).
    pub(crate) fn excluded(&self, i: usize) -> bool {
        matches!(
            self.origin(i),
            ExeOrigin::System | ExeOrigin::Platform | ExeOrigin::AppBundle
        ) || matches!(
            self.cls[i].kind,
            Kind::System | Kind::AppHelper | Kind::GuiApp
        ) || self.cls[i].sig == "emu_sim_runtime"
    }

    /// launchd 밑(ppid 1)에서 도는 것이 정상인 데몬·크래시 리포터. 고아·논리적 고아 판정에서 뺀다.
    pub(crate) fn daemon_by_design(&self, i: usize) -> bool {
        DAEMON_BY_DESIGN.contains(&self.cls[i].sig)
            || self.feats[i].exe_base.ends_with("crashpad_handler")
    }

    fn judge_pid(&self, i: usize, pid: i32) -> (Option<ProcRef>, Option<DeadWhy>) {
        match self.idx.get(&pid) {
            Some(&j) if self.procs[j].start_time_unix_ms <= self.procs[i].start_time_unix_ms => {
                (Some(self.pref(j)), None)
            }
            Some(_) => (None, Some(DeadWhy::PidReused)),
            None => (None, Some(DeadWhy::OwnerDead)),
        }
    }

    fn compute_owner(&self, i: usize) -> Owner {
        if let Some(r) = self.session_root[i]
            && r != i
        {
            return Owner {
                session: Some(self.pref(r)),
                pid: Some(self.procs[r].pid),
                source: Some("lineage"),
                label: Some(self.cls[r].label.clone()),
                alive: Some(true),
                dead: None,
            };
        }
        if self.session_root[i] == Some(i) {
            return Owner::default();
        }
        let p = &self.procs[i];
        for (key, source, label) in ENV_OWNER_KEYS {
            let Some(pid) = p.env.get(*key).and_then(|v| v.trim().parse::<i32>().ok()) else {
                continue;
            };
            if pid <= 1 {
                continue;
            }
            return self.owner_from_pid(i, pid, source, label.to_string(), None);
        }
        if let Some((pid, lbl)) = spawned_by(&p.argv)
            && pid > 1
        {
            let label = match lbl.as_deref() {
                Some("claude") | None => "Claude 세션".to_string(),
                Some(other) => format!("{} 세션", crate::fmt::safe(other)),
            };
            return self.owner_from_pid(
                i,
                pid,
                "argv:spawned_by",
                label,
                Some(DeadWhy::SpawnerDead),
            );
        }
        if let Some(pid) = argv_value(&p.argv, "--parent-pid").and_then(|v| v.parse::<i32>().ok())
            && pid > 1
        {
            return self.owner_from_pid(
                i,
                pid,
                "argv:parent_pid",
                "띄운 프로그램".to_string(),
                Some(DeadWhy::ArgvParentDead),
            );
        }
        if let Some(sid) = p
            .cwd
            .as_deref()
            .filter(|c| agent_tmp_cwd(c))
            .and_then(tmp_session_id)
        {
            let live = self.procs.iter().enumerate().find(|(j, q)| {
                self.cls[*j].kind == Kind::AgentCli
                    && (q.env.get("CLAUDE_CODE_SESSION_ID").map(String::as_str) == Some(sid)
                        || argv_value(&q.argv, "--session-id") == Some(sid))
            });
            return match live {
                Some((j, _)) => Owner {
                    session: Some(self.pref(j)),
                    pid: Some(self.procs[j].pid),
                    source: Some("tmp_cwd"),
                    label: Some(self.cls[j].label.clone()),
                    alive: Some(true),
                    dead: None,
                },
                None => Owner {
                    session: None,
                    pid: None,
                    source: Some("tmp_cwd"),
                    label: Some("Claude 세션".to_string()),
                    alive: Some(false),
                    dead: Some(DeadWhy::TmpSessionGone),
                },
            };
        }
        Owner::default()
    }

    fn owner_from_pid(
        &self,
        i: usize,
        pid: i32,
        source: &'static str,
        label: String,
        dead_as: Option<DeadWhy>,
    ) -> Owner {
        let (session, dead) = self.judge_pid(i, pid);
        let dead = match (dead, dead_as) {
            (Some(DeadWhy::OwnerDead), Some(d)) => Some(d),
            (d, _) => d,
        };
        let label = match session {
            Some(r) => self
                .idx
                .get(&r.pid)
                .map(|&j| self.cls[j].label.clone())
                .unwrap_or(label),
            None => label,
        };
        Owner {
            session,
            pid: Some(pid),
            source: Some(source),
            label: Some(label),
            alive: Some(dead.is_none()),
            dead,
        }
    }
}
