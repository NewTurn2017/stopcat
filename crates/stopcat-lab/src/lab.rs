//! 한 번의 실험실: 임시 루트, 도우미 복사본, anchor 프로세스 그룹, 등록부, 직접 자식, 정리.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::Serialize;
use stopcat_act::Liveness;
use stopcat_model::ProcRef;

use crate::cleanup::{LabReaper, ReapCall};
use crate::kernel::{LabKernel, RealKernel};
use crate::registry::LabRegistry;
use crate::spec::{self, ExecSpec, HELPER_NAMES, Role};
use crate::util::now_ms;

#[derive(Debug, Clone)]
pub struct Meta {
    pub sub: String,
    pub scenario: String,
    pub decoy: bool,
}

impl Meta {
    pub fn new(sub: &str, scenario: &str) -> Self {
        Meta {
            sub: sub.to_string(),
            scenario: scenario.to_string(),
            decoy: false,
        }
    }

    pub fn decoy(sub: &str, scenario: &str) -> Self {
        Meta {
            decoy: true,
            ..Meta::new(sub, scenario)
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CleanupReport {
    pub sigcont_sent: usize,
    pub sigterm_sent: usize,
    pub sigkill_sent: usize,
    pub killpg_used: bool,
    pub direct_children_waited: usize,
    pub pgrp_remaining: usize,
    pub tagged_remaining: usize,
    pub leftover_processes: usize,
    pub seconds: f64,
    pub tmp_files_removed: usize,
    pub calls: Vec<ReapCall>,
}

pub struct Lab {
    pub run_id: String,
    pub root: PathBuf,
    pub bin: PathBuf,
    pub log_path: PathBuf,
    pub registry: LabRegistry,
    pub supervisor: ProcRef,
    pub kernel: RealKernel,
    anchor_child: Option<Child>,
    direct: Vec<Child>,
}

fn helper_source() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| io::Error::other("실행 파일 폴더 없음"))?;
    let p = dir.join("stopcat-lab-helper");
    if p.is_file() {
        Ok(p)
    } else {
        Err(io::Error::other(format!(
            "도우미 바이너리 없음: {}",
            p.display()
        )))
    }
}

fn read_lines(child: &mut Child, timeout: Duration) -> Vec<String> {
    let Some(out) = child.stdout.take() else {
        return Vec::new();
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(l) = line else { break };
            let done = l == "ready";
            if tx.send(l).is_err() || done {
                break;
            }
        }
    });
    let mut lines = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left) {
            Ok(l) => {
                let done = l == "ready";
                lines.push(l);
                if done {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    lines
}

fn child_pids(lines: &[String]) -> Vec<i32> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("child "))
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

impl Lab {
    /// `$TMPDIR/stopcat-lab-<run_id>/`에 도우미를 이름별로 복사하고 anchor(프로세스 그룹 주인)를 띄운다.
    pub fn create(run_id: &str) -> io::Result<Lab> {
        let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = PathBuf::from(tmp).join(format!("stopcat-lab-{run_id}"));
        let bin = root.join("bin");
        fs::create_dir_all(&bin)?;
        let src = helper_source()?;
        for name in HELPER_NAMES {
            let dst = bin.join(name);
            fs::copy(&src, &dst)?;
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))?;
        }
        let log_path = root.join("helpers.log");
        fs::write(&log_path, b"")?;
        let kernel = RealKernel;
        let me = std::process::id() as i32;
        let live = kernel.probe(me);
        let supervisor = ProcRef {
            pid: me,
            start_time_unix_ms: live.start_time_unix_ms,
        };
        let started_at_ms = now_ms();
        let mut lab = Lab {
            run_id: run_id.to_string(),
            root,
            bin,
            log_path,
            registry: LabRegistry::new(
                run_id,
                ProcRef {
                    pid: 0,
                    start_time_unix_ms: 0,
                },
                started_at_ms,
                live.uid,
            ),
            supervisor,
            kernel,
            anchor_child: None,
            direct: Vec::new(),
        };
        let spec = lab.exec_spec("lab-anchor", Role::Idle, &["lab-anchor"], None, &[], 3600);
        let mut cmd = lab.command(&spec);
        cmd.process_group(0);
        let mut child = cmd.spawn()?;
        let _ = read_lines(&mut child, Duration::from_secs(10));
        let pid = child.id() as i32;
        let alive = lab.kernel.probe(pid);
        if alive.liveness != Liveness::Alive || alive.pgid != pid {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other(
                "anchor가 자기 프로세스 그룹을 만들지 못함",
            ));
        }
        lab.registry.anchor = ProcRef {
            pid,
            start_time_unix_ms: alive.start_time_unix_ms,
        };
        lab.anchor_child = Some(child);
        Ok(lab)
    }

    pub fn tag(&self, sub: &str) -> String {
        self.registry.tag(sub)
    }

    pub fn exe(&self, name: &str) -> String {
        self.bin.join(name).to_string_lossy().into_owned()
    }

    pub fn dir(&self, rel: &str) -> io::Result<PathBuf> {
        let d = self.root.join(rel);
        fs::create_dir_all(&d)?;
        Ok(d)
    }

    /// 도우미 env: PATH·HOME·TMPDIR + 감독 ProcRef·역할·최대 수명·로그 + (있으면) STOPCAT_TAG + 추가 값.
    pub fn exec_spec(
        &self,
        name: &str,
        role: Role,
        argv: &[&str],
        tag: Option<&str>,
        extra: &[(&str, String)],
        max_secs: u64,
    ) -> ExecSpec {
        let mut env = BTreeMap::new();
        env.insert("PATH".into(), "/usr/bin:/bin".into());
        if let Ok(h) = std::env::var("HOME") {
            env.insert("HOME".into(), h);
        }
        if let Ok(t) = std::env::var("TMPDIR") {
            env.insert("TMPDIR".into(), t);
        }
        env.insert(
            spec::SUPERVISOR.into(),
            format!(
                "{}:{}",
                self.supervisor.pid, self.supervisor.start_time_unix_ms
            ),
        );
        env.insert(spec::ROLE.into(), role.as_str().into());
        env.insert(spec::MAX_SECS.into(), max_secs.to_string());
        env.insert(
            spec::LOG.into(),
            self.log_path.to_string_lossy().into_owned(),
        );
        if let Some(t) = tag {
            env.insert(spec::TAG.into(), t.to_string());
        }
        for (k, v) in extra {
            env.insert(k.to_string(), v.clone());
        }
        ExecSpec {
            exe: self.exe(name),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            argv_hex: None,
            cwd: self.root.to_string_lossy().into_owned(),
            env,
            count: 1,
        }
    }

    fn command(&self, s: &ExecSpec) -> Command {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let argv = s.argv_bytes();
        let mut cmd = Command::new(&s.exe);
        if let Some(a0) = argv.first() {
            cmd.arg0(OsStr::from_bytes(a0));
        }
        cmd.args(argv.iter().skip(1).map(|a| OsStr::from_bytes(a)))
            .env_clear()
            .envs(&s.env)
            .current_dir(&s.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        match fs::OpenOptions::new().append(true).open(&self.log_path) {
            Ok(f) => cmd.stderr(f),
            Err(_) => cmd.stderr(Stdio::null()),
        };
        if self.registry.anchor.pid > 1 {
            cmd.process_group(self.registry.anchor.pid);
        }
        cmd
    }

    fn register(
        &mut self,
        pid: i32,
        meta: &Meta,
        role: &str,
        name: &str,
        parent: Option<ProcRef>,
    ) -> io::Result<ProcRef> {
        let k = self.kernel;
        self.registry
            .register(
                &k,
                pid,
                &meta.sub,
                &meta.scenario,
                role,
                name,
                meta.decoy,
                parent,
            )
            .map_err(io::Error::other)
    }

    /// 감독 직속 도우미 하나(+ SPAWN 자식). 돌려주는 값: (도우미, 자식들) — 자식 순서는 명세 순서.
    pub fn spawn_direct(
        &mut self,
        meta: Meta,
        mut s: ExecSpec,
        children: Vec<(Meta, ExecSpec)>,
    ) -> io::Result<(ProcRef, Vec<ProcRef>)> {
        let role = s.env.get(spec::ROLE).cloned().unwrap_or_default();
        let name = Path::new(&s.exe)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let expanded: Vec<(Meta, ExecSpec)> = children
            .iter()
            .flat_map(|(m, c)| c.expand().into_iter().map(move |e| (m.clone(), e)))
            .collect();
        if !expanded.is_empty() {
            let raw: Vec<ExecSpec> = expanded.iter().map(|(_, e)| e.clone()).collect();
            s.env.insert(
                spec::SPAWN.into(),
                serde_json::to_string(&raw).map_err(io::Error::other)?,
            );
        }
        let mut child = self.command(&s).spawn()?;
        let lines = read_lines(&mut child, Duration::from_secs(15));
        let pid = child.id() as i32;
        self.direct.push(child);
        let me = self.register(pid, &meta, &role, &name, Some(self.supervisor))?;
        let mut kids = Vec::new();
        for (i, cpid) in child_pids(&lines).into_iter().enumerate() {
            let (m, e) = match expanded.get(i) {
                Some((m, e)) => (
                    m.clone(),
                    (
                        e.env.get(spec::ROLE).cloned().unwrap_or_default(),
                        Path::new(&e.exe)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ),
                ),
                None => (meta.clone(), ("zombie_child".to_string(), name.clone())),
            };
            kids.push(self.register(cpid, &m, &e.0, &e.1, Some(me))?);
        }
        if lines.iter().any(|l| l.starts_with("error")) {
            return Err(io::Error::other(format!(
                "도우미 자식 생성 실패: {lines:?}"
            )));
        }
        Ok((me, kids))
    }

    /// fanout 도우미 하나로 여러 프로세스를 fork+exec하고 그 도우미를 끝내 ppid 1로 만든다(태그 없는 짧은 launcher).
    pub fn spawn_orphans(&mut self, items: Vec<(Meta, ExecSpec)>) -> io::Result<Vec<ProcRef>> {
        let expanded: Vec<(Meta, ExecSpec)> = items
            .iter()
            .flat_map(|(m, c)| c.expand().into_iter().map(move |e| (m.clone(), e)))
            .collect();
        let raw: Vec<ExecSpec> = expanded.iter().map(|(_, e)| e.clone()).collect();
        let fan = self.exec_spec(
            "lab-fanout",
            Role::Fanout,
            &["lab-fanout"],
            None,
            &[(
                spec::FANOUT,
                serde_json::to_string(&raw).map_err(io::Error::other)?,
            )],
            30,
        );
        let mut child = self.command(&fan).spawn()?;
        let lines = read_lines(&mut child, Duration::from_secs(15));
        let _ = child.wait();
        let pids = child_pids(&lines);
        if pids.len() != expanded.len() {
            return Err(io::Error::other(format!(
                "fanout {}개 중 {}개만 생성: {lines:?}",
                expanded.len(),
                pids.len()
            )));
        }
        let mut out = Vec::new();
        for (pid, (m, e)) in pids.into_iter().zip(expanded.iter()) {
            let role = e.env.get(spec::ROLE).cloned().unwrap_or_default();
            let name = Path::new(&e.exe)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(self.register(pid, m, &role, &name, None)?);
        }
        Ok(out)
    }

    /// 곧바로 끝나는 도우미의 pid(이미 끝난 "주인" pid로 쓴다).
    pub fn dead_pid(&mut self) -> io::Result<i32> {
        let s = self.exec_spec("lab-exit", Role::Exit, &["lab-exit"], None, &[], 5);
        let mut c = self.command(&s).spawn()?;
        let pid = c.id() as i32;
        c.wait()?;
        self.registry.dead_pids.push(pid);
        Ok(pid)
    }

    /// 실험실 자체 신호(예: S6 SIGSTOP). 등록된 ProcRef에만.
    pub fn signal(&self, r: ProcRef, sig: i32) -> (bool, Vec<ReapCall>) {
        let mut reaper = LabReaper::new(&self.kernel, self.registry.all_refs());
        let ok = reaper.signal(r, sig);
        (ok, reaper.calls)
    }

    /// 끝난 직접 자식을 회수한다(N4 클라이언트가 끝난 뒤 좀비로 범위에 남지 않게). 회수한 수.
    pub fn reap_exited(&mut self) -> usize {
        let mut n = 0;
        for c in self.direct.iter_mut() {
            if matches!(c.try_wait(), Ok(Some(_))) {
                n += 1;
            }
        }
        n
    }

    pub fn alive(&self, r: ProcRef) -> bool {
        let live = self.kernel.probe(r.pid);
        live.liveness == Liveness::Alive && live.start_time_unix_ms == r.start_time_unix_ms
    }

    /// 지킴이를 모두 끈 뒤 부른다: CONT → TERM → 3초 → 그룹 확인 뒤 KILL → 직접 자식 회수 → 남은 것 확인 → 임시 파일 지움.
    pub fn cleanup(mut self) -> CleanupReport {
        let t0 = now_ms();
        let k = self.kernel;
        let all = self.registry.all_refs();
        let mut rep = CleanupReport::default();
        let mut reaper = LabReaper::new(&k, all.clone());
        let anchor = self.registry.anchor;
        let members: BTreeSet<ProcRef> = all.iter().copied().filter(|r| *r != anchor).collect();
        for r in &members {
            let live = k.probe(r.pid);
            if live.liveness == Liveness::Alive
                && live.start_time_unix_ms == r.start_time_unix_ms
                && live.stopped
                && reaper.signal(*r, libc::SIGCONT)
            {
                rep.sigcont_sent += 1;
            }
        }
        for r in &members {
            if reaper.is_alive(*r) && reaper.signal(*r, libc::SIGTERM) {
                rep.sigterm_sent += 1;
            }
        }
        for _ in 0..30 {
            if reaper.alive_of(&members).is_empty() {
                break;
            }
            k.sleep_ms(100);
        }
        if anchor.pid > 1 {
            rep.killpg_used = reaper.killpg_checked(anchor.pid, libc::SIGKILL);
            if !rep.killpg_used {
                for r in reaper.alive_of(&all) {
                    if reaper.signal(r, libc::SIGKILL) {
                        rep.sigkill_sent += 1;
                    }
                }
            }
        }
        let mut direct: Vec<Child> = std::mem::take(&mut self.direct);
        direct.extend(self.anchor_child.take());
        for mut c in direct {
            for _ in 0..50 {
                if matches!(c.try_wait(), Ok(Some(_)) | Err(_)) {
                    break;
                }
                k.sleep_ms(100);
            }
            if matches!(c.try_wait(), Ok(None)) {
                let _ = c.kill();
                let _ = c.wait();
            }
            rep.direct_children_waited += 1;
        }
        for _ in 0..100 {
            rep.pgrp_remaining = k.pgrp_members(anchor.pid).len();
            if rep.pgrp_remaining == 0 {
                break;
            }
            k.sleep_ms(100);
        }
        rep.tagged_remaining = count_tagged(&self.registry.tag_prefix());
        rep.leftover_processes =
            rep.pgrp_remaining.max(rep.tagged_remaining) + reaper.alive_of(&all).len();
        rep.tmp_files_removed = remove_tree_files(&self.root);
        rep.calls = reaper.calls;
        rep.seconds = (now_ms() - t0) as f64 / 1000.0;
        rep
    }
}

/// STOPCAT_TAG가 `prefix`로 시작하는 살아 있는 프로세스 수(이름·경로는 남기지 않는다).
pub fn count_tagged(prefix: &str) -> usize {
    let s = stopcat_sample::collect(&stopcat_sample::CollectOptions {
        cpu_interval_ms: None,
        launchd: false,
        project_roots: false,
    });
    s.processes
        .iter()
        .filter(|p| p.status != stopcat_model::ProcStatus::Zombie)
        .filter(|p| p.env.get(spec::TAG).is_some_and(|t| t.starts_with(prefix)))
        .count()
}

/// 실험실 임시 루트 아래만, 파일 단위로 지운다(깊은 것부터, 디렉터리는 비었을 때만).
pub fn remove_tree_files(root: &Path) -> usize {
    if !root
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with("stopcat-lab-"))
    {
        return 0;
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        dirs.push(d);
        for e in rd.flatten() {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(_) => files.push(p),
                Err(_) => {}
            }
        }
    }
    let mut n = 0;
    for f in files {
        if f.starts_with(root) && fs::remove_file(&f).is_ok() {
            n += 1;
        }
    }
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for d in dirs {
        if d.starts_with(root) {
            let _ = fs::remove_dir(&d);
        }
    }
    n
}
