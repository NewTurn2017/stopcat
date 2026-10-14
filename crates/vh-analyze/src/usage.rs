//! 사용 판정: 자손 전체를 합산해 '쓰고 있는지'와 근거 코드를 정한다.
//!
//! 문턱값(PLAN `usage_rules.thresholds`):
//! - CPU: 자손 합산 cpu_pct ≥ 0.5(코어 1개 = 100). 두 번 읽기 간격이 200ms 이상일 때만 측정으로 친다.
//! - 디스크: 자손 합산 구간 바이트 / 간격 ≥ 초당 1MiB.
//! - 연결: 자손 밖·기반 시설 아닌 loopback 상대, 외부 상대, 상대를 못 찾은 loopback은 쓰고 있음.
//! - 나이: 자기 나이 < 10분이면 young(자손 나이는 보지 않는다).
//! - 평생 CPU: 자손 합산 cpu_time / 나이 < 0.005이면 lifetime_cpu_low(기록만, state는 바꾸지 않음).

use std::collections::BTreeSet;

use vh_model::{Kind, OwnerState, ProcStatus, Usage, UsageReason, UsageState};

use crate::ctx::Ctx;

/// 코어 1개 = 100 기준 0.5%.
pub(crate) const CPU_ACTIVE_PCT: f32 = 0.5;
/// 초당 1MiB.
pub(crate) const DISK_ACTIVE_BYTES_PER_SEC: u64 = 1 << 20;
/// 두 번 읽기 간격이 이보다 짧으면 CPU·디스크를 측정으로 치지 않는다.
pub(crate) const MIN_INTERVAL_MS: u32 = 200;
pub(crate) const YOUNG_MS: u64 = 10 * 60_000;
/// 평생 평균 CPU가 코어의 0.5% 미만.
pub(crate) const LIFETIME_LOW_RATIO: f64 = 0.005;

#[derive(Default, Clone)]
struct Agg {
    procs: u32,
    cpu: f32,
    disk: u64,
    cpu_time_ns: u64,
    tty: bool,
    tcp_unknown: bool,
    external: bool,
    unresolved: bool,
    outside: BTreeSet<i32>,
    infra: bool,
}

fn owner_state(c: &Ctx, i: usize) -> OwnerState {
    let o = &c.owner[i];
    if o.alive == Some(true) {
        return OwnerState::Alive;
    }
    if o.dead.is_some() {
        return OwnerState::Ended;
    }
    if o.source.is_some() {
        return OwnerState::Unknown;
    }
    let launchd_job = c.s.launchd_job_pids.contains(&c.procs[i].pid);
    let user = matches!(c.cls[i].kind, Kind::GuiApp | Kind::AppHelper | Kind::System)
        || c.excluded(i)
        || launchd_job
        || c.session_root[i] == Some(i)
        || c.procs[i].has_tty;
    if user {
        OwnerState::User
    } else {
        OwnerState::Unknown
    }
}

/// 상대 q가 기반 시설인지(adb 서버 등 `DAEMON_BY_DESIGN`, vh 자신).
fn infra_peer(c: &Ctx, q: usize) -> bool {
    c.daemon_by_design(q) || c.procs[q].pid == c.s.self_pid
}

pub(crate) fn compute(c: &Ctx) -> Vec<Usage> {
    let n = c.procs.len();
    let alive = |i: usize| c.procs[i].status != ProcStatus::Zombie;
    let mut agg: Vec<Agg> = vec![Agg::default(); n];

    // 자손 밖 상대: 연결을 쥔 h에서 위로 올라가며 상대 q의 조상(자기 포함)이 아닌 동안 표시한다(LCA 직전까지).
    for h in 0..n {
        let Some(t) = c.procs[h].tcp.as_ref().filter(|_| alive(h)) else {
            continue;
        };
        for &qpid in &t.peer_pids {
            let Some(&q) = c.idx.get(&qpid) else {
                agg[h].unresolved = true;
                continue;
            };
            let mut q_anc = BTreeSet::new();
            let mut up = Some(q);
            while let Some(a) = up {
                q_anc.insert(a);
                up = c.parent[a];
            }
            let infra = infra_peer(c, q);
            let mut a = Some(h);
            while let Some(x) = a {
                if q_anc.contains(&x) {
                    break;
                }
                if infra {
                    agg[x].infra = true;
                } else {
                    agg[x].outside.insert(qpid);
                }
                a = c.parent[x];
            }
        }
    }

    // 자손 합산: topo 역순(자식 먼저).
    for &i in c.topo.iter().rev() {
        let p = &c.procs[i];
        if alive(i) {
            let a = &mut agg[i];
            a.procs += 1;
            a.cpu += p.cpu_pct.unwrap_or(0.0);
            a.disk = a.disk.saturating_add(p.disk_io_delta_bytes.unwrap_or(0));
            a.cpu_time_ns = a.cpu_time_ns.saturating_add(p.cpu_time_ns.unwrap_or(0));
            a.tty |= p.has_tty;
            match &p.tcp {
                Some(t) => {
                    a.external |= t.external > 0;
                    a.unresolved |= t.unresolved > 0;
                    if t.peer_pids_truncated {
                        a.outside.insert(-1);
                    }
                }
                None => a.tcp_unknown |= p.uid == c.s.self_uid,
            }
        }
        if let Some(par) = c.parent[i] {
            let child = agg[i].clone();
            let a = &mut agg[par];
            a.procs += child.procs;
            a.cpu += child.cpu;
            a.disk = a.disk.saturating_add(child.disk);
            a.cpu_time_ns = a.cpu_time_ns.saturating_add(child.cpu_time_ns);
            a.tty |= child.tty;
            a.tcp_unknown |= child.tcp_unknown;
            a.external |= child.external;
            a.unresolved |= child.unresolved;
            a.infra |= child.infra;
            // 자식의 '자손 밖' 상대 중 부모의 자손 밖이기도 한 것은 위 표시 단계에서 이미 부모에도 들어 있다.
            // 잘린 상대 목록(-1)은 누가 상대인지 모르므로 조상 모두에게 자손 밖 상대가 있다고 본다.
            if child.outside.contains(&-1) {
                a.outside.insert(-1);
            }
        }
    }

    let interval =
        c.s.cpu_sample_interval_ms
            .filter(|&ms| ms >= MIN_INTERVAL_MS);
    (0..n)
        .map(|i| {
            let p = &c.procs[i];
            let a = &agg[i];
            let mut reasons: Vec<UsageReason> = Vec::new();
            let owner = owner_state(c, i);
            match owner {
                OwnerState::Alive => reasons.push(UsageReason::OwnerAlive),
                OwnerState::User => reasons.push(UsageReason::UserOwned),
                _ => {}
            }
            if a.tty {
                reasons.push(UsageReason::HasTty);
            }
            let outside_peer_count = a.outside.iter().filter(|&&q| q >= 0).count() as u32;
            let peer_active = !a.outside.is_empty() || a.external || a.unresolved;
            if !a.outside.is_empty() {
                reasons.push(UsageReason::PeerOutsideSubtree);
            }
            if a.external {
                reasons.push(UsageReason::PeerExternal);
            }
            if a.unresolved {
                reasons.push(UsageReason::PeerUnresolved);
            }
            let subtree_cpu_pct = p.cpu_pct.map(|_| a.cpu);
            let subtree_disk_delta_bytes = p.disk_io_delta_bytes.map(|_| a.disk);
            match (interval, subtree_cpu_pct) {
                (Some(_), Some(pct)) if pct >= CPU_ACTIVE_PCT => {
                    reasons.push(UsageReason::CpuActive)
                }
                (Some(_), Some(_)) => reasons.push(UsageReason::CpuIdle),
                _ => reasons.push(UsageReason::CpuUnknown),
            }
            match (interval, subtree_disk_delta_bytes) {
                (Some(ms), Some(bytes))
                    if bytes.saturating_mul(1000) / u64::from(ms) >= DISK_ACTIVE_BYTES_PER_SEC =>
                {
                    reasons.push(UsageReason::DiskActive)
                }
                (Some(_), Some(_)) => reasons.push(UsageReason::DiskIdle),
                _ => reasons.push(UsageReason::DiskUnknown),
            }
            let age = c.age_ms(i);
            if age < YOUNG_MS {
                reasons.push(UsageReason::Young);
            }
            if !peer_active {
                if a.tcp_unknown || p.tcp.is_none() {
                    reasons.push(UsageReason::PeersUnknown);
                } else {
                    reasons.push(UsageReason::NoPeers);
                    if a.infra {
                        reasons.push(UsageReason::InfraPeersOnly);
                    }
                }
            }
            if age >= YOUNG_MS
                && p.cpu_time_ns.is_some()
                && (a.cpu_time_ns as f64) < LIFETIME_LOW_RATIO * age as f64 * 1_000_000.0
            {
                reasons.push(UsageReason::LifetimeCpuLow);
            }
            reasons.sort_by_key(|r| *r as u8);
            reasons.dedup();
            let has = |r: UsageReason| reasons.contains(&r);
            let active = [
                UsageReason::HasTty,
                UsageReason::PeerOutsideSubtree,
                UsageReason::PeerExternal,
                UsageReason::PeerUnresolved,
                UsageReason::CpuActive,
                UsageReason::DiskActive,
                UsageReason::Young,
            ]
            .into_iter()
            .any(has);
            let state = if active {
                UsageState::Active
            } else if has(UsageReason::CpuIdle)
                && has(UsageReason::DiskIdle)
                && has(UsageReason::NoPeers)
            {
                UsageState::Idle
            } else {
                UsageState::Unknown
            };
            Usage {
                state,
                owner,
                reasons,
                subtree_procs: a.procs,
                subtree_cpu_pct,
                subtree_disk_delta_bytes,
                outside_peer_count,
            }
        })
        .collect()
}
