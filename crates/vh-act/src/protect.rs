//! 보호 규칙 R01~R10 (계획 때 한 번, 신호 직전마다 한 번).

use vh_model::{ExeOrigin, Kind, ProcStatus, Refusal, exe_origin};

use crate::rule::*;
use crate::{Liveness, ProtectCtx};

/// R08: 강제로 끄지 않는 Kind. R09는 자손에 이 Kind가 있으면 대상 전체를 거부한다.
/// AgentHelper는 보호하지 않는다(PM 판정).
pub(crate) const PROTECTED_KINDS: [Kind; 4] = [
    Kind::AgentCli,
    Kind::GuiApp,
    Kind::VirtualMachine,
    Kind::Database,
];

pub(crate) fn refusal(target: vh_model::ProcRef, rule: &str, reason_ko: &str) -> Refusal {
    Refusal {
        target,
        rule: rule.to_string(),
        reason_ko: reason_ko.to_string(),
    }
}

fn has_xpc_or_appex_dir(exe: &str) -> bool {
    let parts: Vec<&str> = exe.split('/').filter(|c| !c.is_empty()).collect();
    let dirs = &parts[..parts.len().saturating_sub(1)];
    dirs.iter()
        .any(|c| c.ends_with(".xpc") || c.ends_with(".appex"))
}

fn path_rule(exe: Option<&str>) -> Option<(&'static str, &'static str)> {
    match exe_origin(exe) {
        ExeOrigin::System => Some((R05_SYSTEM_PATH, "macOS 시스템 구성 요소입니다")),
        ExeOrigin::AppBundle if exe.is_some_and(has_xpc_or_appex_dir) => {
            Some((R06_XPC_APPEX, "앱의 XPC 서비스·확장입니다. 앱이 관리합니다"))
        }
        ExeOrigin::AppBundle => Some((
            R07_APP_BUNDLE,
            "앱 번들 안의 앱·헬퍼입니다. 앱을 종료하면 함께 정리됩니다",
        )),
        ExeOrigin::Platform | ExeOrigin::DevToolBundle | ExeOrigin::User | ExeOrigin::Unknown => {
            None
        }
    }
}

pub(crate) fn check(ctx: &ProtectCtx<'_>) -> Option<Refusal> {
    let t = ctx.target;
    let deny = |rule: &str, reason: &str| Some(refusal(t, rule, reason));
    let live = ctx.live.filter(|l| l.liveness != Liveness::Gone);

    if t.pid <= 1 {
        return deny(
            R01_PID_LE_1,
            "시스템 핵심 프로세스(launchd·kernel)는 건드리지 않습니다",
        );
    }
    if t.pid == ctx.self_pid {
        return deny(R02_SELF, "vh 자신입니다");
    }
    if ctx.self_ancestors.contains(&t.pid) {
        return deny(
            R03_SELF_ANCESTOR,
            "vh를 띄운 터미널·셸·에이전트 세션의 조상입니다. 끊으면 지금 작업이 같이 끝납니다",
        );
    }
    let uids = [live.map(|l| l.uid), ctx.snap.map(|p| p.uid)];
    if uids.iter().flatten().any(|&u| u != ctx.self_uid) {
        return deny(
            R04_OTHER_UID,
            "다른 사용자 또는 시스템 계정의 프로세스입니다",
        );
    }
    let exes = [
        live.and_then(|l| l.exe.as_deref()),
        ctx.snap.and_then(|p| p.exe.as_deref()),
    ];
    for exe in exes.into_iter().flatten() {
        if let Some((rule, reason)) = path_rule(Some(exe)) {
            return deny(rule, reason);
        }
    }
    if ctx.kind.is_some_and(|k| PROTECTED_KINDS.contains(&k)) {
        return deny(
            R08_KIND_PROTECTED,
            "에이전트 세션·GUI 앱·VM·데이터베이스는 강제로 끄지 않습니다(에이전트: 핸드오프 저장 후 재시작 권장, DB: 손상 위험)",
        );
    }
    if ctx
        .subtree_kinds
        .iter()
        .any(|(_, k)| PROTECTED_KINDS.contains(k))
    {
        return deny(
            R09_PROTECTED_IN_SUBTREE,
            "이 프로세스 아래에 에이전트 세션·앱·VM·데이터베이스가 있습니다. 먼저 그쪽을 정리하세요",
        );
    }
    let zombie = match ctx.live {
        Some(l) => l.liveness == Liveness::Zombie,
        None => ctx.snap.is_some_and(|p| p.status == ProcStatus::Zombie),
    };
    if zombie {
        return deny(
            R10_ZOMBIE,
            "이미 끝난 좀비 프로세스입니다. 부모가 회수해야 사라집니다(부모 재시작 안내)",
        );
    }
    None
}
