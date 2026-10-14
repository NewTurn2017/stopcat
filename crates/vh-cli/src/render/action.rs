//! `vh fix`·`vh kill` 미리보기·결과 화면과 질문 문구.

use std::collections::BTreeSet;
use std::path::Path;

use vh_model::{
    ActionOutcome, ActionPlan, FinalState, PlannedAction, ProcRef, Report, Section, Snapshot, Step,
    Suggestion,
};

use super::{Lookup, Out, confidence_ko, section};
use crate::color::Color;
use crate::fmt;
use crate::target::Target;

pub const FIX_PROMPT: &str = "정리할까요? [y/N] ";
pub const KILL_PROMPT: &str = "끌까요? [y/N] ";
pub const DECLINED: &str = "취소했어요. 아무것도 끄지 않았어요.";
pub const FIX_NOTHING: &str = "정리할 것이 없어요.";
pub const FIX_NOT_RUN: &str = "확인 없이 실행하지 않았어요. 실행하려면: vh fix --yes";
pub const FIX_YES_ONLY_CONFIRMED: &str =
    "  (--yes 로 실행하면 '필요 없음' 중 '확실'인 것만 정리해요)";
pub const ONLY_WARN_WORKING: &str =
    "     주의: 일하는 중이에요 — 지금 쓰고 있어요. 정리하면 하던 일이 끊겨요";
pub const ONLY_WARN_CHECK: &str = "     주의: 확인 필요예요 — 쓰고 있는지 확실하지 않아요";

const LEFT_COL: usize = 53;
const MAX_UNTOUCHED: usize = 5;
const R13_BELOW_CONFIDENCE: &str = "R13_below_confidence";

pub fn kill_not_run(t: Target) -> String {
    format!(
        "확인 없이 끄지 않았어요. 끄려면: vh kill {} --yes",
        t.display()
    )
}

/// 사다리를 사람 말로: "정상 종료 → 3초 기다림 → 안 꺼지면 강제 종료".
pub fn ladder(a: &PlannedAction) -> String {
    let parts: Vec<String> = a
        .steps
        .iter()
        .map(|st| match st {
            Step::Cont => "멈춘 상태 풀기".to_string(),
            Step::Term if a.include_descendants && a.descendant_count > 0 => {
                "자식부터 정상 종료".to_string()
            }
            Step::Term => "정상 종료".to_string(),
            Step::Kill => format!("{} 기다림 → 안 꺼지면 강제 종료", fmt::secs(a.grace_ms)),
            Step::Demote => "우선순위 낮추기".to_string(),
            Step::Undemote => "우선순위 되돌리기".to_string(),
        })
        .collect();
    parts.join(" → ")
}

pub(crate) fn item_label(lk: &Lookup<'_>, a: &PlannedAction) -> String {
    let base = lk.label(a.target);
    if a.include_descendants && a.descendant_count > 0 {
        format!("{base} (자식 {}개 포함)", a.descendant_count)
    } else {
        base
    }
}

pub fn basis_line(text: &str) -> String {
    format!("기준: {text}")
}

pub fn fix_preview(
    s: &Snapshot,
    r: &Report,
    plan: &ActionPlan,
    basis: &str,
    only: &[i32],
    color: bool,
) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);

    for pid in only {
        let planned = plan.items.iter().any(|i| i.target.pid == *pid);
        let refused = plan.refused.iter().any(|i| i.target.pid == *pid);
        if !planned && !refused {
            o.line(&format!(
                "--only {pid} 은 정리 대상이 아니에요(발견 없음). 자세히: vh why {pid}"
            ));
        }
    }

    if plan.items.is_empty() {
        untouched(&mut o, &lk, plan);
        o.line(FIX_NOTHING);
        return o.finish();
    } else {
        let total: u64 = plan.items.iter().map(|i| i.est_reclaim_bytes).sum();
        o.colored(
            &format!(
                "정리 미리보기 — {}건, 최대 약 {} 회수 예상",
                plan.items.len(),
                fmt::bytes(total)
            ),
            Color::Bold,
        );
        o.line(&basis_line(basis));
        for (i, a) in plan.items.iter().enumerate() {
            let left = fmt::truncate(
                &format!("  {}. {}", i + 1, item_label(&lk, a)),
                LEFT_COL - 1,
            );
            let finding = lk.finding(&a.finding_id);
            let conf = finding.map(|f| confidence_ko(f.confidence)).unwrap_or("");
            o.line(&format!(
                "{}{}  {conf}",
                fmt::pad(&left, LEFT_COL),
                fmt::lpad(&fmt::bytes(a.est_reclaim_bytes), 7)
            ));
            let reason = finding
                .map(|f| f.detail_ko.as_str())
                .filter(|d| !d.is_empty())
                .unwrap_or(&a.reason_ko);
            o.wrap("     이유: ", "           ", reason);
            if only.contains(&a.target.pid) {
                o.line("     직접 고른 대상이에요(--only)");
                match finding.map(|f| f.section) {
                    Some(Section::Working) => o.line(ONLY_WARN_WORKING),
                    Some(Section::Check) => o.line(ONLY_WARN_CHECK),
                    _ => {}
                }
                if let Some(f) =
                    finding.filter(|f| matches!(f.section, Section::Working | Section::Check))
                {
                    let (_, long) =
                        section::evidence_for(f, lk.classified(a.target), s.taken_at_unix_ms);
                    if !long.is_empty() {
                        o.wrap("     근거: ", "           ", &long);
                    }
                }
            }
            o.line(&format!("     방법: {}", ladder(a)));
        }
    }
    untouched(&mut o, &lk, plan);
    o.finish()
}

/// "건드리지 않는 것": 보호 규칙 거부 + 에이전트 세션·좀비처럼 자동 조치가 아닌 발견.
fn untouched(o: &mut Out, lk: &Lookup<'_>, plan: &ActionPlan) {
    let mut seen: BTreeSet<ProcRef> = plan.items.iter().map(|i| i.target).collect();
    let mut lines: Vec<String> = Vec::new();
    for f in &lk.r.findings {
        let pid = f.targets.first().map_or(0, |t| t.pid);
        let text = match (f.section, &f.suggestion) {
            (_, Suggestion::HandoffThenRestart) => {
                "AI 세션은 끄지 않아요. 핸드오프 저장 후 직접 재시작".to_string()
            }
            (_, Suggestion::RestartParent { .. }) => {
                "끌 수 없어요. 띄운 앱을 다시 시작하세요".to_string()
            }
            (Section::Check, _) => format!("확인 필요라 뺐어요. 직접: vh fix --only {pid}"),
            (Section::Working, _) => "일하는 중이라 뺐어요".to_string(),
            _ => continue,
        };
        if f.targets.iter().all(|t| seen.contains(t)) {
            continue;
        }
        seen.extend(f.targets.iter().copied());
        let name = match f.targets.first().map(|t| lk.label(*t)) {
            Some(l)
                if f.targets.len() == 1
                    && matches!(f.section, Section::Check | Section::Working) =>
            {
                l
            }
            _ if f.short_ko.is_empty() => f.title_ko.clone(),
            _ => f.short_ko.clone(),
        };
        lines.push(format!("  {name} — {text}"));
    }
    for rf in &plan.refused {
        if rf.rule == R13_BELOW_CONFIDENCE || !seen.insert(rf.target) {
            continue;
        }
        lines.push(format!("  {} — {}", lk.label(rf.target), rf.reason_ko));
    }
    if lines.is_empty() {
        return;
    }
    o.line("건드리지 않는 것");
    for l in lines.iter().take(MAX_UNTOUCHED) {
        o.line(l);
    }
    if lines.len() > MAX_UNTOUCHED {
        o.line(&format!("  … 외 {}건", lines.len() - MAX_UNTOUCHED));
    }
}

pub fn kill_preview(s: &Snapshot, r: &Report, plan: &ActionPlan, t: Target, color: bool) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);
    if !plan.items.is_empty() {
        let what = match t {
            Target::Port(p) => format!(":{p}"),
            Target::Pid(p) => format!("{p}번 프로세스"),
        };
        o.colored(&format!("끄기 미리보기 — {what}"), Color::Bold);
    }
    for a in &plan.items {
        let mut head = format!("  {} · pid {}", lk.label(a.target), a.target.pid);
        if let Some(p) = lk.proc(a.target)
            && let Some(fp) = p.footprint_bytes
        {
            head.push_str(&format!(" · {}", fmt::bytes(fp)));
        }
        if let Some(age) = lk.age(a.target) {
            head.push_str(&format!(" · {age}째"));
        }
        o.line(&head);
        if let Some(cwd) = lk.proc(a.target).and_then(|p| p.cwd.as_deref()) {
            o.line(&format!("  폴더: {}", lk.path(cwd)));
        }
        o.line(&format!("  방법: {}", ladder(a)));
        let (kids, kid_bytes) = lk.descendants(a.target.pid);
        if a.include_descendants && a.descendant_count > 0 {
            o.line(&format!(
                "  자식 {}개도 함께 끕니다(자식부터)",
                a.descendant_count
            ));
        } else if kids > 0 {
            o.line(&format!(
                "  자식 {kids}개({})는 그대로 둡니다. 함께 끄려면 --tree",
                fmt::bytes(kid_bytes)
            ));
        }
    }
    for rf in &plan.refused {
        o.line(&format!("끄지 않았어요: {}", lk.label(rf.target)));
        o.wrap("  ", "  ", &rf.reason_ko);
    }
    if o.is_empty() {
        o.line("끌 대상이 없어요.");
    }
    o.finish()
}

pub(crate) fn state_ko(st: FinalState) -> &'static str {
    match st {
        FinalState::Exited => "종료됨",
        FinalState::StillAlive => "아직 살아 있음",
        FinalState::Skipped => "건너뜀",
        FinalState::Refused => "거부됨",
        FinalState::Vanished => "이미 없음",
        FinalState::Reused => "다른 프로그램",
    }
}

pub(crate) fn how(o: &ActionOutcome) -> String {
    match o.final_state {
        FinalState::Exited => {
            let killed = o.steps.iter().any(|s| s.step == Step::Kill && s.ok);
            if killed {
                format!("{} 뒤 강제 종료", fmt::secs(o.action.grace_ms))
            } else {
                "정상 종료".to_string()
            }
        }
        FinalState::StillAlive => "강제 종료 신호에도 남아 있어요".to_string(),
        FinalState::Vanished => "확인하는 사이에 스스로 끝났어요".to_string(),
        FinalState::Reused => "번호가 다른 프로그램으로 바뀌어 건드리지 않았어요".to_string(),
        FinalState::Skipped | FinalState::Refused => {
            if o.note_ko.is_empty() {
                "건너뛰었어요".to_string()
            } else {
                o.note_ko.clone()
            }
        }
    }
}

pub fn results(
    s: &Snapshot,
    r: &Report,
    title: &str,
    outcomes: &[ActionOutcome],
    audit_log: &Path,
    color: bool,
) -> String {
    let lk = Lookup::new(s, r);
    let mut o = Out::new(color);
    let count = |st: FinalState| outcomes.iter().filter(|x| x.final_state == st).count();
    let exited = count(FinalState::Exited);
    let still = count(FinalState::StillAlive);
    let gone = count(FinalState::Vanished);
    let skipped = outcomes.len() - exited - still - gone;
    let reclaimed: u64 = outcomes
        .iter()
        .filter(|x| x.final_state == FinalState::Exited)
        .map(|x| x.action.est_reclaim_bytes)
        .sum();
    let mut head = format!("{title} — {}건 중 {exited}건 종료", outcomes.len());
    if still > 0 {
        head.push_str(&format!(", {still}건 남음"));
    }
    if gone > 0 {
        head.push_str(&format!(", {gone}건 이미 없음"));
    }
    if skipped > 0 {
        head.push_str(&format!(", {skipped}건 건너뜀"));
    }
    if exited > 0 && reclaimed > 0 {
        head.push_str(&format!(", 예상 회수 약 {}", fmt::bytes(reclaimed)));
    }
    o.colored(&head, Color::Bold);
    for x in outcomes {
        o.line(&format!(
            "  {}  {} — {}",
            fmt::pad(state_ko(x.final_state), 14),
            item_label(&lk, &x.action),
            how(x)
        ));
    }
    o.line(&format!("기록: {}", lk.path(&audit_log.to_string_lossy())));
    if exited > 0 {
        o.line("되살릴 때 필요한 정보도 같은 폴더에 저장했어요.");
    }
    o.finish()
}
