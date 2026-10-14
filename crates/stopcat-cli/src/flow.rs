//! `stopcat fix`·`stopcat kill` 흐름: 미리보기 → (--yes | TTY 확인 | 비 TTY는 멈춤) → 실행 → 결과.

use std::path::PathBuf;

use stopcat_model::{ActionOutcome, ActionPlan, Confidence, Report, Snapshot};

use crate::app::{CliError, Io};
use crate::json;
use crate::render::{action, confidence_ko};
use crate::target::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    NothingToDo,
    NonInteractivePreview,
    Declined,
    Executed,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::NothingToDo => "nothing_to_do",
            Mode::NonInteractivePreview => "non_interactive_preview",
            Mode::Declined => "declined",
            Mode::Executed => "executed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Executed {
    pub outcomes: Vec<ActionOutcome>,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    Explicit,
    Only,
    Yes,
    Confirm,
}

/// 신뢰도 기본값(PM 판정): 명시 `--min-confidence` > `--only`면 possible > `--yes`면 confirmed > 확인 후 실행은 likely.
pub fn min_confidence(explicit: Option<Confidence>, only: bool, yes: bool) -> (Confidence, Basis) {
    if let Some(c) = explicit {
        return (c, Basis::Explicit);
    }
    if only {
        return (Confidence::Possible, Basis::Only);
    }
    if yes {
        (Confidence::Confirmed, Basis::Yes)
    } else {
        (Confidence::Likely, Basis::Confirm)
    }
}

pub fn basis_ko(b: Basis, c: Confidence) -> String {
    match b {
        Basis::Explicit => format!(
            "'필요 없음'만 · {} 이상 (--min-confidence)",
            confidence_ko(c)
        ),
        Basis::Only => {
            "직접 고른 대상(--only)은 구역·신뢰도와 상관없이 포함 · 보호 규칙은 그대로".to_string()
        }
        Basis::Yes => "'필요 없음'만 · 확실한 것만 (--yes 로 바로 실행할 때 기본값)".to_string(),
        Basis::Confirm => {
            "'필요 없음'만 · 확실 + 가능성 높음 (확인하고 실행할 때 기본값)".to_string()
        }
    }
}

pub fn is_yes_answer(line: &str) -> bool {
    matches!(
        line.trim(),
        "y" | "Y" | "yes" | "Yes" | "YES" | "예" | "네" | "ㅇ"
    )
}

pub enum Kind<'a> {
    Fix {
        basis: String,
        only: &'a [i32],
        yes_only_confirmed_note: bool,
    },
    Kill {
        target: Target,
    },
}

pub struct Request<'a> {
    pub s: &'a Snapshot,
    pub r: &'a Report,
    pub plan: &'a ActionPlan,
    pub kind: Kind<'a>,
    pub yes: bool,
    pub json: bool,
    pub color: bool,
}

pub type ExecFn<'e> = dyn FnMut(&ActionPlan) -> anyhow::Result<Executed> + 'e;

/// 미리보기를 보여 주고, 실행 조건이 맞을 때만 `exec`를 한 번 부른다.
pub fn run(req: &Request<'_>, io: &mut Io<'_>, exec: &mut ExecFn<'_>) -> Result<Mode, CliError> {
    let target = match req.kind {
        Kind::Kill { target } => Some(target),
        Kind::Fix { .. } => None,
    };
    if !req.json {
        let text = match &req.kind {
            Kind::Fix { basis, only, .. } => {
                action::fix_preview(req.s, req.r, req.plan, basis, only, req.color)
            }
            Kind::Kill { target } => {
                action::kill_preview(req.s, req.r, req.plan, *target, req.color)
            }
        };
        io.out.write_all(text.as_bytes())?;
    }
    let emit = |io: &mut Io<'_>, mode: Mode, ex: Option<&Executed>| -> Result<(), CliError> {
        let v = json::action(
            req.s,
            target,
            mode.as_str(),
            req.plan,
            ex.map(|e| e.outcomes.as_slice()).unwrap_or(&[]),
            ex.map(|e| e.state_dir.as_path()),
        );
        writeln!(io.out, "{v}")?;
        Ok(())
    };

    if req.plan.items.is_empty() {
        if req.json {
            emit(io, Mode::NothingToDo, None)?;
        }
        return Ok(Mode::NothingToDo);
    }

    if !req.yes {
        if io.interactive(req.json) {
            let prompt = match req.kind {
                Kind::Fix { .. } => action::FIX_PROMPT,
                Kind::Kill { .. } => action::KILL_PROMPT,
            };
            io.err.write_all(prompt.as_bytes())?;
            io.err.flush()?;
            let mut line = String::new();
            io.input.read_line(&mut line)?;
            if !is_yes_answer(&line) {
                writeln!(io.out, "{}", action::DECLINED)?;
                return Ok(Mode::Declined);
            }
        } else {
            if req.json {
                emit(io, Mode::NonInteractivePreview, None)?;
            } else {
                match &req.kind {
                    Kind::Fix {
                        yes_only_confirmed_note,
                        ..
                    } => {
                        writeln!(io.out, "{}", action::FIX_NOT_RUN)?;
                        if *yes_only_confirmed_note {
                            writeln!(io.out, "{}", action::FIX_YES_ONLY_CONFIRMED)?;
                        }
                    }
                    Kind::Kill { target } => {
                        writeln!(io.out, "{}", action::kill_not_run(*target))?;
                    }
                }
            }
            return Ok(Mode::NonInteractivePreview);
        }
    }

    let ex = exec(req.plan)
        .map_err(|e| CliError::internal(format!("정리를 실행하다가 문제가 생겼어요: {e:#}")))?;
    if req.json {
        emit(io, Mode::Executed, Some(&ex))?;
    } else {
        let title = match req.kind {
            Kind::Fix { .. } => "정리 결과",
            Kind::Kill { .. } => "끄기 결과",
        };
        let audit = stopcat_act::audit_log_path(&ex.state_dir);
        let text = action::results(req.s, req.r, title, &ex.outcomes, &audit, req.color);
        io.out.write_all(text.as_bytes())?;
    }
    Ok(Mode::Executed)
}
