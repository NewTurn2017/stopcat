use vh_model::{Confidence, Finding, FindingKind, Group, Health, HealthLevel, Suggestion};

use crate::ctx::Ctx;
use crate::findings::{Draft, build};
use crate::fmt::{size, size_pair};

fn level_rank(l: HealthLevel) -> u8 {
    match l {
        HealthLevel::Ok => 0,
        HealthLevel::Watch => 1,
        HealthLevel::Critical => 2,
    }
}

fn raise(cur: &mut HealthLevel, to: HealthLevel) {
    if level_rank(to) > level_rank(*cur) {
        *cur = to;
    }
}

fn word(l: HealthLevel) -> &'static str {
    match l {
        HealthLevel::Ok => "정상",
        HealthLevel::Watch => "주의",
        HealthLevel::Critical => "위험",
    }
}

fn top_groups(groups: &[Group], by_count: bool) -> String {
    let mut g: Vec<&Group> = groups.iter().collect();
    if by_count {
        g.sort_by(|a, b| {
            b.members
                .len()
                .cmp(&a.members.len())
                .then_with(|| a.id.cmp(&b.id))
        });
    }
    g.iter()
        .take(3)
        .map(|x| {
            if by_count {
                format!("{} {}개", x.title, x.members.len())
            } else {
                format!("{} {}", x.title, size(x.footprint_bytes))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn health(c: &Ctx, groups: &[Group]) -> (Health, Vec<Finding>) {
    let m = &c.s.memory;
    let h = &c.s.host;
    let lim = &c.s.limits;
    let mut findings = Vec::new();
    let mut reasons = Vec::new();

    let mut mem_level = match m.pressure_level {
        1 => HealthLevel::Ok,
        2 => HealthLevel::Watch,
        4 => HealthLevel::Critical,
        _ => HealthLevel::Watch,
    };
    match m.pressure_level {
        1 => {}
        2 => reasons
            .push("메모리 압력이 경고(2) 단계예요. 스왑이 늘고 느려지기 시작해요.".to_string()),
        4 => reasons
            .push("메모리 압력이 위험(4) 단계예요. 앱이 강제로 종료될 수 있어요.".to_string()),
        other => reasons.push(format!("알 수 없는 압력 값 {other}이라 주의로 표시해요.")),
    }
    if h.mem_total_bytes > 0 && m.compressor_bytes >= h.mem_total_bytes / 2 {
        raise(&mut mem_level, HealthLevel::Watch);
        reasons.push(format!(
            "압축 메모리가 실제 메모리의 절반을 넘었어요({}/{}).",
            size(m.compressor_bytes),
            size(h.mem_total_bytes)
        ));
    }
    if h.mem_total_bytes > 0 && m.swap_used_bytes >= h.mem_total_bytes / 4 {
        raise(&mut mem_level, HealthLevel::Watch);
        reasons.push(format!(
            "스왑을 실제 메모리의 4분의 1 넘게 쓰고 있어요({}).",
            size(m.swap_used_bytes)
        ));
    }
    let mut level = mem_level;

    if m.pressure_level != 1 {
        let (code, title) = match m.pressure_level {
            2 => ("pressure_warn", "메모리 압력 경고"),
            4 => ("pressure_critical", "메모리 압력 위험"),
            _ => ("pressure_unknown_value", "메모리 압력 값 확인 필요"),
        };
        findings.push(build(
            c,
            Draft {
                id: "memory_pressure".into(),
                kind: FindingKind::MemoryPressure,
                confidence: Confidence::Confirmed,
                targets: vec![],
                with_desc: false,
                title: title.into(),
                short: format!("압력 {}", m.pressure_level),
                detail: format!(
                    "메모리를 가장 많이 쓰는 묶음: {}. 위의 정리 제안부터 보세요. 무엇을 끌지는 사람이 판단할 일이에요.",
                    top_groups(groups, false)
                ),
                reasons: vec![code.into()],
                suggestion: Suggestion::Review,
            },
        ));
    }

    let limits = [
        (
            "maxprocperuid",
            lim.user_proc_count,
            lim.maxprocperuid,
            "procs_ge_80pct_maxprocperuid",
            "프로세스 수",
        ),
        (
            "maxfiles",
            lim.num_files,
            lim.maxfiles,
            "files_ge_80pct_maxfiles",
            "열린 파일 수",
        ),
    ];
    for (key, used, max, code, what) in limits {
        if max == 0 || u64::from(used) * 10 < u64::from(max) * 8 {
            continue;
        }
        let critical = u64::from(used) * 100 >= u64::from(max) * 95;
        raise(
            &mut level,
            if critical {
                HealthLevel::Critical
            } else {
                HealthLevel::Watch
            },
        );
        let mut rc = vec![code.to_string()];
        if critical {
            rc.push("ge_95pct".into());
        }
        reasons.push(format!("{what}가 한도에 가까워요({used}/{max})."));
        findings.push(build(
            c,
            Draft {
                id: format!("limit_nearing:{key}"),
                kind: FindingKind::LimitNearing,
                confidence: Confidence::Confirmed,
                targets: vec![],
                with_desc: false,
                title: format!("{what}가 한도에 가까움 ({used}/{max})"),
                short: format!("{what} {used}/{max}"),
                detail: format!(
                    "한도를 넘으면 새 프로그램 실행이나 파일 열기가 실패해요. 프로세스가 많은 묶음: {}. 무엇을 정리할지는 사람이 판단할 일이에요.",
                    top_groups(groups, true)
                ),
                reasons: rc,
                suggestion: Suggestion::Review,
            },
        ));
    }

    if reasons.is_empty() {
        reasons.push("위기 아님: 메모리 압력 정상".to_string());
    }
    let swap = if m.swap_total_bytes == 0 {
        "스왑 없음".to_string()
    } else {
        format!("스왑 {}", size_pair(m.swap_used_bytes, m.swap_total_bytes))
    };
    let headline = format!(
        "메모리 {} — 압력 {} · 압축 {} · {swap} · 부하 {:.1}/{}코어",
        word(mem_level),
        m.pressure_level,
        size(m.compressor_bytes),
        h.loadavg[0],
        h.ncpu
    );
    (
        Health {
            level,
            headline_ko: headline,
            reasons_ko: reasons,
        },
        findings,
    )
}
