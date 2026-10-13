use vh_model::redact_argv;

pub(crate) const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

pub(crate) fn gb_number(bytes: u64) -> String {
    let v = bytes as f64 / GIB as f64;
    if v >= 10.0 {
        format!("{}", v.round() as u64)
    } else {
        let s = format!("{v:.1}");
        s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
    }
}

pub(crate) fn size(bytes: u64) -> String {
    if bytes >= GIB {
        format!("{}GB", gb_number(bytes))
    } else {
        format!("{}MB", (bytes as f64 / MIB as f64).round() as u64)
    }
}

pub(crate) fn size_pair(used: u64, total: u64) -> String {
    if total >= GIB {
        format!("{}/{}GB", gb_number(used), gb_number(total))
    } else {
        let mb = |b: u64| (b as f64 / MIB as f64).round() as u64;
        format!("{}/{}MB", mb(used), mb(total))
    }
}

pub(crate) fn age(ms: u64) -> String {
    let mins = ms / 60_000;
    let hours = mins / 60;
    let days = hours / 24;
    if days > 0 {
        let h = hours % 24;
        if h > 0 {
            format!("{days}일 {h}시간")
        } else {
            format!("{days}일")
        }
    } else if hours > 0 {
        format!("{hours}시간")
    } else if mins > 0 {
        format!("{mins}분")
    } else {
        "1분 미만".to_string()
    }
}

/// argv에서 나온 조각을 문자열에 넣기 전에 마스킹한다(계약 규칙).
pub(crate) fn safe(fragment: &str) -> String {
    redact_argv(&[fragment.to_string()])
        .pop()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(41 * GIB), "41GB");
        assert_eq!(size(GIB * 16 / 10), "1.6GB");
        assert_eq!(size(GIB / 2), "512MB");
        assert_eq!(size(15 * GIB / 2), "7.5GB");
        assert_eq!(size_pair(GIB * 16 / 10, 2 * GIB), "1.6/2GB");
        assert_eq!(size_pair(0, 0), "0/0MB");
    }

    #[test]
    fn ages() {
        assert_eq!(age(3 * 86_400_000 + 4 * 3_600_000), "3일 4시간");
        assert_eq!(age(7 * 3_600_000 + 59 * 60_000), "7시간");
        assert_eq!(age(25 * 60_000), "25분");
        assert_eq!(age(10), "1분 미만");
    }
}
