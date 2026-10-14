//! launchd 잡 PID: 외부 명령 `launchctl list` 1회(stopcat-sample의 유일한 외부 명령).

use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};

pub(crate) fn spawn() -> std::io::Result<Child> {
    Command::new("/bin/launchctl")
        .arg("list")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

pub(crate) fn finish(child: Child) -> Result<(Vec<i32>, BTreeMap<i32, String>), String> {
    let out = child
        .wait_with_output()
        .map_err(|e| format!("launchctl list 대기 실패: {e}"))?;
    if !out.status.success() {
        return Err(format!("launchctl list 비정상 종료: {}", out.status));
    }
    Ok(parse(&String::from_utf8_lossy(&out.stdout)))
}

/// `PID\tStatus\tLabel` 표. PID가 `-`인 줄(실행 중이 아님)은 건너뛴다.
pub(crate) fn parse(text: &str) -> (Vec<i32>, BTreeMap<i32, String>) {
    let mut pids = Vec::new();
    let mut labels = BTreeMap::new();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let (Some(pid), Some(_status), Some(label)) = (cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if let Ok(pid) = pid.trim().parse::<i32>()
            && pid > 0
        {
            pids.push(pid);
            labels.insert(pid, label.trim().to_string());
        }
    }
    pids.sort_unstable();
    pids.dedup();
    (pids, labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchctl_parse() {
        let text = "PID\tStatus\tLabel\n-\t0\tcom.demo.idle\n123\t0\tcom.demo.stt\n\n77\t-9\tapplication.demo.1\nbroken line\n";
        let (pids, labels) = parse(text);
        assert_eq!(pids, [77, 123]);
        assert_eq!(labels[&123], "com.demo.stt");
        assert_eq!(labels.len(), 2);
    }
}
