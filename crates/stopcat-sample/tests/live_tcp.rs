//! 실기기 읽기 전용: 자기 자식과의 loopback 연결이 양쪽 pid로 풀리는지 확인한다.
//! 신호는 이 테스트가 띄운 자식에게만 보낸다.

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};

use stopcat_sample::{CollectOptions, collect};

#[test]
fn own_loopback_connection_resolves_to_child_pid() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().unwrap().port();
    let mut child = Command::new("/bin/bash")
        .args([
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}; read -r _ <&0"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("자식 실행");
    let child_pid = child.id() as i32;
    // 자식이 접속할 때까지 accept가 막힌다(시간 기다림 없음).
    let (mut conn, _) = listener.accept().expect("accept");
    let s = collect(&CollectOptions {
        cpu_interval_ms: None,
        launchd: false,
        project_roots: false,
    });
    let me = s
        .processes
        .iter()
        .find(|p| p.pid == s.self_pid)
        .expect("자기");
    let kid = s
        .processes
        .iter()
        .find(|p| p.pid == child_pid)
        .expect("자식");
    let my_tcp = me.tcp.clone().expect("자기 tcp");
    let kid_tcp = kid.tcp.clone().expect("자식 tcp");
    drop(child.stdin.take());
    let _ = child.kill();
    let _ = child.wait();
    let mut sink = [0u8; 1];
    let _ = conn.read(&mut sink);
    assert!(my_tcp.peer_pids.contains(&child_pid), "{my_tcp:?}");
    assert!(kid_tcp.peer_pids.contains(&s.self_pid), "{kid_tcp:?}");
    assert!(kid_tcp.established >= 1 && kid_tcp.loopback >= 1);
}
