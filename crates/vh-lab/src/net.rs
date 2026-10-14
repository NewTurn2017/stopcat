//! 실험실 HTTP 서버·클라이언트(std::net만). 서버는 127.0.0.1에만 bind 한다.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";

/// `addr`가 127.0.0.1이 아니면 bind 하지 않고 오류. bind 뒤 실제 주소도 다시 확인한다.
pub fn bind_loopback(addr: &str) -> io::Result<TcpListener> {
    let sa: SocketAddr = addr
        .parse()
        .map_err(|_| io::Error::other(format!("주소 해석 실패: {addr}")))?;
    if sa.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::other(format!("127.0.0.1이 아니라 거부: {addr}")));
    }
    let l = TcpListener::bind(sa)?;
    let local = l.local_addr()?;
    if local.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::other(format!(
            "bind 결과가 127.0.0.1이 아님: {local}"
        )));
    }
    Ok(l)
}

fn handle(stream: TcpStream) {
    let Ok(mut w) = stream.try_clone() else {
        return;
    };
    let mut r = BufReader::new(stream);
    loop {
        let mut saw_request = false;
        loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) if line == "\r\n" || line == "\n" => break,
                Ok(_) => saw_request = true,
            }
        }
        if saw_request && w.write_all(RESPONSE).is_err() {
            return;
        }
    }
}

/// 요청마다 짧은 200 응답, 상대가 닫을 때까지 연결 유지. 연결마다 스레드 하나.
pub fn serve(listener: TcpListener) {
    std::thread::spawn(move || {
        for s in listener.incoming() {
            match s {
                Ok(s) => {
                    std::thread::spawn(move || handle(s));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    });
}

/// 127.0.0.1:`port`에 연결해 GET 한 번, 200 응답을 확인하고 연결을 돌려준다.
pub fn connect_and_get(port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let sa = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let mut s = TcpStream::connect_timeout(&sa, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")?;
    let mut buf = vec![0u8; RESPONSE.len()];
    s.read_exact(&mut buf)?;
    if !buf.starts_with(b"HTTP/1.1 200") {
        return Err(io::Error::other("200 응답 아님"));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_loopback_addresses() {
        for a in [
            "0.0.0.0:0",
            "[::]:0",
            "[::1]:0",
            "192.168.0.1:0",
            "localhost:0",
        ] {
            assert!(bind_loopback(a).is_err(), "{a}");
        }
    }

    #[test]
    fn loopback_server_answers_and_keeps_connection() {
        let l = bind_loopback("127.0.0.1:0").expect("bind");
        let local = l.local_addr().expect("addr");
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(local.port() >= 1024);
        serve(l);
        let mut s = connect_and_get(local.port(), Duration::from_secs(5)).expect("get");
        s.write_all(b"GET /again HTTP/1.1\r\n\r\n").expect("again");
        let mut buf = vec![0u8; RESPONSE.len()];
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        s.read_exact(&mut buf).expect("second response");
        assert_eq!(buf, RESPONSE);
    }
}
