//! ESTABLISHED TCP 연결 요약과 loopback 상대 pid 풀이(순수 함수, 시스템 호출 없음).
//!
//! loopback 연결의 반대쪽 소켓은 같은 스냅샷에서 (로컬 포트, 상대 포트)가 뒤집힌 소켓이다.
//! loopback은 빼지 않는다(브라우저 → 개발 서버도 loopback이다). 외부 상대는 수만 센다.

use std::collections::HashMap;

use stopcat_model::{MAX_PEER_PIDS, TcpSummary};

use crate::sockets::EstabSock;

/// 한 번 수집에서 모으는 ESTABLISHED 기록 상한(16바이트 × 65,536 ≈ 1MiB).
pub(crate) const MAX_CONNS: usize = 65_536;

/// 프로세스(인덱스) 하나가 쥔 ESTABLISHED 소켓 하나.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Conn {
    pub proc_idx: usize,
    pub sock: EstabSock,
}

/// `known[i]`가 true인 프로세스만 `Some(TcpSummary)`(연결 0개도 Some), 나머지는 None.
pub(crate) fn summarize(conns: &[Conn], pids: &[i32], known: &[bool]) -> Vec<Option<TcpSummary>> {
    let mut by_ports: HashMap<(u16, u16), Vec<usize>> = HashMap::new();
    for c in conns.iter().filter(|c| c.sock.f_loopback) {
        by_ports
            .entry((c.sock.lport, c.sock.fport))
            .or_default()
            .push(c.proc_idx);
    }
    let mut out: Vec<Option<TcpSummary>> =
        known.iter().map(|&k| k.then(TcpSummary::default)).collect();
    let mut peers: Vec<Vec<i32>> = vec![Vec::new(); pids.len()];
    for c in conns {
        let Some(s) = out.get_mut(c.proc_idx).and_then(Option::as_mut) else {
            continue;
        };
        s.established = s.established.saturating_add(1);
        if !c.sock.f_loopback {
            s.external = s.external.saturating_add(1);
            continue;
        }
        s.loopback = s.loopback.saturating_add(1);
        match by_ports.get(&(c.sock.fport, c.sock.lport)) {
            Some(holders) => {
                let me = pids[c.proc_idx];
                peers[c.proc_idx].extend(holders.iter().map(|&h| pids[h]).filter(|&p| p != me));
            }
            None => s.unresolved = s.unresolved.saturating_add(1),
        }
    }
    for (s, mut p) in out.iter_mut().zip(peers) {
        let Some(s) = s else { continue };
        p.sort_unstable();
        p.dedup();
        if p.len() > MAX_PEER_PIDS {
            p.truncate(MAX_PEER_PIDS);
            s.peer_pids_truncated = true;
        }
        s.peer_pids = p;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(proc_idx: usize, lport: u16, fport: u16, f_loopback: bool) -> Conn {
        Conn {
            proc_idx,
            sock: EstabSock {
                lport,
                fport,
                f_loopback,
            },
        }
    }

    #[test]
    fn loopback_pair_resolves_both_sides() {
        let pids = [100, 200];
        let s = summarize(
            &[c(0, 50_000, 3000, true), c(1, 3000, 50_000, true)],
            &pids,
            &[true, true],
        );
        let a = s[0].as_ref().unwrap();
        let b = s[1].as_ref().unwrap();
        assert_eq!(
            (a.established, a.loopback, a.external, a.unresolved),
            (1, 1, 0, 0)
        );
        assert_eq!(a.peer_pids, vec![200]);
        assert_eq!(b.peer_pids, vec![100]);
    }

    #[test]
    fn shared_socket_counts_each_holder() {
        // 부모(0)와 자식(1)이 같은 서버 소켓을 쥐고, 클라이언트(2)가 붙어 있다.
        let pids = [10, 11, 20];
        let s = summarize(
            &[
                c(0, 8080, 51_000, true),
                c(1, 8080, 51_000, true),
                c(2, 51_000, 8080, true),
            ],
            &pids,
            &[true, true, true],
        );
        assert_eq!(s[2].as_ref().unwrap().peer_pids, vec![10, 11]);
        assert_eq!(s[0].as_ref().unwrap().peer_pids, vec![20]);
        assert_eq!(s[1].as_ref().unwrap().established, 1);
    }

    #[test]
    fn self_connection_excluded_and_unresolved_counted() {
        let pids = [7];
        let s = summarize(
            &[
                c(0, 40_000, 40_001, true),
                c(0, 40_001, 40_000, true),
                c(0, 40_002, 5432, true),
            ],
            &pids,
            &[true],
        );
        let a = s[0].as_ref().unwrap();
        assert!(a.peer_pids.is_empty());
        assert_eq!((a.established, a.loopback, a.unresolved), (3, 3, 1));
    }

    #[test]
    fn external_never_stores_address() {
        let s = summarize(&[c(0, 52_000, 443, false)], &[5], &[true]);
        let a = s[0].as_ref().unwrap();
        assert_eq!((a.established, a.external, a.loopback), (1, 1, 0));
        assert!(a.peer_pids.is_empty());
        let v = serde_json::to_value(a).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert!(
            keys.iter()
                .all(|k| !k.contains("addr") && !k.contains("port")),
            "{keys:?}"
        );
    }

    #[test]
    fn peer_cap_truncates_at_64() {
        let mut pids = vec![1];
        let mut conns = Vec::new();
        for k in 0..70u16 {
            pids.push(1000 + i32::from(k));
            conns.push(c(0, 9000, 20_000 + k, true));
            conns.push(c(usize::from(k) + 1, 20_000 + k, 9000, true));
        }
        let known = vec![true; pids.len()];
        let s = summarize(&conns, &pids, &known);
        let srv = s[0].as_ref().unwrap();
        assert_eq!(srv.established, 70);
        assert_eq!(srv.peer_pids.len(), MAX_PEER_PIDS);
        assert!(srv.peer_pids_truncated);
        assert_eq!(srv.peer_pids[0], 1000);
        assert!(!s[1].as_ref().unwrap().peer_pids_truncated);
    }

    #[test]
    fn conn_cap_marks_rest_unknown() {
        // 상한을 넘은 프로세스는 known=false로 들어온다: 요약 None, 그래도 상대 쪽 풀이에는 쓰이지 않는다.
        let s = summarize(&[c(0, 1, 2, true)], &[1, 2], &[true, false]);
        assert!(s[1].is_none());
        assert_eq!(s[0].as_ref().unwrap().unresolved, 1);
    }
}
