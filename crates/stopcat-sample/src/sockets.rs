//! TCP 소켓: PROC_PIDLISTFDS → PROX_FDTYPE_SOCKET → PROC_PIDFDSOCKETINFO.
//! LISTEN은 `Listener`로, ESTABLISHED는 상대 풀이용 `Conn`으로 꺼낸다(같은 fdinfo 한 번 읽기).

use std::net::{Ipv4Addr, Ipv6Addr};

use stopcat_model::{Family, Listener};

use crate::ffi::{self, ProcFdInfo, SocketFdInfo};
use crate::procinfo;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ListenSock {
    pub family: Family,
    pub addr: String,
    pub port: u16,
    pub all_interfaces: bool,
    pub loopback: bool,
    pub dual_stack: bool,
}

/// ESTABLISHED TCP 소켓 하나. 상대 주소는 loopback 여부만 남긴다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EstabSock {
    pub lport: u16,
    pub fport: u16,
    pub f_loopback: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TcpSock {
    Listen(ListenSock),
    Established(EstabSock),
}

fn port_at(b: &[u8], off: usize) -> u16 {
    u16::from_be((ffi::rd_i32(b, off) as u32 & 0xffff) as u16)
}

fn v6_loopback(a: Ipv6Addr) -> bool {
    a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
}

/// socket_fdinfo 바이트에서 TCP LISTEN·ESTABLISHED 소켓을 꺼낸다. 그 밖(다른 상태·UDP·unix)은 None.
pub(crate) fn parse_tcp(b: &[u8]) -> Option<TcpSock> {
    if b.len() < ffi::SOCKET_FDINFO_SIZE || ffi::rd_i32(b, ffi::SOI_KIND) != ffi::SOCKINFO_TCP {
        return None;
    }
    let family = ffi::rd_i32(b, ffi::SOI_FAMILY);
    if family != ffi::AF_INET && family != ffi::AF_INET6 {
        return None;
    }
    match ffi::rd_i32(b, ffi::TCPSI_STATE) {
        ffi::TSI_S_LISTEN => {
            let vflag = b[ffi::INSI_VFLAG];
            let port = port_at(b, ffi::INSI_LPORT);
            Some(TcpSock::Listen(if family == ffi::AF_INET {
                let a = Ipv4Addr::from(ffi::rd_array::<4>(b, ffi::INSI_LADDR4));
                ListenSock {
                    family: Family::V4,
                    addr: a.to_string(),
                    port,
                    all_interfaces: a.is_unspecified(),
                    loopback: a.is_loopback(),
                    dual_stack: false,
                }
            } else {
                let a = Ipv6Addr::from(ffi::rd_array::<16>(b, ffi::INSI_LADDR6));
                ListenSock {
                    family: Family::V6,
                    addr: a.to_string(),
                    port,
                    all_interfaces: a.is_unspecified(),
                    loopback: v6_loopback(a),
                    dual_stack: vflag & ffi::INI_IPV4 != 0,
                }
            }))
        }
        ffi::TSI_S_ESTABLISHED => {
            let f_loopback = if family == ffi::AF_INET {
                Ipv4Addr::from(ffi::rd_array::<4>(b, ffi::INSI_FADDR4)).is_loopback()
            } else {
                v6_loopback(Ipv6Addr::from(ffi::rd_array::<16>(b, ffi::INSI_FADDR6)))
            };
            Some(TcpSock::Established(EstabSock {
                lport: port_at(b, ffi::INSI_LPORT),
                fport: port_at(b, ffi::INSI_FPORT),
                f_loopback,
            }))
        }
        _ => None,
    }
}

/// socket_fdinfo 바이트에서 TCP LISTEN 소켓만 꺼낸다.
#[cfg(test)]
pub(crate) fn parse_listen(b: &[u8]) -> Option<ListenSock> {
    match parse_tcp(b)? {
        TcpSock::Listen(l) => Some(l),
        TcpSock::Established(_) => None,
    }
}

/// 소켓 단계 결과: 리스너와 실패한 fd 수. ESTABLISHED는 호출자가 준 `estab`에 붙인다.
pub(crate) struct PidSockets {
    pub listeners: Vec<Listener>,
    pub fd_errors: usize,
}

pub(crate) fn sockets_of(
    pid: i32,
    start_time_unix_ms: u64,
    nfiles_hint: usize,
    fdbuf: &mut Vec<ProcFdInfo>,
    sockbuf: &mut SocketFdInfo,
    estab: &mut Vec<EstabSock>,
) -> Result<PidSockets, i32> {
    let n = procinfo::list_fds(pid, fdbuf, nfiles_hint)?;
    let mut out = PidSockets {
        listeners: Vec::new(),
        fd_errors: 0,
    };
    for fd in &fdbuf[..n] {
        if fd.proc_fdtype != ffi::PROX_FDTYPE_SOCKET {
            continue;
        }
        if procinfo::socket_info(pid, fd.proc_fd, sockbuf).is_err() {
            out.fd_errors += 1;
            continue;
        }
        match parse_tcp(&sockbuf.0) {
            Some(TcpSock::Listen(s)) => {
                let dup = out
                    .listeners
                    .iter()
                    .any(|l| l.family == s.family && l.local_addr == s.addr && l.port == s.port);
                if !dup {
                    out.listeners.push(Listener {
                        pid,
                        start_time_unix_ms,
                        family: s.family,
                        local_addr: s.addr,
                        port: s.port,
                        all_interfaces: s.all_interfaces,
                        loopback: s.loopback,
                        dual_stack: s.dual_stack,
                    });
                }
            }
            Some(TcpSock::Established(e)) => estab.push(e),
            None => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(family: i32, kind: i32, state: i32, vflag: u8, port: u16, addr: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; ffi::SOCKET_FDINFO_SIZE];
        b[ffi::SOI_FAMILY..ffi::SOI_FAMILY + 4].copy_from_slice(&family.to_ne_bytes());
        b[ffi::SOI_KIND..ffi::SOI_KIND + 4].copy_from_slice(&kind.to_ne_bytes());
        b[ffi::TCPSI_STATE..ffi::TCPSI_STATE + 4].copy_from_slice(&state.to_ne_bytes());
        b[ffi::INSI_VFLAG] = vflag;
        let lport = i32::from(port.to_be());
        b[ffi::INSI_LPORT..ffi::INSI_LPORT + 4].copy_from_slice(&lport.to_ne_bytes());
        let off = if family == ffi::AF_INET {
            ffi::INSI_LADDR4
        } else {
            ffi::INSI_LADDR6
        };
        b[off..off + addr.len()].copy_from_slice(addr);
        b
    }

    #[test]
    fn listener_addr_format() {
        let v4_any = parse_listen(&sock(ffi::AF_INET, 2, 1, 1, 8080, &[0, 0, 0, 0])).unwrap();
        assert_eq!((v4_any.addr.as_str(), v4_any.port), ("0.0.0.0", 8080));
        assert!(v4_any.all_interfaces && !v4_any.loopback && !v4_any.dual_stack);
        let v4_lo = parse_listen(&sock(ffi::AF_INET, 2, 1, 1, 3000, &[127, 0, 0, 1])).unwrap();
        assert_eq!(v4_lo.addr, "127.0.0.1");
        assert!(v4_lo.loopback && !v4_lo.all_interfaces);
        let v6_any = parse_listen(&sock(ffi::AF_INET6, 2, 1, 3, 4723, &[0; 16])).unwrap();
        assert_eq!((v6_any.family, v6_any.addr.as_str()), (Family::V6, "::"));
        assert!(v6_any.all_interfaces && v6_any.dual_stack);
        let mut one = [0u8; 16];
        one[15] = 1;
        let v6_lo = parse_listen(&sock(ffi::AF_INET6, 2, 1, 2, 5173, &one)).unwrap();
        assert_eq!(v6_lo.addr, "::1");
        assert!(v6_lo.loopback && !v6_lo.dual_stack);
    }

    #[test]
    fn non_listen_or_non_tcp_is_skipped() {
        assert!(parse_listen(&sock(ffi::AF_INET, 2, 4, 1, 80, &[0; 4])).is_none());
        assert!(parse_listen(&sock(ffi::AF_INET, 1, 1, 1, 80, &[0; 4])).is_none());
        assert!(parse_listen(&sock(1, 2, 1, 0, 80, &[0; 4])).is_none());
        assert!(parse_listen(&[0u8; 10]).is_none());
    }

    fn estab(family: i32, lport: u16, fport: u16, faddr: &[u8]) -> Vec<u8> {
        let mut b = sock(family, 2, 4, 1, lport, &[]);
        let fp = i32::from(fport.to_be());
        b[ffi::INSI_FPORT..ffi::INSI_FPORT + 4].copy_from_slice(&fp.to_ne_bytes());
        let off = if family == ffi::AF_INET {
            ffi::INSI_FADDR4
        } else {
            ffi::INSI_FADDR6
        };
        b[off..off + faddr.len()].copy_from_slice(faddr);
        b
    }

    fn est(b: &[u8]) -> EstabSock {
        match parse_tcp(b) {
            Some(TcpSock::Established(e)) => e,
            other => panic!("ESTABLISHED가 아님: {other:?}"),
        }
    }

    #[test]
    fn established_v4_loopback_parsed() {
        let e = est(&estab(ffi::AF_INET, 50_000, 3000, &[127, 0, 0, 1]));
        assert_eq!((e.lport, e.fport, e.f_loopback), (50_000, 3000, true));
        let ext = est(&estab(ffi::AF_INET, 50_001, 443, &[93, 184, 216, 34]));
        assert_eq!((ext.lport, ext.fport, ext.f_loopback), (50_001, 443, false));
        assert!(parse_listen(&estab(ffi::AF_INET, 50_000, 3000, &[127, 0, 0, 1])).is_none());
    }

    #[test]
    fn established_v6_and_mapped_loopback() {
        let mut one = [0u8; 16];
        one[15] = 1;
        assert!(est(&estab(ffi::AF_INET6, 1, 2, &one)).f_loopback);
        let mapped_lo = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
        assert!(est(&estab(ffi::AF_INET6, 1, 2, &mapped_lo)).f_loopback);
        let mapped_lan = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        assert!(!est(&estab(ffi::AF_INET6, 1, 2, &mapped_lan)).f_loopback);
        let doc = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(!est(&estab(ffi::AF_INET6, 1, 2, &doc)).f_loopback);
    }

    #[test]
    fn listen_unchanged_and_other_states_skipped() {
        let l = parse_tcp(&sock(ffi::AF_INET, 2, 1, 1, 8080, &[0, 0, 0, 0]));
        assert!(matches!(l, Some(TcpSock::Listen(ref s)) if s.port == 8080 && s.all_interfaces));
        for state in [2, 3, 5, 6, 7, 8, 9, 10] {
            assert!(
                parse_tcp(&sock(ffi::AF_INET, 2, state, 1, 80, &[0; 4])).is_none(),
                "{state}"
            );
        }
        assert!(parse_tcp(&sock(ffi::AF_INET, 1, 4, 1, 80, &[0; 4])).is_none());
        assert!(parse_tcp(&sock(1, 2, 4, 0, 80, &[0; 4])).is_none());
    }
}
