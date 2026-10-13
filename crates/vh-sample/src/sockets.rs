//! TCP LISTEN 소켓: PROC_PIDLISTFDS → PROX_FDTYPE_SOCKET → PROC_PIDFDSOCKETINFO.

use std::net::{Ipv4Addr, Ipv6Addr};

use vh_model::{Family, Listener};

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

/// socket_fdinfo 바이트에서 TCP LISTEN 소켓만 꺼낸다.
pub(crate) fn parse_listen(b: &[u8]) -> Option<ListenSock> {
    if b.len() < ffi::SOCKET_FDINFO_SIZE
        || ffi::rd_i32(b, ffi::SOI_KIND) != ffi::SOCKINFO_TCP
        || ffi::rd_i32(b, ffi::TCPSI_STATE) != ffi::TSI_S_LISTEN
    {
        return None;
    }
    let vflag = b[ffi::INSI_VFLAG];
    let port = u16::from_be((ffi::rd_i32(b, ffi::INSI_LPORT) as u32 & 0xffff) as u16);
    match ffi::rd_i32(b, ffi::SOI_FAMILY) {
        ffi::AF_INET => {
            let a = Ipv4Addr::from(ffi::rd_array::<4>(b, ffi::INSI_LADDR4));
            Some(ListenSock {
                family: Family::V4,
                addr: a.to_string(),
                port,
                all_interfaces: a.is_unspecified(),
                loopback: a.is_loopback(),
                dual_stack: false,
            })
        }
        ffi::AF_INET6 => {
            let a = Ipv6Addr::from(ffi::rd_array::<16>(b, ffi::INSI_LADDR6));
            let loopback = a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback());
            Some(ListenSock {
                family: Family::V6,
                addr: a.to_string(),
                port,
                all_interfaces: a.is_unspecified(),
                loopback,
                dual_stack: vflag & ffi::INI_IPV4 != 0,
            })
        }
        _ => None,
    }
}

/// 소켓 단계 결과: 리스너와 실패한 fd 수.
pub(crate) struct PidSockets {
    pub listeners: Vec<Listener>,
    pub fd_errors: usize,
}

pub(crate) fn listeners_of(
    pid: i32,
    start_time_unix_ms: u64,
    nfiles_hint: usize,
    fdbuf: &mut Vec<ProcFdInfo>,
    sockbuf: &mut SocketFdInfo,
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
        if let Some(s) = parse_listen(&sockbuf.0) {
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
}
