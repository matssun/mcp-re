//! Owns `SO_REUSEPORT` listener construction for the per-core fleet.

use std::net::SocketAddr;

/// Create a `SO_REUSEPORT` (+ `SO_REUSEADDR`) TCP listener bound to `addr` and put it
/// in listening state. `SO_REUSEPORT` must be set BEFORE `bind`, which `std::net`
/// does not expose — hence the raw socket construction. On Linux the kernel then
/// load-balances accepted connections across every listener in the port's
/// `SO_REUSEPORT` group (one per core).
#[cfg(unix)]
pub(super) fn reuseport_listener(
    addr: SocketAddr,
    backlog: i32,
) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    let family = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    // SAFETY: `socket(2)` with a valid family/type returns a new fd or -1. We wrap a
    // successful fd in an `OwnedFd` IMMEDIATELY so every early return below closes it
    // (RAII), and hand ownership to `TcpListener` only on the success path.
    let owned = unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    let fd = {
        use std::os::fd::AsRawFd;
        owned.as_raw_fd()
    };

    set_sockopt(fd, libc::SO_REUSEADDR)?;
    set_sockopt(fd, libc::SO_REUSEPORT)?;

    // Build the bind sockaddr for the address family and bind + listen. On any error
    // `owned` drops and closes the fd.
    bind_and_listen(fd, addr, backlog)?;

    Ok(std::net::TcpListener::from(owned))
}

/// Non-Unix platforms have no `SO_REUSEPORT`; the per-core fleet is a Unix
/// (Linux-production) data plane. Fail closed rather than silently binding a single
/// non-shared listener.
#[cfg(not(unix))]
pub(super) fn reuseport_listener(
    _addr: SocketAddr,
    _backlog: i32,
) -> std::io::Result<std::net::TcpListener> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_REUSEPORT per-core fleet is only supported on Unix",
    ))
}

/// Set a boolean `SOL_SOCKET` option to 1 on `fd`, failing closed on error.
#[cfg(unix)]
fn set_sockopt(fd: std::os::fd::RawFd, option: libc::c_int) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a valid open socket; `&one` points to a `c_int` of the declared
    // length. `setsockopt` reads that many bytes and does not retain the pointer.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `bind(2)` + `listen(2)` `fd` to `addr`, constructing the family-appropriate
/// sockaddr. Ports and IPv4 addresses go on the wire in network byte order.
#[cfg(unix)]
fn bind_and_listen(fd: std::os::fd::RawFd, addr: SocketAddr, backlog: i32) -> std::io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sockaddr = libc::sockaddr_in {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                // `octets()` is already network-order bytes; `from_ne_bytes` keeps
                // that in-memory byte layout, which is what `s_addr` (network order)
                // expects.
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `fd` is a valid socket; the sockaddr pointer + length describe a
            // fully-initialized `sockaddr_in`. `bind` copies it and does not retain
            // the pointer.
            unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sockaddr = libc::sockaddr_in6 {
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above for the IPv6 sockaddr.
            unsafe {
                libc::bind(
                    fd,
                    &sockaddr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `fd` is a valid bound socket.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
