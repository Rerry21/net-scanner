use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
        };
        f.pad(text)
    }
}

#[derive(Debug, Clone)]
pub struct PortResult {
    pub addr: SocketAddr,
    pub state: PortState,
    pub reason: &'static str,
    pub elapsed: Duration,
}

pub fn scan_host(ip: IpAddr, ports: &[u16], timeout:Duration) -> Vec<PortResult> {
    ports
        .iter()
        .map(|&port| scan_port(SocketAddr::new(ip, port), timeout))
        .collect()
}

pub fn scan_port(addr: SocketAddr, timeout: Duration) -> PortResult {
    let started = Instant::now();

    let (state, reason) = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => (PortState::Open, "connected"),
        Err(error) => classify(&error),
    };

    PortResult {
        addr,
        state,
        reason,
        elapsed: started.elapsed(),
    }
}

fn classify(error: &io::Error) -> (PortState, &'static str) {
    match error.kind() {
        ErrorKind::ConnectionRefused => (PortState::Closed, "connection refused"),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => {
            (PortState::Filtered, "no response (timeout)")
        }
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
            (PortState::Filtered, "unreachable")
        }
        _=> (PortState::Filtered, "connection error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn open_port_is_detected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let result = scan_port(addr, Duration::from_secs(2));

        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.reason, "connected");
    }

    #[test]
    fn errors_are_classified() {
        let refused = io::Error::from(ErrorKind::ConnectionRefused);
        assert_eq!(classify(&refused).0, PortState::Closed);

        let timeout = io::Error::from(ErrorKind::TimedOut);
        assert_eq!(classify(&timeout).0, PortState::Filtered);

        let other = io::Error::from(ErrorKind::PermissionDenied);
        assert_eq!(classify(&other).0, PortState::Filtered);
    }

    #[test]
    fn scan_host_returns_one_result_per_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let results = scan_host("127.0.0.1".parse().unwrap(), &[port], Duration::from_secs(2));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].addr.port(), port);
    }
}