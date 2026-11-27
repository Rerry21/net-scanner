use std::fmt;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};


#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub retries: u32,
    pub threads: usize,
}

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
    pub attempts: u32,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Latency {
    pub min: Duration,
    pub avg: Duration,
    pub max: Duration,
}

pub fn scan_host(ip: IpAddr, ports: &[u16], config: ScanConfig) -> Vec<PortResult> {
    let workers = config.threads.clamp(1, ports.len().max(1));
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel();

    thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(&port) = ports.get(index) else {
                    break;
                };
                let result = scan_port(SocketAddr::new(ip, port), config);
                if tx.send(result).is_err() {
                    break;
                }
            });
        }
        drop(tx);
    });

    let mut results: Vec<PortResult> = rx.into_iter().collect();
    results.sort_by_key(|r| r.addr.port());
    results
}

pub fn scan_port(addr: SocketAddr, config: ScanConfig) -> PortResult {
    let mut attempts = 0;

    let (state, reason, elapsed) = loop {
        attempts += 1;

        let started = Instant::now();
        let (state, reason) = attempt(addr, config.timeout);
        let elapsed = started.elapsed();

        if state != PortState::Filtered || attempts > config.retries {
            break (state, reason, elapsed);
        }
    };

    PortResult {
        addr,
        state,
        reason,
        attempts,
        elapsed,
    }
}

pub fn open_latency(results: &[PortResult]) -> Option<Latency> {
    let times: Vec<Duration> = results
        .iter()
        .filter(|r| r.state == PortState::Open)
        .map(|r| r.elapsed)
        .collect();

    let count = u32::try_from(times.len()).ok().filter(|&n| n > 0)?;
    let total: Duration = times.iter().sum();

    Some(Latency {
        min: *times.iter().min()?,
        avg: total / count,
        max: *times.iter().max()?,
    })
}

fn attempt(addr: SocketAddr, timeout: Duration) -> (PortState, &'static str) {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => (PortState::Open, "connected"),
        Err(error) => classify(&error),
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
        _ => (PortState::Filtered, "connection error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn config(retries: u32) -> ScanConfig {
        ScanConfig {
            timeout: Duration::from_secs(2),
            retries,
            threads: 1,
        }
    }

    fn fake(state: PortState, millis: u64) -> PortResult {
        PortResult {
            addr: "127.0.0.1:80".parse().unwrap(),
            state,
            reason: "test",
            attempts: 1,
            elapsed: Duration::from_millis(millis),
        }
    }

    #[test]
    fn open_port_is_detected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let result = scan_port(addr, config(0));

        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.reason, "connected");
        assert_eq!(result.attempts, 1);
    }

    #[test]
    fn open_port_is_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let result = scan_port(addr, config(3));

        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.attempts, 1);
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
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let results = scan_host(ip, &[port], config(0));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].addr.port(), port);
    }

    #[test]
    fn parallel_scan_returns_sorted_results() {
        let listeners: Vec<TcpListener> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let mut ports: Vec<u16> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        ports.sort_unstable();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let parallel = ScanConfig {
            threads: 4,
            ..config(0)
        };

        let results = scan_host(ip, &ports, parallel);

        let scanned: Vec<u16> = results.iter().map(|r| r.addr.port()).collect();
        assert_eq!(scanned, ports);
        assert!(results.iter().all(|r| r.state == PortState::Open));
    }

    #[test]
    fn more_threads_than_ports_and_empty_list() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let many = ScanConfig {
            threads: 64,
            ..config(0)
        };

        assert!(scan_host(ip, &[], many).is_empty());

        let listener = TcpListener::bind("127.0.0.1:10").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(scan_host(ip, &[port], many).len(), 1);
    }

    #[test]
    fn latency_uses_only_open_ports() {
        let results = vec![
            fake(PortState::Open, 2),
            fake(PortState::Closed, 2000),
            fake(PortState::Open, 4),
        ];

        let latency = open_latency(&results).unwrap();

        assert_eq!(latency.min, Duration::from_millis(2));
        assert_eq!(latency.avg, Duration::from_millis(3));
        assert_eq!(latency.max, Duration::from_millis(4));
    }

    #[test]
    fn latency_is_none_without_open_ports() {
        assert_eq!(open_latency(&[fake(PortState::Closed, 5)]), None);
        assert_eq!(open_latency(&[]), None);
    }
}