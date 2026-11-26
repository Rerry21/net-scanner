use std::fmt;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

use thiserror::Error;

const MAX_TARGETS: u64 = 65_536;

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Ip(IpAddr),
    Host(String),
    Cidr { network: Ipv4Addr, prefix: u8 },
    Range { start: Ipv4Addr, end: Ipv4Addr },
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum TargetError {
    #[error("target is empty")]
    Empty,
    #[error("'{0}' is not a valid IP address")]
    InvalidIp(String),
    #[error("'{0}' is not a valid prefix length (0-32)")]
    InvalidPrefix(String),
    #[error("'{0}' is not a valid range (example: 192.168.1.10-50)")]
    InvalidRange(String),
    #[error("'{0}' is not a valid hostname")]
    InvalidHostname(String),
    #[error("target expands to {0} addresses (limit is 65536)")]
    TooLarge(u64),
    #[error("could not resolve '{host}': {reason}")]
    Resolve { host: String, reason: String },
    #[error("no address found for '{0}'")]
    NoAddress(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Host(name) => write!(f, "{name}"),
            Target::Cidr { network, prefix } => write!(f, "{network}/{prefix}"),
            Target::Range { start, end } => write!(f, "{start}-{end}"),
        }
    }
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(TargetError::Empty);
        }

        if let Some((ip_part, prefix_part)) = input.split_once('/') {
            return parse_cidr(ip_part, prefix_part);
        }

        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Target::Ip(ip));
        }

        if let Some(result) = parse_range(input) {
            return result;
        }

        if input.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Err(TargetError::InvalidIp(input.to_string()));
        }

        if is_valid_hostname(input) {
            Ok(Target::Host(input.to_ascii_lowercase()))
        } else {
            Err(TargetError::InvalidHostname(input.to_string()))
        }
    }
}

impl Target {
    pub fn addresses(&self) -> Result<Vec<IpAddr>, TargetError> {
        match self {
            Target::Ip(ip) => Ok(vec![*ip]),
            Target::Host(name) => resolve_host(name),
            Target::Cidr { network, prefix } => Ok(cidr_hosts(*network, *prefix)),
            Target::Range { start, end } => Ok((u32::from(*start)..=u32::from(*end))
                .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
                .collect()),
        }
    }
}

fn check_size(count: u64) -> Result<(), TargetError> {
    if count > MAX_TARGETS {
        Err(TargetError::TooLarge(count))
    } else {
        Ok(())
    }
}

fn parse_cidr(ip_part: &str, prefix_part: &str) -> Result<Target, TargetError> {
    let network: Ipv4Addr = ip_part
        .parse()
        .map_err(|_| TargetError::InvalidIp(ip_part.to_string()))?;

    let prefix = prefix_part
        .parse::<u8>()
        .ok()
        .filter(|p| *p <= 32)
        .ok_or_else(|| TargetError::InvalidPrefix(prefix_part.to_string()))?;

    check_size(1u64 << (32 - u32::from(prefix)))?;
    Ok(Target::Cidr { network, prefix })
}

fn parse_range(input: &str) -> Option<Result<Target, TargetError>> {
    let (left, right) = input.rsplit_once('-')?;
    let start: Ipv4Addr = left.parse().ok()?;
    Some(build_range(input, start, right))
}

fn build_range(input: &str, start: Ipv4Addr, right: &str) -> Result<Target, TargetError> {
    let bad_range = || TargetError::InvalidRange(input.to_string());

    let end = match right.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            let last: u8 = right.parse().map_err(|_| bad_range())?;
            let [a, b, c, _] = start.octets();
            Ipv4Addr::new(a, b, c, last)
        }
    };

    if u32::from(end) < u32::from(start) {
        return Err(bad_range());
    }

    let count = u64::from(u32::from(end)) - u64::from(u32::from(start)) + 1;
    check_size(count)?;
    Ok(Target::Range { start, end })
}

fn is_valid_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn resolve_host(name: &str) -> Result<Vec<IpAddr>, TargetError> {
    let mut ips: Vec<IpAddr> = (name, 0)
        .to_socket_addrs()
        .map_err(|e| TargetError::Resolve {
            host: name.to_string(),
            reason: e.to_string(),
        })?
        .map(|addr| addr.ip())
        .collect();

    ips.dedup();

    if ips.is_empty() {
        Err(TargetError::NoAddress(name.to_string()))
    } else {
        Ok(ips)
    }
}

fn cidr_hosts(network: Ipv4Addr, prefix: u8) -> Vec<IpAddr> {
    let host_bits = 32 - u32::from(prefix);
    let mask = u32::MAX << host_bits;
    let base = u32::from(network) & mask;
    let size = 1u32 << host_bits;

    let (first, last) = if prefix >= 31 {
        (0, size - 1)
    } else {
        (1, size - 2)
    };

    (first..=last)
        .map(|offset| IpAddr::V4(Ipv4Addr::from(base + offset)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(input: &str) -> Vec<String> {
        input
            .parse::<Target>()
            .unwrap()
            .addresses()
            .unwrap()
            .iter()
            .map(|ip| ip.to_string())
            .collect()
    }

    #[test]
    fn single_ip_v4_and_v6() {
        assert_eq!(addrs("192.168.1.10"), ["192.168.1.10"]);
        assert_eq!(addrs("::1"), ["::1"]);
    }

    #[test]
    fn cidr_24_has_254_hosts() {
        let hosts = addrs("192.168.1.0/24");
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.1.1");
        assert_eq!(hosts[253], "192.168.1.254");
    }

    #[test]
    fn cidr_30_31_32() {
        assert_eq!(addrs("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"]);
        assert_eq!(addrs("192.168.1.0/31"), ["192.168.1.0", "192.168.1.1"]);
        assert_eq!(addrs("192.168.1.5/32"), ["192.168.1.5"]);
    }

    #[test]
    fn cidr_masks_host_bits() {
        assert_eq!(addrs("192.168.1.77/30"), ["192.168.1.77", "192.168.1.78"]);
    }

    #[test]
    fn ranges() {
        assert_eq!(
            addrs("192.168.1.10-12"),
            ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        );
        assert_eq!(
            addrs("192.168.1.10-192.168.1.11"),
            ["192.168.1.10", "192.168.1.11"]
        );
    }

    #[test]
    fn hyphenated_hostname_is_not_a_range() {
        assert_eq!(
            "web-1.example.com".parse::<Target>(),
            Ok(Target::Host("web-1.example.com".to_string()))
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!("  ".parse::<Target>(), Err(TargetError::Empty));
        assert!(matches!(
            "1270.0.1".parse::<Target>(),
            Err(TargetError::InvalidIp(_))
        ));
        assert!(matches!(
            "10.0.0.0/33".parse::<Target>(),
            Err(TargetError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "10.0.0.9-3".parse::<Target>(),
            Err(TargetError::InvalidRange(_))
        ));
        assert!(matches!(
            "10.0.0.0/8".parse::<Target>(),
            Err(TargetError::TooLarge(_))
        ));
        assert!(matches!(
            "bad host".parse::<Target>(),
            Err(TargetError::InvalidHostname(_))
        ));
    }
}
