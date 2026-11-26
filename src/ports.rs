use std::collections::BTreeSet;
use std::str::FromStr;

use thiserror::Error;

const TOP_100: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427,
    49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900,
    3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

#[derive(Debug, Clone, PartialEq)]
pub struct PortSpec(Vec<u16>);

#[derive(Debug, Clone, PartialEq, Error)]
pub enum PortSpecError {
    #[error("port list is empty or contains an empty entry")]
    Empty,
    #[error("'{0}' is not a valid port (1-65535)")]
    InvalidPort(String),
    #[error("port 0 is nor scannable (use 1-65535)")]
    ZeroPort,
    #[error("range {start}-{end} is backwards (start must not exceed end)")]
    ReversedRange { start: u16, end: u16},
}

impl PortSpec {
    pub fn ports(&self) -> &[u16] {
        &self.0
    }
}

impl FromStr for PortSpec {
    type Err = PortSpecError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input.is_empty() {
            return Err(PortSpecError::Empty);
        }

        let mut set = BTreeSet::new();
        for part in input.split(',') {
            let part = part.trim();
            match part.to_ascii_lowercase().as_str() {
                "top100" => set.extend(TOP_100.iter().copied()),
                "all" => set.extend(1..=65535u16),
                _=> parse_part(part, &mut set)?,
            }
        }

        Ok(PortSpec(set.into_iter().collect()))
    }
}

fn parse_part(part: &str, set: &mut BTreeSet<u16>) -> Result<(), PortSpecError> {
    if part.is_empty() {
        return Err(PortSpecError::Empty);
    }

    match part.split_once('-') {
        Some((left, right)) => {
            let start = parse_port(left)?;
            let end = parse_port(right)?;
            if start > end {
                return Err(PortSpecError::ReversedRange { start, end });
            }
            set.extend(start..=end);
        }
        None => {
            set.insert(parse_port(part)?);
        }
    }
    Ok(())
}

fn parse_port(text: &str) -> Result<u16, PortSpecError> {
    let text = text.trim();
    match text.parse::<u16>() {
        Ok(0) => Err(PortSpecError::ZeroPort),
        Ok(port) => Ok(port),
        Err(_) => Err(PortSpecError::InvalidPort(text.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(input: &str) -> Vec<u16> {
        input.parse::<PortSpec>().unwrap().ports().to_vec()
    }

    #[test]
    fn single_ports_sorted_and_duplicated() {
        assert_eq!(spec("443,80,80"), [80, 443]);
        assert_eq!(spec(" 22, 80 "), [22, 80]);
    }

    #[test]
    fn range_and_mixed() {
        assert_eq!(spec("8000-8003"), [8000, 8001, 8002, 8003]);
        assert_eq!(spec(" 22,80-82"), [22, 80, 81, 82]);
        assert_eq!(spec("80-82,81-83"), [80, 81, 82, 83]);
    }

    #[test]
    fn top100_has_100_unique_ports() {
        assert_eq!(spec("top100").len(), 100);
    }

    #[test]
    fn all_is_every_port() {
        let all = spec("all");
        assert_eq!(all.len(), 65535);
        assert_eq!(all[0], 1);
        assert_eq!(all[65534], 65535);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!("".parse::<PortSpec>(), Err(PortSpecError::Empty));
        assert_eq!("80,,443".parse::<PortSpec>(), Err(PortSpecError::Empty));
        assert_eq!("0".parse::<PortSpec>(), Err(PortSpecError::ZeroPort));
        assert!(matches!(
            "70000".parse::<PortSpec>(),
            Err(PortSpecError::InvalidPort(_))
        ));
        assert!(matches!(
            "abc".parse::<PortSpec>(),
            Err(PortSpecError::InvalidPort(_))
        ));
        assert!(matches!(
            "1-".parse::<PortSpec>(),
            Err(PortSpecError::InvalidPort(_))
        ));
        assert_eq!(
            "90-80".parse::<PortSpec>(),
            Err(PortSpecError::ReversedRange { start: 90, end: 80 })
        );
    }
}