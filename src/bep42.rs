//! BEP 42 node IDs and conservative external-address voting.
//! https://www.bittorrent.org/beps/bep_0042.html
use crate::proto::{NodeId, Version};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Defaults to learning each family's public IP from correlated DHT replies.
/// Explicit addresses pin that family and disable automatic discovery for it.
#[derive(Clone, Debug)]
pub struct Bep42Config {
    pub enabled: bool,
    pub public_ipv4: Option<Ipv4Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
}
impl Default for Bep42Config {
    fn default() -> Self {
        Self {
            enabled: true,
            public_ipv4: None,
            public_ipv6: None,
        }
    }
}
impl Bep42Config {
    pub(crate) fn pinned(&self, v4: bool) -> Option<IpAddr> {
        if v4 {
            self.public_ipv4.map(IpAddr::V4)
        } else {
            self.public_ipv6.map(IpAddr::V6)
        }
    }
}

// CRC-32C / Castagnoli, reflected polynomial, standard initial/final complement.
// At most eight input bytes: a table or hardware dependency is unnecessary here.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn prefix(ip: IpAddr, random: u8) -> [u8; 4] {
    let crc = match canonical(ip) {
        IpAddr::V4(ip) => {
            let masked = (u32::from(ip) & 0x030f3fff) | (u32::from(random & 7) << 29);
            crc32c(&masked.to_be_bytes())
        }
        IpAddr::V6(ip) => {
            let upper = u64::from_be_bytes(ip.octets()[..8].try_into().unwrap());
            let masked = (upper & 0x0103070f1f3f7fff) | (u64::from(random & 7) << 61);
            crc32c(&masked.to_be_bytes())
        }
    };
    crc.to_be_bytes()
}

/// Adjust a 20-byte ID's constrained prefix, preserving its random suffix.
/// Returns false for malformed IDs without modifying them.
pub fn secure_id(id: &mut NodeId, ip: IpAddr) -> bool {
    if id.0.len() != 20 {
        return false;
    }
    let p = prefix(ip, id.0[19]);
    id.0[0] = p[0];
    id.0[1] = p[1];
    id.0[2] = (p[2] & 0xf8) | (id.0[2] & 7);
    true
}

/// Generate a random ID valid for this external IPv4 or IPv6 address.
pub fn generate_id(ip: IpAddr) -> NodeId {
    let mut id = NodeId::generate_nodeid();
    secure_id(&mut id, ip);
    id
}

/// Strict prefix check, including for private addresses. Does not apply exemptions.
pub fn matches_ip(id: &NodeId, ip: IpAddr) -> bool {
    if id.0.len() != 20 {
        return false;
    }
    let p = prefix(ip, id.0[19]);
    id.0[0] == p[0] && id.0[1] == p[1] && id.0[2] & 0xf8 == p[2] & 0xf8
}

/// Validation for remote nodes, including local-address exemptions.
/// This is not an authentication or trust check.
pub fn is_valid(id: &NodeId, ip: IpAddr) -> bool {
    if id.0.len() != 20 {
        return false;
    }
    is_local(ip) || matches_ip(id, ip)
}

fn is_local(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

/// Log suffix describing a remote node's BEP 42 status: empty when compliant, otherwise
/// " (...)" noting the exemption or, for noncompliant nodes, their KRPC "v" client/version.
pub fn compliance_note(id: &NodeId, ip: IpAddr, version: Option<&Version>) -> String {
    if matches_ip(id, ip) {
        String::new()
    } else if id.0.len() == 20 && is_local(ip) {
        " (BEP 42 exempt, local address)".to_string()
    } else {
        format!(" (not BEP 42 compliant, client {})", client(version))
    }
}

/// Conventionally a two-character client code followed by version bytes, e.g. "LT" 0x0102.
fn client(version: Option<&Version>) -> String {
    match version.map(|v| v.0.as_slice()) {
        None => "unknown".to_string(),
        Some([a, b, rest @ ..]) if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() => {
            format!("{}{} 0x{}", *a as char, *b as char, hex::encode_upper(rest))
        }
        Some(bytes) => format!("0x{}", hex::encode_upper(bytes)),
    }
}

/// Conservative filter for public-address reports, not a complete IANA registry.
pub(crate) fn public_address(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            !ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
                && !ip.is_documentation() && ip.octets()[0] != 0 && ip.octets()[0] < 224
                && n & 0xffc00000 != 0x64400000 // shared address space
                && n & 0xfffe0000 != 0xc6120000 // benchmarking
        }
        IpAddr::V6(ip) => {
            ip.segments()[0] & 0xe000 == 0x2000
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}

const VOTE_TTL: Duration = Duration::from_secs(300);
const MAX_VOTERS: usize = 256;
const MIN_VOTES: usize = 3;

/// One vote per /24 (IPv4) or /48 (IPv6), shared by all identities on a socket.
/// Reports must already have passed transaction and source-address validation.
#[derive(Default)]
pub(crate) struct AddressVotes {
    pub current: Option<IpAddr>,
    votes: HashMap<IpAddr, (IpAddr, Instant)>,
}
impl AddressVotes {
    /// Record a report; returns true if it changed the agreed address.
    pub fn observe(&mut self, reporter: IpAddr, reported: IpAddr, now: Instant) -> bool {
        let (reporter, reported) = (canonical(reporter), canonical(reported));
        if reporter.is_ipv4() != reported.is_ipv4()
            || !public_address(reporter)
            || !public_address(reported)
        {
            return false;
        }
        self.votes
            .retain(|_, (_, at)| now.duration_since(*at) < VOTE_TTL);
        let group = match reporter {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & 0xffffff00)),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (!0u128 << 80))),
        };
        if !self.votes.contains_key(&group) && self.votes.len() >= MAX_VOTERS {
            return false;
        }
        self.votes.insert(group, (reported, now));
        let count = self
            .votes
            .values()
            .filter(|(ip, _)| *ip == reported)
            .count();
        if count >= MIN_VOTES && count * 2 > self.votes.len() && self.current != Some(reported) {
            self.current = Some(reported);
            return true;
        }
        false
    }
}

#[derive(Default)]
pub(crate) struct ExternalAddresses {
    pub v4: AddressVotes,
    pub v6: AddressVotes,
}
impl ExternalAddresses {
    pub fn family(&mut self, v4: bool) -> &mut AddressVotes {
        if v4 { &mut self.v4 } else { &mut self.v6 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        for (ip, id) in [
            ("124.31.75.21", "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
            ("21.75.31.124", "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"),
            ("65.23.51.170", "a5d43220bc8f112a3d426c84764f8c2a1150e616"),
            ("84.124.73.14", "1b0321dd1bb1fe518101ceef99462b947a01ff41"),
            ("43.213.53.83", "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"),
        ] {
            let ip = ip.parse().unwrap();
            let expected = NodeId::from_hex(id);
            assert!(matches_ip(&expected, ip));
            let mut generated = expected.clone();
            generated.0[0] ^= 0xff;
            assert!(!matches_ip(&generated, ip));
            assert!(secure_id(&mut generated, ip));
            assert_eq!(generated, expected);
        }
    }
    #[test]
    fn ipv6_and_masked_bits() {
        let ip: IpAddr = "2001:4860:1234:5678::1".parse().unwrap();
        let id = generate_id(ip);
        assert!(matches_ip(
            &id,
            "2001:4860:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
        assert!(!matches_ip(&id, "2001:4860:1234:5679::1".parse().unwrap()));
        let mut changed = id.clone();
        changed.0[2] ^= 7;
        changed.0[10] ^= 255;
        changed.0[19] ^= 0xf8;
        assert!(matches_ip(&changed, ip));
        changed.0[19] ^= 1;
        assert!(!matches_ip(&changed, ip));
        assert!(!secure_id(&mut NodeId::new(vec![]), ip));
        assert!(!is_valid(
            &NodeId::new(vec![]),
            "127.0.0.1".parse().unwrap()
        ));
        assert!(is_valid(
            &NodeId::new(vec![0; 20]),
            "192.168.1.1".parse().unwrap()
        ));
        assert!(is_valid(
            &NodeId::new(vec![0; 20]),
            "fd00::1".parse().unwrap()
        ));
        let v4 = generate_id("8.8.8.8".parse().unwrap());
        assert!(matches_ip(&v4, "::ffff:8.8.8.8".parse().unwrap()));
        let lt = Version::new(b"LT\x01\x02".to_vec());
        assert_eq!(compliance_note(&v4, "8.8.8.8".parse().unwrap(), Some(&lt)), "");
        assert_eq!(compliance_note(&v4, "8.8.4.4".parse().unwrap(), Some(&lt)), " (not BEP 42 compliant, client LT 0x0102)");
        assert_eq!(compliance_note(&v4, "8.8.4.4".parse().unwrap(), None), " (not BEP 42 compliant, client unknown)");
        assert_eq!(compliance_note(&v4, "8.8.4.4".parse().unwrap(), Some(&Version::new(vec![0, 1]))), " (not BEP 42 compliant, client 0x0001)");
        assert_eq!(compliance_note(&v4, "192.168.1.1".parse().unwrap(), None), " (BEP 42 exempt, local address)");
        assert_eq!(compliance_note(&NodeId::new(vec![]), "192.168.1.1".parse().unwrap(), None), " (not BEP 42 compliant, client unknown)");
    }
    #[test]
    fn votes_require_independent_recent_majority() {
        let mut votes = AddressVotes::default();
        let now = Instant::now();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        for reporter in ["8.8.8.1", "8.8.8.2", "8.8.8.3", "127.0.0.1"] {
            votes.observe(reporter.parse().unwrap(), ip, now);
        }
        assert_eq!(votes.current, None);
        votes.observe("1.1.1.1".parse().unwrap(), ip, now);
        votes.observe("4.2.2.2".parse().unwrap(), ip, now);
        assert_eq!(votes.current, Some(ip));
        let next = "9.9.9.10".parse().unwrap();
        votes.observe("5.5.5.5".parse().unwrap(), next, now);
        assert_eq!(votes.current, Some(ip));
        let later = now + VOTE_TTL;
        for reporter in ["8.8.8.1", "1.1.1.1", "4.2.2.2"] {
            votes.observe(reporter.parse().unwrap(), next, later);
        }
        assert_eq!(votes.current, Some(next));
        votes.observe(
            "6.6.6.6".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            later,
        );
        assert_eq!(votes.current, Some(next));
    }
    #[test]
    fn ipv6_votes_group_by_48_and_do_not_mix_families() {
        let mut votes = AddressVotes::default();
        let now = Instant::now();
        let ip = "2606:4700:4700::1111".parse().unwrap();
        for reporter in [
            "2001:4860:1:1::1",
            "2001:4860:1:2::1",
            "2001:4860:1:3::1",
            "8.8.8.8",
        ] {
            votes.observe(reporter.parse().unwrap(), ip, now);
        }
        assert_eq!(votes.current, None);
        votes.observe("2001:4860:2::1".parse().unwrap(), ip, now);
        votes.observe("2001:4860:3::1".parse().unwrap(), ip, now);
        assert_eq!(votes.current, Some(ip));
    }
    #[test]
    fn v4_mapped_votes_are_canonicalised() {
        let mut votes = AddressVotes::default();
        let now = Instant::now();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        for reporter in ["::ffff:8.8.8.1", "::ffff:1.1.1.1", "4.2.2.2"] {
            votes.observe(reporter.parse().unwrap(), "::ffff:9.9.9.9".parse().unwrap(), now);
        }
        assert_eq!(votes.current, Some(ip));
        // Mapped reporters in distinct /24s are distinct voters, not one /48 group.
        assert_eq!(votes.votes.len(), 3);
    }
}
