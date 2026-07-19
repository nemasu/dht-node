use bendy::encoding::{Error, SingleItemEncoder, ToBencode};
use bendy::decoding::FromBencode;
use std::net::{SocketAddrV4, SocketAddrV6};
use byteorder::{
    NetworkEndian,
    WriteBytesExt,
};
use rand::RngExt;
use core::fmt;

use log::{trace, warn};

#[derive(PartialEq, Clone, Eq, Hash)]
pub struct ByteArray(pub Vec<u8>);

impl ByteArray {
    pub fn new(bytes: Vec<u8>) -> Self {
        ByteArray(bytes)
    }

    pub fn generate(length: usize) -> ByteArray {
        let mut rng = rand::rng();
        let mut id_bytes = vec![0u8; length];
        rng.fill(&mut id_bytes[..]);

        ByteArray(id_bytes)
    }

    pub fn generate_range(min: ByteArray, max: ByteArray) -> ByteArray {
        let mut rng = rand::rng();

        let mut difference = ByteArray::subtract(&max, &min);
        for byte in &mut difference.0 {
            *byte = rng.random_range(0..=*byte);
        }

        let ret = ByteArray::add(&min, &difference);

        assert!(ret >= min);
        assert!(ret <= max);
        ret
    }

    pub fn generate_nodeid() -> ByteArray {
        ByteArray::generate(20)
    }

    pub fn new_from_i32(num: i32) -> Self {
        ByteArray(num.to_be_bytes().to_vec())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn from_hex(hex_str: &str) -> Self {
        //Remove spaces from hex_str
        let hex_str = hex_str.replace(" ", "");

        ByteArray(hex::decode(hex_str).unwrap())
    }

    /// Callers should only ever pass same-length (NodeId/InfoHash-shaped) inputs, but this
    /// still can't panic if one doesn't - a value that reached here from the wire without
    /// going through the NODE_ID_LEN check in KRPCMessage::decode_bencode_object (or a
    /// future caller that forgets to) shouldn't be able to crash the whole process over a
    /// malformed packet. Missing bytes on the shorter side XOR against 0, which just makes
    /// a malformed value's computed "distance" meaningless rather than a valid comparison -
    /// fine, since a mismatched-length input was already invalid data with no correct
    /// answer to give.
    pub fn xor_bytearray(a: &ByteArray, b: &ByteArray) -> ByteArray {
        let len = a.0.len().max(b.0.len());
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            result.push(a.0.get(i).copied().unwrap_or(0) ^ b.0.get(i).copied().unwrap_or(0));
        }
        ByteArray::new(result)
    }

    pub fn divide_by_2(a: &ByteArray) -> (ByteArray, Option<u8>) {
        let mut result = Vec::with_capacity(a.0.len());
        let mut carry = 0;
        let mut remainder = None;
    
        for &byte in &a.0 {
            let new_byte = (byte >> 1) | (carry << 7);
            carry = byte & 1;
            result.push(new_byte);
        }
    
        // If there is a carry left, it means there is a remainder
        if carry != 0 {
            remainder = Some(carry);
        }
    
        (ByteArray::new(result), remainder)
    }

    /// Fixed-width (mod 2^(8*len)) increment: the result is always exactly `a.0.len()`
    /// bytes, wrapping around on overflow rather than growing - callers rely on
    /// NodeId/InfoHash-shaped values always staying the same length (bucket ranges,
    /// PartialOrd, etc. all assume a fixed width).
    pub fn add_one(a: &ByteArray) -> ByteArray {
        let mut result = Vec::with_capacity(a.0.len());
        let mut carry = 1;

        for &byte in a.0.iter().rev() {
            let (new_byte, new_carry) = byte.overflowing_add(carry);
            carry = if new_carry { 1 } else { 0 };
            result.push(new_byte);
        }
        // Any carry out of the most significant byte wraps around rather than growing
        // the array, matching normal fixed-width unsigned overflow.

        result.reverse();
        ByteArray::new(result)
    }

    /// Fixed-width (mod 2^(8*max(a.len(), b.len()))) addition - see `add_one` for why the
    /// result must never grow beyond the operands' length.
    pub fn add(a: &ByteArray, b: &ByteArray) -> ByteArray {
        let max_len = std::cmp::max(a.0.len(), b.0.len());
        let mut result = Vec::with_capacity(max_len);
        let mut carry = 0;

        for i in 0..max_len {
            let byte_a = a.0.get(a.0.len().wrapping_sub(1).wrapping_sub(i)).copied().unwrap_or(0);
            let byte_b = b.0.get(b.0.len().wrapping_sub(1).wrapping_sub(i)).copied().unwrap_or(0);

            let (new_byte, carry1) = byte_a.overflowing_add(byte_b);
            let (new_byte, carry2) = new_byte.overflowing_add(carry);
            carry = (carry1 as u8) + (carry2 as u8);

            result.push(new_byte);
        }
        // Any carry out of the most significant byte wraps around rather than growing
        // the array, matching normal fixed-width unsigned overflow.

        result.reverse();
        ByteArray::new(result)
    }

    /// Fixed-width (mod 2^(8*max(a.len(), b.len()))) subtraction - the result keeps
    /// leading zero bytes rather than trimming them, so it's always the same length as
    /// the operands (see `add_one` for why that matters).
    pub fn subtract(a: &ByteArray, b: &ByteArray) -> ByteArray {
        let max_len = std::cmp::max(a.0.len(), b.0.len());
        let mut result = Vec::with_capacity(max_len);
        let mut borrow = 0;

        for i in 0..max_len {
            let byte_a = a.0.get(a.0.len().wrapping_sub(1).wrapping_sub(i)).copied().unwrap_or(0);
            let byte_b = b.0.get(b.0.len().wrapping_sub(1).wrapping_sub(i)).copied().unwrap_or(0);

            let (byte_b_plus_borrow, add_overflowed) = byte_b.overflowing_add(borrow);
            let (new_byte, sub_overflowed) = byte_a.overflowing_sub(byte_b_plus_borrow);
            borrow = if add_overflowed || sub_overflowed { 1 } else { 0 };

            result.push(new_byte);
        }

        result.reverse();
        ByteArray::new(result)
    }
}
impl PartialOrd for ByteArray {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        //First check the number of bytes, larger is greater
        if self.0.len() > other.0.len() {
            return Some(std::cmp::Ordering::Greater);
        } else if self.0.len() < other.0.len() {
            return Some(std::cmp::Ordering::Less);
        }
        
        //Ordering is done by comparing the bytes in the array, this is in big-endian order.
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            if a > b {
                return Some(std::cmp::Ordering::Greater);
            } else if a < b {
                return Some(std::cmp::Ordering::Less);
            }
        }

        Some(std::cmp::Ordering::Equal)
    }
}
impl Ord for ByteArray {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl ToBencode for ByteArray {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_bytes(&self.0)
    }
}
impl FromBencode for ByteArray {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        Ok(ByteArray(bytes.to_vec()))
    }
}
impl fmt::Display for ByteArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for ByteArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0).to_ascii_uppercase())
    }
}

pub type NodeId = ByteArray;

pub type InfoHash = ByteArray;

/// Both NodeId and InfoHash are always 160-bit (SHA-1-sized) quantities per BEP5 - used to
/// reject malformed `id`/`target`/`info_hash` fields from the wire at decode time (see
/// KRPCMessage::decode_bencode_object), rather than letting a wrong-length value survive
/// into XOR-distance code that assumes a fixed width.
const NODE_ID_LEN: usize = 20;

pub type Version = ByteArray;

pub type TransactionId = ByteArray;

pub type Token = ByteArray;

pub type CompactIp = ByteArray;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum CompactAddress {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}
impl CompactAddress {

    pub fn new_from_sockaddr(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(addr_v4) => CompactAddress::V4(addr_v4),
            std::net::SocketAddr::V6(addr_v6) => CompactAddress::V6(addr_v6),
        }
    }

    /// Decode from the "Compact IP-address/port info" format. The address
    /// family is determined by length: 6 bytes (4-byte IP + 2-byte port)
    /// for IPv4, 18 bytes (16-byte IP + 2-byte port) for IPv6.
    pub fn new(bytes: Vec<u8>) -> Self {
        match bytes.len() {
            6 => {
                let addr = SocketAddrV4::new(
                    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                    <NetworkEndian as byteorder::ByteOrder>::read_u16(&bytes[4..6]),
                );
                CompactAddress::V4(addr)
            }
            18 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[0..16]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = <NetworkEndian as byteorder::ByteOrder>::read_u16(&bytes[16..18]);

                //An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is really an IPv4 address
                //smuggled into a 16-byte field; treat it as V4 so it's routed to (and
                //sent over) the IPv4 stack instead of a v6-only socket, which will
                //refuse to send to it.
                match ip.to_ipv4_mapped() {
                    Some(ipv4) => CompactAddress::V4(SocketAddrV4::new(ipv4, port)),
                    None => CompactAddress::V6(SocketAddrV6::new(ip, port, 0, 0)),
                }
            }
            n => panic!("CompactAddress: unexpected byte length {} (expected 6 or 18)", n),
        }
    }

    pub fn socket_addr(&self) -> std::net::SocketAddr {
        match self {
            CompactAddress::V4(addr) => std::net::SocketAddr::V4(*addr),
            CompactAddress::V6(addr) => std::net::SocketAddr::V6(*addr),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            CompactAddress::V4(addr) => addr.port(),
            CompactAddress::V6(addr) => addr.port(),
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, CompactAddress::V4(_))
    }

    #[allow(dead_code)]
    pub fn is_v6(&self) -> bool {
        matches!(self, CompactAddress::V6(_))
    }

    /// True if this is the "unspecified" placeholder address (all-zero IP and/or port
    /// 0) - never a legitimate remote peer contact, but nothing validates compact node/
    /// peer entries decoded from the wire, so malformed or malicious data can produce
    /// one. Sending to it fails with EINVAL, so callers should skip it rather than
    /// store/use it and find out on the next send attempt.
    pub fn is_unspecified(&self) -> bool {
        match self {
            CompactAddress::V4(addr) => addr.ip().is_unspecified() || addr.port() == 0,
            CompactAddress::V6(addr) => addr.ip().is_unspecified() || addr.port() == 0,
        }
    }

    /// Encode with the "Compact IP-address/port info" format
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            CompactAddress::V4(addr) => {
                let mut raw = vec![0u8; 6];
                raw[..4].clone_from_slice(&addr.ip().octets());
                (&mut raw[4..6])
                    .write_u16::<NetworkEndian>(addr.port())
                    .expect("Failed to encode port.");
                raw
            }
            CompactAddress::V6(addr) => {
                let mut raw = vec![0u8; 18];
                raw[..16].clone_from_slice(&addr.ip().octets());
                (&mut raw[16..18])
                    .write_u16::<NetworkEndian>(addr.port())
                    .expect("Failed to encode port.");
                raw
            }
        }
    }
}
impl ToBencode for CompactAddress {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_bytes(&self.to_bytes())
    }
}
impl FromBencode for CompactAddress {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        match bytes.len() {
            6 | 18 => Ok(CompactAddress::new(bytes.to_vec())),
            n => Err(bendy::decoding::Error::unexpected_field(format!("CompactAddress: unexpected byte length {} (expected 6 or 18)", n))),
        }
    }
}
impl fmt::Display for CompactAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for CompactAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompactAddress::V4(addr) => write!(f, "{:?}", addr),
            CompactAddress::V6(addr) => write!(f, "{:?}", addr),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct CompactNodeList(pub Vec<CompactNode>);
impl CompactNodeList {
    pub fn new_from_vec(nodes: Vec<CompactNode>) -> Self {
        CompactNodeList(nodes)
    }

    /// Decode a "nodes" field: a blob of concatenated 26-byte entries
    /// (20-byte node id + 6-byte compact IPv4 address/port).
    pub fn decode_v4(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        Self::decode_with_addr_len(object, 6)
    }

    /// Decode a "nodes6" field: a blob of concatenated 38-byte entries
    /// (20-byte node id + 18-byte compact IPv6 address/port).
    pub fn decode_v6(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        Self::decode_with_addr_len(object, 18)
    }

    fn decode_with_addr_len(object: bendy::decoding::Object, addr_len: usize) -> Result<Self, bendy::decoding::Error> {
        let mut nodes = Vec::new();

        let bytes = object.try_into_bytes()?;
        let mut bytes = bytes.to_vec();

        let entry_len = 20 + addr_len;

        if bytes.len() < entry_len {
            return Err(bendy::decoding::Error::unexpected_field("CompactNodeList is empty/too short."));
        }

        loop {
            let node_bytes = bytes.drain(0..20).collect();
            let addr_bytes = bytes.drain(0..addr_len).collect();

            let id = NodeId::new(node_bytes);
            let addr = CompactAddress::new(addr_bytes);

            nodes.push(CompactNode { id, addr });

            if bytes.is_empty() || bytes.len() < entry_len {

                if bytes.len() > 0 {
                    warn!("CompactNodeList too short");
                }

                break;
            }
        }

        Ok(CompactNodeList(nodes))
    }
}
impl ToBencode for CompactNodeList {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {

        let mut output = Vec::new();
        for node in &self.0 {
            output.extend_from_slice(&node.to_bytes());
        }

        encoder.emit_bytes(&output)
    }
}
impl Clone for CompactNodeList {
    fn clone(&self) -> Self {
            let mut nodes = Vec::new();
            for node in &self.0 {
                nodes.push((*node).clone());
            }
    
            CompactNodeList(nodes)
        }
}

#[derive(Debug, PartialEq)]
pub struct CompactNode {
    pub id: NodeId,
    pub addr: CompactAddress,
}
impl CompactNode {
    pub fn new(id: NodeId, addr: CompactAddress) -> Self {
        CompactNode { id, addr }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.id.0.clone();
        bytes.extend_from_slice(&self.addr.to_bytes());

        bytes
    }
}
impl Clone for CompactNode {
    fn clone(&self) -> Self {
        CompactNode { id: self.id.clone(), addr: self.addr.clone() }
    }
}
impl ToBencode for CompactNode {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_list(|e| {
            e.emit_bytes(&self.id.0)?;
            e.emit_bytes(&self.addr.to_bytes())?;

            Ok(())
        })
    }
}
impl FromBencode for CompactNode {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut bytes = object.try_into_bytes().unwrap().to_vec();

        if bytes.len() < 20 {
            return Err(bendy::decoding::Error::unexpected_field("CompactNode is too short/empty."));
        }

        let addr_bytes = bytes.split_off(20).to_vec();

        let id = NodeId::new(bytes);
        let addr = CompactAddress::new(addr_bytes);
      
        Ok(CompactNode { id, addr })
    }
}

#[derive(PartialEq)]
pub struct KRPCError(pub u8, pub String);
impl ToBencode for KRPCError {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_list(|e| {
            e.emit_int(self.0)?;
            e.emit_str(&self.1)?;

            Ok(())
        })
    }
}
impl FromBencode for KRPCError {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut list = object.try_into_list()?;

        let error_code = list.next_object()?.ok_or(bendy::decoding::Error::missing_field("error_code"))?;
        let error_code = u8::decode_bencode_object(error_code)?;

        let message = list.next_object()?.ok_or(bendy::decoding::Error::missing_field("error_code"))?;
        let message = String::decode_bencode_object(message)?;

        Ok(KRPCError(error_code, message))
    }
}
impl fmt::Display for KRPCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for KRPCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ code: {}, message: {} }}", self.0, self.1)
    }
}


#[derive(Debug, PartialEq)]
pub struct KRPCMessage {
    pub payload: KRPCPayload, //contents of 'a' or 'r' or 'e'
    pub transaction_id: TransactionId,
    pub message_type: String, //'r' or 'q' for 'y'
    pub query: Option<String>, //The query type, 'ping', 'find_node', 'get_peers', 'announce_peer'

    pub ip: Option<CompactAddress>, //Optional IP of the sender. For ping response, this is the IP and port of the sender.
    pub version: Option<Version>, //Optional version string
}

impl KRPCMessage {

    pub fn error(error_code: u8, message: String, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCError(KRPCError(error_code, message)),
            transaction_id: transaction_id,
            message_type: "e".to_string(),
            query: None,
            ip: None,
            version: None,
        }
    }

    pub fn find_node(node_id: NodeId, target: NodeId, want: Option<Vec<String>>, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryFindNodeRequest {
                id: node_id,
                target: target,
                want: want,
            },
            transaction_id: transaction_id,
            message_type: "q".to_string(),
            query: Some("find_node".to_string()),
            ip: None,
            version: None,
        }
    }

    pub fn find_node_response(node_id: NodeId, nodes: Option<CompactNodeList>, nodes6: Option<CompactNodeList>, transaction_id: TransactionId, target_addr: CompactAddress) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryFindNodeResponse {
                id: node_id,
                nodes: nodes,
                nodes6: nodes6,
                p: Some(target_addr.port() as u32),
            },
            transaction_id: transaction_id,
            message_type: "r".to_string(),
            query: None,
            ip: Some(target_addr),
            version: None,
        }
    }

    #[allow(dead_code)]
    pub fn announce_peer(node_id: NodeId, info_hash: InfoHash, token: Token, port: u32, transaction_id: TransactionId) -> Self{
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryAnnouncePeerRequest {
                id: node_id,
                info_hash: info_hash,
                token: token,
                port: port,
                implied_port: None,
                seed: None,
            },
            transaction_id: transaction_id,
            message_type: "q".to_string(),
            query: Some("announce_peer".to_string()),
            ip: None,
            version: None,
        }
    }

    #[allow(dead_code)]
    pub fn announce_peer_response(node_id: NodeId, transaction_id: TransactionId, target_addr: CompactAddress) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryIdResponse {
                id: node_id,
                p: Some(target_addr.port() as u32),
            },
            transaction_id: transaction_id,
            message_type: "r".to_string(),
            query: None,
            ip: Some(target_addr),
            version: None,
        }
    }

    pub fn get_peers(node_id: NodeId, info_hash: InfoHash, want: Option<Vec<String>>, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryGetPeersRequest {
                id: node_id,
                info_hash: info_hash,
                want: want,
            },
            transaction_id: transaction_id.clone(),
            message_type: "q".to_string(),
            query: Some("get_peers".to_string()),
            ip: None,
            version: None,
        }
    }

    pub fn get_peers_response(node_id: NodeId, token: Token, nodes: Option<CompactNodeList>, nodes6: Option<CompactNodeList>, values: Option<Vec<CompactAddress>>, values6: Option<Vec<CompactAddress>>, transaction_id: TransactionId, target_addr: CompactAddress) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryGetPeersResponse {
                id: node_id,
                token: token,
                nodes: nodes,
                nodes6: nodes6,
                values: values,
                values6: values6,
                p: Some(target_addr.port() as u32),
            },
            transaction_id: transaction_id.clone(),
            message_type: "r".to_string(),
            query: None,
            ip: Some(target_addr),
            version: None,
        }
    }

    pub fn ping(node_id: NodeId, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryPingRequest {
                id: node_id,
            },
            transaction_id: transaction_id.clone(),
            message_type: "q".to_string(),
            query: Some("ping".to_string()),
            ip: None,
            version: None,
        }
    }

    pub fn id_response(node_id: NodeId, transaction_id: TransactionId, target_addr: CompactAddress) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryIdResponse {
                id: node_id,
                p: Some(target_addr.port() as u32),
            },
            transaction_id: transaction_id.clone(),
            message_type: "r".to_string(),
            query: None,
            ip: Some(target_addr),
            version: None,
        }
    }
}

impl ToBencode for KRPCMessage {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_unsorted_dict(|e| {
            e.emit_pair(b"t", &self.transaction_id)?;
            e.emit_pair(b"y", &self.message_type)?;

            match &self.payload {
                KRPCPayload::KRPCQueryPingRequest { .. } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryIdResponse { .. } => {
                    e.emit_pair(b"r", &self.payload)?;
                },
                KRPCPayload::KRPCError(error) => {
                    e.emit_pair(b"e", error)?;
                },
                KRPCPayload::KRPCQueryGetPeersRequest { .. } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryGetPeersResponse { .. } => {
                    e.emit_pair(b"r", &self.payload)?;
                },
                KRPCPayload::KRPCQueryAnnouncePeerRequest { .. } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryFindNodeRequest { .. } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryFindNodeResponse { .. } => {
                    e.emit_pair(b"r", &self.payload)?;
                },
            }

            if let Some(ip) = &self.ip {
                e.emit_pair(b"ip", ip)?;
            }

            if let Some(version) = &self.version {
                e.emit_pair(b"v", version)?;
            }

            Ok(())
        })

    }
}
impl FromBencode for KRPCMessage {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut dict = object.try_into_dictionary()?;

        let mut transaction_id = None;
        let mut message_type = None;
        let mut version = None;
        let mut payload = None;
        let mut ip = None;
        let mut query = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"t", value) => {
                    transaction_id = Some(TransactionId::decode_bencode_object(value)?);
                },
                (b"y", value) => {
                    message_type = Some(String::decode_bencode_object(value)?);
                },
                (b"q", value) => {
                    query = Some(String::decode_bencode_object(value)?);
                },
                (b"a", value) => {
                    let mut dict = value.try_into_dictionary()?;

                    let mut id = None;
                    let mut info_hash = None;

                    let mut token = None;
                    let mut port = None;
                    let mut implied_port = None;
                    let mut seed = None;

                    let mut target = None;
                    let mut want = None;

                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok().filter(|v: &NodeId| v.0.len() == NODE_ID_LEN);
                            },
                            (b"info_hash", value) => {
                                info_hash = InfoHash::decode_bencode_object(value).ok().filter(|v: &InfoHash| v.0.len() == NODE_ID_LEN);
                            },
                            (b"token", value) => {
                                token = Token::decode_bencode_object(value).ok();
                            },
                            (b"port", value) => {
                                port = u32::decode_bencode_object(value).ok();
                            },
                            (b"implied_port", value) => {
                                implied_port = u32::decode_bencode_object(value).ok();
                            },
                            (b"seed", value) => {
                                seed = u32::decode_bencode_object(value).ok();
                            },
                            (b"target", value) => {
                                target = NodeId::decode_bencode_object(value).ok().filter(|v: &NodeId| v.0.len() == NODE_ID_LEN);
                            },
                            (b"want", value) => {
                                want = Vec::<String>::decode_bencode_object(value).ok();
                            },
                            //Unknown/extension fields (e.g. "noseed") are ignored rather than
                            //failing the whole message, matching real-world client behavior.
                            (key, _) => {
                                trace!("Ignoring unrecognized query argument: {:?}", String::from_utf8_lossy(key));
                            },
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)]
                    if id.is_some() && info_hash.is_some() && token.is_some() && port.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryAnnouncePeerRequest { id: id.unwrap(), info_hash: info_hash.unwrap(), token: token.unwrap(), port: port.unwrap(), implied_port, seed});
                    } else if id.is_some() && target.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryFindNodeRequest { id: id.unwrap(), target: target.unwrap(), want });
                    } else if info_hash.is_some() && id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryGetPeersRequest { id: id.unwrap(), info_hash: info_hash.unwrap(), want });
                    } else if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryPingRequest { id: id.unwrap() });
                    }

                },
                (b"r", value) => {  
                    let mut dict = value.try_into_dictionary()?;

                    let mut id = None;
                    let mut port = None;
                    let mut token = None;
                    let mut nodes = None;
                    let mut nodes6 = None;
                    let mut values = None;
                    let mut values6 = None;

                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok().filter(|v: &NodeId| v.0.len() == NODE_ID_LEN);
                            },
                            (b"p", value) => {
                                port = u32::decode_bencode_object(value).ok();
                            },
                            (b"token", value) => {
                                token = Token::decode_bencode_object(value).ok();
                            },
                            (b"nodes", value) => {
                                nodes = CompactNodeList::decode_v4(value).ok();
                            },
                            (b"nodes6", value) => {
                                nodes6 = CompactNodeList::decode_v6(value).ok();
                            },
                            (b"values", value) => {
                                values = Vec::<CompactAddress>::decode_bencode_object(value).ok();
                            }
                            (b"values6", value) => {
                                values6 = Vec::<CompactAddress>::decode_bencode_object(value).ok();
                            }
                            (b"ip", value) => {
                                if let Some(ip) = CompactIp::decode_bencode_object(value).ok() {
                                    if matches!(ip.0.len(), 6 | 18) {
                                        trace!("Received IP in response: {:?}", CompactAddress::new(ip.0));
                                    }
                                }
                            }
                            //Unknown/extension fields are ignored rather than failing the whole message.
                            (key, _) => {
                                trace!("Ignoring unrecognized response field: {:?}", String::from_utf8_lossy(key));
                            },
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)]
                    if id.is_some() && token.is_some() && (nodes.is_some() || nodes6.is_some() || values.is_some() || values6.is_some()) {
                        payload = Some(KRPCPayload::KRPCQueryGetPeersResponse { id: id.unwrap(), token: token.unwrap(), nodes, nodes6, values, values6, p: port });
                    } else if id.is_some() && (nodes.is_some() || nodes6.is_some()) {
                        payload = Some(KRPCPayload::KRPCQueryFindNodeResponse { id: id.unwrap(), nodes, nodes6, p: port });
                    } else if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryIdResponse { id: id.unwrap(), p: port });
                    }
                },
                (b"e", value) => {
                    let error = KRPCError::decode_bencode_object(value)?;
                    payload = Some(KRPCPayload::KRPCError(error));
                },
                (b"ip", value) => {
                    ip = Some(CompactAddress::decode_bencode_object(value)?);
                },
                (b"v", value) => {
                    version = Version::decode_bencode_object(value).ok();
                },
                //Unknown/extension top-level fields are ignored rather than failing the whole message.
                (key, _) => {
                    trace!("Ignoring unrecognized top-level field: {:?}", String::from_utf8_lossy(key));
                },
            }
        }

        if payload.is_some() && transaction_id.is_some() && message_type.is_some() {
            Ok(KRPCMessage{ payload: payload.unwrap(), transaction_id: transaction_id.unwrap(), message_type: message_type.unwrap(), ip, version, query })
        } else {
            Err(bendy::decoding::Error::missing_field("payload, transaction_id, or message_type"))
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KRPCPayload {
    KRPCQueryPingRequest{
        id: NodeId,

    },
    //Used for ping and announce_peer responses
    KRPCQueryIdResponse {
        id: NodeId,
        p: Option<u32>,}, //The port of the requestor

    KRPCQueryGetPeersRequest {
        id: NodeId,
        info_hash: InfoHash,
        want: Option<Vec<String>>, //BEP32: ["n4"], ["n6"], or both
    },
    KRPCQueryGetPeersResponse {
        id: NodeId,
        token: ByteArray,
        nodes: Option<CompactNodeList>,
        nodes6: Option<CompactNodeList>,
        values: Option<Vec<CompactAddress>>, //Why this is a list and nodes isn't is a mystery.
        values6: Option<Vec<CompactAddress>>,
        p: Option<u32>, //The port of the requestor
    },

    KRPCQueryAnnouncePeerRequest {
        id: NodeId,
        info_hash: InfoHash,
        token: Token,
        port: u32,
        implied_port: Option<u32>,
        seed: Option<u32>, //Not sure what this is yet
    },

    KRPCQueryFindNodeRequest {
        id: NodeId,
        target: NodeId,
        want: Option<Vec<String>>, //BEP32: ["n4"], ["n6"], or both
    },
    KRPCQueryFindNodeResponse {
        id: NodeId,
        nodes: Option<CompactNodeList>,
        nodes6: Option<CompactNodeList>,
        p: Option<u32>, //The port of the requestor
    },

    KRPCError(KRPCError),
}
impl ToBencode for KRPCPayload {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        match self {
            KRPCPayload::KRPCQueryPingRequest { id } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryIdResponse { id, p } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;

                    if let Some(p) = p {
                        e.emit_pair(b"p", p)?;
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCError(error) => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"e", error)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryGetPeersRequest { id, info_hash, want } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"info_hash", info_hash)?;

                    if let Some(want) = want {
                        if !want.is_empty() {
                            e.emit_pair(b"want", want)?;
                        }
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes, nodes6, values, values6, p } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"token", token)?;
                    if let Some(nodes) = nodes {
                        e.emit_pair(b"nodes", nodes.clone())?;
                    }

                    if let Some(nodes6) = nodes6 {
                        e.emit_pair(b"nodes6", nodes6.clone())?;
                    }

                    if let Some(values) = values {
                        e.emit_pair(b"values", values.clone())?;
                    }

                    if let Some(values6) = values6 {
                        e.emit_pair(b"values6", values6.clone())?;
                    }

                    if let Some(p) = p {
                        e.emit_pair(b"p", p)?;
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryAnnouncePeerRequest { id, info_hash, token, port, implied_port, seed } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"info_hash", info_hash)?;
                    e.emit_pair(b"token", token)?;
                    e.emit_pair(b"port", port)?;

                    if let Some(implied_port) = implied_port {
                        e.emit_pair(b"implied_port", implied_port)?;
                    }

                    if let Some(seed) = seed {
                        e.emit_pair(b"seed", seed)?;
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryFindNodeRequest { id, target, want } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"target", target)?;

                    if let Some(want) = want {
                        if !want.is_empty() {
                            e.emit_pair(b"want", want)?;
                        }
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryFindNodeResponse { id, nodes, nodes6, p } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;

                    if let Some(nodes) = nodes {
                        e.emit_pair(b"nodes", nodes)?;
                    }

                    if let Some(nodes6) = nodes6 {
                        e.emit_pair(b"nodes6", nodes6)?;
                    }

                    if let Some(p) = p {
                        e.emit_pair(b"p", p)?;
                    }

                    Ok(())
                })
            },
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_real_find_node() {
        let hex_str = "64313a6164323a696432303a38383838383838384964cd1f98f78de3c8a4fd51363a74617267657432303ad1b6caac6bfe42fc9592a6299d2f7986d4cfc50f65313a71393a66696e645f6e6f6465313a74343a666e0000313a76343a34423f77313a79313a7165";
        let vecs = hex::decode(hex_str).unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();
        println!("{:?}", decoded);
    }

    #[test]
    fn test_find_node_with_wrong_length_target_is_not_a_valid_query() {
        // A real find_node query, but with a 19-byte (not 20-byte) target - regression
        // test for a remotely-triggerable panic: this used to decode into a
        // KRPCQueryFindNodeRequest with a malformed target anyway, which later panicked
        // ("index out of bounds") the first time something computed an XOR distance
        // against it (e.g. the multiplexing demux's identity-guessing, or a get_peers/
        // find_node response). It must instead fail to decode as that query variant at
        // all - see the NODE_ID_LEN filters in decode_bencode_object.
        let id20 = "A".repeat(NODE_ID_LEN);
        let target19 = "A".repeat(NODE_ID_LEN - 1);
        let bencoded = format!("d1:ad2:id20:{}6:target19:{}e1:q9:find_node1:t2:aa1:y1:qe", id20, target19);
        let decoded = KRPCMessage::from_bencode(bencoded.as_bytes()).unwrap();
        assert!(
            !matches!(decoded.payload, KRPCPayload::KRPCQueryFindNodeRequest { .. }),
            "a malformed-length target must not produce a valid FindNodeRequest: {:?}",
            decoded.payload
        );
    }

    #[test]
    fn test_xor_bytearray_does_not_panic_on_mismatched_lengths() {
        let a = NodeId::new(vec![0xFF; NODE_ID_LEN]);
        let b = NodeId::new(vec![0xFF; NODE_ID_LEN - 1]);
        let result = ByteArray::xor_bytearray(&a, &b);
        assert_eq!(result.0.len(), NODE_ID_LEN);
    }

    #[test]
    fn test_real_get_peers_with_values() {
        let hex_str = "64313a7264323a696432303a505e3263273333913f5236c25cb1f7a2246d22d3353a746f6b656e323a6778363a76616c7565736c363ac39ab5e1d6cf6565313a74343a00000181313a79313a7265";
        let vecs = hex::decode(hex_str).unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();
        println!("{:?}", decoded);
    }

    #[test]
    fn test_real_announce_peer() {
        let hex_str = "64313a6164323a696432303a56b00038266cf21f555466609a850476f4d0888a31323a696d706c6965645f706f7274693165393a696e666f5f6861736832303a3f9aac158c7de8dfcab171ea58a17aabdf7fbc93343a706f727469333636393065343a73656564693065353a746f6b656e343a00e583a565313a7131333a616e6e6f756e63655f70656572313a74323a1c71313a76343a4c540206313a79313a7165";
        let vecs = hex::decode(hex_str).unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();
        println!("{:?}", decoded);
    }

    #[test]
    fn test_real_get_peers_request() {
        let hex_str = "64313a6164323a696432303ac47faf4d6c854dcf87b17883efb5b83a9f2dd6db393a696e666f5f6861736832303ace61e24e1a2f51ffbe2ab4e6ff0e878783f7b92c65313a71393a6765745f7065657273313a74323a14c5313a76343a4c540206313a79313a7165";
        let vecs = hex::decode(hex_str).unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();
        println!("{:?}", decoded);
    }

    #[test]
    fn test_real_get_peers_response() {
        let hex_str = "64323a6970363adc92d6358f52313a7264323a696432303ad29bfc9a4f94d7fa1c19e7efb3e9b413767f6ced353a6e6f6465733230383acf1cfa870c3e99245e0d1c06b747deb3124dc8db0e22b2dd47e1cc218502e27bf1fa12e219b3977eff0ca93c33362e14c21a0bd1ca29113f2d6ff91d56eecafb0f0ae0bc00ddb9036671f1850017cbef229ba302a9dc81c68801098e585fc9fa46682e965cf14d44c968f32c7fbec2c4be8c79e0c8fda6cb8712f034dc50f7e9bfc4c65ba78380c0f7fb4ac8553c1ac87e401e2fed97bca34ae322ecc6fd7949f1f1bbe9ebb3a6db3c870c3e99245e52d5a096ec7c73c6d341ad58014202f3b492c0695f51490a43fcfeb06fb2edf4b3313a7069333636393065353a746f6b656e343a1afdd9de65313a74323a14c5313a76343a4c54012f313a79313a7265";
        let vecs = hex::decode(hex_str).unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();
        println!("{:?}", decoded);
    }

    #[test]
    fn test_query_get_peers() {
        let get_peers = KRPCMessage::get_peers(NodeId::generate_nodeid(), InfoHash::generate(20), None, TransactionId::generate(4));

        let vecs = get_peers.to_bencode().unwrap();

        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(get_peers, decoded);
    }

    #[test]
    fn test_query_ping_response() {
        let ping_reponse = KRPCMessage::id_response(NodeId::generate_nodeid(), TransactionId::generate(4), CompactAddress::new_from_sockaddr(std::net::SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080))));

        let vecs = ping_reponse.to_bencode().unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(ping_reponse, decoded);
    }

    #[test]
    fn test_query_ping() {
        let ping = KRPCMessage::ping(NodeId::generate_nodeid(), TransactionId::new_from_i32(1));

        let vecs = ping.to_bencode().unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(ping, decoded);
    }

    #[test]
    fn test_ping_payload() {
        let payload = KRPCPayload::KRPCQueryPingRequest {
            id: NodeId::generate_nodeid(),
        };

        let _ = payload.to_bencode().unwrap();

        //There's no FromBencode for Requests because the context of the parent object is required.
    }

    #[test]
    fn test_address() {
        let addr = CompactAddress::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080));

        let vecs = addr.to_bencode().unwrap();
        let decoded = CompactAddress::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_v6() {
        let addr = CompactAddress::V6(SocketAddrV6::new(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 6881, 0, 0));

        let vecs = addr.to_bencode().unwrap();
        assert_eq!(vecs.len(), 18 + 3); //bencode byte-string prefix + 18 raw bytes

        let decoded = CompactAddress::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(addr, decoded);
        assert!(decoded.is_v6());
    }

    #[test]
    fn test_compact_address_family_autodetect() {
        let v4 = CompactAddress::new(vec![127, 0, 0, 1, 0x1a, 0xe1]);
        assert!(v4.is_v4());
        assert_eq!(v4.port(), 0x1ae1);

        let v6_bytes = {
            let mut b = vec![0u8; 18];
            b[15] = 1; //::1
            b[16] = 0x1a;
            b[17] = 0xe1;
            b
        };
        let v6 = CompactAddress::new(v6_bytes);
        assert!(v6.is_v6());
        assert_eq!(v6.port(), 0x1ae1);
    }

    #[test]
    fn test_compact_address_is_unspecified() {
        // All-zero (IP and port) - the classic malformed/empty compact address.
        assert!(CompactAddress::new(vec![0, 0, 0, 0, 0, 0]).is_unspecified());
        // Zero port alone is enough to make send_to() fail with EINVAL, regardless of IP.
        assert!(CompactAddress::new(vec![127, 0, 0, 1, 0, 0]).is_unspecified());
        // Zero IP alone, non-zero port - still not a real peer address.
        assert!(CompactAddress::new(vec![0, 0, 0, 0, 0x1a, 0xe1]).is_unspecified());
        // A real-looking address should not be flagged.
        assert!(!CompactAddress::new(vec![127, 0, 0, 1, 0x1a, 0xe1]).is_unspecified());

        let v6_zero = {
            let mut b = vec![0u8; 18];
            b[16] = 0x1a;
            b[17] = 0xe1;
            b
        };
        assert!(CompactAddress::new(v6_zero).is_unspecified());

        let v6_real = {
            let mut b = vec![0u8; 18];
            b[15] = 1; //::1
            b[16] = 0x1a;
            b[17] = 0xe1;
            b
        };
        assert!(!CompactAddress::new(v6_real).is_unspecified());
    }

    #[test]
    fn test_compact_address_v4_mapped_normalized_to_v4() {
        //An IPv4-mapped IPv6 address (::ffff:a.b.c.d) arriving in an 18-byte "nodes6"/
        //"values6" entry must be treated as V4: sending to it over a v6-only socket
        //fails with "Network unreachable".
        let mapped_bytes = {
            let mut b = vec![0u8; 18];
            b[10] = 0xff;
            b[11] = 0xff;
            b[12] = 178;
            b[13] = 162;
            b[14] = 174;
            b[15] = 225;
            b[16] = 0x1a;
            b[17] = 0xe1;
            b
        };

        let addr = CompactAddress::new(mapped_bytes);
        assert!(addr.is_v4());
        assert_eq!(addr.port(), 0x1ae1);
        assert_eq!(addr.socket_addr(), std::net::SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(178, 162, 174, 225), 0x1ae1)));
    }

    #[test]
    fn test_query_find_node_want() {
        let find_node = KRPCMessage::find_node(NodeId::generate_nodeid(), NodeId::generate_nodeid(), Some(vec!["n4".to_string(), "n6".to_string()]), TransactionId::generate(4));

        let vecs = find_node.to_bencode().unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(find_node, decoded);

        if let KRPCPayload::KRPCQueryFindNodeRequest { want, .. } = decoded.payload {
            assert_eq!(want, Some(vec!["n4".to_string(), "n6".to_string()]));
        } else {
            panic!("Expected KRPCQueryFindNodeRequest");
        }
    }

    #[test]
    fn test_get_peers_response_nodes6_values6() {
        let node_id = NodeId::generate_nodeid();
        let addr_v6 = CompactAddress::V6(SocketAddrV6::new(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), 6881, 0, 0));

        let nodes6 = CompactNodeList::new_from_vec(vec![CompactNode::new(NodeId::generate_nodeid(), addr_v6.clone())]);
        let values6 = vec![addr_v6.clone()];

        let response = KRPCMessage::get_peers_response(
            node_id,
            Token::generate(4),
            None,
            Some(nodes6),
            None,
            Some(values6.clone()),
            TransactionId::generate(4),
            addr_v6,
        );

        let vecs = response.to_bencode().unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(response, decoded);

        if let KRPCPayload::KRPCQueryGetPeersResponse { nodes, nodes6, values, values6: decoded_values6, .. } = decoded.payload {
            assert!(nodes.is_none());
            assert!(nodes6.is_some());
            assert!(values.is_none());
            assert_eq!(decoded_values6, Some(values6));
        } else {
            panic!("Expected KRPCQueryGetPeersResponse");
        }
    }

    #[test]
    fn test_error() {
        let error = KRPCError(201, "Generic Error".to_string());
        let vecs = error.to_bencode().unwrap();
        let decoded = KRPCError::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(error, decoded);
    }

    #[test]
    fn test_node_id() {
        let node_id = NodeId::generate_nodeid();
        let vecs = node_id.to_bencode().unwrap();
        let decoded = NodeId::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(node_id, decoded);
    }

    #[test]
    fn test_bytearray_random_range() {
        let a = ByteArray::generate(20);
        let b = ByteArray::generate(20);

        if a > b {
            println!("{:?} > {:?}", b, a);
            let r = ByteArray::generate_range(b, a);
            println!("{:?}", r);
        } else {
            println!("{:?} > {:?}", a, b);
            let r = ByteArray::generate_range(a, b);
            println!("{:?}", r);
        }
    }

    #[test]
    fn test_bytearray_ordering() {
        let a = ByteArray::new(vec![0x57, 0x9c, 0xbf, 0xd0, 0xcd, 0x1b, 0x56, 0x5d]);
        let b = ByteArray::new(vec![0x7C, 0xD5, 0x63, 0x21, 0xED, 0x45, 0x87, 0xCD]);
        let c = ByteArray::new(vec![0x7C, 0xD5, 0x63, 0x21, 0xED, 0x45, 0x87, 0xCA]);

        let mut set = std::collections::BTreeSet::new();
        set.insert(a.clone());
        set.insert(b.clone());
        set.insert(c.clone());

        //Check that they are in the correct order: a, c, b
        let mut iter = set.iter();
        assert_eq!(iter.next().unwrap(), &a);
        assert_eq!(iter.next().unwrap(), &c);
        assert_eq!(iter.next().unwrap(), &b);
    }

    #[test]
    fn test_bytearray_divide() {
        let a = ByteArray::new_from_i32(10000);
        let (b, remainder) = ByteArray::divide_by_2(&a);
        assert_eq!(b, ByteArray::new_from_i32(5000));
        assert_eq!(remainder.unwrap_or(0), 0);


        let a = ByteArray::from_hex("57 9c bf d0 cd 1b 56 ff ff");
        let (b, remainder) = ByteArray::divide_by_2(&a);
        assert_eq!(b, ByteArray::from_hex("2B CE 5F E8 66 8D AB 7F FF"));
        assert_eq!(remainder.unwrap_or(0), 1);
    }

    #[test]
    fn test_bytearray_subtract_borrow_chain_does_not_overflow() {
        //Regression test: subtracting a byte of 0xFF at a position where the incoming
        //borrow is already 1 used to panic with "attempt to add with overflow" (0xFF + 1
        //overflows u8) instead of correctly propagating the borrow.
        let a = ByteArray::from_hex("01 FF 00");
        let b = ByteArray::from_hex("00 FF 01");
        let result = ByteArray::subtract(&a, &b);
        //Leading zero bytes are kept, not trimmed - the result must stay the same length
        //as the operands (see test_bytearray_arithmetic_preserves_length for why).
        assert_eq!(result, ByteArray::from_hex("00 FF FF"));
    }

    #[test]
    fn test_bytearray_add_one() {
        let a = ByteArray::new_from_i32(10000);
        let b = ByteArray::add_one(&a);
        assert_eq!(b, ByteArray::new_from_i32(10001));

        let a = ByteArray::from_hex("57 9c bf d0 cd 1b 56 ff ff");
        let b = ByteArray::add_one(&a);
        assert_eq!(b, ByteArray::from_hex("57 9c bf d0 cd 1b 57 00 00"));
    }

    #[test]
    fn test_bytearray_arithmetic_preserves_length() {
        //Regression test: add/add_one/subtract used to grow the result on overflow (add,
        //add_one) or trim leading zero bytes (subtract), producing a ByteArray with a
        //different length than its 20-byte NodeId inputs. Since PartialOrd for ByteArray
        //compares length before value (proto.rs), a stray length change silently breaks
        //numeric ordering - which is exactly what corrupted DHT bucket splitting
        //(bucket.rs) under real load: a computed bucket boundary ended up 21 bytes instead
        //of 20, comparing as "greater than" values it was numerically smaller than.
        let max = ByteArray::from_hex("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
        let one = ByteArray::add_one(&max);
        assert_eq!(one.0.len(), 20, "add_one must not grow on overflow");
        assert_eq!(one, ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"));

        let sum = ByteArray::add(&max, &ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"));
        assert_eq!(sum.0.len(), 20, "add must not grow on overflow");
        assert_eq!(sum, ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"));

        let min = ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01");
        let diff = ByteArray::subtract(&min, &ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"));
        assert_eq!(diff.0.len(), 20, "subtract must not trim leading zero bytes");
        assert_eq!(diff, ByteArray::from_hex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"));
    }
}