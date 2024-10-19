use bendy::encoding::{Error, SingleItemEncoder, ToBencode};
use bendy::decoding::FromBencode;
use std::net::SocketAddrV4;
use byteorder::{
    NetworkEndian,
    WriteBytesExt,
};
use rand::Rng;
use core::fmt;

use log::warn;

#[derive(PartialEq, Clone, Eq, Hash)]
pub struct ByteArray(pub Vec<u8>);

impl ByteArray {
    pub fn new(bytes: Vec<u8>) -> Self {
        ByteArray(bytes)
    }

    pub fn generate(length: usize) -> ByteArray {
        let mut rng = rand::thread_rng();
        let mut id_bytes = vec![0u8; length];
        rng.fill(&mut id_bytes[..]);

        ByteArray(id_bytes)
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
        ByteArray(hex::decode(hex_str).unwrap())
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

pub type Version = ByteArray;

pub type TransactionId = ByteArray;

pub type Token = ByteArray;

pub type CompactIp = ByteArray;

#[derive(PartialEq, Eq, Hash)]
pub struct CompactAddress {
    pub addr: SocketAddrV4,
}
impl CompactAddress {

    pub fn new_from_sockaddr(addr: std::net::SocketAddr) -> Self {
        let addr = match addr {
            std::net::SocketAddr::V4(addr_v4) => addr_v4,
            std::net::SocketAddr::V6(_) => panic!("Expected SocketAddrV4, found SocketAddrV6"),
        };
        CompactAddress { addr }
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        let addr = SocketAddrV4::new(
            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            <NetworkEndian as byteorder::ByteOrder>::read_u16(&bytes[4..]),
        );

        CompactAddress { addr }
    }

    /// Encode with the "Compact IP-address/port info" format
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut raw = [0u8; 6];
        
        let ip = self.addr.ip();
        let port = self.addr.port();

        raw[..4].clone_from_slice(&ip.octets());
        (&mut raw[4..])
            .write_u16::<NetworkEndian>(port)
            .expect("Failed to encode port.");

        raw
    }
}
impl Clone for CompactAddress {
    fn clone(&self) -> Self {
        CompactAddress { addr: self.addr.clone() }
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
        Ok(CompactAddress::new(bytes.to_vec()))
    }
}
impl fmt::Display for CompactAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for CompactAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.addr)
    }
}

#[derive(Debug, PartialEq)]
pub struct CompactNodeList(pub Vec<CompactNode>);
impl CompactNodeList {
    pub fn new_from_vec(nodes: Vec<CompactNode>) -> Self {
        CompactNodeList(nodes)
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
impl FromBencode for CompactNodeList {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut nodes = Vec::new();

        let bytes = object.try_into_bytes()?;
        let mut bytes = bytes.to_vec();

        if bytes.len() < 26 {
            return Err(bendy::decoding::Error::unexpected_field("CompactNodeList is empty/too short."));
        }

        loop {
            let node_bytes = bytes.drain(0..20).collect();
            let addr_bytes = bytes.drain(0..6).collect();

            let id = NodeId::new(node_bytes);
            let addr = CompactAddress::new(addr_bytes);

            nodes.push(CompactNode { id, addr });

            if bytes.is_empty() || bytes.len() < 26 {

                if bytes.len() > 0 {
                    warn!("CompactNodeList too short");
                }
                
                break;
            }
        }

        Ok(CompactNodeList(nodes))
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

    pub fn find_node(node_id: NodeId, target: NodeId, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryFindNodeRequest {
                id: node_id,
                target: target,
            },
            transaction_id: transaction_id,
            message_type: "q".to_string(),
            query: Some("find_node".to_string()),
            ip: None,
            version: None,
        }
    }

    pub fn find_node_response(node_id: NodeId, nodes: CompactNodeList, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryFindNodeResponse {
                id: node_id,
                nodes: nodes,
            },
            transaction_id: transaction_id,
            message_type: "r".to_string(),
            query: None,
            ip: None,
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
    pub fn announce_peer_response(node_id: NodeId, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryIdResponse {
                id: node_id,
                port: None,
                ip: None,
            },
            transaction_id: transaction_id,
            message_type: "r".to_string(),
            query: None,
            ip: None,
            version: None,
        }
    }

    pub fn get_peers(node_id: NodeId, info_hash: InfoHash, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryGetPeersRequest {
                id: node_id,
                info_hash: info_hash,
            },
            transaction_id: transaction_id.clone(),
            message_type: "q".to_string(),
            query: Some("get_peers".to_string()),
            ip: None,
            version: None,
        }
    }

    pub fn get_peers_response(node_id: NodeId, token: Token, nodes: CompactNodeList, transaction_id: TransactionId, values: Option<Vec<CompactAddress>>) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryGetPeersResponse {
                id: node_id,
                token: token,
                nodes: Some(nodes),
                values: values,
            },
            transaction_id: transaction_id.clone(),
            message_type: "r".to_string(),
            query: None,
            ip: None,
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

    pub fn id_response(node_id: NodeId, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryIdResponse {
                id: node_id,
                port: None,
                ip: None,
            },
            transaction_id: transaction_id.clone(),
            message_type: "r".to_string(),
            query: None,
            ip: None,
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
                KRPCPayload::KRPCQueryPingRequest { id: _ } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryIdResponse { id: _, port: _, ip: _} => {
                    e.emit_pair(b"r", &self.payload)?;
                },
                KRPCPayload::KRPCError(error) => {
                    e.emit_pair(b"e", error)?;
                },
                KRPCPayload::KRPCQueryGetPeersRequest { id: _, info_hash: _ } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryGetPeersResponse { id: _, token: _, nodes: _ , values: _ } => {
                    e.emit_pair(b"r", &self.payload)?;
                },
                KRPCPayload::KRPCQueryAnnouncePeerRequest { id: _, info_hash: _, token: _, port: _, implied_port: _, seed: _ } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryFindNodeRequest { id: _, target: _ } => {
                    e.emit_pair(b"q", self.query.clone().unwrap())?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryFindNodeResponse { id: _, nodes: _ } => {
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
                   
                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok();
                            },
                            (b"info_hash", value) => {
                                info_hash = InfoHash::decode_bencode_object(value).ok();
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
                                target = NodeId::decode_bencode_object(value).ok();
                            },
                            //TODO add more potential request fields here
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)] 
                    if id.is_some() && info_hash.is_some() && token.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryAnnouncePeerRequest { id: id.unwrap(), info_hash: info_hash.unwrap(), token: token.unwrap(), port: port.unwrap(), implied_port, seed});
                    } else if id.is_some() && target.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryFindNodeRequest { id: id.unwrap(), target: target.unwrap() });
                    } else if info_hash.is_some() && id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryGetPeersRequest { id: id.unwrap(), info_hash: info_hash.unwrap() });
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
                    let mut values = None;
                    let mut ip = None;

                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok();
                            },
                            (b"p", value) => {
                                port = u32::decode_bencode_object(value).ok();
                            },
                            (b"token", value) => {
                                token = Token::decode_bencode_object(value).ok();
                            },
                            (b"nodes", value) => {
                                nodes = CompactNodeList::decode_bencode_object(value).ok();
                            },
                            (b"values", value) => {
                                values = Vec::<CompactAddress>::decode_bencode_object(value).unwrap().into();
                            }
                            (b"ip", value) => {
                                ip = CompactIp::decode_bencode_object(value).unwrap().into();
                            }
                            //TODO add more potential response fields here
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)]
                    if id.is_some() && token.is_some() && (nodes.is_some() || values.is_some()) {
                        payload = Some(KRPCPayload::KRPCQueryGetPeersResponse { id: id.unwrap(), token: token.unwrap(), nodes: nodes, values: values });
                    } else if id.is_some() && nodes.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryFindNodeResponse { id: id.unwrap(), nodes: nodes.unwrap() });
                    } else if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryIdResponse { id: id.unwrap(), port, ip });
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
                (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
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
        port: Option<u32>, //Appears to be the port that they received the request on
        ip: Option<CompactIp>,//Sometimes the IP shows up here
    },

    KRPCQueryGetPeersRequest {
        id: NodeId,
        info_hash: InfoHash,
    },
    KRPCQueryGetPeersResponse {
        id: NodeId,
        token: ByteArray,
        nodes: Option<CompactNodeList>,
        values: Option<Vec<CompactAddress>>, //Why this is a list and nodes isn't is a mystery.
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
    },
    KRPCQueryFindNodeResponse {
        id: NodeId,
        nodes: CompactNodeList,
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
            KRPCPayload::KRPCQueryIdResponse { id, port, ip } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;

                    if let Some(port) = port {
                        e.emit_pair(b"port", port)?;
                    }

                    if let Some(ip) = ip {
                        e.emit_pair(b"ip", ip)?;
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
            KRPCPayload::KRPCQueryGetPeersRequest { id, info_hash } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"info_hash", info_hash)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes, values } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"token", token)?;
                    if nodes.is_some() {
                        e.emit_pair(b"nodes", nodes.clone().unwrap())?;
                    }
                    
                    if values.is_some() {
                        e.emit_pair(b"values", values.clone().unwrap())?;
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
            KRPCPayload::KRPCQueryFindNodeRequest { id, target } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"target", target)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryFindNodeResponse { id, nodes } => {
                encoder.emit_unsorted_dict(|e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"nodes", nodes)?;

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
        let get_peers = KRPCMessage::get_peers(NodeId::generate_nodeid(), InfoHash::generate(20), TransactionId::generate(4));

        let vecs = get_peers.to_bencode().unwrap();

        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(get_peers, decoded);
    }

    #[test]
    fn test_query_ping_response() {
        let ping_reponse = KRPCMessage::id_response(NodeId::generate_nodeid(), TransactionId::generate(4));

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
        let addr = CompactAddress {
            addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080),
        };

        let vecs = addr.to_bencode().unwrap();
        let decoded = CompactAddress::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(addr, decoded);
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
}