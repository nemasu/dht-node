use bendy::encoding::{Error, SingleItemEncoder, ToBencode};
use bendy::decoding::FromBencode;
use std::net::SocketAddrV4;
use byteorder::{
    NetworkEndian,
    WriteBytesExt,
};
use rand::Rng;
use core::fmt;

#[derive(PartialEq, Clone)]
pub struct ByteArray(Vec<u8>);

impl ByteArray {
    pub fn new(bytes: Vec<u8>) -> Self {
        ByteArray(bytes)
    }

    pub fn generate() -> ByteArray {
        let mut rng = rand::thread_rng();
        let mut id_bytes = vec![0u8; 20];
        rng.fill(&mut id_bytes[..]);

        ByteArray(id_bytes)
    }

    pub fn new_from_i32(num: i32) -> Self {
        ByteArray(num.to_be_bytes().to_vec())
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

#[derive(PartialEq)]
pub struct CompactAddress {
    pub addr: SocketAddrV4,
}
impl CompactAddress {

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

        while !bytes.is_empty() {
            let node_bytes = bytes.split_off(26).to_vec();
            let addr_bytes = bytes.split_off(20).to_vec();

            let id = NodeId::new(node_bytes);
            let addr = CompactAddress::new(addr_bytes);

            nodes.push(CompactNode { id, addr });
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

        let id_bytes = bytes.split_off(20).to_vec();

        let id = NodeId::new(id_bytes);
        let addr = CompactAddress::new(bytes);
      
        Ok(CompactNode { id, addr })
    }
}

#[derive(PartialEq)]
pub struct KRPCError(u8, String);
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

    pub ip: Option<CompactAddress>, //Optional IP of the sender
    pub version: Option<Version>, //Optional version string
}

impl KRPCMessage {

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

    pub fn get_peers_response(node_id: NodeId, token: Token, nodes: CompactNodeList, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryGetPeersResponse {
                id: node_id,
                token: token,
                nodes: nodes,
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
    
            ip: Some(CompactAddress { addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080) } ),
            
            version: Some( Version::new(b"NN40".to_vec())),
        }
    }

    pub fn ping_response(node_id: NodeId, transaction_id: TransactionId) -> Self {
        KRPCMessage {
            payload: KRPCPayload::KRPCQueryPingResponse {
                id: node_id,
                port: None,
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
                KRPCPayload::KRPCQueryPingResponse { id: _, port: _ } => {
                    e.emit_pair(b"r", &self.payload)?;
                },
                KRPCPayload::KRPCError(error) => {
                    e.emit_pair(b"e", error)?;
                },
                KRPCPayload::KRPCQueryGetPeersRequest { id, info_hash } => {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"info_hash", info_hash)?;
                },
                KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes } => {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"token", token)?;
                    e.emit_pair(b"nodes", nodes)?;
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
                   
                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok();
                            },
                            (b"info_hash", value) => {
                                info_hash = InfoHash::decode_bencode_object(value).ok();
                            },
                            //TODO add more potential request fields here
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)] 
                    if info_hash.is_some() && id.is_some() {
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
                            //TODO add more potential response fields here
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    //We determine the payload type based off the arguments present.
                    //Other libraries do this too using #[serde(untagged)]
                    if id.is_some() && token.is_some() && nodes.is_some(){
                        payload = Some(KRPCPayload::KRPCQueryGetPeersResponse { id: id.unwrap(), token: token.unwrap(), nodes: nodes.unwrap() });
                    } else if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryPingResponse { id: id.unwrap(), port });
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

        Ok(KRPCMessage{ payload: payload.unwrap(), transaction_id: transaction_id.unwrap(), message_type: message_type.unwrap(), ip, version, query })
    }
}

#[derive(Debug, PartialEq)]
pub enum KRPCPayload {
    KRPCQueryPingRequest{
        id: NodeId,

    },
    KRPCQueryPingResponse {
        id: NodeId,
        port: Option<u32>, //Why is port showing up?
    },

    KRPCQueryGetPeersRequest {
        id: NodeId,
        info_hash: InfoHash,
    },
    KRPCQueryGetPeersResponse {
        id: NodeId,
        token: ByteArray,
        nodes: CompactNodeList,
    },

    KRPCError(KRPCError),
}
impl ToBencode for KRPCPayload {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        match self {
            KRPCPayload::KRPCQueryPingRequest { id } => {
                encoder.emit_dict(|mut e| {
                    e.emit_pair(b"id", id)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryPingResponse { id, port } => {
                encoder.emit_dict(|mut e| {
                    e.emit_pair(b"id", id)?;

                    if let Some(port) = port {
                        e.emit_pair(b"port", port)?;
                    }

                    Ok(())
                })
            },
            KRPCPayload::KRPCError(error) => {
                encoder.emit_dict(|mut e| {
                    e.emit_pair(b"e", error)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryGetPeersRequest { id, info_hash } => {
                encoder.emit_dict(|mut e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"info_hash", info_hash)?;

                    Ok(())
                })
            },
            KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes } => {
                encoder.emit_dict(|mut e| {
                    e.emit_pair(b"id", id)?;
                    e.emit_pair(b"token", token)?;
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
    fn test_query_ping() {
        let ping = KRPCMessage {
            payload: KRPCPayload::KRPCQueryPingRequest {
                id: NodeId::generate(),
            },
            transaction_id: TransactionId::new(b"1234".to_vec()),
            message_type: "q".to_string(),
    
            ip: Some(CompactAddress { addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080) } ),
            
            version: Some( Version::new(b"NN40".to_vec())),
            query: Some("ping".to_string()),
        };

        let vecs = ping.to_bencode().unwrap();
        let decoded = KRPCMessage::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(ping, decoded);
    }

    #[test]
    fn test_ping_payload() {
        let payload = KRPCPayload::KRPCQueryPingRequest {
            id: NodeId::generate(),
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
        let node_id = NodeId::generate();
        let vecs = node_id.to_bencode().unwrap();
        let decoded = NodeId::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(node_id, decoded);
    }
}