use bendy::encoding::{Error, SingleItemEncoder, ToBencode, UnsortedDictEncoder};
use bendy::decoding::FromBencode;
use std::net::SocketAddrV4;
use byteorder::{
    NetworkEndian,
    WriteBytesExt,
};
use rand::Rng;
use core::fmt;

#[derive(PartialEq)]
pub struct NodeId {
    pub id: Vec<u8>,
}
impl NodeId {
    pub fn generate() -> NodeId {
        let mut rng = rand::thread_rng();
        let mut id_bytes = vec![0u8; 20];
        rng.fill(&mut id_bytes[..]);

        NodeId { id: id_bytes }
    }
}
impl ToBencode for NodeId {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_bytes(&self.id)
    }
}
impl FromBencode for NodeId {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        Ok(NodeId { id: bytes.to_vec() })
    }
}
impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.id).to_ascii_uppercase())
    }
}

//Info hashes are also just a byte array.
pub type InfoHash = NodeId;

//Version string is just a byte array.
pub type Version = NodeId;

//Transaction ID is also just a byte array.
type TransactionId = NodeId;

#[derive(Debug, PartialEq)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addr: Option<Address>,
}

#[derive(PartialEq)]
pub struct Address {
    pub addr: SocketAddrV4,
}
impl Address {
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
impl ToBencode for Address {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_bytes(&self.to_bytes())
    }
}
impl FromBencode for Address {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let bytes = object.try_into_bytes()?;
        let ip = SocketAddrV4::new(
            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            <NetworkEndian as byteorder::ByteOrder>::read_u16(&bytes[4..]),
        );

        Ok(Address { addr: ip })
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.addr)
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

    pub ip: Option<Address>, //Optional IP of the sender
    pub version: Option<Version>, //Optional version string
}
impl ToBencode for KRPCMessage {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_unsorted_dict(|e| {
            e.emit_pair(b"t", &self.transaction_id)?;
            e.emit_pair(b"y", &self.message_type)?;

            match &self.payload {
                KRPCPayload::KRPCQueryPingRequest { id } => {
                    e.emit_pair(b"q", "ping")?;
                    e.emit_pair(b"a", &self.payload)?;
                },
                KRPCPayload::KRPCQueryPingResponse { id, port } => {
                    e.emit_pair(b"r", &id)?;

                    if let Some(port) = port {
                        e.emit_pair(b"port", port)?;
                    }
                },
                KRPCPayload::KRPCError(error) => {
                    e.emit_pair(b"e", error)?;
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

        let mut q = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"t", value) => {
                    println!("t");
                    transaction_id = Some(TransactionId::decode_bencode_object(value)?);
                },
                (b"y", value) => {
                    println!("y");
                    message_type = Some(String::decode_bencode_object(value)?);
                },
                (b"q", value) => {
                    println!("q");
                    q = Some(String::decode_bencode_object(value)?);
                },
                (b"a", value) => {
                    println!("a");
                    let mut dict = value.try_into_dictionary()?;

                    //TODO check for other possible fields in 'a'
                    let mut id = None;
                   
                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok();
                            },
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryPingRequest { id: id.unwrap() });
                    }
                    
                },
                (b"r", value) => {
                    println!("r");

                    let mut dict = value.try_into_dictionary()?;

                    //TODO check for other possible fields in 'r'
                    let mut id = None;
                    let mut port: Option<u32> = None;

                    while let Some(pair) = dict.next_pair()? {
                        match pair {
                            (b"id", value) => {
                                id = NodeId::decode_bencode_object(value).ok();
                            },
                            (b"p", value) => {
                                port = u32::decode_bencode_object(value).ok();
                            },
                            (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
                        }
                    }

                    if id.is_some() {
                        payload = Some(KRPCPayload::KRPCQueryPingResponse { id: id.unwrap(), port: port });
                    }
                },
                (b"e", value) => {
                    println!("e");
                    let error = KRPCError::decode_bencode_object(value)?;
                    payload = Some(KRPCPayload::KRPCError(error));
                },
                (b"ip", value) => {
                    println!("ip");
                    ip = Some(Address::decode_bencode_object(value)?);
                },
                (b"v", value) => {
                    println!("v");
                    version = Version::decode_bencode_object(value).ok();
                },
                (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
            }
        }

        Ok((KRPCMessage{ payload: payload.unwrap(), transaction_id: transaction_id.unwrap(), message_type: message_type.unwrap(), ip, version }))
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
            transaction_id: TransactionId { id: b"1234".to_vec() },
            message_type: "q".to_string(),
    
            ip: Some(Address { addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080) } ),
            
            version: Some( Version { id: b"NN40".to_vec() } ),
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
        let addr = Address {
            addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080),
        };

        let vecs = addr.to_bencode().unwrap();
        let decoded = Address::from_bencode(&vecs).unwrap();

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