use bendy::encoding::{Error, SingleItemEncoder, ToBencode};
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
    id: Vec<u8>,
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
pub struct DHTError(u8, String);
impl ToBencode for DHTError {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_list(|e| {
            e.emit_int(self.0)?;
            e.emit_str(&self.1)?;

            Ok(())
        })
    }
}
impl FromBencode for DHTError {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut list = object.try_into_list()?;

        let error_code = list.next_object()?.ok_or(bendy::decoding::Error::missing_field("error_code"))?;
        let error_code = u8::decode_bencode_object(error_code)?;

        let message = list.next_object()?.ok_or(bendy::decoding::Error::missing_field("error_code"))?;
        let message = String::decode_bencode_object(message)?;

        Ok(DHTError(error_code, message))
    }
}
impl fmt::Display for DHTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl fmt::Debug for DHTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ code: {}, message: {} }}", self.0, self.1)
    }
}


#[derive(Debug, PartialEq)]
pub struct DHTQueryPing {
    pub payload: DHTQueryPingPayload,
    pub transaction_id: u32,

    pub ip: Option<Address>, //Optional IP of the sender
    pub read_only: Option<u8>, //Optional read-only flag
}
impl ToBencode for DHTQueryPing {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_unsorted_dict(|e| {
            e.emit_pair(b"a", &self.payload)?;
            e.emit_pair(b"q", "ping")?;
            e.emit_pair(b"t", &self.transaction_id)?;
            e.emit_pair(b"y", "q")?;

            if let Some(ip) = &self.ip {
                e.emit_pair(b"ip", ip)?;
            }

            if let Some(read_only) = &self.read_only {
                e.emit_pair(b"ro", read_only)?;
            }

            Ok(())
        })
    }
}
impl FromBencode for DHTQueryPing {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut dict = object.try_into_dictionary()?;

        let mut payload = None;
        let mut transaction_id = None;
        let mut ip = None;
        let mut read_only = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"a", value) => {
                    payload = Some(DHTQueryPingPayload::decode_bencode_object(value)?);
                }
                (b"q", value) => {
                    Some(String::decode_bencode_object(value)?);
                }
                (b"t", value) => {
                    transaction_id = Some(u32::decode_bencode_object(value)?);
                }
                (b"y", value) => {
                    Some(String::decode_bencode_object(value)?);
                }
                (b"ip", value) => {
                    ip = Some(Address::decode_bencode_object(value)?);
                }
                (b"ro", value) => {
                    read_only = Some(u8::decode_bencode_object(value)?);
                }
                (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
            }
        }

        Ok(DHTQueryPing {
            payload: payload.unwrap(),
            transaction_id: transaction_id.unwrap(),
            ip,
            read_only,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct DHTQueryPingPayload {
    pub id: NodeId,
}
impl ToBencode for DHTQueryPingPayload {
    const MAX_DEPTH: usize = 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"id", &self.id)?;

            Ok(())
        })
    }
}
impl FromBencode for DHTQueryPingPayload {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut dict = object.try_into_dictionary()?;

        let mut id = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = Some(NodeId::decode_bencode_object(value)?);
                }
                (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
            }
        }

        Ok(DHTQueryPingPayload { id: id.unwrap() })
    }
}
#[derive(Debug, PartialEq)]
pub struct DHTResponse {
    pub transaction_id: Vec<u8>,
    pub response: DHTResponsePayload,
    pub ip: Option<Address>, //Optional IP of the sender
    pub version: Option<Vec<u8>>, //Client version string
}
impl FromBencode for DHTResponse {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut dict = object.try_into_dictionary()?;

        let mut transaction_id = None;
        let mut response = None;
        let mut ip = None;
        let mut version = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"t", value) => {
                    let bytes = value.try_into_bytes()?;
                    transaction_id = Some(bytes.to_vec());
                }
                (b"r", value) => {
                    response = Some(DHTResponsePayload::decode_bencode_object(value)?);
                }
                (b"y", value) => {
                    Some(String::decode_bencode_object(value)?);
                }
                (b"ip", value) => {
                    ip = Some(Address::decode_bencode_object(value)?);
                }
                (b"v", value) => {
                    let v = value.try_into_bytes()?;
                    version = Some(v.to_vec());
                }
                (key, _) => {
                    println!("unknown field, key: {:?}", key);
                    return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string()))
                }
            }
        }

        Ok(DHTResponse {
            transaction_id: transaction_id.unwrap(),
            response: response.unwrap(),
            ip,
            version,
        })
    }
}
#[derive(Debug, PartialEq)]
pub struct DHTResponsePayload {
    pub id: NodeId,
    pub port: Option<u16>,
}
impl FromBencode for DHTResponsePayload {
    fn decode_bencode_object(object: bendy::decoding::Object) -> Result<Self, bendy::decoding::Error> {
        let mut dict = object.try_into_dictionary()?;

        let mut id = None;
        let mut port = None;

        while let Some(pair) = dict.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = Some(NodeId::decode_bencode_object(value)?);
                }
                (b"p", value) => {
                    port = Some(u16::decode_bencode_object(value)?);
                }
                (key, _) => return Err(bendy::decoding::Error::unexpected_field(String::from_utf8_lossy(key).to_string())),
            }
        }

        Ok(DHTResponsePayload { id: id.unwrap(), port })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_ping() {
        let query = DHTQueryPing {
            payload: DHTQueryPingPayload {
                id: NodeId::generate(),
            },
            transaction_id: 1,
            ip: Some(Address {
                addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080),
            }),
            read_only: Some(1),
        };

        let vecs = query.to_bencode().unwrap();
        let decoded = DHTQueryPing::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(query, decoded);
    }

    #[test]
    fn test_ping_payload() {
        let payload = DHTQueryPingPayload {
            id: NodeId::generate(),
        };

        let vecs = payload.to_bencode().unwrap();
        let decoded = DHTQueryPingPayload::from_bencode(&vecs).unwrap();

        println!("{:?}", decoded);

        assert_eq!(payload, decoded);
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
        let error = DHTError(201, "Generic Error".to_string());
        let vecs = error.to_bencode().unwrap();
        let decoded = DHTError::from_bencode(&vecs).unwrap();

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