use bendy::{decoding::FromBencode, encoding::ToBencode};
use tokio::net::UdpSocket;
use std::{io, net::{SocketAddr, SocketAddrV4}, sync::Arc};

mod proto;
mod routing_table;

#[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:35000".parse::<SocketAddr>().unwrap()).await?;
    let r = Arc::new(sock);
    let s = r.clone();

    tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            let (len, addr) = r.recv_from(&mut buf).await.unwrap();
            let msg = proto::KRPCMessage::from_bencode(&buf[..len]).unwrap();
            println!("Received: {:?} from {:?}", msg, addr);
        }
    });

    let ping = proto::KRPCMessage {
        payload: proto::KRPCPayload::KRPCQueryPingRequest {
            id: proto::NodeId::generate(),
        },
        transaction_id: proto::Version::new(b"1234".to_vec()),
        message_type: "q".to_string(),

        ip: Some(proto::Address { addr: SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080) } ),
        
        version: Some( proto::Version::new(b"NN40".to_vec())),
    };

    println!("{:?}", ping);

    s.send_to(&ping.to_bencode().unwrap(), "127.0.0.1:36690").await?;

    println!("Sent ping");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}