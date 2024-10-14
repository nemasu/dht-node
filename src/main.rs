use bendy::{decoding::FromBencode, encoding::ToBencode};
use tokio::net::UdpSocket;
use std::{io, net::SocketAddr, sync::Arc};

mod proto;

#[tokio::main]
async fn main() -> io::Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:35000".parse::<SocketAddr>().unwrap()).await?;
    let r = Arc::new(sock);
    let s = r.clone();

    tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            let (len, addr) = r.recv_from(&mut buf).await.unwrap();
            let msg = proto::DHTResponse::from_bencode(&buf[..len]).unwrap();
            println!("Received: {:?} from {:?}", msg, addr);
        }
    });


   let ping = proto::DHTQueryPing {
        payload: proto::DHTQueryPingPayload {
            id: proto::NodeId::generate(),
        },
        transaction_id: 1000,
        ip: Some(proto::Address {
            addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 35000),
        }),
        read_only: Some(1),
    };

    println!("{:?}", ping);

    s.send_to(&ping.to_bencode().unwrap(), "127.0.0.1:36690").await?;

    println!("Sent ping");
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}