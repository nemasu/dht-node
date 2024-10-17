use bendy::{decoding::FromBencode, encoding::ToBencode};
use tokio::net::UdpSocket;
use std::{io, net::SocketAddr, ops::Deref, sync::Arc};

mod proto;
mod routing_table;

#[tokio::main]
async fn main() -> io::Result<()> {

    let mut addr: Option<String> = None;
    let mut addr2: Option<String> = None;

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.get(0).map(|r| r.deref()) {
        Some(p)=>{
            addr = Some(p.to_string());
            
            if args.get(1).is_some() {
                addr2 = Some(args.get(1).unwrap().to_string());
            }
        }
        _ => {
            println!("Usage: dht-node <address>:<port>");
            return Ok(());
        }
    }

    let sock = UdpSocket::bind(addr.unwrap().parse::<SocketAddr>().unwrap()).await?;
    let r = Arc::new(sock);

    let s = r.clone();
    let inner_s = r.clone();

    let node_id = proto::NodeId::generate();
    let inner_node_id = proto::NodeId::generate();

    let mut transaction_counter = 1000; //TODO Turn this into a struct

    tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            let (len, addr) = r.recv_from(&mut buf).await.unwrap();
            let msg = proto::KRPCMessage::from_bencode(&buf[..len]).unwrap();
            println!("Received: {:?} from {:?}", msg, addr);

            match msg.message_type.as_str() {
                "q" => {
                    match msg.query.unwrap().as_str() {
                        "ping" => {
                            let pong = proto::KRPCMessage::ping_response(inner_node_id.clone(), msg.transaction_id);
                            println!("Pong: {:?}", pong);
                            inner_s.send_to(&pong.to_bencode().unwrap(), addr).await.unwrap();
                        }
                        "get_peers" => {
                            
                        }
                        q => {
                            println!("Unknown query type: {:?}", q);
                        }
                    }
                }
                "r" => {

                }
                "e" => {

                }
                _ => {
                    println!("Unknown message type: {:?}", msg.message_type);
                }
               
            }
            
        }
    });

    if addr2.is_some() {
        let ping = proto::KRPCMessage::ping(node_id, proto::TransactionId::new_from_i32(transaction_counter));
        transaction_counter+=1;
        
        println!("{:?}", ping);
    
        s.send_to(&ping.to_bencode().unwrap(), addr2.unwrap()).await?;
        println!("Sent ping");
    }

    
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}