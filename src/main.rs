use bendy::{decoding::FromBencode, encoding::ToBencode};
use proto::{CompactAddress, KRPCMessage, KRPCPayload};
use tokio::net::UdpSocket;
use std::{io, net::SocketAddr, ops::Deref, sync::Arc};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use log::{debug, error, info, warn, trace, LevelFilter};


mod proto;
mod routing_table;

#[tokio::main]
async fn main() -> io::Result<()> {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto).unwrap();

    let mut addr: Option<String> = None;
    
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.get(0).map(|r| r.deref()) {
        Some(p)=>{
            addr = Some(p.to_string());
        }
        _ => {
            println!("Usage: dht-node <address>:<port>");
            return Ok(());
        }
    }

    let routing_table = Arc::new(tokio::sync::Mutex::new(routing_table::RoutingTable::load_or_new("")));
    let inner_routing_table = routing_table.clone();

    let sock = UdpSocket::bind(addr.unwrap().parse::<SocketAddr>().unwrap()).await?;
    let r = Arc::new(sock);

    let s = r.clone();
    let inner_s = r.clone();

    let node_id = proto::NodeId::generate_nodeid();
    let inner_node_id = node_id.clone();

    tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            trace!("Routing Table: {:?}", inner_routing_table);
            inner_routing_table.lock().await.debug_stats();

            let (len, addr) = r.recv_from(&mut buf).await.unwrap();
            
            let _  = match proto::KRPCMessage::from_bencode(&buf[..len]) {
                Ok(msg) => {

                    trace!("Received: {:?} from {:?}", msg, addr);

                    match msg.message_type.as_str() {
                        "q" => {
                            match msg.query.unwrap().as_str() {
                                "ping" => {
                                    //Add node to routing table
                                    if let KRPCPayload::KRPCQueryPingRequest{ id } = msg.payload {
                                        inner_routing_table.lock().await.add_node(id, CompactAddress::new_from_sockaddr(addr));

                                        //Response
                                        let ping_response = proto::KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);
                                        
                                        trace!("ping response: {:?}", ping_response);
                                        
                                        inner_s.send_to(&ping_response.to_bencode().unwrap(), addr).await.unwrap();
                                    }
                                }
                                "get_peers" => {
                                    if let KRPCPayload::KRPCQueryGetPeersRequest{ id, info_hash } = msg.payload {

                                        //Add node to routing table
                                        inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                        
                                        //Officially we should only be tracking 8 nodes, but for now we will track all nodes
                                        //TODO calculate closest nodes
                                        let nodes = inner_routing_table.lock().await.get_node_list_for_info_hash(&info_hash);
                                        
                                        let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                        inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                        //Response
                                        let get_peers_response = KRPCMessage::get_peers_response(inner_node_id.clone(), token, nodes, msg.transaction_id, None);

                                        debug!("get_peers response: {:?}", get_peers_response);

                                        inner_s.send_to(&get_peers_response.to_bencode().unwrap(), addr).await.unwrap();
                                    }
                                }
                                "announce_peer" => {
                                    if let KRPCPayload::KRPCQueryAnnouncePeerRequest{ id, info_hash, port, token, implied_port, seed: _ } = msg.payload {
                                        //Add node to routing table
                                        inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                        
                                        //Add info hash for this node
                                        inner_routing_table.lock().await.add_info_hash(info_hash.clone(), id.clone());

                                        let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                        inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                        //TODO check token

                                        //Response
                                        let get_peers_response = KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);

                                        debug!("get_peers response: {:?}", get_peers_response);

                                        //TODO implied_port
                                        inner_s.send_to(&get_peers_response.to_bencode().unwrap(), addr).await.unwrap();
                                    }
                                }
                                q => {
                                    warn!("Unknown query type: {:?}", q);
                                }
                            }
                        }
                        "r" => {
                            match msg.payload {
                                //TODO check the transaction id
                                KRPCPayload::KRPCQueryIdResponse { id, port } => {
                                    //Add node to routing table
                                    inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                    inner_routing_table.lock().await.ping_get(&id);
                                }
                                _ => {
                                    warn!("Unimplemented response type: {:?}", msg.payload);
                                }
                            }
                        }
                        "e" => {
                            match msg.payload {
                                KRPCPayload::KRPCError(error) => {
                                    warn!("Error: {:?}", error);
                                }
                                _ => {
                                    warn!("Unimplemented error type: {:?}", msg.payload);
                                }
                            }
                        }
                        _ => {
                            warn!("Unknown message type: {:?}", msg.message_type);
                        }
                    }
                },
                Err(e) => {
                    error!("Error decoding message: {:?}", e);
                    continue;
                }
            };
        }
    });

    
    //Initial pings
    //read in a file, and loop for every line
    let file = std::fs::File::open("nodes.txt").unwrap();
    let mut transaction_counter: i32 = 0;
    for line in io::BufRead::lines(std::io::BufReader::new(file)) {
        let addr = line.unwrap();
        let addr = addr.trim();
        let addr = addr.parse::<SocketAddr>().unwrap();
        let ping = proto::KRPCMessage::ping(node_id.clone(), proto::TransactionId::new_from_i32(transaction_counter));
        transaction_counter += 1;
        s.send_to(&ping.to_bencode().unwrap(), addr).await?;
        trace!("{:?}", ping);
    }

    loop {
        //Every x seconds, ping all nodes in the routing table
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        //Remove dead nodes
        routing_table.lock().await.ping_remove_dead();

        let nodes = routing_table.lock().await.get_all_nodes();
        for node in nodes {
            let ping = proto::KRPCMessage::ping(node.id.clone(), proto::TransactionId::new_from_i32(transaction_counter));
            transaction_counter += 1;
            s.send_to(&ping.to_bencode().unwrap(), node.addr.addr).await?;
            routing_table.lock().await.ping_expect_response(&node.id);
            trace!("{:?}", ping);
        }
    }
}