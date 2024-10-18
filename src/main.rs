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
                                        inner_routing_table.lock().await.ping_update(&id.clone());

                                        //Response
                                        let ping_response = proto::KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);
                                        
                                        trace!("sending ping response: {:?}", ping_response);
                                        
                                        inner_s.send_to(&ping_response.to_bencode().unwrap(), addr).await.unwrap();
                                    }
                                }
                                "get_peers" => {
                                    if let KRPCPayload::KRPCQueryGetPeersRequest{ id, info_hash } = msg.payload {

                                        //Add node to routing table
                                        inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                        
                                        //Officially we should only be tracking 8 nodes, but for now we will track all nodes
                                        let nodes = inner_routing_table.lock().await.get_node_list_for_info_hash(&info_hash);
                                        
                                        let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                        inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                        //Response
                                        let get_peers_response = KRPCMessage::get_peers_response(inner_node_id.clone(), token, nodes, msg.transaction_id, None);

                                        trace!("sending get_peers response: {:?}", get_peers_response);

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

                                        debug!("sending annouce_peers response: {:?}", get_peers_response);

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
                                KRPCPayload::KRPCQueryIdResponse { id, port: _, ip: _ } => {
                                    //Add node to routing table
                                    inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                }
                                KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes, values: values } => {
                                    //Add node to routing table
                                    inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                    inner_routing_table.lock().await.add_token(id.clone(), token.clone());

                                    //Add nodes to routing table
                                    trace!("get_peers response from {:?}. Nodes: {:?}", id, nodes);
                                    if nodes.is_some() {
                                        for node in nodes.unwrap().0 {
                                            inner_routing_table.lock().await.add_node(node.id.clone(), node.addr.clone());
                                        }
                                    }

                                    if values.is_some() {
                                       //TODO
                                       //There's no node_id, so we need to ping these addresses to get them
                                    }
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
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        if current_time % 10 == 0 {
            routing_table.lock().await.debug_stats();
        }

        //Node management
        routing_table.lock().await.node_remove_dead();

        let nodes = routing_table.lock().await.node_get_for_ping();
        for node in nodes {
            let ping = proto::KRPCMessage::ping(node_id.clone(), proto::TransactionId::new_from_i32(transaction_counter));
            transaction_counter += 1;
            s.send_to(&ping.to_bencode().unwrap(), node.addr.addr).await?;
            routing_table.lock().await.node_time_update(&node.id);
            trace!("Pinging {:?}", ping);
        }

        //Get more nodes via get_peers every 30 seconds
        //from 5 random nodes for now
        if current_time % 30 == 0 {
            let nodes = routing_table.lock().await.get_random_nodes(5);
            for node in nodes {
                let get_peers = proto::KRPCMessage::get_peers(node_id.clone(), proto::InfoHash::generate(20), proto::TransactionId::new_from_i32(transaction_counter));
                transaction_counter += 1;
                s.send_to(&get_peers.to_bencode().unwrap(), node.addr.addr).await?;
                routing_table.lock().await.node_time_update(&node.id);
                trace!("get_peers {:?}", get_peers);
            }
        }
    }
}