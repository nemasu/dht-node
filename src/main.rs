use bendy::{decoding::FromBencode, encoding::ToBencode};
use proto::{CompactAddress, KRPCMessage, KRPCPayload};
use tokio::net::UdpSocket;
use std::{io, net::SocketAddr, ops::Deref, sync::Arc};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use log::{debug, error, info, trace, warn, LevelFilter};


mod proto;
mod routing_table;

const DATA_PATH: &str  = "./data.json";

#[tokio::main]
async fn main() -> io::Result<()> {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto).unwrap();

    #[allow(unused_assignments)] //Seems silly the compiler complains here.
    let mut addr = None;

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

    let routing_table = Arc::new(tokio::sync::Mutex::new(routing_table::RoutingTable::load_or_new(DATA_PATH)));
    let inner_routing_table = routing_table.clone();

    let transaction_counter = Arc::new(tokio::sync::Mutex::new(routing_table::TransactionCounter::new()));
    let inner_transaction_counter = transaction_counter.clone();

    let sock = UdpSocket::bind(addr.unwrap().parse::<SocketAddr>().unwrap()).await?;
    let r = Arc::new(sock);

    let s = r.clone();
    let inner_s = r.clone();

    let node_id = routing_table.lock().await.node_id.clone();
    let inner_node_id = node_id.clone();

    tokio::spawn(async move {
        let mut buf = [0; 1024];
        loop {
            trace!("Routing Table: {:?}", inner_routing_table);
                
            if let Ok((len, addr)) = r.recv_from(&mut buf).await {
                let _  = match proto::KRPCMessage::from_bencode(&buf[..len]) {
                    Ok(msg) => {

                        trace!("Received: {:?} from {:?}", msg, addr);

                        match msg.message_type.as_str() {
                            "q" => {
                                match msg.query.unwrap().as_str() {
                                    "ping" => {
                                        //Add node to routing table
                                        if let KRPCPayload::KRPCQueryPingRequest{ id } = msg.payload {
                                            debug!("Received ping from {:?}", id);

                                            inner_routing_table.lock().await.ping_update(&id.clone());

                                            //Response
                                            let ping_response = proto::KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);
                                            
                                            trace!("sending ping response: {:?}", ping_response);
                                            
                                            if let Err(e) = inner_s.send_to(&ping_response.to_bencode().unwrap(), addr).await {
                                                warn!("Error sending ping response: {:?} to {:?}. Removing node.", e, addr);
                                                inner_routing_table.lock().await.remove_node(&id);
                                            }
                                        }
                                    }
                                    "get_peers" => {
                                        if let KRPCPayload::KRPCQueryGetPeersRequest{ id, info_hash } = msg.payload {
                                            debug!("Received get_peers from {:?} for info_hash {:?}", id, info_hash);

                                            //Add node to routing table
                                            inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                            
                                            let (nodes, values) = inner_routing_table.lock().await.get_node_list_for_info_hash(&info_hash);
                                            
                                            let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                            inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                            //Response
                                            let get_peers_response = KRPCMessage::get_peers_response(inner_node_id.clone(), token, nodes, msg.transaction_id, values);

                                            trace!("sending get_peers response: {:?}", get_peers_response);

                                            if let Err(e) = inner_s.send_to(&get_peers_response.to_bencode().unwrap(), addr).await {
                                                warn!("Error sending get_peers response: {:?} to {:?}. Removing node.", e, addr);
                                                inner_routing_table.lock().await.remove_node(&id);
                                            }
                                        }
                                    }
                                    "announce_peer" => {
                                        if let KRPCPayload::KRPCQueryAnnouncePeerRequest{ id, info_hash, port, token, implied_port, seed: _ } = msg.payload {
                                            debug!("Received announce_peer from {:?} for info_hash {:?}", id, info_hash);
                                            
                                            //Add node to routing table
                                            inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                            
                                            //Add info hash for this node
                                            inner_routing_table.lock().await.add_info_hash(info_hash.clone(), id.clone());

                                            let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                            inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                            //TODO check token

                                            //Response
                                            let get_peers_response = KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);

                                            trace!("sending annouce_peers response: {:?}", get_peers_response);

                                            //TODO implied_port
                                            if let Err(e) = inner_s.send_to(&get_peers_response.to_bencode().unwrap(), addr).await {
                                                warn!("Error sending annouce_peers response: {:?} to {:?}. Removing node.", e, addr);
                                                inner_routing_table.lock().await.remove_node(&id);
                                            }
                                        }
                                    }
                                    "find_node" => {
                                        if let KRPCPayload::KRPCQueryFindNodeRequest{ id, target } = msg.payload {
                                            debug!("Received find_node from {:?} for target {:?}", id, target);

                                            //Add node to routing table
                                            inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                            
                                            //Find nodes
                                            let nodes = inner_routing_table.lock().await.get_node_list_for_node_id(&target);
                                            
                                            //Response
                                            let find_node_response = KRPCMessage::find_node_response(inner_node_id.clone(), nodes, msg.transaction_id);

                                            trace!("sending find_node response: {:?}", find_node_response);

                                            if let Err(e) = inner_s.send_to(&find_node_response.to_bencode().unwrap(), addr).await {
                                                warn!("Error sending find_node response: {:?} to {:?}. Removing node.", e, addr);
                                                inner_routing_table.lock().await.remove_node(&id);
                                            }
                                        }
                                    }
                                    q => {
                                        warn!("Unknown query type: {:?}", q);
                                        //Send back 204 - Method Unknown error
                                        let tc = inner_transaction_counter.lock().await;
                                        let addr = tc.get_addr_for_tranaction_id(msg.transaction_id.clone()).unwrap();

                                        let error = KRPCMessage::error(204, "Method Unknown".to_string(), msg.transaction_id);
                                        if let Err(e) = inner_s.send_to(&error.to_bencode().unwrap(), addr.addr).await {
                                            warn!("Error sending error: {:?} to {:?}. Removing node.", e, addr);
                                            inner_routing_table.lock().await.remove_node_by_addr(addr);
                                        }
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
                                    KRPCPayload::KRPCQueryFindNodeResponse { id, nodes } => {
                                        //Add node to routing table
                                        inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));

                                        //Add nodes to routing table
                                        trace!("find_node response from {:?}. Nodes: {:?}", id, nodes);
                                        for node in nodes.0 {
                                            inner_routing_table.lock().await.add_node(node.id.clone(), node.addr.clone());
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
                                        if error.0 == 202 {
                                            debug!("Error: {:?}", error);
                                            
                                            //If a server error occurs, just remove it from the routing table
                                            let tc = inner_transaction_counter.lock().await;
                                            let addr = tc.get_addr_for_tranaction_id(msg.transaction_id).unwrap();

                                            inner_routing_table.lock().await.remove_node_by_addr(addr);
                                        } {
                                            warn!("Error: {:?}", error);
                                        }
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
        }
    });

    //Initial find_nodes
    let node_list = routing_table.lock().await.get_random_nodes(5);
    for node in node_list {
        let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
        
        if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
            warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
            routing_table.lock().await.remove_node(&node_id);
        } else {
            trace!("{:?}", find_node);
        }
    }

    //Bootstrap - use nodes.txt
    /*
       nodes.txt should be a list of nodes in the following format:
       <ip>:<port>
       <ip2>:<port2>
     */
    if routing_table.lock().await.nodes.len() == 0 {
        info!("No nodes in routing table, bootstrapping from nodes.txt");
        let file = std::fs::File::open("nodes.txt").unwrap();
        for line in io::BufRead::lines(std::io::BufReader::new(file)) {
            let addr = line.unwrap();
            let addr = addr.trim();
            let addr = addr.parse::<SocketAddr>().unwrap();
            let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(CompactAddress::new_from_sockaddr(addr)));
            if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), addr).await {
                warn!("Error sending find_node: {:?} to {:?}, removing node.", e, addr);
                routing_table.lock().await.remove_node(&node_id);
            } else {
                trace!("{:?}", find_node);
            }
        }
    }

    loop {
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        if current_time % 30 == 0 {
            routing_table.lock().await.debug_stats();
            routing_table.lock().await.save(DATA_PATH);
        }

        //Node management
        routing_table.lock().await.node_remove_dead();
        let nodes = routing_table.lock().await.node_get_for_ping();
        for node in nodes {
            let ping = proto::KRPCMessage::ping(node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
            
            if let Err(e) = s.send_to(&ping.to_bencode().unwrap(), node.addr.addr).await {
                warn!("Error sending ping: {:?} to {:?}, removing node.", e, node.addr);
                routing_table.lock().await.remove_node(&node_id);
            } else {
                routing_table.lock().await.ping_update(&node.id);
                trace!("Pinging {:?}", ping);
            }
        }

        //Get closer nodes via find_node every 5 minutes
        if current_time % (60*5) == 0 {
            //For our node
            let nodes = routing_table.lock().await.get_closest_nodes(&node_id, 3);
            for node in nodes {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
                
                if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
                    warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
                    routing_table.lock().await.remove_node(&node_id);
                } else {
                    trace!("get_peers {:?}", find_node);
                }
            }
        }
        
        //For random nodes, to build up our routing table
        if current_time % 60 == 0 { 
            let nodes = routing_table.lock().await.get_random_nodes(5);
            for node in nodes {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), proto::NodeId::generate_nodeid(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
                
                if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
                    warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
                    routing_table.lock().await.remove_node(&node_id);
                } else {
                    trace!("get_peers {:?}", find_node);
                }
            }
        }

        //Get more nodes via get_peers every minute for any info_hashes we have
        //TODO if this is a lot, we'll need to split it up over time
        if current_time % 60 == 0 {
            let info_hashes = routing_table.lock().await.get_all_info_hashes(); 
            for info_hash in info_hashes {
                let nodes = routing_table.lock().await.get_random_nodes(2);
                for node in nodes {
                    let get_peers = proto::KRPCMessage::get_peers(node_id.clone(), info_hash.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
                    
                    if let Err(e) = s.send_to(&get_peers.to_bencode().unwrap(), node.addr.addr).await {
                        warn!("Error sending get_peers: {:?} to {:?}, removing node.", e, node.addr);
                        routing_table.lock().await.remove_node(&node_id);
                    } else {
                        trace!("get_peers {:?}", get_peers);
                    }
                }
            }
        }
    }
}