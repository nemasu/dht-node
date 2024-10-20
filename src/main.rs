use bendy::{decoding::FromBencode, encoding::ToBencode};
use proto::{CompactAddress, KRPCMessage, KRPCPayload};
use tokio::net::UdpSocket;
use std::{io, net::SocketAddr, ops::Deref, sync::Arc};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use log::{debug, info, trace, warn, LevelFilter};


mod proto;
mod routing_table;
mod bucket;

async fn resolve_hostname(hostname: &str) -> Option<SocketAddr> {
    match std::net::ToSocketAddrs::to_socket_addrs(&hostname) {
        Ok(addrs) => {
            for a in addrs {
                if a.is_ipv4() {
                    return Some(a);
                }
            }
            None
        },
        Err(e) => {
            warn!("Failed to resolve hostname {}: {:?}", hostname, e);
            None
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto).unwrap();

    #[allow(unused_assignments)] //Seems silly the compiler complains here.
    let mut addr = None;
    let mut node_id = None;

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.get(0).map(|r| r.deref()) {
        Some(p)=>{
            addr = Some(p.to_string());

            if args.len() > 1 {
                node_id = Some(proto::NodeId::from_hex(args.get(1).unwrap()));
            }
        }
        _ => {
            println!("Usage: dht-node <address>:<port> <node_id>. eg. \"dht-node 192.168.1.100:6881\" or \"dht-node 192.168.1.100:6881 0123456789abcdef0123456789abcdef01234567\"\n If no node_id is provided, one will be generated.");
            return Ok(());
        }
    }

    let routing_table = Arc::new(tokio::sync::Mutex::new(routing_table::RoutingTable::load_or_new(node_id)));
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
                                        if let KRPCPayload::KRPCQueryAnnouncePeerRequest{ id, info_hash, port: _, token, implied_port: _, seed: _ } = msg.payload {
                                            debug!("Received announce_peer from {:?} for info_hash {:?} with token {:?}", id, info_hash, token);
                                            
                                            //check token
                                            let sent_token = inner_routing_table.lock().await.get_sent_token(&inner_node_id);
                                            if sent_token.unwrap() != token {
                                                warn!("Token mismatch for announce_peer from {:?} for info_hash {:?}", id, info_hash);
                                                let error = KRPCMessage::error(203, "Protocol Error".to_string(), msg.transaction_id.clone());
                                                if let Err(e) = inner_s.send_to(&error.to_bencode().unwrap(), addr).await {
                                                    warn!("Error sending error: {:?} to {:?}. Removing node.", e, addr);
                                                    inner_routing_table.lock().await.remove_node(&id);
                                                }
                                                return;
                                            }

                                            //Add node to routing table
                                            inner_routing_table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(addr));
                                            
                                            //Add info hash for this node
                                            inner_routing_table.lock().await.add_info_hash(info_hash.clone(), id.clone());

                                            let token = inner_routing_table.lock().await.get_token(&id).unwrap().clone();

                                            inner_routing_table.lock().await.add_sent_token(&id, token.clone());

                                            //Response
                                            let get_peers_response = KRPCMessage::id_response(inner_node_id.clone(), msg.transaction_id);

                                            trace!("sending annouce_peers response: {:?}", get_peers_response);

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
                                    KRPCPayload::KRPCQueryGetPeersResponse { id, token, nodes, values: _ } => {
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

                                        //TODO
                                        //Ping the nodes in values, and add the node to info_hash
                                        // if values.is_some() {
                                        // }
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
                        warn!("Error decoding message: {:?}, message.", e);
                        let error = KRPCMessage::error(203, "Protocol Error".to_string(), proto::TransactionId::new_from_i32(0));
                        if let Err(e) = inner_s.send_to(&error.to_bencode().unwrap(), addr).await {
                            warn!("Error sending error '{:?}' to: {:?}. Removing node.", e, addr);
                            let a = CompactAddress::new_from_sockaddr(addr);
                            inner_routing_table.lock().await.remove_node_by_addr(&a);
                        }
                    }
                };
            }
        }
    });

    if routing_table.lock().await.nodes.len() == 0 {
        info!("No nodes in routing table, bootstrapping");
        let bootstrap_addresses: Vec<&str> = vec!["router.bittorrent.com:6881", "router.utorrent.com:6881", "dht.transmissionbt.com:6881", "dht.aelitis.com:6881"];
        for addr in bootstrap_addresses {
            let addr = match resolve_hostname(addr).await {
                Some(a) => {
                    a
                }
                None => {
                    warn!("Failed to resolve hostname: {:?}", addr);
                    continue;
                }
            };

            let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(CompactAddress::new_from_sockaddr(addr)));
            if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), addr).await {
                warn!("Error sending find_node: {:?} to {:?}, removing node.", e, addr);
                routing_table.lock().await.remove_node(&node_id.clone());
            } else {
                trace!("{:?}", find_node);
            }
        }        
    }

    //Initial find_nodes to populate routing table
    let node_list = routing_table.lock().await.get_random_nodes(10);
    for node in node_list {
        let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
        
        if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
            warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
            routing_table.lock().await.remove_node(&node_id);
        } else {
            trace!("{:?}", find_node);
        }
    }

    //Find closest nodes to us
    let start_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut last_nodes_count = routing_table.lock().await.nodes.len();
    loop {
        let nodes = routing_table.lock().await.get_closest_nodes(&node_id, 5);
        for node in nodes {
            let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
            
            if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
                warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
                routing_table.lock().await.remove_node(&node_id);
            } else {
                trace!("{:?}", find_node);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        let nodes_size = routing_table.lock().await.nodes.len();
        if nodes_size == last_nodes_count {
            break;
        } else {
            last_nodes_count = nodes_size;
        }

        //We should give up after a certain period of time.
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - start_time > 60 {
            break;
        }
    }

    loop {
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        if current_time % 30 == 0 {
            routing_table.lock().await.debug_stats();
            routing_table.lock().await.save();
        }

        if current_time % 10 == 0 {
            //Node management
            routing_table.lock().await.node_remove_dead();
            let nodes = routing_table.lock().await.node_get_for_ping();
            for node in nodes {
                let ping = proto::KRPCMessage::ping(node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
                
                if let Err(e) = s.send_to(&ping.to_bencode().unwrap(), node.addr.addr).await {
                    warn!("Error sending ping: {:?} to {:?}, removing node {:?}.", e, node.addr, node);
                    routing_table.lock().await.remove_node(&node.id);
                } else {
                    routing_table.lock().await.ping_update(&node.id);
                    trace!("Pinging {:?}", ping);
                }
            }
            
            //Refreshing bucket uses a random ID in the range (currently this is a random node we have in the bucket), and sends a find_node to the closest nodes to that ID.
            let nodes = routing_table.lock().await.node_get_for_refresh();
            for node in nodes {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), node.id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));
                
                if let Err(e) = s.send_to(&find_node.to_bencode().unwrap(), node.addr.addr).await {
                    warn!("Error sending find_node: {:?} to {:?}, removing node {:?}.", e, node.addr, node);
                    routing_table.lock().await.remove_node(&node.id);
                } else {
                    trace!("{:?}", find_node);
                }
            }
        }

        //TODO Should we make sure that the nodes we have stored for info_hashes still has the torrent?
    }
}