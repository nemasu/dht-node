use bendy::{decoding::FromBencode, encoding::ToBencode};
use crate::proto::{self, CompactAddress, InfoHash, KRPCMessage, KRPCPayload, NodeId, Version};
use crate::routing_table::{RoutingTable, TransactionCounter};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use std::{collections::HashSet, io, net::SocketAddr, sync::Arc};
use log::{debug, error, info, trace, warn};

const BOOTSTRAP_HOSTS: &[&str] = &["router.bittorrent.com:6881", "router.utorrent.com:6881", "dht.transmissionbt.com:6881", "dht.aelitis.com:6881"];

async fn resolve_hostname(hostname: &str, want_v4: bool) -> Option<SocketAddr> {
    match std::net::ToSocketAddrs::to_socket_addrs(&hostname) {
        Ok(addrs) => {
            for a in addrs {
                if a.is_ipv4() == want_v4 {
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

/// A UDP socket paired with the routing table for the address family it's bound to.
#[derive(Clone)]
struct Stack {
    sock: Arc<UdpSocket>,
    table: Arc<Mutex<RoutingTable>>,
}

/// What a library consumer can learn from this node as it participates in the DHT.
/// Only DHT itself never carries torrent metadata (file names/sizes/piece data) - just
/// these info_hash/peer associations. Fetching actual metadata for a hash requires a
/// separate BEP 9 (ut_metadata) exchange with one of the discovered peers.
#[derive(Debug, Clone, PartialEq)]
pub enum DhtEvent {
    /// A remote node sent us an announce_peer query: it explicitly holds data for
    /// `info_hash`, reachable at `peer`.
    PeerAnnounced { info_hash: InfoHash, node_id: NodeId, peer: CompactAddress },
    /// One of our own get_peers queries got back a values/values6 entry: `peer` holds
    /// data for `info_hash`.
    PeerDiscovered { info_hash: InfoHash, peer: CompactAddress },
    /// A remote node sent us a get_peers query for `info_hash`: it exists/is wanted
    /// somewhere in the swarm. `querier`/`querier_addr` identify who asked, but a node
    /// asking about a hash is not confirmed to hold it - don't treat `querier_addr` as
    /// a metadata source the way you would `PeerAnnounced`/`PeerDiscovered`'s `peer`.
    InfoHashObserved { info_hash: InfoHash, querier: NodeId, querier_addr: CompactAddress },
}

/// Shared state visible to every socket's receive loop. Holds both stacks (when dual-stack)
/// so cross-family node/peer info learned on one socket can be routed into the other family's
/// routing table.
#[derive(Clone)]
struct DhtContext {
    node_id: NodeId,
    v4: Option<Stack>,
    v6: Option<Stack>,
    transaction_counter: Arc<Mutex<TransactionCounter>>,
    invalid_ping_response_version: Version,
    event_tx: mpsc::UnboundedSender<DhtEvent>,
    bootstrap_nodes: Vec<SocketAddr>,
}

impl DhtContext {
    /// The BEP32 "want" value matching the families this node currently runs.
    fn want_list(&self) -> Vec<String> {
        let mut want = Vec::new();
        if self.v4.is_some() {
            want.push("n4".to_string());
        }
        if self.v6.is_some() {
            want.push("n6".to_string());
        }
        want
    }

    /// The stack matching a given compact address's own family, regardless of which
    /// socket the packet carrying that address arrived on.
    fn stack_for(&self, addr: &CompactAddress) -> Option<&Stack> {
        if addr.is_v4() { self.v4.as_ref() } else { self.v6.as_ref() }
    }

    /// BEP32: honor an explicit "want", otherwise default to the family the packet was
    /// physically received on.
    fn effective_want(&self, requested: &Option<Vec<String>>, received_on_v4: bool) -> HashSet<&'static str> {
        match requested {
            Some(w) => w.iter().filter_map(|s| match s.as_str() {
                "n4" => Some("n4"),
                "n6" => Some("n6"),
                _ => None,
            }).collect(),
            None => {
                let mut s = HashSet::new();
                s.insert(if received_on_v4 { "n4" } else { "n6" });
                s
            }
        }
    }
}

async fn handle_packet(ctx: &DhtContext, own: &Stack, src: SocketAddr, buf: &[u8]) {
    match proto::KRPCMessage::from_bencode(buf) {
        Ok(msg) => {
            trace!("Received: {:?} from {:?}", msg, src);

            match msg.message_type.as_str() {
                "q" => {
                    match msg.query.as_deref().unwrap_or("") {
                        "ping" => {
                            if let KRPCPayload::KRPCQueryPingRequest { id } = msg.payload {
                                debug!("Received ping from {:?}", id);

                                own.table.lock().await.ping_update(&id.clone());

                                let ping_response = KRPCMessage::id_response(ctx.node_id.clone(), msg.transaction_id, CompactAddress::new_from_sockaddr(src));

                                trace!("sending ping response: {:?}", ping_response);

                                if let Err(e) = own.sock.send_to(&ping_response.to_bencode().unwrap(), src).await {
                                    warn!("Error sending ping response: {:?} to {:?}. Removing node.", e, src);
                                    own.table.lock().await.remove_node(&id);
                                }
                            }
                        }
                        "get_peers" => {
                            if let KRPCPayload::KRPCQueryGetPeersRequest { id, info_hash, want } = msg.payload {
                                debug!("Received get_peers from {:?} for info_hash {:?}", id, info_hash);

                                own.table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(src));

                                let _ = ctx.event_tx.send(DhtEvent::InfoHashObserved { info_hash: info_hash.clone(), querier: id.clone(), querier_addr: CompactAddress::new_from_sockaddr(src) });

                                let effective_want = ctx.effective_want(&want, src.is_ipv4());

                                let mut nodes_v4 = None;
                                let mut values_v4 = None;
                                let mut nodes_v6 = None;
                                let mut values_v6 = None;

                                if effective_want.contains("n4") {
                                    if let Some(stack) = &ctx.v4 {
                                        let (n, v) = stack.table.lock().await.get_node_list_for_info_hash(&info_hash);
                                        nodes_v4 = Some(n);
                                        values_v4 = v;
                                    }
                                }
                                if effective_want.contains("n6") {
                                    if let Some(stack) = &ctx.v6 {
                                        let (n, v) = stack.table.lock().await.get_node_list_for_info_hash(&info_hash);
                                        nodes_v6 = Some(n);
                                        values_v6 = v;
                                    }
                                }

                                let token = own.table.lock().await.generate_token(&id);

                                let get_peers_response = KRPCMessage::get_peers_response(ctx.node_id.clone(), token, nodes_v4, nodes_v6, values_v4, values_v6, msg.transaction_id, CompactAddress::new_from_sockaddr(src));

                                trace!("sending get_peers response: {:?}", get_peers_response);

                                if let Err(e) = own.sock.send_to(&get_peers_response.to_bencode().unwrap(), src).await {
                                    warn!("Error sending get_peers response: {:?} to {:?}. Removing node.", e, src);
                                    own.table.lock().await.remove_node(&id);
                                }
                            }
                        }
                        "announce_peer" => {
                            if let KRPCPayload::KRPCQueryAnnouncePeerRequest{ id, info_hash, port, token, implied_port, seed: _ } = msg.payload {
                                debug!("Received announce_peer from {:?} for info_hash {:?}", id, info_hash);

                                //check token
                                let token_valid = own.table.lock().await.token_is_valid(&id, &token);
                                if !token_valid {
                                    debug!("Token mismatch for announce_peer from {:?} for info_hash {:?}", id, info_hash);
                                    let error = KRPCMessage::error(203, "Protocol Error".to_string(), msg.transaction_id.clone());
                                    if let Err(e) = own.sock.send_to(&error.to_bencode().unwrap(), src).await {
                                        warn!("Error sending error: {:?} to {:?}. Removing node.", e, src);
                                        own.table.lock().await.remove_node(&id);
                                    }
                                    return;
                                }
                                own.table.lock().await.remove_token(&id);

                                //Add node to routing table
                                own.table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(src));

                                //Add info hash for this node
                                own.table.lock().await.add_info_hash(info_hash.clone(), id.clone());

                                let announced_addr = resolve_announced_addr(src, port, implied_port);

                                let _ = ctx.event_tx.send(DhtEvent::PeerAnnounced { info_hash: info_hash.clone(), node_id: id.clone(), peer: announced_addr });

                                //Response
                                let get_peers_response = KRPCMessage::id_response(ctx.node_id.clone(), msg.transaction_id, CompactAddress::new_from_sockaddr(src));

                                trace!("sending annouce_peers response: {:?}", get_peers_response);

                                if let Err(e) = own.sock.send_to(&get_peers_response.to_bencode().unwrap(), src).await {
                                    warn!("Error sending annouce_peers response: {:?} to {:?}. Removing node.", e, src);
                                    own.table.lock().await.remove_node(&id);
                                }
                            }
                        }
                        "find_node" => {
                            if let KRPCPayload::KRPCQueryFindNodeRequest{ id, target, want } = msg.payload {
                                debug!("Received find_node from {:?} for target {:?}", id, target);

                                own.table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(src));

                                let effective_want = ctx.effective_want(&want, src.is_ipv4());

                                let mut nodes_v4 = None;
                                let mut nodes_v6 = None;
                                if effective_want.contains("n4") {
                                    if let Some(stack) = &ctx.v4 {
                                        nodes_v4 = Some(stack.table.lock().await.get_node_list_for_node_id(&target));
                                    }
                                }
                                if effective_want.contains("n6") {
                                    if let Some(stack) = &ctx.v6 {
                                        nodes_v6 = Some(stack.table.lock().await.get_node_list_for_node_id(&target));
                                    }
                                }

                                let find_node_response = KRPCMessage::find_node_response(ctx.node_id.clone(), nodes_v4, nodes_v6, msg.transaction_id, CompactAddress::new_from_sockaddr(src));

                                trace!("sending find_node response: {:?}", find_node_response);

                                if let Err(e) = own.sock.send_to(&find_node_response.to_bencode().unwrap(), src).await {
                                    warn!("Error sending find_node response: {:?} to {:?}. Removing node.", e, src);
                                    own.table.lock().await.remove_node(&id);
                                }
                            }
                        }
                        q => {
                            warn!("Unknown query type: {:?}", q);
                            //Send back 204 - Method Unknown error
                            let error = KRPCMessage::error(204, "Method Unknown".to_string(), msg.transaction_id);
                            if let Err(e) = own.sock.send_to(&error.to_bencode().unwrap(), src).await {
                                warn!("Error sending error: {:?} to {:?}.", e, src);
                            }
                        }
                    }
                }
                "r" => {
                    match msg.payload {
                        //TODO check the transaction id
                        KRPCPayload::KRPCQueryIdResponse {id, p: _ } => { //P is this hosts port
                            let addr = CompactAddress::new_from_sockaddr(src);
                            let mut suspicious = false;

                            {
                                //Check if the node_id has changed
                                let mut rt = own.table.lock().await;
                                let node_local = rt.get_node(&id.clone());
                                if let Some(node_local) = node_local {
                                    if *node_local != addr {

                                        if id == ctx.node_id {
                                            if msg.version.is_some() && msg.version.clone().unwrap() == ctx.invalid_ping_response_version {
                                                debug!("Node with version {:?} is replying to pings with our node_id, ignoring.", msg.version.unwrap());
                                            } else {
                                                //A real collision on the wider network. This node's own identity is
                                                //compromised, but a caller may run many independent DhtNodes in one
                                                //process - taking down every other one over a single collision would
                                                //be a disproportionate blast radius, so just ignore this response
                                                //instead of trusting/storing it.
                                                error!("Node_id is being used by another node {:?} at {:?} - ignoring this response.", id, addr);
                                            }
                                            suspicious = true;
                                        } else {
                                            debug!("Node {:?} has changed address from {:?} to {:?}, updating.", id, node_local, addr);
                                            rt.remove_node(&id);
                                        }
                                    }
                                }

                                //Add node to routing table, unless this response claimed to be us.
                                if !suspicious {
                                    rt.add_node(id.clone(), addr.clone());
                                }
                            }

                            //If this ping response was a result of a get_peers value check, add the node to the info_hash
                            if own.table.lock().await.ping_info_hash.contains_key(&addr) {
                                let mut rt = own.table.lock().await;
                                let info_hash = rt.ping_info_hash.get(&addr).unwrap().clone();
                                rt.add_info_hash(info_hash.clone(), id.clone());
                                rt.ping_info_hash.remove(&addr);
                            }
                        }
                        KRPCPayload::KRPCQueryGetPeersResponse { id, token: _, nodes, nodes6, values, values6, p: _ } => {
                            //Token is ignored, we don't send announce_peer requests

                            //Add node to routing table
                            own.table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(src));

                            //Add nodes to routing table, each routed to the table matching its own family
                            trace!("get_peers response from {:?}. Nodes: {:?}, Nodes6: {:?}", id, nodes, nodes6);
                            if let Some(nodes) = nodes {
                                for node in nodes.0 {
                                    if let Some(stack) = ctx.stack_for(&node.addr) {
                                        stack.table.lock().await.add_node_reference(node.id.clone(), node.addr.clone());
                                    }
                                }
                            }
                            if let Some(nodes6) = nodes6 {
                                for node in nodes6.0 {
                                    if let Some(stack) = ctx.stack_for(&node.addr) {
                                        stack.table.lock().await.add_node_reference(node.id.clone(), node.addr.clone());
                                    }
                                }
                            }

                            //Ping the nodes in values/values6, and add the node to info_hash
                            let info_hash = own.table.lock().await.get_peer_info_hash.get(&msg.transaction_id).cloned();
                            if let Some(info_hash) = info_hash {
                                let mut all_values = Vec::new();
                                if let Some(values) = values {
                                    all_values.extend(values);
                                }
                                if let Some(values6) = values6 {
                                    all_values.extend(values6);
                                }

                                for value in all_values {
                                    let _ = ctx.event_tx.send(DhtEvent::PeerDiscovered { info_hash: info_hash.clone(), peer: value.clone() });

                                    if let Some(stack) = ctx.stack_for(&value) {
                                        stack.table.lock().await.ping_info_hash.insert(value.clone(), info_hash.clone());

                                        //Ping the node
                                        let ping = proto::KRPCMessage::ping(ctx.node_id.clone(), ctx.transaction_counter.lock().await.get_transaction_id(value.clone()));
                                        if let Err(e) = stack.sock.send_to(&ping.to_bencode().unwrap(), value.socket_addr()).await {
                                            warn!("Error sending ping: {:?} to {:?}.", e, value);
                                        }
                                    }
                                }
                            }
                            own.table.lock().await.get_peer_info_hash.remove(&msg.transaction_id);
                        }
                        KRPCPayload::KRPCQueryFindNodeResponse {id, nodes, nodes6, p: _ } => {
                            //Add node to routing table
                            own.table.lock().await.add_node(id.clone(), CompactAddress::new_from_sockaddr(src));

                            //Add nodes to routing table, each routed to the table matching its own family
                            trace!("find_node response from {:?}. Nodes: {:?}, Nodes6: {:?}", id, nodes, nodes6);
                            if let Some(nodes) = nodes {
                                for node in nodes.0 {
                                    if let Some(stack) = ctx.stack_for(&node.addr) {
                                        stack.table.lock().await.add_node_reference(node.id.clone(), node.addr.clone());
                                    }
                                }
                            }
                            if let Some(nodes6) = nodes6 {
                                for node in nodes6.0 {
                                    if let Some(stack) = ctx.stack_for(&node.addr) {
                                        stack.table.lock().await.add_node_reference(node.id.clone(), node.addr.clone());
                                    }
                                }
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

                                //If a server error occurs, just remove it from the routing table matching the target's family
                                let target_addr = {
                                    let tc = ctx.transaction_counter.lock().await;
                                    tc.get_addr_for_tranaction_id(msg.transaction_id).cloned()
                                };

                                if let Some(target_addr) = target_addr {
                                    if let Some(stack) = ctx.stack_for(&target_addr) {
                                        stack.table.lock().await.remove_node_by_addr(&target_addr);
                                    }
                                }
                            } else {
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
            debug!("Error decoding message: {:?}, message.", e);
            let error = KRPCMessage::error(203, "Protocol Error".to_string(), proto::TransactionId::new_from_i32(0));
            if let Err(e) = own.sock.send_to(&error.to_bencode().unwrap(), src).await {
                warn!("Error sending error '{:?}' to: {:?}. Removing node.", e, src);
                let a = CompactAddress::new_from_sockaddr(src);
                own.table.lock().await.remove_node_by_addr(&a);
            }
        }
    };
}

/// BEP5: `implied_port` means "ignore `port`, use the port this packet actually arrived
/// from" - common for clients sharing one port between DHT and the peer wire protocol.
/// Otherwise `port` is the peer's real BitTorrent port, which can differ from its DHT port.
fn resolve_announced_addr(src: SocketAddr, port: u32, implied_port: Option<u32>) -> CompactAddress {
    if implied_port.map(|p| p != 0).unwrap_or(false) {
        CompactAddress::new_from_sockaddr(src)
    } else {
        CompactAddress::new_from_sockaddr(SocketAddr::new(src.ip(), port as u16))
    }
}

async fn receive_loop(own: Stack, ctx: DhtContext) {
    let mut buf = [0u8; 1024];
    loop {
        trace!("Routing Table ({:?}): {:?}", own.sock.local_addr(), own.table.lock().await);

        if let Ok((len, src)) = own.sock.recv_from(&mut buf).await {
            handle_packet(&ctx, &own, src, &buf[..len]).await;
        }
    }
}

fn bind_v6_only(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let owned_fd: std::os::fd::OwnedFd = socket.into();
    Ok(std::net::UdpSocket::from(owned_fd))
}

/// Bootstrap, warm-up (find nodes close to us), and the ongoing 30s maintenance tick
/// (ping/refresh/save/get_peers-for-empty-info-hash), run once per active stack, forever.
async fn run_maintenance(ctx: DhtContext, stacks: Vec<Stack>) {
    let node_id = ctx.node_id.clone();
    let transaction_counter = ctx.transaction_counter.clone();

    //Bootstrap, per stack
    for stack in &stacks {
        if stack.table.lock().await.nodes.len() == 0 {
            let want_v4 = stack.sock.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);

            let bootstrap_addrs: Vec<SocketAddr> = if !ctx.bootstrap_nodes.is_empty() {
                ctx.bootstrap_nodes.iter().filter(|a| a.is_ipv4() == want_v4).copied().collect()
            } else {
                let mut addrs = Vec::new();
                for hostname in BOOTSTRAP_HOSTS {
                    match resolve_hostname(hostname, want_v4).await {
                        Some(a) => addrs.push(a),
                        None => warn!("Failed to resolve bootstrap hostname {:?} for this address family", hostname),
                    }
                }
                addrs
            };

            info!(
                "No nodes in routing table, bootstrapping ({}) from {} address(es){}",
                if want_v4 { "IPv4" } else { "IPv6" },
                bootstrap_addrs.len(),
                if ctx.bootstrap_nodes.is_empty() { " (public bootstrap hosts)" } else { " (provided)" }
            );

            for addr in bootstrap_addrs {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), Some(ctx.want_list()), transaction_counter.lock().await.get_transaction_id(CompactAddress::new_from_sockaddr(addr)));
                if let Err(e) = stack.sock.send_to(&find_node.to_bencode().unwrap(), addr).await {
                    warn!("Error sending find_node: {:?} to {:?}.", e, addr);
                } else {
                    trace!("{:?}", find_node);
                }
            }
        }
    }

    //Initial find_nodes to populate routing table, per stack
    for stack in &stacks {
        let node_list = stack.table.lock().await.get_random_nodes(10);
        for node in node_list {
            let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), Some(ctx.want_list()), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));

            if let Err(e) = stack.sock.send_to(&find_node.to_bencode().unwrap(), node.addr.socket_addr()).await {
                warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
                stack.table.lock().await.remove_node(&node.id);
            } else {
                trace!("{:?}", find_node);
            }
        }
    }

    //Find closest nodes to us, per stack
    for stack in &stacks {
        let start_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut last_nodes_count = stack.table.lock().await.nodes.len();
        loop {
            let nodes = stack.table.lock().await.get_closest_nodes(&node_id, 5);
            for node in nodes {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), node_id.clone(), Some(ctx.want_list()), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));

                if let Err(e) = stack.sock.send_to(&find_node.to_bencode().unwrap(), node.addr.socket_addr()).await {
                    warn!("Error sending find_node: {:?} to {:?}, removing node.", e, node.addr);
                    stack.table.lock().await.remove_node(&node.id);
                } else {
                    trace!("{:?}", find_node);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let nodes_size = stack.table.lock().await.nodes.len();
            if nodes_size == last_nodes_count {
                break;
            } else {
                last_nodes_count = nodes_size;
            }

            //We should give up after a certain period of time.
            if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - start_time > 25 {
                break;
            }
        }
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        for stack in &stacks {
            stack.table.lock().await.debug_stats();
            stack.table.lock().await.save();

            //Node management
            stack.table.lock().await.node_remove_dead();
            let nodes = stack.table.lock().await.node_get_for_ping();
            for node in nodes {
                let ping = proto::KRPCMessage::ping(node_id.clone(), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));

                if let Err(e) = stack.sock.send_to(&ping.to_bencode().unwrap(), node.addr.socket_addr()).await {
                    warn!("Error sending ping: {:?} to {:?}, removing node {:?}.", e, node.addr, node);
                    stack.table.lock().await.remove_node(&node.id);
                } else {
                    stack.table.lock().await.ping_update(&node.id);
                    trace!("Pinging {:?}", ping);
                }
            }

            //Refreshing bucket uses a random node in the bucket to find a randomly generated node in the bucket's range.
            let nodes = stack.table.lock().await.node_get_for_refresh();
            for (node, random_target) in nodes {
                let find_node = proto::KRPCMessage::find_node(node_id.clone(), random_target, Some(ctx.want_list()), transaction_counter.lock().await.get_transaction_id(node.addr.clone()));

                if let Err(e) = stack.sock.send_to(&find_node.to_bencode().unwrap(), node.addr.socket_addr()).await {
                    warn!("Error sending find_node: {:?} to {:?}, removing node {:?}.", e, node.addr, node);
                    stack.table.lock().await.remove_node(&node.id);
                } else {
                    trace!("{:?}", find_node);
                }
            }

            //Call get_peers for each info_hash we have stored if there are none.
            let info_hashes = stack.table.lock().await.info_hashes.clone();
            for (info_hash, node_set) in info_hashes.iter() {
                if node_set.len() == 0 {
                    let nodes = stack.table.lock().await.get_closest_nodes(&info_hash.clone(), 3);
                    for node in nodes {
                        let transaction_id = transaction_counter.lock().await.get_transaction_id(node.addr.clone());
                        stack.table.lock().await.get_peer_info_hash.insert(transaction_id.clone(), info_hash.clone());
                        let get_peers = proto::KRPCMessage::get_peers(node_id.clone(), info_hash.clone(), Some(ctx.want_list()), transaction_id.clone());

                        if let Err(e) = stack.sock.send_to(&get_peers.to_bencode().unwrap(), node.addr.socket_addr()).await {
                            warn!("Error sending get_peers: {:?} to {:?}, removing node {:?}.", e, node.addr, node);
                            stack.table.lock().await.remove_node(&node.id);
                        } else {
                            trace!("{:?}", get_peers);
                        }
                    }
                }
            }
        }
    }
}

/// Configuration for starting a [`DhtNode`]. At least one of `bind_v4`/`bind_v6` is required.
pub struct DhtNodeConfig {
    pub bind_v4: Option<SocketAddr>,
    pub bind_v6: Option<SocketAddr>,
    pub node_id: Option<NodeId>,
    //Persist this table's nodes to a file, reloaded on the next start with the same
    //node_id. None disables persistence (e.g. short-lived nodes with a rotating node_id,
    //where a saved table would never be reloaded anyway).
    pub rt_v4_path: Option<String>,
    pub rt_v6_path: Option<String>,
    //Addresses to bootstrap from when the routing table is empty, instead of the public
    //BOOTSTRAP_HOSTS. Empty (the default) means "use the public hosts," today's behavior.
    //Useful for callers starting many nodes at once (e.g. a scanner) that want later nodes
    //to bootstrap from already-known-good peers rather than repeatedly hitting shared
    //public infrastructure.
    pub bootstrap_nodes: Vec<SocketAddr>,
}

impl DhtNodeConfig {
    pub fn new() -> Self {
        DhtNodeConfig {
            bind_v4: None,
            bind_v6: None,
            node_id: None,
            rt_v4_path: Some("rt-v4.json".to_string()),
            rt_v6_path: Some("rt-v6.json".to_string()),
            bootstrap_nodes: Vec::new(),
        }
    }
}

impl Default for DhtNodeConfig {
    fn default() -> Self {
        DhtNodeConfig::new()
    }
}

/// A running DHT node. Dropping this does not stop the node - its receive/maintenance
/// tasks keep running in the background for as long as the tokio runtime that spawned
/// them is alive.
pub struct DhtNode {
    pub node_id: NodeId,
    handles: Vec<tokio::task::JoinHandle<()>>,
    stacks: Vec<Stack>,
}

impl DhtNode {
    /// Bind the configured socket(s), load/create routing tables, and start the node's
    /// background tasks (one receive loop per active address family, plus bootstrap/
    /// maintenance). Returns immediately once sockets are bound - bootstrap and warm-up
    /// happen in the background rather than blocking the caller.
    pub async fn start(config: DhtNodeConfig) -> io::Result<(DhtNode, mpsc::UnboundedReceiver<DhtEvent>)> {
        if config.bind_v4.is_none() && config.bind_v6.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "at least one of bind_v4/bind_v6 must be set"));
        }

        let node_id = config.node_id.unwrap_or_else(NodeId::generate_nodeid);
        let invalid_ping_response_version = proto::Version::from_hex("4c540101");

        let transaction_counter = Arc::new(Mutex::new(TransactionCounter::new()));

        let v4_stack = if let Some(addr) = config.bind_v4 {
            let sock = UdpSocket::bind(addr).await?;
            let table = RoutingTable::load_or_new(Some(node_id.clone()), config.rt_v4_path.as_deref());
            Some(Stack { sock: Arc::new(sock), table: Arc::new(Mutex::new(table)) })
        } else {
            None
        };

        let v6_stack = if let Some(addr) = config.bind_v6 {
            let std_sock = bind_v6_only(addr)?;
            let sock = UdpSocket::from_std(std_sock)?;
            let table = RoutingTable::load_or_new(Some(node_id.clone()), config.rt_v6_path.as_deref());
            Some(Stack { sock: Arc::new(sock), table: Arc::new(Mutex::new(table)) })
        } else {
            None
        };

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let ctx = DhtContext {
            node_id: node_id.clone(),
            v4: v4_stack,
            v6: v6_stack,
            transaction_counter,
            invalid_ping_response_version,
            event_tx,
            bootstrap_nodes: config.bootstrap_nodes,
        };

        let stacks: Vec<Stack> = ctx.v4.iter().chain(ctx.v6.iter()).cloned().collect();

        let mut handles = Vec::with_capacity(stacks.len() + 1);

        for stack in &stacks {
            let stack = stack.clone();
            let ctx = ctx.clone();
            handles.push(tokio::spawn(async move {
                receive_loop(stack, ctx).await;
            }));
        }

        {
            let ctx = ctx.clone();
            let stacks = stacks.clone();
            handles.push(tokio::spawn(async move {
                run_maintenance(ctx, stacks).await;
            }));
        }

        Ok((DhtNode { node_id, handles, stacks }, event_rx))
    }

    /// Stop this node's background tasks and release its socket(s). The associated
    /// `DhtEvent` receiver will stop yielding new events once this returns.
    pub fn shutdown(self) {
        for handle in &self.handles {
            handle.abort();
        }
    }

    /// Every peer address currently known across this node's active routing table(s).
    /// Useful for seeding other `DhtNode`s' `bootstrap_nodes` from a real, already-running
    /// node instead of the public bootstrap hosts.
    pub async fn known_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for stack in &self.stacks {
            let table = stack.table.lock().await;
            addrs.extend(table.nodes.values().map(|addr| addr.socket_addr()));
        }
        addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_resolve_announced_addr_implied_port_true_uses_source_port() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 6881));
        let resolved = resolve_announced_addr(src, 51413, Some(1));
        assert_eq!(resolved.socket_addr(), src);
    }

    #[test]
    fn test_resolve_announced_addr_implied_port_false_uses_announced_port() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 6881));
        let resolved = resolve_announced_addr(src, 51413, Some(0));
        assert_eq!(resolved.socket_addr(), SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 51413)));
    }

    #[test]
    fn test_resolve_announced_addr_implied_port_absent_uses_announced_port() {
        //Most real clients always send `port`; implied_port is optional and defaults to
        //"not set" when absent, which per BEP5 means the explicit port argument is used.
        let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 6881, 0, 0));
        let resolved = resolve_announced_addr(src, 51413, None);
        assert_eq!(resolved.socket_addr(), SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 51413, 0, 0)));
    }
}
