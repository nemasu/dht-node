use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use json;

use crate::proto::{ByteArray, CompactAddress, CompactNode, CompactNodeList, InfoHash, NodeId, Token, TransactionId};

use crate::bucket::Buckets;

use log::{debug, trace, warn};

#[derive(Debug, Clone)]
pub struct RoutingTable {

    //This clients node_id
    pub node_id: NodeId,

    //Path this table is persisted to/loaded from (kept separate per address family).
    //None disables persistence entirely (e.g. short-lived nodes with rotating node_ids,
    //where a saved table would never be reloaded under the same id anyway).
    pub path: Option<String>,

    //Buckets
    pub buckets: Buckets,

    //Map of node to peer info (ip, address)
    pub nodes: HashMap<NodeId, CompactAddress>,
    
    //Map of info_hash to node list
    pub info_hashes: HashMap<InfoHash, HashSet<NodeId>>,

    //Map of node to the tokens we've handed it in recent get_peers responses. A node may
    //legitimately query get_peers for several info_hashes before announcing any of them, so
    //we keep a short bounded history per node rather than only the single most recent token.
    pub tokens: HashMap<NodeId, Vec<Token>>,

    //Node -> (last heard from, last refresh time)
    pub nodes_time: HashMap<NodeId, (u64,u64)>,

    //These is used for resolving get_peer responses to node_id
    //sent TransactionId -> InfoHash
    pub get_peer_info_hash: HashMap<TransactionId, InfoHash>,
    //info_hash we're looking for -> address that has it
    pub ping_info_hash: HashMap<CompactAddress, InfoHash>,

    //TODO Keep track of stale/old nodes as backup?

    pub last_printed_nodes_len: usize,
    pub last_printed_info_hashes_len: usize,
    pub last_printed_tokens_len: usize,
    pub last_printed_nodes_time_len: usize,
    pub last_printed_buckets_len: usize,
}

impl RoutingTable {

    pub fn new(node_id: &NodeId, path: Option<&str>) -> Self {
        RoutingTable {
            node_id: node_id.clone(),
            path: path.map(|p| p.to_string()),
            nodes: HashMap::new(),
            info_hashes: HashMap::new(),
            tokens: HashMap::new(),
            nodes_time: HashMap::new(),
            buckets: Buckets::new(&node_id),
            get_peer_info_hash: HashMap::new(),
            ping_info_hash: HashMap::new(),

            last_printed_nodes_len: 0,
            last_printed_info_hashes_len: 0,
            last_printed_tokens_len: 0,
            last_printed_nodes_time_len: 0,
            last_printed_buckets_len: 0,
        }
    }

    pub fn debug_stats(&mut self) {

        if     self.last_printed_nodes_len != self.nodes.len()
            || self.last_printed_info_hashes_len != self.info_hashes.len()
            || self.last_printed_tokens_len != self.tokens.len()
            || self.last_printed_nodes_time_len != self.nodes_time.len()
            || self.last_printed_buckets_len != self.buckets.buckets.len() {

                debug!("Routing Table Stats - nodes size {:?}, info_hashes size {:?}, tokens size {:?}, pinged_nodes size {:?}, bucket size {:?}",
                    self.nodes.len(),
                    self.info_hashes.len(),
                    self.tokens.len(),
                    self.nodes_time.len(),
                    self.buckets.buckets.len(),
                );

                self.last_printed_nodes_len = self.nodes.len();
                self.last_printed_info_hashes_len = self.info_hashes.len();
                self.last_printed_tokens_len = self.tokens.len();
                self.last_printed_nodes_time_len = self.nodes_time.len();
                self.last_printed_buckets_len = self.buckets.buckets.len();
        }
    }

    //Save the routing table to a file, if persistence is enabled for this table.
    pub fn save(&self) {

        let path = match &self.path {
            Some(path) => path,
            None => return,
        };

        let mut data = json::object!{
            nodes: {},
        };

        //Nodes
        for (node_id, addr) in &self.nodes {
            let addr_hex = hex::encode(addr.to_bytes());

            data["nodes"][node_id.to_hex()] = json::object!{
                "addr": addr_hex,
            };
        }

        //node_id, info_hashes, node_times, tokens and sent_tokens are not saved

        std::fs::write(path, data.dump()).unwrap();
    }

    //Load the routing table from a file, or start a fresh one if persistence is disabled
    //(path is None) or no file exists yet at path.
    pub fn load_or_new(cmdline_node_id: Option<NodeId>, path: Option<&str>) -> Self {

        let node_id: Option<NodeId>;
        if let Some(id) = cmdline_node_id {
            node_id = Some(id.clone());
        } else {
            //If not, generate a new node_id
            node_id = Some(NodeId::generate_nodeid());
        }

        //Check if the file exists located at path
        if path.is_some_and(|p| Path::new(p).exists()) {
            let path = path.unwrap();

            //Load the file
            let data = json::parse(std::fs::read_to_string(path).unwrap().as_str()).unwrap();

            //NodeId
            let node_id = node_id.unwrap();
            let mut routing_table = RoutingTable {
                node_id: node_id.clone(),
                path: Some(path.to_string()),
                nodes: HashMap::new(),
                info_hashes: HashMap::new(),
                tokens: HashMap::new(),
                nodes_time: HashMap::new(),
                buckets: Buckets::new(&node_id),
                get_peer_info_hash: HashMap::new(),
                ping_info_hash: HashMap::new(),

                last_printed_nodes_len: 0,
                last_printed_info_hashes_len: 0,
                last_printed_tokens_len: 0,
                last_printed_nodes_time_len: 0,
                last_printed_buckets_len: 0,
            };

            //Nodes
            for (node_id_hex, node_data) in data["nodes"].entries() {
                let node_id = NodeId::from_hex(node_id_hex);
                let addr = CompactAddress::new(hex::decode(node_data["addr"].as_str().unwrap()).unwrap());
                routing_table.nodes.insert(node_id, addr);
            }

            //Insert nodes into buckets
            let mut nodes_to_remove = Vec::new();
            for (node_id, _) in &routing_table.nodes {
                if !routing_table.buckets.add(node_id.clone()) {
                    nodes_to_remove.push(node_id.clone());
                }
            }
            for node_id in nodes_to_remove {
                routing_table.remove_node(&node_id);
            }

            debug!("Loaded routing table, node_id: {:?}.", &node_id.clone());

            routing_table

        } else {
            debug!("Routing table not found, node_id: {:?}.", &node_id.clone().unwrap());
            RoutingTable::new(&node_id.unwrap(), path)
        }
    }

    pub fn node_time_update(&mut self, node_id: &NodeId) {
        //Insert/update node_id and current time
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if let Some(value) = self.nodes_time.get_mut(node_id)  {
            value.0 = current_time;
        } else {
            let time = (current_time, current_time);
            self.nodes_time.insert(node_id.clone(), time);
        }
    }

    pub fn node_get_for_ping(&mut self) -> Vec<CompactNode> {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut nodes_to_ping = Vec::new();
        for (node_id, addr) in &self.nodes {
            if let Some(time) = self.nodes_time.get(node_id) {
                //Ping node if it has not communicated in 15 minutes, and it has not been pinged in the last minute
                if (current_time as i64 - time.0 as i64) > (60*15) && (current_time as i64 - time.1 as i64) > 60 {
                    nodes_to_ping.push(CompactNode::new(node_id.clone(), addr.clone()));
                }
            } else {
                nodes_to_ping.push(CompactNode::new(node_id.clone(), addr.clone()));
                self.nodes_time.insert(node_id.clone(), (current_time, current_time));
            }
        }
        nodes_to_ping
    }

    pub fn node_get_for_refresh(&mut self) ->Vec<(CompactNode,NodeId)> {
        let mut to_refresh = Vec::new();

        for bucket in self.buckets.buckets.iter() {
            if bucket.last_changed + 60*15 < std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() {
                if bucket.nodes.len() == 0 {
                    continue;
                }
                
                //Destination node_id is a random node_id in the bucket
                let random_index = rand::RngExt::random_range(&mut rand::rng(), 0..bucket.nodes.len());
                let dest_node_id = bucket.nodes.get(random_index).unwrap();

                //Skip our own node_id
                if *dest_node_id == self.node_id {
                    trace!("node_get_for_refresh: Skipping our own node_id.");
                    continue;
                }

                //Target node_id is a random node_id in the bucket's range
                let rand_node_id = ByteArray::generate_range(bucket.min.clone(), bucket.max.clone());

                if let Some(addr) = self.nodes.get(dest_node_id) {
                    to_refresh.push((CompactNode::new(dest_node_id.clone(), addr.clone()), rand_node_id));
                } else {
                    warn!("node_get_for_refresh: Node {:?} not found in nodes map.", dest_node_id);
                }
            }
        }

        to_refresh
    }

    pub fn ping_update(&mut self, node_id: &NodeId) {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if let Some(time) = self.nodes_time.get_mut(node_id) {
            time.1 = current_time;
        }
    }

    pub fn node_remove_dead(&mut self) {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut nodes_to_remove = Vec::new();

        for (node_id, time) in &self.nodes_time {
            //Remove node if it has not responded in 17  minutes
            if current_time as i64 - time.0 as i64 > (60*17) {
                trace!("Node {} has not responded. Last message @ {}, last ping @ {}", node_id, time.0, time.1);
                nodes_to_remove.push(node_id.clone());
            }
        }

        //Remove nodes from all maps/sets that have not responded to ping
        for node_id in nodes_to_remove {
            self.remove_node(&node_id);
        }
    }

    pub fn remove_node(&mut self, node_id: &NodeId) {
        trace!("Removing node: {:?}", node_id);

        let addr = self.nodes.get(node_id).cloned();
        if addr.is_none() {
            //Nothing to do: this node was never in this table (e.g. our own node_id,
            //or a node belonging to the other address family's table).
            return;
        }

        self.nodes.remove(node_id);

        //Remove the hashset entry from info_hashes
        for (info_hash, node_set) in &mut self.info_hashes.clone() {
            for node in node_set.clone() {
                if node == *node_id {
                    self.info_hashes.get_mut(info_hash).unwrap().remove(node_id);
                }
            }
        }

        self.tokens.remove(node_id);

        self.nodes_time.remove(node_id);

        self.buckets.remove(node_id);

        if let Some(addr) = addr {
            self.ping_info_hash.remove(&addr);
        }
    }

    pub fn remove_node_by_addr(&mut self, addr: &CompactAddress) {
        let mut node_id = None;
        for (node_id_from_map, addr_from_map) in &self.nodes {
            if addr == addr_from_map {
                node_id = Some(node_id_from_map.clone());
                break;
            }
        }

        if let Some(node_id) = node_id {
            self.remove_node(&node_id);
        }
    }

    //used for get_peers response
    pub fn get_node_list_for_info_hash(&self, info_hash: &InfoHash) -> (CompactNodeList, Option<Vec<CompactAddress>>){
        let mut value_list = None;

        if let Some(node_set) = self.get_info_hash(info_hash) {
            value_list = Some(Vec::new());
            for node_id in node_set {
                if let Some(addr) = self.get_node(node_id) {
                    value_list.as_mut().unwrap().push(addr.clone());
                }
            }
        }

        let mut node_list = BTreeMap::new();
        //Calculate closest nodes to respond with if we don't have the info_hash
        for (node_id, addr) in &self.nodes {
            //XOR distance between node_id and info_hash
            let xor_result = ByteArray::xor_bytearray(node_id, &info_hash);
            node_list.insert(xor_result, CompactNode::new(node_id.clone(), addr.clone()));
        }

        // Create a CompactNodeList of the lowest 8 elements from the BTreeMap
        let lowest_nodes = node_list.iter().take(8).map(|(_, node)| node.clone()).collect::<Vec<CompactNode>>();
        let compact_node_list = CompactNodeList::new_from_vec(lowest_nodes);
                
        (compact_node_list, value_list)
    }

    //used for find_node response
    pub fn get_node_list_for_node_id(&self, node_id: &NodeId) -> CompactNodeList {
        //Calculate closest nodes to respond with
        let mut node_list = BTreeMap::new();
        for (node_id_from_map, addr) in &self.nodes {
            //XOR distance between node_id_from_map and node_id
            let xor_result = ByteArray::xor_bytearray(&node_id_from_map, &node_id);
            node_list.insert(xor_result, CompactNode::new(node_id_from_map.clone(), addr.clone()));
        }

        // Create a CompactNodeList of the lowest 8 elements from the BTreeMap
        let lowest_nodes = node_list.iter().take(8).map(|(_, node)| node.clone()).collect::<Vec<CompactNode>>();
        let compact_node_list = CompactNodeList::new_from_vec(lowest_nodes);

        compact_node_list
    }

    pub fn add_node(&mut self, node_id: NodeId, addr: CompactAddress) {
        //Only add this node if it's added to a bucket.
        if self.buckets.add(node_id.clone()) {
            self.node_time_update(&node_id);
            self.nodes.insert(node_id.clone(), addr);
        }
    }

    //This is used to add nodes that we have heard about, but not heard from yet.
    pub fn add_node_reference(&mut self, node_id: NodeId, addr: CompactAddress) {
        //Only add this node if it's added to a bucket.
        if self.buckets.add(node_id.clone()) {
            let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - (15*60);
            if self.nodes_time.get_mut(&node_id).is_none()  { //Only add the time if it doesn't exist yet.
                let time = (time, time);
                self.nodes_time.insert(node_id.clone(), time);
            }
            self.nodes.insert(node_id.clone(), addr);
        }
    }

    pub fn get_node(&self, node_id: &NodeId) -> Option<&CompactAddress> {
        self.nodes.get(node_id)
    }

    pub fn get_random_nodes(&self, amount: usize) -> Vec<CompactNode> {
        let mut rng = rand::rng();
        let mut node_list = Vec::new();

        //Get amount number of random nodes from node_list

        //Generate amount number of random indexes between 0 and node_list.len()
        let node_list_len = self.nodes.len();
        let mut indexes: Vec<usize> = Vec::new();
        while indexes.len() < amount && indexes.len() < node_list_len {
            let index = rand::RngExt::random_range(&mut rng, 0..node_list_len);
            if !indexes.contains(&index) {
                indexes.push(index);
            }
        }
        
        for index in indexes {
            let (node_id, addr) = self.nodes.iter().nth(index).unwrap();
            node_list.push(CompactNode::new(node_id.clone(), addr.clone()));
        }

        node_list
    }

    pub fn get_closest_nodes(&self, node_id: &NodeId, amount: usize) -> Vec<CompactNode> {
        let mut node_list = Vec::new();
        let mut node_map = BTreeMap::new();

        for (node_id_from_map, addr) in &self.nodes {
            //XOR distance between node_id_from_map and node_id
            let xor_result = ByteArray::xor_bytearray(node_id_from_map, node_id);
            node_map.insert(xor_result, CompactNode::new(node_id_from_map.clone(), addr.clone()));
        }

        // Create a CompactNodeList of the lowest 8 elements from the BTreeMap
        let lowest_nodes = node_map.iter().take(amount).map(|(_, node)| node.clone()).collect::<Vec<CompactNode>>();
        node_list.extend(lowest_nodes);

        node_list
    }

    pub fn add_info_hash(&mut self, info_hash: InfoHash, node_id: NodeId) {
        self.node_time_update(&node_id);
        let node_set = self.info_hashes.entry(info_hash).or_insert(HashSet::new());
        node_set.insert(node_id);
    }

    pub fn get_info_hash(&self, info_hash: &InfoHash) -> Option<&HashSet<NodeId>> {
        self.info_hashes.get(info_hash)
    }

    const MAX_TOKENS_PER_NODE: usize = 8;

    pub fn generate_token(&mut self, node_id: &NodeId) -> Token {
        let token = ByteArray::generate(4);
        self.node_time_update(&node_id);

        let tokens = self.tokens.entry(node_id.clone()).or_insert_with(Vec::new);
        tokens.push(token.clone());
        if tokens.len() > Self::MAX_TOKENS_PER_NODE {
            tokens.remove(0);
        }

        token
    }

    pub fn token_is_valid(&self, node_id: &NodeId, token: &Token) -> bool {
        self.tokens.get(node_id).map(|tokens| tokens.contains(token)).unwrap_or(false)
    }

    pub fn remove_token(&mut self, node_id: &NodeId) {
        self.tokens.remove(node_id);
    }
}

pub struct TransactionCounter {
    pub transaction_id: i32,

    pub id_addr_map: HashMap<i32, CompactAddress>,
}
impl TransactionCounter {
    pub fn new() -> Self {
        TransactionCounter {
            transaction_id: 0,
            id_addr_map: HashMap::new(),
        }
    }

    pub fn get_addr_for_tranaction_id(&self, id: TransactionId) -> Option<&CompactAddress> {
        //Reachable from network input (a peer's "e" error message can carry an arbitrary
        //transaction id) - decline rather than take down every other node sharing this
        //process over one malformed packet. The caller already treats None as "unknown
        //transaction, nothing to do."
        if id.0.len() != 4 {
            warn!("TransactionId is not 4 bytes long, ignoring.");
            return None;
        }

        //Convert id to i32 and get the address from the map
        let int_id = i32::from_be_bytes([id.0[0], id.0[1], id.0[2], id.0[3]]);

         // Get the address from the map
        self.id_addr_map.get(&int_id)
    }

    pub fn get_transaction_id(&mut self, addr: CompactAddress) -> ByteArray {
        self.transaction_id += 1;

        //Add the transaction id to the map
        self.id_addr_map.insert(self.transaction_id, addr);

        ByteArray::new_from_i32(self.transaction_id)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;

    #[test]
    fn test_xor() {
        let a = ByteArray::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let b = ByteArray::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let result = ByteArray::xor_bytearray(&a, &b);
        assert_eq!(result, ByteArray::new(vec![0, 0, 0, 0, 0, 0, 0, 0]));

        let a = ByteArray::new(vec![0x57, 0x9c, 0xbf, 0xd0, 0xcd, 0x1b, 0x56, 0x5d]);
        let b = ByteArray::new(vec![0x7C, 0xD5, 0x63, 0x21, 0xED, 0x45, 0x87, 0xCD]);
        let result = ByteArray::xor_bytearray(&a, &b);
        assert_eq!(result, ByteArray::new(vec![0x2B, 0x49, 0xDC, 0xF1, 0x20, 0x5E, 0xD1, 0x90]));
    }

    #[test]
    fn test_routing_table() {
        let node_id = NodeId::generate_nodeid();
        let mut routing_table = RoutingTable::new(&node_id, Some("rt-test.json"));

        let addr: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080);
        let compact_addr = CompactAddress::new_from_sockaddr(std::net::SocketAddr::V4(addr));

        routing_table.add_node(node_id.clone(), compact_addr.clone());

        let info_hash = InfoHash::generate(20);
        routing_table.add_info_hash(info_hash.clone(), node_id.clone());
        
        let node_list = routing_table.get_node_list_for_info_hash(&info_hash);
        println!("{:?}", node_list);
        assert_eq!(node_id, node_list.0.0.get(0).unwrap().id);
    }
}