use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use json;

use crate::proto::{self, ByteArray, CompactAddress, CompactNode, CompactNodeList, InfoHash, NodeId, Token, TransactionId};

use crate::bucket::Buckets;

use log::{debug, info, trace};

#[derive(Debug, Clone)]
pub struct RoutingTable {

    //This clients node_id
    pub node_id: NodeId,

    //Buckets
    pub buckets: Buckets,

    //Map of node to peer info (ip, address)
    pub nodes: HashMap<NodeId, CompactAddress>,
    
    //Map of info_hash to node list
    pub info_hashes: HashMap<InfoHash, HashSet<NodeId>>,

    //Map of node to get_peer response
    pub tokens: HashMap<NodeId, Token>,

    //Map of node to generated tokens sent 
    pub sent_tokens: HashMap<NodeId, Token>,

    //Node -> (last heard from, last refresh time)
    pub nodes_time: HashMap<NodeId, (u64,u64)>,

    //TODO Keep track of stale/old nodes as backup?

    pub last_printed_nodes_len: usize,
    pub last_printed_info_hashes_len: usize,
    pub last_printed_tokens_len: usize,
    pub last_printed_sent_tokens_len: usize,
    pub last_printed_nodes_time_len: usize,
    pub last_printed_buckets_len: usize,
}

impl RoutingTable {

    pub fn new(node_id: &NodeId) -> Self {
        RoutingTable {
            node_id: node_id.clone(),
            nodes: HashMap::new(),
            info_hashes: HashMap::new(),
            tokens: HashMap::new(),
            sent_tokens: HashMap::new(),
            nodes_time: HashMap::new(),
            buckets: Buckets::new(&node_id),
            last_printed_nodes_len: 0,
            last_printed_info_hashes_len: 0,
            last_printed_tokens_len: 0,
            last_printed_sent_tokens_len: 0,
            last_printed_nodes_time_len: 0,
            last_printed_buckets_len: 0,
        }
    }

    pub fn debug_stats(&mut self) {

        if     self.last_printed_nodes_len != self.nodes.len()
            || self.last_printed_info_hashes_len != self.info_hashes.len()
            || self.last_printed_tokens_len != self.tokens.len()
            || self.last_printed_sent_tokens_len != self.sent_tokens.len()
            || self.last_printed_nodes_time_len != self.nodes_time.len()
            || self.last_printed_buckets_len != self.buckets.buckets.len() {

                debug!("Routing Table Stats - nodes size {:?}, info_hashes size {:?}, sent_tokens size {:?}, tokens size {:?}, pinged_nodes size {:?}, bucket size {:?}",
                    self.nodes.len(),
                    self.info_hashes.len(),
                    self.sent_tokens.len(),
                    self.tokens.len(),
                    self.nodes_time.len(),
                    self.buckets.buckets.len(),
                );

                self.last_printed_nodes_len = self.nodes.len();
                self.last_printed_info_hashes_len = self.info_hashes.len();
                self.last_printed_tokens_len = self.tokens.len();
                self.last_printed_sent_tokens_len = self.sent_tokens.len();
                self.last_printed_nodes_time_len = self.nodes_time.len();
                self.last_printed_buckets_len = self.buckets.buckets.len();
        }
    }

    //Save the routing table to a file
    pub fn save(&self) {

        let path = self.node_id.to_hex() + ".json";

        //NodeId
        let mut data = json::object!{
            node_id: self.node_id.to_hex(),
            nodes: {},
            info_hashes: {},
        };

        //Nodes
        for (node_id, addr) in &self.nodes {
            let addr_hex = hex::encode(addr.to_bytes());
            
            data["nodes"][node_id.to_hex()] = json::object!{
                "addr": addr_hex,
            };
        }

        //info_hashes
        for (info_hash, node_set) in &self.info_hashes {
            let mut node_set_hex = Vec::new();
            for node_id in node_set {
                node_set_hex.push(node_id.to_hex());
            }
            data["info_hashes"][info_hash.to_hex()] = json::array!(node_set_hex);
        }

        //node_times, tokens and sent_tokens are not saved

        std::fs::write(path, data.dump()).unwrap();
    }

    //Load the routing table from a file
    pub fn load_or_new(cmdline_node_id: Option<NodeId>) -> Self {

        #[allow(unused_assignments)] //Seems silly the compiler complains here.
        let mut node_id: Option<NodeId> = None;

        #[allow(unused_assignments)] //Seems silly the compiler complains here.
        let mut path = None;

        if let Some(id) = cmdline_node_id {
            node_id = Some(id.clone());
            path = Some(id.to_hex() + ".json");
        } else {
            //Check if there's a .json file in the current working directory
            let current_dir = std::env::current_dir().unwrap();
            if let Ok(entries) = std::fs::read_dir(current_dir) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let check_path = entry.path();
                        if check_path.is_file() && check_path.extension().and_then(|s| s.to_str()) == Some("json") {
                            //Use this json file as the routing table
                            let mut file_name = check_path.file_name().unwrap().to_str().unwrap().to_string();
                            file_name = file_name.replace(".json", "");
                            node_id = Some(NodeId::from_hex(file_name.as_str()));
                            path = Some(node_id.clone().unwrap().clone().to_hex() + ".json");
                            info!("Found routing table file: {:?}, trying to load...", path.clone().unwrap());
                        }
                    }
                }

                if path.is_none() {
                    //If not, generate a new node_id
                    node_id = Some(NodeId::generate_nodeid());
                    path = Some(node_id.clone().unwrap().clone().to_hex() + ".json");
                }
            }
        }

        let path = path.unwrap();

        //Check if the file exists located at path
        if Path::new(&path).exists() {
            //Load the file
            let data = json::parse(std::fs::read_to_string(path).unwrap().as_str()).unwrap();

            //NodeId
            let node_id = NodeId::from_hex(data["node_id"].as_str().unwrap());
            let mut routing_table = RoutingTable {
                node_id: node_id.clone(),
                nodes: HashMap::new(),
                info_hashes: HashMap::new(),
                tokens: HashMap::new(),
                sent_tokens: HashMap::new(),
                nodes_time: HashMap::new(),
                buckets: Buckets::new(&node_id),
                last_printed_nodes_len: 0,
                last_printed_info_hashes_len: 0,
                last_printed_tokens_len: 0,
                last_printed_sent_tokens_len: 0,
                last_printed_nodes_time_len: 0,
                last_printed_buckets_len: 0,
            };

            //Nodes
            for (node_id_hex, node_data) in data["nodes"].entries() {
                let node_id = NodeId::from_hex(node_id_hex);
                let addr = CompactAddress::new(hex::decode(node_data["addr"].as_str().unwrap()).unwrap());
                routing_table.nodes.insert(node_id, addr);
            }

            //info_hashes
            for (info_hash_hex, node_set) in data["info_hashes"].entries() {
                let info_hash = InfoHash::from_hex(info_hash_hex);
                let mut node_set_data = HashSet::new();
                for node_ids in node_set.members() {
                    for node_id_hex in node_ids.members() {
                        let node_id = NodeId::from_hex(node_id_hex.as_str().unwrap());
                        node_set_data.insert(node_id);
                    }
                }
                routing_table.info_hashes.insert(info_hash, node_set_data);
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

            debug!("Loaded routing table.");

            routing_table

        } else {
            debug!("Rotuing table not found, creating new using node_id: {:?}.", &node_id.clone().unwrap());
            RoutingTable::new(&node_id.unwrap())
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
                //Ping node if it has not communicated in 11 minutes, and it has not been pinged in the last minute
                if (current_time as i64 - time.0 as i64) > (60*11) && (current_time as i64 - time.1 as i64) > 60 {
                    nodes_to_ping.push(CompactNode::new(node_id.clone(), addr.clone()));
                }
            } else {
                nodes_to_ping.push(CompactNode::new(node_id.clone(), addr.clone()));
                self.nodes_time.insert(node_id.clone(), (current_time, current_time));
            }
        }
        nodes_to_ping
    }

    pub fn node_get_for_refresh(&mut self) ->Vec<CompactNode> {
        let mut to_refresh = Vec::new();

        for bucket in self.buckets.buckets.iter() {
            if bucket.last_changed + 60*15 < std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() {
                if bucket.nodes.len() == 0 {
                    continue;
                }
                
                let random_index = rand::Rng::gen_range(&mut rand::thread_rng(), 0..bucket.nodes.len());
                let node_id = bucket.nodes.get(random_index).unwrap();

                let addr = self.nodes.get(node_id).unwrap();
                to_refresh.push(CompactNode::new(node_id.clone(), addr.clone()));
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
            //Remove node if it has not responded in 15  minutes
            if current_time as i64 - time.0 as i64 > (60*15) {
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

        self.sent_tokens.remove(node_id);

        self.nodes_time.remove(node_id);

        self.buckets.remove(node_id);   
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
        let mut value_list = Vec::new();

        if let Some(node_set) = self.get_info_hash(info_hash) {
            for node_id in node_set {
                if let Some(addr) = self.get_node(node_id) {
                    value_list.push(addr.clone());
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
                
        (compact_node_list, Some(value_list))
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
        self.node_time_update(&node_id);
        self.nodes.insert(node_id.clone(), addr);
        self.buckets.add(node_id.clone());
    }

    pub fn get_node(&self, node_id: &NodeId) -> Option<&CompactAddress> {
        self.nodes.get(node_id)
    }

    pub fn get_random_nodes(&self, amount: usize) -> Vec<CompactNode> {
        let mut rng = rand::thread_rng();
        let mut node_list = Vec::new();

        //Get amount number of random nodes from node_list

        //Generate amount number of random indexes between 0 and node_list.len()
        let node_list_len = self.nodes.len();
        let mut indexes: Vec<usize> = Vec::new();
        while indexes.len() < amount && indexes.len() < node_list_len {
            let index = rand::Rng::gen_range(&mut rng, 0..node_list_len);
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

    //TODO
    #[allow(dead_code)]
    pub fn get_all_info_hashes(&self) -> Vec<InfoHash> {
        let mut info_hash_list = Vec::new();

        for info_hash in self.info_hashes.keys() {
            info_hash_list.push(info_hash.clone());
        }

        info_hash_list
    }

    pub fn add_token(&mut self, node_id: NodeId, token: Token) {
        self.node_time_update(&node_id);
        self.tokens.insert(node_id, token);
    }

    pub fn get_token(&mut self, node_id: &NodeId) -> Option<&Token> {
        if !self.tokens.contains_key(node_id) {
            let token = proto::Token::generate(4);
            self.tokens.insert(node_id.clone(), token);
        }
        self.tokens.get(node_id)
    }

    pub fn add_sent_token(&mut self, node_id: &NodeId, token: Token) {
        self.node_time_update(&node_id);
        self.sent_tokens.insert(node_id.clone(), token);
    }

    pub fn get_sent_token(&self, node_id: &NodeId) -> Option<Token> {
        let token = self.sent_tokens.get(node_id).unwrap().clone();
        Some(token)
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
        if id.0.len() != 4 {
            panic!("TransactionId is not 4 bytes long");
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
        let mut routing_table = RoutingTable::new(&node_id);

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