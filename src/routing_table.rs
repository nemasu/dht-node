use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::proto::{self, CompactAddress, CompactNode, CompactNodeList, InfoHash, NodeId, Token};

use log::{debug, error, info, warn, trace};

#[derive(Debug, Clone)]
pub struct RoutingTable {
    //Map of node to peer info (ip, address)
    pub nodes: HashMap<NodeId, CompactAddress>,
    
    //Map of info_hash to node list
    pub info_hashes: HashMap<InfoHash, HashSet<NodeId>>,

    //Map of node to get_peer response
    pub tokens: HashMap<NodeId, Token>,

    //Map of node to generated tokens sent 
    pub sent_tokens: HashMap<NodeId, HashSet<Token>>,

    //Node -> (last heard from, last pinged)
    pub nodes_time: HashMap<NodeId, (u64,u64)>,
}

impl RoutingTable {

    pub fn debug_stats(&self) {
        debug!("Routing Table Stats - nodes size {:?}, info_hashes size {:?}, sent_tokens size {:?}, tokens size {:?} pinged_nodes size {:?}",
            self.nodes.len(),
            self.info_hashes.len(),
            self.sent_tokens.len(),
            self.tokens.len(),
            self.nodes_time.len()
        );
    }

    //Save the routing table to a file
    pub fn save(&self, path: &str) {
       //TODO
    }

    //Load the routing table from a file
    pub fn load_or_new(path: &str) -> Self {

        //Check if the file exists located at path
        if Path::new(path).exists() {
            RoutingTable::new()
        } else {
            //let data: Vec<u8> = std::fs::read(path).unwrap();

            RoutingTable::new()
        }
    }

    pub fn new() -> Self {
        RoutingTable {
            nodes: HashMap::new(),
            info_hashes: HashMap::new(),
            tokens: HashMap::new(),
            sent_tokens: HashMap::new(),
            nodes_time: HashMap::new(),
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

    pub fn node_get_for_ping(&self) -> Vec<CompactNode> {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut nodes_to_ping = Vec::new();
        for (node_id, addr) in &self.nodes {
            if let Some(time) = self.nodes_time.get(node_id) {
                //Ping node if it has not communicated in 11 minutes, and it has not been pinged in the last minute
                if (current_time as i64 - time.0 as i64) > (60*11) && (current_time as i64 - time.1 as i64) > 60 {
                    nodes_to_ping.push(CompactNode::new(node_id.clone(), addr.clone()));
                }
            }
        }
        nodes_to_ping
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
            self.nodes.remove(&node_id);
            
            //Remove the hashset entry from info_hashes
            for (info_hash, node_set) in &mut self.info_hashes.clone() {
                for node in node_set.clone() {
                    if node == node_id {
                        self.info_hashes.get_mut(info_hash).unwrap().remove(&node_id);
                    }
                }
            }

            self.tokens.remove(&node_id);

            self.sent_tokens.remove(&node_id);

            self.nodes_time.remove(&node_id);
        }
    }

    //used for get_peers response
    pub fn get_node_list_for_info_hash(&self, info_hash: &InfoHash) -> CompactNodeList {
        let mut node_list = Vec::new();

        if let Some(node_set) = self.get_info_hash(info_hash) {
            for node_id in node_set {
                if let Some(addr) = self.get_node(node_id) {
                    node_list.push(CompactNode::new(node_id.clone(), addr.clone()));
                }
            }
        }

        //TODO calculate closest nodes to respond with if we don't have the info_hash
        //Random for now
        while node_list.len() < 8 {
            let random_node = self.get_random_nodes(1);
            node_list.push(random_node[0].clone());
        }
                
        CompactNodeList::new_from_vec(node_list)
    }

    //used for find_node response
    pub fn get_node_list_for_node_id(&self, node_id: &NodeId) -> CompactNodeList {
        let mut node_list = Vec::new();

        //TODO calculate closest nodes to respond with
        //Random for now
        while node_list.len() < 8 {
            let random_node = self.get_random_nodes(1);
            node_list.push(random_node[0].clone());
        }
                
        CompactNodeList::new_from_vec(node_list)
    }
    

    pub fn add_node(&mut self, node_id: NodeId, addr: CompactAddress) {
        self.node_time_update(&node_id);
        self.nodes.insert(node_id, addr);
    }

    pub fn get_node(&self, node_id: &NodeId) -> Option<&CompactAddress> {
        self.nodes.get(node_id)
    }

    pub fn remove_node(&mut self, node_id: &NodeId) {
        self.nodes.remove(node_id);
    }

    pub fn get_all_nodes(&self) -> Vec<CompactNode> {
        let mut node_list = Vec::new();

        for (node_id, addr) in &self.nodes {
            node_list.push(CompactNode::new(node_id.clone(), addr.clone()));
        }

        node_list
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

    pub fn add_info_hash(&mut self, info_hash: InfoHash, node_id: NodeId) {
        self.node_time_update(&node_id);
        let node_set = self.info_hashes.entry(info_hash).or_insert(HashSet::new());
        node_set.insert(node_id);
    }

    pub fn get_info_hash(&self, info_hash: &InfoHash) -> Option<&HashSet<NodeId>> {
        self.info_hashes.get(info_hash)
    }

    pub fn remove_info_hash(&mut self, info_hash: &InfoHash, node_id: &NodeId) {
        if let Some(node_set) = self.info_hashes.get_mut(info_hash) {
            node_set.remove(node_id);
        }
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

    pub fn remove_token(&mut self, node_id: &NodeId) {
        self.tokens.remove(node_id);
    }

    pub fn add_sent_token(&mut self, node_id: &NodeId, token: Token) {
        self.node_time_update(&node_id);
        let token_set = self.sent_tokens.entry(node_id.clone()).or_insert(HashSet::new());
        token_set.insert(token);
    }

    pub fn get_sent_token(&self, node_id: &NodeId) -> Option<&HashSet<Token>> {
        self.sent_tokens.get(node_id)
    }

    pub fn remove_sent_token(&mut self, node_id: &NodeId, token: &Token) {
        if let Some(token_set) = self.sent_tokens.get_mut(node_id) {
            token_set.remove(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;

    #[test]
    fn test_routing_table() {
        let mut routing_table = RoutingTable::new();

        let node_id = NodeId::generate_nodeid();
        let addr: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080);
        let compact_addr = CompactAddress::new_from_sockaddr(std::net::SocketAddr::V4(addr));

        routing_table.add_node(node_id.clone(), compact_addr.clone());

        let info_hash = InfoHash::generate(20);
        routing_table.add_info_hash(info_hash.clone(), node_id.clone());
        
        let node_list = routing_table.get_node_list_for_info_hash(&info_hash);
        println!("{:?}", node_list);
        assert_eq!(node_id, node_list.0.get(0).unwrap().id);
    }
}