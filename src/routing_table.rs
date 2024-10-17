use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::proto::{self, CompactAddress, CompactNode, CompactNodeList, InfoHash, NodeId, Token};

use log::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct RoutingTable {
    //Map of node to peer info (ip, address)
    pub nodes: HashMap<NodeId, CompactAddress>,
    
    //Map of info_hash to node list
    pub info_hashes: HashMap<InfoHash, HashSet<NodeId>>,

    //Map of node to announce_peer token recv'd by get_peers query.
    pub tokens: HashMap<NodeId, Token>,

    //Map of node to generated tokens
    pub sent_tokens: HashMap<NodeId, HashSet<Token>>,

    pub pinged_nodes: HashMap<NodeId, u32>,
}

impl RoutingTable {

    pub fn debug_stats(&self) {
        debug!("Routing Table Stats - nodes size {:?}, info_hashes size {:?}, sent_tokens size {:?}, tokens size {:?} pinged_nodes size {:?}",
            self.nodes.len(),
            self.info_hashes.len(),
            self.sent_tokens.len(),
            self.tokens.len(),
            self.pinged_nodes.len()
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
            pinged_nodes: HashMap::new(),
        }
    }

    pub fn ping_expect_response(&mut self, node_id: &NodeId) {
        //Insert node_id and current time
        self.pinged_nodes.insert(node_id.clone(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32);
    }

    pub fn ping_get(&mut self, node_id: &NodeId) {
        if self.pinged_nodes.contains_key(node_id) {
            self.pinged_nodes.remove(node_id);
        }
    }

    pub fn ping_remove_dead(&mut self) {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;

        let mut nodes_to_remove = Vec::new();

        for (node_id, time) in &self.pinged_nodes {
            if current_time - time > 10 {
                debug!("Node {} / {} has not responded to ping. Now: {}", node_id, time, current_time);
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

            self.pinged_nodes.remove(&node_id);
        }
    }

    pub fn get_node_list_for_info_hash(&self, info_hash: &InfoHash) -> CompactNodeList {
        let mut node_list = Vec::new();

        if let Some(node_set) = self.get_info_hash(info_hash) {
            for node_id in node_set {
                if let Some(addr) = self.get_node(node_id) {
                    node_list.push(CompactNode::new(node_id.clone(), addr.clone()));
                }
            }
        }
        
        CompactNodeList::new_from_vec(node_list)
    }

    pub fn add_node(&mut self, node_id: NodeId, addr: CompactAddress) {
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

    pub fn add_info_hash(&mut self, info_hash: InfoHash, node_id: NodeId) {
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
    fn test_ping_management() {
        let mut routing_table = RoutingTable::new();

        let node_id = NodeId::generate_nodeid();
        let addr: SocketAddrV4 = SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6881);
        let compact_addr = CompactAddress::new_from_sockaddr(std::net::SocketAddr::V4(addr));

        routing_table.add_node(node_id.clone(), compact_addr.clone());

        routing_table.ping_expect_response(&node_id);

        routing_table.ping_remove_dead();

        assert_eq!(routing_table.pinged_nodes.len(), 1);

        std::thread::sleep(std::time::Duration::from_secs(11));

        routing_table.ping_remove_dead();

        assert_eq!(routing_table.pinged_nodes.len(), 0);
    }

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