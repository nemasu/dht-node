use std::collections::{HashMap, HashSet};

use crate::proto::{InfoHash, NodeId, CompactAddress};

#[derive(Debug, PartialEq)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addr: Option<CompactAddress>,
}

pub struct RoutingTable {
    nodes: HashMap<InfoHash, HashSet<PeerInfo>>,
}