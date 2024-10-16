use std::collections::{HashMap, HashSet};

use crate::proto::{PeerInfo, InfoHash};

pub struct RoutingTable {
    nodes: HashMap<InfoHash, HashSet<PeerInfo>>,
}