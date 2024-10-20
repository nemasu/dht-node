use std::collections::BTreeSet;

use crate::proto::{ByteArray, NodeId};

#[derive(Debug, Clone)]
pub struct Buckets {
    pub my_node_id: NodeId,
    pub buckets: BTreeSet<BucketNode>,
}
impl Buckets {
    pub fn new(my_node_id: &NodeId) -> Buckets {

        let mut buckets = BTreeSet::new();
        buckets.insert(BucketNode {
            min: NodeId::new_from_i32(0),
            max: NodeId::from_hex("ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"),
            nodes: vec![],
            last_changed: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        });

        let mut buckets = Buckets {
            my_node_id: my_node_id.clone(),
            buckets,
        };

        buckets.add(my_node_id.clone());
        buckets
    }
    pub fn add(&mut self, node_id: NodeId) -> bool {
        //Find the bucket that this belongs to
        let mut bucket_to_change = None;
        let mut is_split = false;
        for bucket in self.buckets.iter() {
            if node_id >= bucket.min && node_id <= bucket.max {
                bucket_to_change = Some(bucket.min.clone()); //Order/key is based on min
                if bucket.nodes.len() >= 8 && bucket.nodes.contains(&self.my_node_id) {
                    is_split = true;
                } else if bucket.nodes.len() >= 8 {
                    return false;
                }

                break
            }
        }

        if bucket_to_change.is_none() {
            println!("Buckets: {:?}, Node: {:?}", self.buckets, node_id);
        }

        let to_change = BucketNode::new_for_remove(bucket_to_change.unwrap());
        let mut bucket = self.buckets.take(&to_change).unwrap();
        if !is_split {
            bucket.nodes.push(node_id);
            
            bucket.last_changed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            self.buckets.insert(bucket);
        } else {
            let nodes_to_re_add = bucket.nodes.clone();

            let last_changed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            //First split, we split between 2^159 and 2^160
            if self.buckets.len() == 0 {
                
                let new_min_max = ByteArray::from_hex("80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

                let new_one = BucketNode {
                    min: ByteArray::new_from_i32(0),
                    max: new_min_max.clone(),
                    nodes: vec![],
                    last_changed,
                };

                let new_two = BucketNode {
                    min: ByteArray::add_one(&new_min_max),
                    max: ByteArray::from_hex("FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"),
                    nodes: vec![],
                    last_changed,
                };

                self.buckets.insert(new_one);
                self.buckets.insert(new_two);

                //Add them after just in case we need to split again.
                for node in nodes_to_re_add {
                    self.add(node);
                }
            } else {
                let middle = ByteArray::subtract(&bucket.max, &bucket.min);
                let middle = ByteArray::divide_by_2(&middle);
                let middle = ByteArray::add(&bucket.min, &middle.0);

                let mut new_one = BucketNode {
                    min: bucket.min.clone(),
                    max: middle.clone(),
                    nodes: vec![],
                    last_changed,
                };

                let mut new_two = BucketNode {
                    min: ByteArray::add_one(&middle.clone()),
                    max: bucket.max.clone(),
                    nodes: vec![],
                    last_changed,
                };

                for node in nodes_to_re_add {
                    if node >= new_one.min && node <= new_one.max {
                        new_one.nodes.push(node);
                    } else {
                        new_two.nodes.push(node);
                    }
                }

                if new_one.max <= new_one.min {
                    panic!("bucket range error! new_one: {:?}", new_one);
                } else if new_two.max <= new_two.min {
                    panic!("bucket range error! new_two: {:?}", new_two);
                }

                self.buckets.insert(new_one);
                self.buckets.insert(new_two);
            }
            
            self.add(node_id);
        }

        true
    }

    pub fn remove(&mut self, node_id: &NodeId) {
        //Find the bucket that this belongs to
        let mut bucket_to_change = None;
        for bucket in self.buckets.iter() {
            if *node_id >= bucket.min && *node_id <= bucket.max {
                bucket_to_change = Some(bucket.min.clone()); //Order/key is based on min
                break
            }
        }

        let to_change = BucketNode::new_for_remove(bucket_to_change.unwrap());
        let mut bucket = self.buckets.take(&to_change).unwrap();
        bucket.nodes.retain(|x| *x != *node_id);
        self.buckets.insert(bucket);
    }
}

#[derive(Debug, Clone)]
pub struct BucketNode {
    pub min: NodeId, //inclusive
    pub max: NodeId, //inclusive
    pub nodes: Vec<NodeId>,
    pub last_changed: u64,
}
impl BucketNode {
    pub fn new_for_remove(min: ByteArray) -> BucketNode {

        BucketNode {
            min: min,
            max: ByteArray::new_from_i32(0),
            nodes: vec![],
            last_changed: 0,
        }
    }
}
impl Ord for BucketNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}
impl PartialOrd for BucketNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.min < other.min {
            Some(std::cmp::Ordering::Less)
        } else if self.min > other.min {
            Some(std::cmp::Ordering::Greater)
        } else {
            Some(std::cmp::Ordering::Equal)
        }
    }
}
impl PartialEq for BucketNode {
    fn eq(&self, other: &Self) -> bool {
        self.min == other.min
    }
}
impl Eq for BucketNode { }

//add (NodeId) -> return true if added, return false if discarded
//get (NodeId) -> return all nodes in the bucket
//remove (NodeId) -> null


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket() {
        let mut buckets = Buckets::new(&NodeId::from_hex("2f 93 f9 66 9e fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 5c"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 5d"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 5e"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 5f"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 60"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 61"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 62"));
        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 63"));

        
        println!("{:?}", buckets.buckets);
        assert_eq!(buckets.buckets.len(), 1);

        buckets.add(NodeId::from_hex("00 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 64"));
        println!("{:?}", buckets.buckets);
        assert_eq!(buckets.buckets.len(), 4);
        
        buckets.add(NodeId::from_hex("50 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 64"));
        println!("{:?}", buckets.buckets);
        assert_eq!(buckets.buckets.len(), 4);

        buckets.add(NodeId::from_hex("80 00 00 00 00 fa 5b e2 04 8f 82 89 34 dc 0a c4 76 2d 8a 64"));
        println!("{:?}", buckets.buckets);
        assert_eq!(buckets.buckets.len(), 4);
    }

    #[test]
    fn test_bucket_node() {
        let node1 = BucketNode {
            min: NodeId::new_from_i32(0),
            max: NodeId::new_from_i32(10),
            nodes: vec![],
            last_changed: 0,
        };
        let node2 = BucketNode {
            min: NodeId::new_from_i32(11),
            max: NodeId::new_from_i32(20),
            nodes: vec![],
            last_changed: 0,
        };
        assert_eq!(node1 > node2, false);


        let node1 = BucketNode {
            min: NodeId::from_hex("aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa"),
            max: NodeId::from_hex("ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
            nodes: vec![],
            last_changed: 0,
        };
        let node2 = BucketNode {
            min: NodeId::from_hex("ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"),
            max: NodeId::from_hex("ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"),
            nodes: vec![],
            last_changed: 0,
        };
        assert_eq!(node1 < node2, true);
    }
}