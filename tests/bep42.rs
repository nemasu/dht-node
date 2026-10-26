//! Wire-level BEP 42 checks using local UDP sockets only.
use bendy::{decoding::FromBencode, encoding::ToBencode};
use dht_node::proto::{KRPCMessage, KRPCPayload, NodeId, TransactionId};
use dht_node::{Bep42Config, DhtSocket, NodeIdentityConfig, bep42};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

async fn ping(peer: &UdpSocket, destination: SocketAddr) -> NodeId {
    let tx = TransactionId::new(vec![0x42, 0x01]);
    let query = KRPCMessage::ping(NodeId::new(vec![0; 20]), tx.clone());
    peer.send_to(&query.to_bencode().unwrap(), destination)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut buffer = [0; 2048];
        loop {
            let (len, _) = peer.recv_from(&mut buffer).await.unwrap();
            let reply = KRPCMessage::from_bencode(&buffer[..len]).unwrap();
            if reply.message_type == "r" && reply.transaction_id == tx {
                assert_eq!(reply.ip.unwrap().socket_addr(), peer.local_addr().unwrap());
                match reply.payload {
                    KRPCPayload::KRPCQueryIdResponse { id, .. } => return id,
                    other => panic!("unexpected ping response: {other:?}"),
                }
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn generated_and_custom_ids_are_used_on_both_wire_families() {
    let peer4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let ip4 = "9.9.9.9".parse().unwrap();
    let ip6 = "2001:4860:4860::8888".parse().unwrap();
    let socket = DhtSocket::bind_with_bep42(
        Some("127.0.0.1:0".parse().unwrap()),
        Some("[::1]:0".parse().unwrap()),
        Bep42Config {
            public_ipv4: Some(ip4),
            public_ipv6: Some(ip6),
            ..Bep42Config::default()
        },
    )
    .await
    .unwrap();
    let bootstrap = vec![peer4.local_addr().unwrap(), peer6.local_addr().unwrap()];
    let (node, _) = socket
        .start_node(
            0,
            NodeIdentityConfig {
                bootstrap_nodes: bootstrap.clone(),
                ..NodeIdentityConfig::new()
            },
        )
        .await
        .unwrap();
    let id4 = ping(&peer4, socket.local_addr_v4().unwrap().unwrap()).await;
    let id6 = ping(&peer6, socket.local_addr_v6().unwrap().unwrap()).await;
    assert!(bep42::matches_ip(&id4, IpAddr::V4(ip4)));
    assert!(bep42::matches_ip(&id6, IpAddr::V6(ip6)));
    assert_eq!(node.node_id_v4().await, Some(id4));
    assert_eq!(node.node_id_v6().await, Some(id6));
    node.shutdown();

    // Reuse the same socket/slot; explicit IDs override pinned addresses as well.
    let custom = NodeId::new(vec![0x55; 20]);
    let (node, _) = socket
        .start_node(
            0,
            NodeIdentityConfig {
                node_id: Some(custom.clone()),
                bootstrap_nodes: bootstrap,
                ..NodeIdentityConfig::new()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        ping(&peer4, socket.local_addr_v4().unwrap().unwrap()).await,
        custom
    );
    assert_eq!(
        ping(&peer6, socket.local_addr_v6().unwrap().unwrap()).await,
        custom
    );
    node.shutdown();
}

#[tokio::test]
async fn malformed_custom_ids_are_rejected_without_panicking() {
    let socket = DhtSocket::bind(Some("127.0.0.1:0".parse().unwrap()), None)
        .await
        .unwrap();
    let result = socket
        .start_node(
            0,
            NodeIdentityConfig {
                node_id: Some(NodeId::new(vec![1; 19])),
                ..NodeIdentityConfig::new()
            },
        )
        .await;
    assert!(matches!(result, Err(e) if e.kind() == std::io::ErrorKind::InvalidInput));
}
