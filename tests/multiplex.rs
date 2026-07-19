//! Integration tests for `DhtSocket` (many logical DHT identities sharing one UDP socket
//! per address family) over real loopback UDP - no public DHT/network access needed.
//! These only exercise the crate's public API (`DhtSocket`/`DhtNode`/`DhtEvent`/`proto`);
//! see `src/dht.rs`'s own `#[cfg(test)]` module for white-box unit tests of the private
//! `Registry`/`guess_identity` routing internals.

use bendy::decoding::FromBencode;
use bendy::encoding::ToBencode;
use dht_node::proto::{CompactAddress, KRPCMessage, KRPCPayload, NodeId, TransactionId};
use dht_node::{DhtEvent, DhtNode, DhtNodeConfig, DhtSocket, NodeIdentityConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn nid(byte: u8) -> NodeId {
    NodeId::new(vec![byte; 20])
}

/// Waits (bounded) for the next event matching `pred`, discarding non-matching events -
/// `handle_packet` can emit unrelated events (e.g. from background maintenance traffic)
/// interleaved with the one a test cares about.
async fn recv_event_matching<F: Fn(&DhtEvent) -> bool>(rx: &mut UnboundedReceiver<DhtEvent>, timeout: Duration, pred: F) -> Option<DhtEvent> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) if pred(&event) => return Some(event),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

#[tokio::test]
async fn get_peers_routes_to_xor_closest_identity_on_first_contact() {
    let dht_socket = DhtSocket::bind(Some(loopback(0)), None).await.unwrap();
    let addr = dht_socket.local_addr_v4().unwrap().unwrap();

    let ids = [nid(0x11), nid(0x55), nid(0xAA)];
    let mut nodes = Vec::new();
    let mut receivers = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let identity = NodeIdentityConfig { node_id: Some(id.clone()), ..NodeIdentityConfig::new() };
        let (node, rx) = dht_socket.start_node(i as u16, identity).await.unwrap();
        nodes.push(node);
        receivers.push(rx);
    }

    for (i, id) in ids.iter().enumerate() {
        // A fresh source address per send, so each query is genuinely a "first contact"
        // decided by content (XOR-closest), not by a sticky entry from an earlier send.
        let test_sock = UdpSocket::bind(loopback(0)).await.unwrap();
        let query = KRPCMessage::get_peers(nid(0xFF), id.clone(), None, TransactionId::new(vec![0, 0, 0, 1]));
        test_sock.send_to(&query.to_bencode().unwrap(), addr).await.unwrap();

        let observed = recv_event_matching(&mut receivers[i], Duration::from_secs(2), |e| matches!(e, DhtEvent::InfoHashObserved { .. })).await;
        assert!(observed.is_some(), "identity {} did not see its own get_peers query", i);

        for (j, rx) in receivers.iter_mut().enumerate() {
            if j == i {
                continue;
            }
            let unexpected = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
            assert!(unexpected.is_err(), "identity {} unexpectedly saw identity {}'s query", j, i);
        }
    }
}

#[tokio::test]
async fn get_peers_then_announce_peer_round_trips_through_same_identity() {
    let dht_socket = DhtSocket::bind(Some(loopback(0)), None).await.unwrap();
    let addr = dht_socket.local_addr_v4().unwrap().unwrap();

    let id_a = nid(0x11);
    let id_b = nid(0xEE);
    let (_node_a, mut rx_a) = dht_socket.start_node(0, NodeIdentityConfig { node_id: Some(id_a.clone()), ..NodeIdentityConfig::new() }).await.unwrap();
    let (_node_b, mut rx_b) = dht_socket.start_node(1, NodeIdentityConfig { node_id: Some(id_b.clone()), ..NodeIdentityConfig::new() }).await.unwrap();

    let test_sock = UdpSocket::bind(loopback(0)).await.unwrap();
    let peer_id = nid(0x99);
    let mut buf = [0u8; 1024];

    // Prime identity A's routing table with one entry (test_sock itself), so the
    // upcoming get_peers response's "nodes" list is non-empty - an *empty* compact node
    // list is a pre-existing, unrelated wire-encoding quirk (it fails to decode back as
    // itself), not something specific to multiplexing; this just avoids hitting it. This
    // find_node also establishes sticky[test_sock_addr] = A, via the first-contact
    // XOR-closest guess (target is A's exact node id, distance 0).
    let find_node = KRPCMessage::find_node(peer_id.clone(), id_a.clone(), None, TransactionId::new(vec![0, 0, 0, 1]));
    test_sock.send_to(&find_node.to_bencode().unwrap(), addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), test_sock.recv_from(&mut buf)).await.unwrap().unwrap();

    // get_peers from the same address - sticky keeps routing it to A.
    let get_peers = KRPCMessage::get_peers(peer_id.clone(), id_a.clone(), None, TransactionId::new(vec![0, 0, 0, 2]));
    test_sock.send_to(&get_peers.to_bencode().unwrap(), addr).await.unwrap();

    let observed = recv_event_matching(&mut rx_a, Duration::from_secs(2), |e| matches!(e, DhtEvent::InfoHashObserved { .. })).await;
    assert!(observed.is_some(), "identity A did not observe the get_peers query");

    let (len, _) = tokio::time::timeout(Duration::from_secs(2), test_sock.recv_from(&mut buf)).await.unwrap().unwrap();
    let response = KRPCMessage::from_bencode(&buf[..len]).unwrap();
    let token = match response.payload {
        KRPCPayload::KRPCQueryGetPeersResponse { token, .. } => token,
        other => panic!("expected a get_peers response with a token, got {:?}", other),
    };

    // announce_peer from the same source port/socket - sticky[addr] must still point at
    // A (not B), or this token (minted by A's own RoutingTable) would spuriously fail
    // validation there. This is the single most important invariant the whole
    // multiplexing design depends on.
    let announce = KRPCMessage::announce_peer(peer_id.clone(), id_a.clone(), token, 6881, TransactionId::new(vec![0, 0, 0, 3]));
    test_sock.send_to(&announce.to_bencode().unwrap(), addr).await.unwrap();

    let announced = recv_event_matching(&mut rx_a, Duration::from_secs(2), |e| matches!(e, DhtEvent::PeerAnnounced { .. })).await;
    assert!(announced.is_some(), "identity A did not see the announce_peer - token routing broke");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx_b.recv()).await.is_err(),
        "identity B unexpectedly saw traffic meant for A"
    );
}

#[tokio::test]
async fn sticky_address_wins_over_content_guess_once_established() {
    let dht_socket = DhtSocket::bind(Some(loopback(0)), None).await.unwrap();
    let addr = dht_socket.local_addr_v4().unwrap().unwrap();

    let id_a = nid(0x11);
    let id_b = nid(0xEE);
    let (_node_a, mut rx_a) = dht_socket.start_node(0, NodeIdentityConfig { node_id: Some(id_a.clone()), ..NodeIdentityConfig::new() }).await.unwrap();
    let (_node_b, mut rx_b) = dht_socket.start_node(1, NodeIdentityConfig { node_id: Some(id_b.clone()), ..NodeIdentityConfig::new() }).await.unwrap();

    let test_sock = UdpSocket::bind(loopback(0)).await.unwrap();
    let peer_id = nid(0x77);

    // First contact from this address targets A's exact node id - establishes
    // sticky[test_sock_addr] = A.
    let first = KRPCMessage::get_peers(peer_id.clone(), id_a.clone(), None, TransactionId::new(vec![0, 0, 0, 1]));
    test_sock.send_to(&first.to_bencode().unwrap(), addr).await.unwrap();
    let seen_a = recv_event_matching(&mut rx_a, Duration::from_secs(2), |e| matches!(e, DhtEvent::InfoHashObserved { .. })).await;
    assert!(seen_a.is_some());

    // Second query from the SAME address now targets B's exact node id - by content
    // alone this "should" go to B, but the documented (accepted, not "ideal") behavior
    // is that a live sticky entry always wins over re-deriving from a query's content,
    // so it still routes to A.
    let second = KRPCMessage::get_peers(peer_id.clone(), id_b.clone(), None, TransactionId::new(vec![0, 0, 0, 2]));
    test_sock.send_to(&second.to_bencode().unwrap(), addr).await.unwrap();

    let seen_a_again = recv_event_matching(&mut rx_a, Duration::from_secs(2), |e| matches!(e, DhtEvent::InfoHashObserved { .. })).await;
    assert!(seen_a_again.is_some(), "expected the second query to still be routed to A via the sticky entry");

    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx_b.recv()).await.is_err(),
        "B should never see traffic once A holds the sticky entry for this address"
    );
}

#[tokio::test]
async fn dht_socket_identity_interoperates_with_plain_dht_node() {
    // Identity A lives on a DhtSocket (the new multiplexed path).
    let dht_socket = DhtSocket::bind(Some(loopback(0)), None).await.unwrap();
    let addr_a = dht_socket.local_addr_v4().unwrap().unwrap();
    let id_a = nid(0x33);
    let (_node_a, _rx_a) = dht_socket.start_node(0, NodeIdentityConfig { node_id: Some(id_a.clone()), ..NodeIdentityConfig::new() }).await.unwrap();

    // Node B is a completely ordinary, unmodified single-socket DhtNode, bootstrapped
    // straight at A - this exercises the existing DhtNode::start path unchanged, talking
    // to an identity on the new shared-socket path.
    let config_b = DhtNodeConfig {
        bind_v4: Some(loopback(0)),
        bind_v6: None,
        node_id: Some(nid(0x99)),
        rt_v4_path: None,
        rt_v6_path: None,
        bootstrap_nodes: vec![addr_a],
    };
    let (node_b, _rx_b) = DhtNode::start(config_b).await.unwrap();

    // B's own startup bootstrap (run_maintenance) sends a find_node to A; give it a
    // moment to round-trip over real loopback UDP.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let known = node_b.known_addrs().await;
    assert!(known.contains(&addr_a), "B never learned about A from a real bootstrap round trip through the shared socket");
}

#[tokio::test]
async fn response_to_own_outbound_query_routes_back_via_transaction_id_key_not_guessing() {
    let dht_socket = DhtSocket::bind(Some(loopback(0)), None).await.unwrap();
    let addr = dht_socket.local_addr_v4().unwrap().unwrap();

    let peer_sock = UdpSocket::bind(loopback(0)).await.unwrap();
    let peer_addr = peer_sock.local_addr().unwrap();
    let peer_id = nid(0x44);

    let id_a = nid(0x11);
    let id_b = nid(0xEE);
    let (node_a, _rx_a) = dht_socket
        .start_node(0, NodeIdentityConfig { node_id: Some(id_a.clone()), bootstrap_nodes: vec![peer_addr], ..NodeIdentityConfig::new() })
        .await
        .unwrap();
    let (_node_b, mut rx_b) = dht_socket.start_node(1, NodeIdentityConfig { node_id: Some(id_b.clone()), ..NodeIdentityConfig::new() }).await.unwrap();

    // A's own maintenance bootstrap sends a find_node to peer_addr on startup (its table
    // is empty and bootstrap_nodes is non-empty) - receive it to grab A's real
    // transaction id (with A's key encoded in its top 16 bits).
    let mut buf = [0u8; 1024];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), peer_sock.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(from, addr, "A's outbound query should appear to come from the shared socket's address");
    let query = KRPCMessage::from_bencode(&buf[..len]).unwrap();

    // Reply as a real peer would. This must come back to A specifically (not B) purely
    // because of the transaction id's embedded key - an "r" message with a live key
    // always wins, with no sticky/content guessing involved.
    let response = KRPCMessage::find_node_response(peer_id, None, None, query.transaction_id, CompactAddress::new_from_sockaddr(addr));
    peer_sock.send_to(&response.to_bencode().unwrap(), addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        node_a.known_addrs().await.contains(&peer_addr),
        "A never recorded the peer it bootstrapped from - its own response wasn't routed back to it"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx_b.recv()).await.is_err(),
        "B must not see A's own outbound query's response"
    );
}
