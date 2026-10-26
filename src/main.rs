use dht_node::proto::NodeId;
use dht_node::{bep42, Bep42Config, DhtEvent, DhtNode, DhtNodeConfig};
use std::{io, net::SocketAddr};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use log::{debug, info, LevelFilter};

const USAGE: &str = "Usage: dht-node <bind-address>... [node_id]\n  eg. \"dht-node 0.0.0.0:6881\" (IPv4 only)\n      \"dht-node [::]:6881\" (IPv6 only)\n      \"dht-node 0.0.0.0:6881 [::]:6881\" (dual-stack)\n      \"dht-node 0.0.0.0:6881 [::]:6881 0123456789abcdef0123456789abcdef01234567\" (explicit node_id)\nAt least one IPv4 or IPv6 bind address is required. Without node_id, BEP 42 identities are generated after public-IP discovery.\nOptional --public-ipv4 <ip> and --public-ipv6 <ip> pin the public addresses.\nAn explicit node_id is used unchanged, even if it is not BEP 42 compliant.";

#[tokio::main]
async fn main() -> io::Result<()> {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto).unwrap();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut bep42 = Bep42Config::default();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--public-ipv4" || args[i] == "--public-ipv6" {
            let flag = args.remove(i);
            if i == args.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} requires an address")));
            }
            let value = args.remove(i);
            if flag == "--public-ipv4" {
                bep42.public_ipv4 = Some(value.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid public IPv4 address"))?);
            } else {
                bep42.public_ipv6 = Some(value.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid public IPv6 address"))?);
            }
        } else { i += 1; }
    }

    let mut bind_v4: Option<SocketAddr> = None;
    let mut bind_v6: Option<SocketAddr> = None;
    let mut cmdline_node_id: Option<NodeId> = None;

    if args.is_empty() {
        println!("{}", USAGE);
        return Ok(());
    }

    for arg in &args {
        match arg.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(a)) => {
                if bind_v4.is_some() {
                    println!("Multiple IPv4 bind addresses given.\n{}", USAGE);
                    return Ok(());
                }
                bind_v4 = Some(SocketAddr::V4(a));
            }
            Ok(SocketAddr::V6(a)) => {
                if bind_v6.is_some() {
                    println!("Multiple IPv6 bind addresses given.\n{}", USAGE);
                    return Ok(());
                }
                bind_v6 = Some(SocketAddr::V6(a));
            }
            Err(_) => {
                if cmdline_node_id.is_some() {
                    println!("Unrecognized argument: {}\n{}", arg, USAGE);
                    return Ok(());
                }
                //Length is validated by DhtNode::start_with_bep42.
                let bytes = hex::decode(arg).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "node ID must be hexadecimal"))?;
                cmdline_node_id = Some(NodeId::new(bytes));
            }
        }
    }

    if bind_v4.is_none() && bind_v6.is_none() {
        println!("{}", USAGE);
        return Ok(());
    }

    let config = DhtNodeConfig {
        bind_v4,
        bind_v6,
        node_id: cmdline_node_id,
        ..DhtNodeConfig::new()
    };

    let (node, mut events) = DhtNode::start_with_bep42(config, bep42).await?;
    info!("Started DHT node, IPv4 ID: {:?}, IPv6 ID: {:?}", node.node_id_v4().await, node.node_id_v6().await);

    while let Some(event) = events.recv().await {
        match event {
            DhtEvent::PeerAnnounced { info_hash, node_id, peer, version } => {
                debug!("Peer announced: info_hash {:?}, node {:?}{}, peer {:?}", info_hash, node_id, bep42::compliance_note(&node_id, peer.socket_addr().ip(), version.as_ref()), peer);
            }
            DhtEvent::PeerDiscovered { info_hash, peer } => {
                debug!("Peer discovered: info_hash {:?}, peer {:?}", info_hash, peer);
            }
            DhtEvent::InfoHashObserved { info_hash, querier, querier_addr, version } => {
                debug!("Info hash observed: {:?}, querier {:?}{}, querier_addr {:?}", info_hash, querier, bep42::compliance_note(&querier, querier_addr.socket_addr().ip(), version.as_ref()), querier_addr);
            }
        }
    }

    Ok(())
}
