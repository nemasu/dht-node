use dht_node::proto::NodeId;
use dht_node::{DhtEvent, DhtNode, DhtNodeConfig};
use std::{io, net::SocketAddr};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use log::{debug, info, LevelFilter};

const USAGE: &str = "Usage: dht-node <bind-address>... [node_id]\n  eg. \"dht-node 0.0.0.0:6881\" (IPv4 only)\n      \"dht-node [::]:6881\" (IPv6 only)\n      \"dht-node 0.0.0.0:6881 [::]:6881\" (dual-stack)\n      \"dht-node 0.0.0.0:6881 [::]:6881 0123456789abcdef0123456789abcdef01234567\" (explicit node_id)\nAt least one IPv4 or IPv6 bind address is required. If no node_id is provided, one will be generated.";

#[tokio::main]
async fn main() -> io::Result<()> {
    TermLogger::init(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto).unwrap();

    let args = std::env::args().skip(1).collect::<Vec<_>>();

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
                cmdline_node_id = Some(NodeId::from_hex(arg));
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

    let (node, mut events) = DhtNode::start(config).await?;
    info!("Started DHT node, node_id: {:?}", node.node_id);

    while let Some(event) = events.recv().await {
        match event {
            DhtEvent::PeerAnnounced { info_hash, node_id, peer } => {
                debug!("Peer announced: info_hash {:?}, node {:?}, peer {:?}", info_hash, node_id, peer);
            }
            DhtEvent::PeerDiscovered { info_hash, peer } => {
                debug!("Peer discovered: info_hash {:?}, peer {:?}", info_hash, peer);
            }
            DhtEvent::InfoHashObserved { info_hash, querier, querier_addr } => {
                debug!("Info hash observed: {:?}, querier {:?}, querier_addr {:?}", info_hash, querier, querier_addr);
            }
        }
    }

    Ok(())
}
