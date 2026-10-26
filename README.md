![Build Status](https://github.com/nemasu/dht-node/actions/workflows/rust.yml/badge.svg)

# dht-node
BitTorrent DHT node.

This is a Rust library and standalone client for Mainline DHT. ([BEP-0005](https://www.bittorrent.org/beps/bep_0005.html))

It supports IPv4, IPv6, and multiple identities sharing one UDP socket per address family.

It uses [Bendy](https://github.com/P3KI/bendy) for bencode serialization/deserialization.

A few improvements can still be made:
- Old/stale node storage.
- Sending `announce_peer` requests.

The routing tables are stored in JSON files in the working directory as: `rt-v4.json` and `rt-v6.json`

Usage:
`dht-node <bind-address>... [node_id] [--public-ipv4 <ip>] [--public-ipv6 <ip>]`

eg. `dht-node 0.0.0.0:6881 [::]:6881`

## Node IDs ([BEP-0042](https://www.bittorrent.org/beps/bep_0042.html))

If no node_id is provided, a random node_id is used until the public IP is known, then it is
replaced with a BEP 42 node_id. IPv4 and IPv6 have independent node_ids.

The public IP is learned from the `ip` field of DHT responses. It must be reported by at least
three different /24 (IPv4) or /48 (IPv6) networks and by a majority of recent reports.

`--public-ipv4` / `--public-ipv6` set the public IP directly and skip discovery.

A provided node_id is always used unchanged, even if it is not BEP 42 compliant.

Requests from non-compliant nodes are still answered, as BEP 42 requires. They are logged
with the client version they report.
