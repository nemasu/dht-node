![Build Status](https://github.com/nemasu/dht-node/actions/workflows/rust.yml/badge.svg)

# dht-node
BitTorrent DHT node.

This is a standalone client for Mainline DHT. ([BEP-0005](https://www.bittorrent.org/beps/bep_0005.html))

It uses [Bendy](https://github.com/P3KI/bendy) for bencode serialization/deserialization.

It is mostly in a working state, but a few improvements can be made:
- Transaction ID confirmation.
- Old/stale node storage.
- IPV6 support

The routing table is stored in a JSON file in the working directory as: `<node_id_in_hex>.json`

Usage:
`dht-node <ip>:<port> <node_id>`
or
`dht-node <ip>:<port>`

If no node_id is provided, the working directory will be searched for a JSON file to use, if none are found a new node_id will be generated.
