#!/usr/bin/env bash
# Four-namespace inline lab: pc1 -- d1 -- d2 -- pc2
set -euo pipefail

NAMESPACES=(isc-pc1 isc-d1 isc-d2 isc-pc2)
cleanup() {
  for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
}

case "${1:-}" in
  down)
    cleanup
    echo "Lab namespaces removed."
    ;;
  up)
    if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0 up" >&2; exit 1; fi
    cleanup
    for ns in "${NAMESPACES[@]}"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

    # Create links and move each endpoint into its namespace.
    ip link add p1 type veth peer name d1h
    ip link set p1 netns isc-pc1; ip link set d1h netns isc-d1
    ip -n isc-pc1 link set p1 name eth0; ip -n isc-d1 link set d1h name h0

    ip link add d1p type veth peer name d2p
    ip link set d1p netns isc-d1; ip link set d2p netns isc-d2
    ip -n isc-d1 link set d1p name p0; ip -n isc-d2 link set d2p name p0

    ip link add d2h type veth peer name p2
    ip link set d2h netns isc-d2; ip link set p2 netns isc-pc2
    ip -n isc-d2 link set d2h name h0; ip -n isc-pc2 link set p2 name eth0

    # Hosts have a deliberately smaller MTU to leave 16 bytes for the GCM tag.
    ip -n isc-pc1 link set eth0 mtu 1484 up
    ip -n isc-pc2 link set eth0 mtu 1484 up
    ip -n isc-d1 link set h0 mtu 1500 up
    ip -n isc-d1 link set p0 mtu 1500 up
    ip -n isc-d2 link set p0 mtu 1500 up
    ip -n isc-d2 link set h0 mtu 1500 up

    ip -n isc-pc1 addr add 10.10.0.1/24 dev eth0
    ip -n isc-pc2 addr add 10.10.0.2/24 dev eth0
    ip -n isc-d1 addr add 192.0.2.1/30 dev p0
    ip -n isc-d2 addr add 192.0.2.2/30 dev p0

    # Do not let either inline device route an unprotected kernel copy.
    ip netns exec isc-d1 sysctl -q -w net.ipv4.ip_forward=0
    ip netns exec isc-d2 sysctl -q -w net.ipv4.ip_forward=0

    # Static neighbors avoid needing to bridge ARP broadcasts in this prototype.
    PC1_MAC=$(ip -n isc-pc1 -o link show eth0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    D1H_MAC=$(ip -n isc-d1 -o link show h0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    D1P_MAC=$(ip -n isc-d1 -o link show p0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    D2P_MAC=$(ip -n isc-d2 -o link show p0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    D2H_MAC=$(ip -n isc-d2 -o link show h0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    PC2_MAC=$(ip -n isc-pc2 -o link show eth0 | sed -n 's/.*link\/ether \([^ ]*\).*/\1/p')
    ip -n isc-pc1 neigh replace 10.10.0.2 lladdr "$D1H_MAC" dev eth0 nud permanent
    ip -n isc-pc2 neigh replace 10.10.0.1 lladdr "$D2H_MAC" dev eth0 nud permanent

    cat <<INFO
Lab is ready.
PC1: 10.10.0.1, MAC $PC1_MAC
Device1 host/peer: $D1H_MAC / $D1P_MAC
Device2 peer/host: $D2P_MAC / $D2H_MAC
PC2: 10.10.0.2, MAC $PC2_MAC

Start Device2 first, then Device1 (from the repository root):
  sudo ip netns exec isc-d2 ./inline-device server h0 p0 192.0.2.2 certs/d2.crt certs/d2.key certs/ca.crt dev1 $PC2_MAC $D1P_MAC 10.10.0.2 10.10.0.1 8080
  sudo ip netns exec isc-d1 ./inline-device client h0 p0 192.0.2.2 certs/d1.crt certs/d1.key certs/ca.crt dev2 $PC1_MAC $D2P_MAC 10.10.0.1 10.10.0.2 8080

Then run a TCP service on PC2 and connect from PC1. Remove the lab with: sudo $0 down
INFO
    ;;
  *) echo "Usage: sudo $0 {up|down}" >&2; exit 2 ;;
esac
