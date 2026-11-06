# Inline Secure TCP Payload Channel

A Linux/C prototype of an inline link encryptor for a selected TCP/IPv4 flow:

```text
PC1  <──Ethernet──>  Device1  <──direct Ethernet──>  Device2  <──Ethernet──>  PC2
                         \_____ authenticated TLS control _____/
```

Device1 and Device2 first establish a mutually authenticated TLS 1.3 control session configured to use the finite-field `ffdhe2048` group. The ephemeral Diffie–Hellman exchange creates fresh session secrets. The devices derive separate directional AES-256 keys and nonce prefixes with the TLS exporter. Only after the handshake succeeds does either device forward selected traffic.

The data plane uses Linux `AF_PACKET` raw sockets. A protected Ethernet frame is sent directly to the peer device: there is no UDP tunnel, outer IP header, or custom data-plane header. The IPv4 and TCP headers remain visible. Only the TCP payload is encrypted; the 16-byte GCM tag is appended immediately after the ciphertext.

## What is implemented

- Mutual certificate authentication for the two devices (private CA for the lab).
- TLS 1.3 with finite-field ephemeral DH (`ffdhe2048`).
- TLS exporter derivation of two independent 256-bit traffic keys and two 32-bit nonce prefixes.
- AES-256-GCM protection of only the TCP payload, with a 128-bit tag.
- A monotonically increasing 64-bit counter per sending direction. A nonce is `4-byte session prefix || 8-byte big-endian counter`; the counter is never reused under a traffic key.
- A separate authenticated TLS control record carrying the 12-byte nonce and SHA-256 fingerprint of the protected packet. The receiver uses the fingerprint to associate a nonce with a raw Ethernet frame even if the two paths arrive in a different order. This control record is not added to the data packet.
- Authentication before plaintext release. Failed GCM verification discards the packet.
- IPv4 and TCP checksum recalculation after both protection and restoration.
- A narrow flow selector (configured host IPv4 pair and TCP service port), bounded receive queues, queue expiry, and basic replay detection.
- Unprivileged unit tests for packet parsing, encryption/decryption, tamper rejection, and policy matching.

## Requirements

Tested build target: Ubuntu/Debian Linux, GCC, `make`, OpenSSL 1.1.1 or 3.x development headers, and `iproute2`.

```bash
sudo apt update
sudo apt install build-essential libssl-dev iproute2 iputils-ping curl
make
make test
```

Raw packet sockets require root or `CAP_NET_RAW`. The namespace lab requires root and network-namespace support.

## Build and unit tests

```bash
make
make test
```

Expected test output:

```text
PASS: parsing, checksums, AES-GCM, tamper rejection, nonce/frame matching, replay filter, and TCP policy
```

## Two-device network-namespace lab

The lab script creates four namespaces and three veth links. The two host namespaces use `10.10.0.1` and `10.10.0.2`. Device1 and Device2 use `192.0.2.1/30` and `192.0.2.2/30` on their direct peer link for the TLS control connection. Static neighbor entries direct host traffic to the adjacent inline device. Host MTU is 1484 so a 16-byte GCM tag fits inside the 1500-byte inter-device Ethernet MTU.

1. Create the topology:

   ```bash
   sudo scripts/lab.sh up
   ```

2. Generate a lab CA and one certificate for each device. The private CA key is for the lab only; do not commit private keys or generated certificates to a public repository.

   ```bash
   ./scripts/generate-certs.sh certs
   ```

3. In terminal 1, start Device2 (the TLS server):

   ```bash
   sudo ip netns exec isc-d2 ./inline-device server h0 p0 192.0.2.2 certs/d2.crt certs/d2.key certs/ca.crt dev1 <PC2_MAC> <D1_PEER_MAC> 10.10.0.2 10.10.0.1 8080
   ```

4. In terminal 2, start Device1 (the TLS client):

   ```bash
   sudo ip netns exec isc-d1 ./inline-device client h0 p0 192.0.2.2 certs/d1.crt certs/d1.key certs/ca.crt dev2 <PC1_MAC> <D2_PEER_MAC> 10.10.0.1 10.10.0.2 8080
   ```

   Replace the four MAC placeholders with the values printed by `scripts/lab.sh up`. The output also lists the corresponding interface names and MAC addresses.

5. In terminal 3, start a TCP service on PC2:

   ```bash
   sudo ip netns exec isc-pc2 python3 -m http.server 8080 --bind 10.10.0.2
   ```

6. From PC1, make a request:

   ```bash
   sudo ip netns exec isc-pc1 curl http://10.10.0.2:8080/
   ```

7. Ask either device to print counters with `SIGUSR1` (find its PID with `pgrep -a inline-device` inside the relevant namespace):

   ```bash
   sudo ip netns exec isc-d1 pkill -USR1 inline-device
   ```

8. Remove the namespaces:

   ```bash
   sudo scripts/lab.sh down
   ```

## Command-line arguments

```text
inline-device server|client HOST_IF PEER_IF CONTROL_IP CERT KEY CA PEER_DNS HOST_MAC PEER_MAC LOCAL_HOST_IP REMOTE_HOST_IP SERVICE_PORT
```

- `server|client`: Device2 listens; Device1 connects.
- `HOST_IF`: interface connected to the adjacent PC.
- `PEER_IF`: direct interface connected to the other inline device.
- `CONTROL_IP`: Device2's peer-link IPv4 address, TCP port 9443.
- `CERT`, `KEY`, `CA`: local certificate, private key, and trusted CA certificate.
- `PEER_DNS`: expected peer certificate DNS name (`dev1` or `dev2`).
- `HOST_MAC`: MAC address of the adjacent PC.
- `PEER_MAC`: MAC address of the other device's peer interface.
- `LOCAL_HOST_IP`, `REMOTE_HOST_IP`: protected host pair from this device's perspective.
- `SERVICE_PORT`: TCP port selected for protection, in either direction.

## Packet format and nonce association

For an original TCP payload `P`, the protected frame is:

```text
[Ethernet header][original IPv4 header][original TCP header][AES-GCM ciphertext(P)][16-byte GCM tag]
```

The IPv4 total length increases by 16. TCP sequence and acknowledgement numbers are not changed because the receiving device restores the original payload length before the destination host sees the segment. IPv4 and TCP checksums are recalculated for the protected frame and again for the restored frame.

AES-GCM needs a nonce at the receiver, but the assignment's data frame format has no space for a nonce field. Therefore, each sender announces the nonce and a SHA-256 fingerprint over the authenticated TLS control channel. The receiver matches this announcement to the raw data frame. The data frame remains a direct Ethernet frame with only ciphertext and tag appended to the TCP payload. A fresh counter value is consumed for every encrypted packet, including retransmissions of the same TCP sequence range. Directional keys and prefixes prevent cross-direction nonce reuse.

The handshake, key schedule, nonce association record, and receive-path invariants are described in [docs/protocol.md](docs/protocol.md).

## Scope and limitations

This is a course prototype, not a production VPN or a general-purpose transparent bridge.

- Supports untagged Ethernet-II IPv4/TCP only. VLAN tags, IPv6, UDP, IP fragments, and IP reassembly are not implemented.
- The policy protects one configured pair of host IPv4 addresses and one TCP service port. Other frames are not forwarded by this prototype; the lab uses static neighbor entries to avoid ARP forwarding.
- The two devices must have a direct L2 peer link and a reachable peer control address. TCP port 9443 is reserved for the TLS control session.
- The lab limits host MTU to 1484 bytes so the appended tag fits in a 1500-byte middle link. Oversized packets are dropped rather than fragmented.
- Queue sizes and lifetimes are bounded. If a data frame or its control announcement is lost, the unmatched item expires and the protected packet is dropped.
- The demo does not implement high availability, automatic reconnect, key rotation during a running process, or persistent replay state across restarts. A fresh TLS handshake creates new traffic keys and nonce prefixes.
- The example lab uses a generated local CA. Real deployments require secure CA provisioning, protected private keys, firewalling, and a full threat model.

## Security notes

- Do not disable certificate verification. Both peers must trust the same CA and verify the expected peer DNS identity.
- Do not reuse a traffic key with a reset nonce counter. Restart both devices to establish a new TLS session if the counter is exhausted or a process restarts.
- The control record is sent before the corresponding data frame. The receiver still authenticates the ciphertext/tag with AES-GCM before forwarding plaintext; the SHA-256 fingerprint is only an association key, not a substitute for GCM authentication.
- The host-facing kernel forwarding path is disabled in the lab. Do not deploy the prototype in a topology where a parallel plaintext path can bypass the inline devices.

## Repository hygiene

`certs/`, private keys, generated binaries, and packet captures are intentionally ignored by Git. Commit source, tests, scripts, and documentation only.
