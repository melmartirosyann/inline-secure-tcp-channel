# Protocol and security invariants

## Topology

```text
+------+       +----------+      direct Ethernet      +----------+       +------+
| PC1  |-------| Device 1 |===========================| Device 2 |-------| PC2  |
+------+       +----------+                            +----------+       +------+
                    \________ TLS 1.3 control ________/
```

The data and control paths are separate. `AF_PACKET` carries the original Ethernet frame between devices. A TCP connection on port 9443 carries only nonce/fingerprint control records. It does not carry host packets.

## Handshake and key schedule

1. Device2 listens on its peer-link control address. Device1 connects.
2. Both sides negotiate TLS 1.3 with the `ffdhe2048` finite-field ephemeral Diffie–Hellman group and `TLS_AES_256_GCM_SHA384`.
3. Each side validates the certificate chain against the configured CA and verifies the expected peer DNS identity. Both sides present certificates.
4. Once TLS reports a successful handshake, both sides call `SSL_export_keying_material` with the same exporter label and 72-byte output length.
5. The output is partitioned into client-to-server AES key (32 bytes), server-to-client AES key (32 bytes), client nonce prefix (4 bytes), and server nonce prefix (4 bytes).

The two AES directions use different keys, so nonce counters can independently start at zero without creating the same key/nonce pair. TLS session resumption is disabled for this prototype; a process restart establishes fresh handshake secrets.

## Data packet format

```text
Ethernet | IPv4 header | TCP header | ciphertext | 128-bit GCM tag
```

No nonce is inserted in this packet. The IPv4 total length is increased by the tag length. The TCP header, including its sequence and acknowledgement numbers, is retained. The IP and TCP checksums are recalculated because the protected TCP segment is longer.

The complete IPv4 and TCP headers are GCM additional authenticated data (AAD). TTL and the IP/TCP checksum fields are normalized to zero in AAD: TTL can be modified by a routed hop and checksums necessarily change during transformation. Ethernet addresses are excluded because they are link-local and are rewritten for the next Ethernet segment. All other parsed IP/TCP header bytes are authenticated.

## Nonce and association control record

For every protected frame, the sender increments a 64-bit counter and constructs:

```text
nonce = directional_4_byte_prefix || counter_as_8_byte_big_endian
record = nonce || SHA256(canonical_IP_TCP_headers || ciphertext || tag)
```

The 44-byte record is written to the authenticated TLS stream before the Ethernet frame is sent. TLS provides confidentiality, integrity, peer authentication, and ordered delivery for these records. The receiver checks the 4-byte expected directional prefix and requires each counter to be strictly greater than the previous accepted counter.

The receiver may see the control record before or after its corresponding raw frame. It stores both in bounded queues and matches them by the SHA-256 fingerprint. The fingerprint is an association key only: it does not authorize plaintext release. The receiver still runs AES-GCM verification with the associated nonce and directional key. Only successful `EVP_CipherFinal_ex` authentication allows the decrypted bytes to be committed and forwarded.

Every retransmitted TCP segment is encrypted again with a new counter value. The nonce is therefore not derived from TCP sequence numbers, which can repeat during retransmission.

## Receive path

1. Receive a direct Ethernet frame on the peer-facing raw socket.
2. Validate the supported Ethernet/IPv4/TCP structure and configured reverse flow policy.
3. Queue the protected frame and its fingerprint.
4. Match it with the nonce/fingerprint record from TLS.
5. Verify the GCM tag before releasing any plaintext.
6. Remove the trailing tag, restore the original IPv4 total length, and recalculate IP and TCP checksums.
7. Rewrite only the Ethernet source/destination addresses for the host-facing link and transmit the restored frame.

## Security and correctness invariants

- No selected packet is sent before mutual TLS authentication and exporter key derivation complete.
- No AES key/nonce pair is reused within a live session: each direction has a distinct key and a monotonically increasing counter.
- Counter wrap is fatal; both devices must establish a new session.
- A frame without an authenticated control record is never decrypted by guessing a nonce.
- A failed tag check never forwards plaintext.
- An authenticated control record cannot be replayed with an old counter.
- A duplicate data frame already accepted in the current bounded replay cache is dropped.
- The data-plane Ethernet frame is not UDP-encapsulated and carries no custom nonce header.
