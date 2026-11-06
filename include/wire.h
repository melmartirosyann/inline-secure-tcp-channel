#ifndef ISC_WIRE_H
#define ISC_WIRE_H
#include <stddef.h>
#include <stdint.h>

#define ISC_FRAME_CAP 2048u
#define ISC_GCM_TAG 16u
#define ISC_GCM_NONCE 12u
#define ISC_AES_KEY 32u
#define ISC_DIGEST 32u
#define ISC_CONTROL_RECORD (ISC_GCM_NONCE + ISC_DIGEST)

struct ipv4_tcp_view {
    size_t ip_off;
    size_t tcp_off;
    size_t data_off;
    size_t end_off;
};

/* Supports Ethernet-II, untagged IPv4 and complete (unfragmented) TCP packets. */
int isc_parse_ipv4_tcp(const uint8_t *frame, size_t frame_len,
                       struct ipv4_tcp_view *view);
void isc_repair_checksums(uint8_t *frame, const struct ipv4_tcp_view *view);
int isc_gcm_transform(uint8_t *frame, size_t *frame_len,
                      const uint8_t key[ISC_AES_KEY],
                      const uint8_t nonce[ISC_GCM_NONCE], int encrypt);
int isc_packet_fingerprint(const uint8_t *frame, size_t frame_len,
                           uint8_t digest[ISC_DIGEST]);
#endif
