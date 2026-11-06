#include "wire.h"
#include <string.h>
#include <openssl/evp.h>

static uint16_t read_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void write_be16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }

static uint32_t checksum_sum(const uint8_t *p, size_t n, uint32_t sum) {
    while (n >= 2) { sum += read_be16(p); p += 2; n -= 2; }
    if (n) sum += (uint32_t)p[0] << 8;
    return sum;
}
static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

int isc_parse_ipv4_tcp(const uint8_t *f, size_t n, struct ipv4_tcp_view *v) {
    if (!f || !v || n < 14u + 20u + 20u) return 0;
    if (read_be16(f + 12) != 0x0800 || (f[14] >> 4) != 4 || f[23] != 6) return 0;
    size_t ihl = (size_t)(f[14] & 0x0f) * 4u;
    size_t ip_total = read_be16(f + 16);
    if (ihl < 20 || ihl > 60 || ip_total < ihl + 20 || ip_total > 65535u) return 0;
    if (ip_total + 14u > n) return 0;
    /* Reject reserved/MF/fragment-offset bits; DF is permitted. */
    if (read_be16(f + 20) & 0xbfffu) return 0;
    size_t tcp = 14u + ihl;
    size_t thl = (size_t)(f[tcp + 12] >> 4) * 4u;
    if (thl < 20 || thl > 60 || ihl + thl > ip_total) return 0;
    v->ip_off = 14;
    v->tcp_off = tcp;
    v->data_off = tcp + thl;
    v->end_off = 14u + ip_total;
    return 1;
}

void isc_repair_checksums(uint8_t *f, const struct ipv4_tcp_view *v) {
    size_t ip_hlen = v->tcp_off - v->ip_off;
    size_t tcp_len = v->end_off - v->tcp_off;
    f[v->ip_off + 10] = f[v->ip_off + 11] = 0;
    write_be16(f + v->ip_off + 10,
               checksum_finish(checksum_sum(f + v->ip_off, ip_hlen, 0)));
    f[v->tcp_off + 16] = f[v->tcp_off + 17] = 0;
    /* IPv4 pseudo-header: source+destination, zero/protocol, TCP length. */
    uint32_t sum = checksum_sum(f + v->ip_off + 12, 8, 6u + (uint32_t)tcp_len);
    write_be16(f + v->tcp_off + 16,
               checksum_finish(checksum_sum(f + v->tcp_off, tcp_len, sum)));
}

/* Authenticate the visible IP/TCP headers, but exclude mutable TTL and checksums.
 * Ethernet addresses are deliberately excluded because each link has its own L2 hop.
 */
static size_t make_aad(const uint8_t *f, const struct ipv4_tcp_view *v, uint8_t out[120]) {
    size_t n = v->data_off - v->ip_off;
    memcpy(out, f + v->ip_off, n);
    out[8] = 0;                 /* IPv4 TTL */
    out[10] = out[11] = 0;     /* IPv4 checksum */
    size_t tcp_rel = v->tcp_off - v->ip_off;
    out[tcp_rel + 16] = out[tcp_rel + 17] = 0; /* TCP checksum */
    return n;
}

int isc_packet_fingerprint(const uint8_t *f, size_t n, uint8_t digest[ISC_DIGEST]) {
    struct ipv4_tcp_view v;
    uint8_t aad[120]; unsigned int got = 0;
    if (!isc_parse_ipv4_tcp(f, n, &v)) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    size_t aad_len = make_aad(f, &v, aad);
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, aad, aad_len) == 1 &&
             EVP_DigestUpdate(ctx, f + v.data_off, v.end_off - v.data_off) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &got) == 1 && got == ISC_DIGEST;
    EVP_MD_CTX_free(ctx);
    return ok;
}

int isc_gcm_transform(uint8_t *f, size_t *n,
                      const uint8_t key[ISC_AES_KEY],
                      const uint8_t nonce[ISC_GCM_NONCE], int encrypt) {
    struct ipv4_tcp_view v;
    uint8_t temporary[ISC_FRAME_CAP], aad[120];
    int out_len = 0, final_len = 0;
    if (!f || !n || !key || !nonce || !isc_parse_ipv4_tcp(f, *n, &v)) return 0;
    size_t payload_len = v.end_off - v.data_off;
    if (encrypt) {
        if (v.end_off + ISC_GCM_TAG > ISC_FRAME_CAP ||
            read_be16(f + 16) > 65535u - ISC_GCM_TAG) return 0;
        v.end_off += ISC_GCM_TAG;
        write_be16(f + 16, (uint16_t)(read_be16(f + 16) + ISC_GCM_TAG));
    } else {
        if (payload_len < ISC_GCM_TAG) return 0;
        payload_len -= ISC_GCM_TAG;
    }
    size_t aad_len = make_aad(f, &v, aad);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, encrypt) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ISC_GCM_NONCE, NULL) == 1 &&
             EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, encrypt) == 1 &&
             EVP_CipherUpdate(ctx, NULL, &out_len, aad, (int)aad_len) == 1 &&
             EVP_CipherUpdate(ctx, temporary, &out_len, f + v.data_off, (int)payload_len) == 1;
    if (ok && !encrypt)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ISC_GCM_TAG,
                                 f + v.data_off + payload_len) == 1;
    if (ok) ok = EVP_CipherFinal_ex(ctx, temporary + out_len, &final_len) == 1;
    if (ok && encrypt)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ISC_GCM_TAG,
                                 temporary + payload_len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0; /* Never expose unauthenticated plaintext. */
    memcpy(f + v.data_off, temporary, payload_len + (encrypt ? ISC_GCM_TAG : 0));
    if (!encrypt) {
        v.end_off -= ISC_GCM_TAG;
        write_be16(f + 16, (uint16_t)(read_be16(f + 16) - ISC_GCM_TAG));
    }
    isc_repair_checksums(f, &v);
    *n = v.end_off;
    return 1;
}
