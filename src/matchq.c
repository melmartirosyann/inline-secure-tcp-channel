#include "matchq.h"
#include <string.h>

void isc_queue_init(struct isc_match_queue *q) { memset(q, 0, sizeof(*q)); }
static int was_seen(const struct isc_match_queue *q, const uint8_t id[ISC_DIGEST]) {
    for (size_t i = 0; i < q->seen_count; ++i)
        if (memcmp(q->seen[i], id, ISC_DIGEST) == 0) return 1;
    return 0;
}
int isc_queue_add_frame(struct isc_match_queue *q, const uint8_t *f, size_t n, uint64_t now) {
    uint8_t id[ISC_DIGEST];
    if (n > ISC_FRAME_CAP || !isc_packet_fingerprint(f, n, id)) return 0;
    if (was_seen(q, id)) { q->stats.replay++; return 0; }
    for (size_t i = 0; i < ISC_QUEUE_CAP; ++i) if (!q->frames[i].occupied) {
        q->frames[i].occupied = 1; q->frames[i].arrived = now; q->frames[i].length = n;
        memcpy(q->frames[i].bytes, f, n); memcpy(q->frames[i].id, id, ISC_DIGEST); return 1;
    }
    q->stats.overflow++; return 0;
}
int isc_queue_add_nonce(struct isc_match_queue *q, const uint8_t rec[ISC_CONTROL_RECORD], uint64_t now) {
    for (size_t i = 0; i < ISC_QUEUE_CAP; ++i) if (!q->nonces[i].occupied) {
        q->nonces[i].occupied = 1; q->nonces[i].arrived = now;
        memcpy(q->nonces[i].record, rec, ISC_CONTROL_RECORD); return 1;
    }
    q->stats.overflow++; return 0;
}
void isc_queue_expire(struct isc_match_queue *q, uint64_t now) {
    for (size_t i = 0; i < ISC_QUEUE_CAP; ++i) {
        if (q->frames[i].occupied && now - q->frames[i].arrived >= ISC_QUEUE_TTL) {
            q->frames[i].occupied = 0; q->stats.unmatched++;
        }
        if (q->nonces[i].occupied && now - q->nonces[i].arrived >= ISC_QUEUE_TTL) {
            q->nonces[i].occupied = 0; q->stats.expired++;
        }
    }
}
int isc_queue_decrypt_one(struct isc_match_queue *q, const uint8_t key[ISC_AES_KEY],
                          uint8_t out[ISC_FRAME_CAP], size_t *length) {
    for (size_t fi = 0; fi < ISC_QUEUE_CAP; ++fi) {
        struct isc_queue_entry *f = &q->frames[fi];
        if (!f->occupied) continue;
        if (was_seen(q, f->id)) { f->occupied = 0; q->stats.replay++; continue; }
        for (size_t ni = 0; ni < ISC_QUEUE_CAP; ++ni) {
            struct isc_nonce_entry *r = &q->nonces[ni];
            if (!r->occupied || memcmp(f->id, r->record + ISC_GCM_NONCE, ISC_DIGEST)) continue;
            memcpy(out, f->bytes, f->length); *length = f->length;
            f->occupied = 0; r->occupied = 0;
            if (!isc_gcm_transform(out, length, key, r->record, 0)) {
                q->stats.auth_fail++; return 0;
            }
            memcpy(q->seen[q->seen_cursor], f->id, ISC_DIGEST);
            q->seen_cursor = (q->seen_cursor + 1) % ISC_QUEUE_CAP;
            if (q->seen_count < ISC_QUEUE_CAP) q->seen_count++;
            return 1;
        }
    }
    return 0;
}
