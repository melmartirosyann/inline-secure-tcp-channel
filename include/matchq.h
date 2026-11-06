#ifndef ISC_MATCHQ_H
#define ISC_MATCHQ_H
#include "wire.h"
#include <stdint.h>
#define ISC_QUEUE_CAP 128u
#define ISC_QUEUE_TTL 8u
struct isc_queue_entry { int occupied; uint64_t arrived; size_t length; uint8_t bytes[ISC_FRAME_CAP]; uint8_t id[ISC_DIGEST]; };
struct isc_nonce_entry { int occupied; uint64_t arrived; uint8_t record[ISC_CONTROL_RECORD]; };
struct isc_queue_stats { unsigned long replay, unmatched, expired, auth_fail, overflow; };
struct isc_match_queue {
    struct isc_queue_entry frames[ISC_QUEUE_CAP];
    struct isc_nonce_entry nonces[ISC_QUEUE_CAP];
    uint8_t seen[ISC_QUEUE_CAP][ISC_DIGEST];
    size_t seen_count, seen_cursor;
    struct isc_queue_stats stats;
};
void isc_queue_init(struct isc_match_queue *q);
int isc_queue_add_frame(struct isc_match_queue *q, const uint8_t *frame, size_t len, uint64_t now);
int isc_queue_add_nonce(struct isc_match_queue *q, const uint8_t record[ISC_CONTROL_RECORD], uint64_t now);
void isc_queue_expire(struct isc_match_queue *q, uint64_t now);
int isc_queue_decrypt_one(struct isc_match_queue *q, const uint8_t key[ISC_AES_KEY],
                          uint8_t output[ISC_FRAME_CAP], size_t *length);
#endif
