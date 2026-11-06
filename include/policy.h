#ifndef ISC_POLICY_H
#define ISC_POLICY_H
#include <stdint.h>
#include <stddef.h>
struct isc_policy { uint8_t local_ip[4], remote_ip[4]; uint16_t service_port; };
int isc_parse_port(const char *s, uint16_t *port);
int isc_policy_accept(const struct isc_policy *p, const uint8_t *frame,
                      size_t frame_len, int arrived_from_host);
#endif
