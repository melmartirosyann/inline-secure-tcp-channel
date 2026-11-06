#include "policy.h"
#include "wire.h"
#include <string.h>

int isc_parse_port(const char *s, uint16_t *port) {
    unsigned value = 0;
    if (!s || !*s || !port) return 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return 0;
        value = value * 10u + (unsigned)(*s - '0');
        if (value > 65535u) return 0;
    }
    if (!value) return 0;
    *port = (uint16_t)value;
    return 1;
}

int isc_policy_accept(const struct isc_policy *p, const uint8_t *f,
                      size_t n, int from_host) {
    struct ipv4_tcp_view v;
    if (!p || !isc_parse_ipv4_tcp(f, n, &v)) return 0;
    const uint8_t *src = f + 26, *dst = f + 30;
    const uint8_t *expected_src = from_host ? p->local_ip : p->remote_ip;
    const uint8_t *expected_dst = from_host ? p->remote_ip : p->local_ip;
    if (memcmp(src, expected_src, 4) || memcmp(dst, expected_dst, 4)) return 0;
    unsigned sport = ((unsigned)f[v.tcp_off] << 8) | f[v.tcp_off + 1];
    unsigned dport = ((unsigned)f[v.tcp_off + 2] << 8) | f[v.tcp_off + 3];
    return sport == p->service_port || dport == p->service_port;
}
