#include "wire.h"
#include "policy.h"
#include "matchq.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t show_stats = 0;
static unsigned long protected_count, restored_count, filtered_count;
static struct isc_match_queue queue_state;

static void on_signal(int sig) { if (sig == SIGUSR1) show_stats = 1; else keep_running = 0; }
static void fatal(const char *what) { perror(what); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
static void require_ok(int ok, const char *what) { if (!ok) fatal(what); }
static uint64_t monotonic_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) fatal("clock_gettime");
    return (uint64_t)ts.tv_sec;
}
static void print_stats(void) {
    fprintf(stderr, "stats protected=%lu restored=%lu filtered=%lu replay=%lu unmatched=%lu expired_nonce=%lu auth_fail=%lu queue_full=%lu\n",
            protected_count, restored_count, filtered_count, queue_state.stats.replay,
            queue_state.stats.unmatched, queue_state.stats.expired,
            queue_state.stats.auth_fail, queue_state.stats.overflow);
    fflush(stderr);
}

static void parse_mac(const char *s, uint8_t mac[6]) {
    unsigned x[6]; char tail;
    if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5], &tail) != 6)
        fatal("MAC address syntax");
    for (int i = 0; i < 6; ++i) { if (x[i] > 255) fatal("MAC octet out of range"); mac[i] = (uint8_t)x[i]; }
}

static int open_packet_socket(const char *ifname, uint8_t mac[6]) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) fatal("AF_PACKET socket (root/CAP_NET_RAW required)");
    struct ifreq req; memset(&req, 0, sizeof(req));
    if (strlen(ifname) >= IFNAMSIZ) fatal("interface name too long");
    strcpy(req.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) fatal("read interface MAC");
    memcpy(mac, req.ifr_hwaddr.sa_data, 6);
    unsigned index = if_nametoindex(ifname);
    if (!index) fatal("interface index");
    struct sockaddr_ll bind_addr; memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET; bind_addr.sll_protocol = htons(ETH_P_ALL);
    bind_addr.sll_ifindex = (int)index;
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) fatal("bind packet socket");
    return fd;
}

static void transmit_frame(int fd, uint8_t *frame, size_t len,
                           const uint8_t src[6], const uint8_t dst[6]) {
    memcpy(frame, dst, 6); memcpy(frame + 6, src, 6);
    if (send(fd, frame, len, 0) != (ssize_t)len) fatal("send Ethernet frame");
}

static SSL *establish_control(int server, const char *control_ip,
                              const char *cert, const char *private_key,
                              const char *ca_file, const char *peer_dns,
                              SSL_CTX **ctx_out) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    require_ok(ctx != NULL, "create TLS context"); *ctx_out = ctx;
    require_ok(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
               SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1, "require TLS 1.3");
    /* TLS 1.3 performs ephemeral finite-field Diffie-Hellman in FFDHE-2048. */
    require_ok(SSL_CTX_set1_groups_list(ctx, "ffdhe2048") == 1, "configure FFDHE group");
    require_ok(SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") == 1, "configure TLS cipher suite");
    require_ok(SSL_CTX_use_certificate_chain_file(ctx, cert) == 1 &&
               SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) == 1 &&
               SSL_CTX_check_private_key(ctx) == 1, "load device identity");
    require_ok(SSL_CTX_load_verify_locations(ctx, ca_file, NULL) == 1, "load trusted CA");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) fatal("control TCP socket");
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(9443);
    require_ok(inet_pton(AF_INET, control_ip, &addr.sin_addr) == 1, "control IPv4 address");
    if (server) {
        int yes = 1; (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        require_ok(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, 1) == 0, "listen for peer control connection");
        int accepted = accept(fd, NULL, NULL);
        if (accepted < 0) fatal("accept peer control connection");
        close(fd); fd = accepted;
    } else if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) fatal("connect to peer control service");
    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    SSL *ssl = SSL_new(ctx);
    require_ok(ssl != NULL, "allocate TLS session");
    require_ok(SSL_set1_host(ssl, peer_dns) == 1 && SSL_set_fd(ssl, fd) == 1, "set peer certificate identity");
    int result = server ? SSL_accept(ssl) : SSL_connect(ssl);
    require_ok(result == 1 && SSL_get_verify_result(ssl) == X509_V_OK, "mutually authenticated FFDHE handshake");
    fprintf(stderr, "Secure control session established with %s (TLS 1.3, FFDHE-2048)\n", peer_dns);
    return ssl;
}

static void tls_write_all(SSL *ssl, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        size_t n = 0;
        if (SSL_write_ex(ssl, data + sent, len - sent, &n) != 1 || n == 0) fatal("TLS control write");
        sent += n;
    }
}

static void deliver_ready(int host_fd, const uint8_t rx_key[ISC_AES_KEY],
                          const uint8_t host_mac[6], const uint8_t host_peer[6]) {
    uint8_t frame[ISC_FRAME_CAP]; size_t len;
    while (isc_queue_decrypt_one(&queue_state, rx_key, frame, &len)) {
        transmit_frame(host_fd, frame, len, host_mac, host_peer);
        restored_count++;
    }
}

int main(int argc, char **argv) {
    if (argc != 14) {
        fprintf(stderr, "Usage: %s server|client HOST_IF PEER_IF CONTROL_IP CERT KEY CA PEER_DNS HOST_MAC PEER_MAC LOCAL_HOST_IP REMOTE_HOST_IP SERVICE_PORT\n", argv[0]);
        return 2;
    }
    int server = strcmp(argv[1], "server") == 0;
    if (!server && strcmp(argv[1], "client") != 0) { fprintf(stderr, "role must be server or client\n"); return 2; }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal); signal(SIGUSR1, on_signal); signal(SIGPIPE, SIG_IGN);

    uint8_t host_mac[6], peer_mac[6], host_destination[6], peer_destination[6];
    parse_mac(argv[9], host_destination); parse_mac(argv[10], peer_destination);
    struct isc_policy policy;
    require_ok(inet_pton(AF_INET, argv[11], policy.local_ip) == 1 &&
               inet_pton(AF_INET, argv[12], policy.remote_ip) == 1 &&
               memcmp(policy.local_ip, policy.remote_ip, 4) != 0, "host IPv4 policy");
    require_ok(isc_parse_port(argv[13], &policy.service_port), "service TCP port");
    fprintf(stderr, "Protecting TCP flow %s <-> %s, service port %u\n", argv[11], argv[12], policy.service_port);

    /* Bind both interfaces before the handshake, but do not forward selected
     * traffic until the authenticated key-establishment step has succeeded. */
    int host_fd = open_packet_socket(argv[2], host_mac);
    int peer_fd = open_packet_socket(argv[3], peer_mac);
    SSL_CTX *tls_ctx = NULL;
    SSL *tls = establish_control(server, argv[4], argv[5], argv[6], argv[7], argv[8], &tls_ctx);

    uint8_t key_material[72];
    const char *exporter_label = "EXPORTER-isc-inline-payload-v1";
    require_ok(SSL_export_keying_material(tls, key_material, sizeof(key_material),
              exporter_label, strlen(exporter_label), NULL, 0, 0) == 1, "derive traffic keys from DH session");
    /* Independent directional AES keys and nonce prefixes. */
    const uint8_t *tx_key = key_material + (server ? 32 : 0);
    const uint8_t *rx_key = key_material + (server ? 0 : 32);
    const uint8_t *tx_prefix = key_material + 64 + (server ? 4 : 0);
    const uint8_t *rx_prefix = key_material + 64 + (server ? 0 : 4);
    uint64_t tx_counter = 0, rx_counter = 0;
    uint8_t control_in[ISC_CONTROL_RECORD]; size_t control_have = 0;
    isc_queue_init(&queue_state);

    struct pollfd fds[3] = {
        {.fd = SSL_get_fd(tls), .events = POLLIN},
        {.fd = host_fd, .events = POLLIN},
        {.fd = peer_fd, .events = POLLIN}
    };
    while (keep_running) {
        if (show_stats) { print_stats(); show_stats = 0; }
        int ready = poll(fds, 3, SSL_pending(tls) ? 0 : 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) fatal("poll");
        for (int i = 0; i < 3; ++i)
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = ECONNRESET; fatal("interface/control socket closed"); }
        isc_queue_expire(&queue_state, monotonic_seconds());

        if ((fds[0].revents & POLLIN) || SSL_pending(tls)) {
            int n = SSL_read(tls, control_in + control_have, (int)(sizeof(control_in) - control_have));
            if (n <= 0) fatal("read nonce control record");
            control_have += (size_t)n;
            if (control_have == sizeof(control_in)) {
                uint64_t counter = 0;
                for (int i = 4; i < 12; ++i) counter = (counter << 8) | control_in[i];
                require_ok(memcmp(control_in, rx_prefix, 4) == 0 && counter > rx_counter,
                           "reject wrong-session or repeated nonce");
                rx_counter = counter;
                require_ok(isc_queue_add_nonce(&queue_state, control_in, monotonic_seconds()), "nonce queue full");
                control_have = 0;
            }
        }

        for (int side = 1; side <= 2; ++side) {
            if (!(fds[side].revents & POLLIN)) continue;
            uint8_t frame[ISC_FRAME_CAP]; struct sockaddr_ll from; socklen_t from_len = sizeof(from);
            ssize_t got = recvfrom(fds[side].fd, frame, sizeof(frame), MSG_TRUNC,
                                   (struct sockaddr *)&from, &from_len);
            if (got < 0) { if (errno == EINTR) continue; fatal("receive Ethernet frame"); }
            if ((size_t)got > sizeof(frame) || from.sll_pkttype == PACKET_OUTGOING) continue;
            size_t frame_len = (size_t)got;
            if (!isc_policy_accept(&policy, frame, frame_len, side == 1)) { filtered_count++; continue; }
            if (side == 1) {
                struct ipv4_tcp_view view;
                if (!isc_parse_ipv4_tcp(frame, frame_len, &view)) continue;
                if (view.end_off - 14u + ISC_GCM_TAG > 1500u) { filtered_count++; continue; }
                if (tx_counter == UINT64_MAX) { errno = EOVERFLOW; fatal("nonce counter exhausted; restart both peers"); }
                ++tx_counter;
                uint8_t record[ISC_CONTROL_RECORD]; memcpy(record, tx_prefix, 4);
                for (int i = 0; i < 8; ++i) record[11 - i] = (uint8_t)(tx_counter >> (8 * i));
                require_ok(isc_gcm_transform(frame, &frame_len, tx_key, record, 1), "AES-GCM packet protection");
                require_ok(isc_packet_fingerprint(frame, frame_len, record + ISC_GCM_NONCE), "fingerprint protected frame");
                /* Nonce+fingerprint travel only over the authenticated control
                 * connection. The Ethernet data frame itself has no wrapper. */
                tls_write_all(tls, record, sizeof(record));
                transmit_frame(peer_fd, frame, frame_len, peer_mac, peer_destination);
                protected_count++;
            } else {
                (void)isc_queue_add_frame(&queue_state, frame, frame_len, monotonic_seconds());
            }
        }
        deliver_ready(host_fd, rx_key, host_mac, host_destination);
    }

    print_stats();
    OPENSSL_cleanse(key_material, sizeof(key_material));
    close(SSL_get_fd(tls)); SSL_free(tls); SSL_CTX_free(tls_ctx);
    close(host_fd); close(peer_fd);
    return 0;
}
