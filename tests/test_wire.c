#include "wire.h"
#include "policy.h"
#include "matchq.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void put16(unsigned char *p, unsigned v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static unsigned short checksum(const unsigned char *p, size_t n) {
    unsigned sum=0;
    while (n>1) { sum += ((unsigned)p[0]<<8)|p[1]; p+=2; n-=2; }
    if (n) sum += (unsigned)p[0]<<8;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (unsigned short)~sum;
}
static int checksum_is_valid(const unsigned char *p, size_t n) {
    unsigned sum=0;
    while (n>1) { sum += ((unsigned)p[0]<<8)|p[1]; p+=2; n-=2; }
    if (n) sum += (unsigned)p[0]<<8;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (sum & 0xffffu) == 0xffffu;
}
static int tcp_checksum_is_valid(const unsigned char *f, size_t frame_len) {
    struct ipv4_tcp_view v;
    if (!isc_parse_ipv4_tcp(f,frame_len,&v)) return 0;
    unsigned sum=0; size_t tcp_len=v.end_off-v.tcp_off;
    for (int i=26;i<34;i+=2) sum += ((unsigned)f[i]<<8)|f[i+1];
    sum += 6u+(unsigned)tcp_len;
    for (size_t i=v.tcp_off;i+1<v.end_off;i+=2) sum += ((unsigned)f[i]<<8)|f[i+1];
    if (tcp_len&1u) sum += (unsigned)f[v.end_off-1]<<8;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (sum&0xffffu)==0xffffu;
}
static size_t make_tcp_frame(unsigned char *f, const char *payload) {
    size_t plen=strlen(payload), iplen=20+20+plen;
    memset(f,0,ISC_FRAME_CAP);
    for (int i=0;i<6;i++) { f[i]=(unsigned char)(0x10+i); f[6+i]=(unsigned char)(0x20+i); }
    put16(f+12,0x0800);
    f[14]=0x45; f[15]=0; put16(f+16,(unsigned)iplen); put16(f+18,0x1234);
    put16(f+20,0x4000); f[22]=64; f[23]=6;
    inet_pton(AF_INET,"10.1.0.1",f+26); inet_pton(AF_INET,"10.1.0.2",f+30);
    put16(f+34,41000); put16(f+36,443); f[46]=0x50; f[47]=0x18;
    f[54]=0; f[55]=0; f[56]=0; f[57]=0;
    memcpy(f+54,payload,plen);
    put16(f+24,checksum(f+14,20));
    /* TCP checksum via pseudo-header, as used by the implementation. */
    unsigned sum=0;
    for (int i=26;i<34;i+=2) sum += ((unsigned)f[i]<<8)|f[i+1];
    sum += 6u + (unsigned)(20+plen);
    for (size_t i=34;i<54;i+=2) sum += ((unsigned)f[i]<<8)|f[i+1];
    for (size_t i=54;i+1<54+plen;i+=2) sum += ((unsigned)f[i]<<8)|f[i+1];
    if (plen&1u) sum += (unsigned)f[53+plen]<<8;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    put16(f+50,~sum);
    return 14+iplen;
}

int main(void) {
    unsigned char frame[ISC_FRAME_CAP], original[ISC_FRAME_CAP];
    unsigned char key[ISC_AES_KEY], nonce[ISC_GCM_NONCE];
    memset(key,0x5a,sizeof(key)); memset(nonce,0xa3,sizeof(nonce));
    size_t len=make_tcp_frame(frame,"secure payload from host one");
    memcpy(original,frame,len); size_t original_len=len;
    struct ipv4_tcp_view view;
    assert(isc_parse_ipv4_tcp(frame,len,&view));
    assert(view.data_off==54 && view.end_off==len);
    assert(isc_gcm_transform(frame,&len,key,nonce,1));
    assert(checksum_is_valid(frame+14,20));
    assert(tcp_checksum_is_valid(frame,len));
    assert(len==original_len+ISC_GCM_TAG);
    assert(memcmp(frame+54,original+54,original_len-54)!=0);
    assert(isc_gcm_transform(frame,&len,key,nonce,0));
    assert(checksum_is_valid(frame+14,20));
    assert(tcp_checksum_is_valid(frame,len));
    assert(len==original_len && memcmp(frame,original,len)==0);

    len=make_tcp_frame(frame,"tamper check");
    assert(isc_gcm_transform(frame,&len,key,nonce,1));
    frame[len-1]^=0x01;
    size_t protected_len=len;
    assert(!isc_gcm_transform(frame,&len,key,nonce,0));
    assert(len==protected_len);

    /* Queue joins the separate authenticated nonce announcement to the raw frame. */
    len=make_tcp_frame(frame,"control association test");
    memcpy(original,frame,len); original_len=len;
    assert(isc_gcm_transform(frame,&len,key,nonce,1));
    unsigned char protected_copy[ISC_FRAME_CAP], digest[ISC_DIGEST], record[ISC_CONTROL_RECORD], restored[ISC_FRAME_CAP];
    size_t protected_len2=len, restored_len=0;
    memcpy(protected_copy,frame,len);
    assert(isc_packet_fingerprint(frame,len,digest));
    memcpy(record,nonce,ISC_GCM_NONCE); memcpy(record+ISC_GCM_NONCE,digest,ISC_DIGEST);
    struct isc_match_queue q; isc_queue_init(&q);
    assert(isc_queue_add_frame(&q,frame,len,100));
    assert(isc_queue_add_nonce(&q,record,100));
    assert(isc_queue_decrypt_one(&q,key,restored,&restored_len));
    assert(restored_len==original_len && memcmp(restored,original,original_len)==0);
    assert(!isc_queue_add_frame(&q,protected_copy,protected_len2,101));
    assert(q.stats.replay==1);

    struct isc_policy p;
    assert(inet_pton(AF_INET,"10.1.0.1",p.local_ip)==1);
    assert(inet_pton(AF_INET,"10.1.0.2",p.remote_ip)==1);
    p.service_port=443;
    len=make_tcp_frame(frame,"policy");
    assert(isc_policy_accept(&p,frame,len,1));
    assert(!isc_policy_accept(&p,frame,len,0));
    uint16_t port=0;
    assert(isc_parse_port("443",&port) && port==443);
    assert(!isc_parse_port("0",&port));
    assert(!isc_parse_port("443x",&port));
    puts("PASS: parsing, checksums, AES-GCM, tamper rejection, nonce/frame matching, replay filter, and TCP policy");
    return 0;
}
