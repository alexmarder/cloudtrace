from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval

cdef extern from '<arpa/inet.h>':
    cdef int AF_INET, AF_INET6, INET_ADDRSTRLEN, INET6_ADDRSTRLEN
    cdef int inet_pton(int, char*, void*);
    cdef int inet_ntop(int, void*, char*, int);
    cdef unsigned int htonl(unsigned int hostlong);
    cdef unsigned short htons(unsigned short hostshort);
    cdef unsigned int ntohl(unsigned int netlong);
    cdef unsigned short ntohs(unsigned short netshort);

cdef extern from "<sys/time.h>":
    cdef void timersub(timeval *a, timeval *b, timeval *res);

cdef extern from "netinet/ip.h":
    cdef:
        uint8_t IPPROTO_ICMP
        uint8_t IPPROTO_UDP
        uint8_t IPPROTO_TCP

cdef uint16_t checksum(void *data, int length) except -1;

cdef struct ethhdr_s:
    uint8_t h_dest[6]
    uint8_t h_source[6]
    uint16_t h_proto
ctypedef ethhdr_s ethhdr

cdef struct ip_s:
    uint8_t ip_hl
    uint8_t ip_tos
    uint16_t ip_len
    uint16_t id
    uint16_t ip_off
    uint8_t ip_ttl
    uint8_t ip_p
    uint16_t ip_sum
    uint8_t ip_src[4]
    uint8_t ip_dst[4]
ctypedef ip_s ip

cdef void iptohost(ip *iphdr);

cdef struct echo_s:
    uint16_t id
    uint16_t seq
ctypedef echo_s echo

cdef struct unused_s:
    uint16_t __unused
    uint16_t mtu
ctypedef unused_s unused

cdef union icmpunion:
    echo_s echo
    unsigned int gateway
    unused_s frag

cdef struct icmp_s:
    uint8_t type
    uint8_t code
    uint16_t checksum
    icmpunion un
ctypedef icmp_s icmp

cdef void icmptohost(icmp *hdr);

cdef struct udp_s:
    uint16_t source
    uint16_t dest
    short len
    uint16_t check
ctypedef udp_s udp

cdef void udptohost(udp *hdr);

cdef struct udppseudo_s:
    uint8_t src[4]
    uint8_t dst[4]
    uint8_t zeros
    uint8_t proto
    uint16_t length
    uint16_t sport
    uint16_t dport
    uint16_t length2
    uint16_t chksum
    uint8_t data[1472]
ctypedef udppseudo_s udppseudo

cdef struct ip6_hdrctl:
    uint32_t ip6_un1_flow
    uint16_t ip6_un1_plen
    uint8_t ip6_un1_nxt
    uint8_t ip6_un1_hlim

cdef union ip6_un:
    ip6_hdrctl ip6_un1
    uint8_t ip6_un2_vfc

cdef struct icmpexthdr_s:
    uint8_t version
    uint8_t reserved
    uint16_t checksum
ctypedef icmpexthdr_s icmpexthdr

cdef struct icmpext_s:
    uint16_t length
    uint8_t classnum
    uint8_t ctype
ctypedef icmpext_s icmpext

cdef struct ip6_s:
    ip6_un ip6_ctlun
    uint8_t ip6_src[16]
    uint8_t ip6_dst[16]

cpdef float rtt_from_split(uint32_t rxsec, uint32_t rxusec, uint32_t txsec, uint32_t txusec, uint32_t divisor);
