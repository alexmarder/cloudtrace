from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval

cdef struct hop:
    char hop_addr[16]
    uint8_t hop_flags
    uint8_t hop_probe_ttl
    uint16_t hop_probe_id
    uint16_t hop_probe_size
    uint8_t hop_reply_ttl
    uint8_t hop_reply_tos
    uint16_t hop_reply_size
    uint16_t hop_reply_ipid
    uint8_t hop_icmp_type
    uint8_t hop_icmp_code
    uint8_t hop_icmp_q_ttl
    uint8_t hop_icmp_q_tos
    uint16_t hop_icmp_q_ipl
    uint16_t hop_icmp_nhmtu
    timeval hop_tx
    timeval hop_rtt
ctypedef hop hop_t

cdef class Trace:
    cdef:
        char src[16]
        char dst[16]
        timeval start
        hop_t **hops
        uint16_t hop_count
        uint16_t probec
        uint8_t stop_reason
        uint8_t stop_data
        uint8_t type
        uint8_t flags
        uint8_t attempts
        uint8_t hoplimit
        uint8_t gaplimit
        uint8_t gapaction
        uint8_t firsthop
        uint8_t tos
        uint8_t wait
        uint8_t wait_probe
        uint8_t loops
        uint8_t loopaction
        uint8_t confidence
        uint16_t probe_size
        uint16_t sport
        uint16_t dport
        uint16_t offset

    cdef hop_t *new_hop(self, uint8_t probe_ttl) except *;
