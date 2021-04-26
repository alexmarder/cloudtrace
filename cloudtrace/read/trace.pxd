from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval

cdef class BaseObj:
    @staticmethod
    cdef BaseObj loads(void *buf);
    @staticmethod
    cdef TraceHop new_ptr();
    @staticmethod
    cdef TraceHop from_ptr(void *ptr);

cdef struct trace_hop:
    char[4] addr
    uint8_t probe_id
    uint8_t probe_ttl
    uint16_t probe_size
    uint8_t reply_ttl
    uint8_t reply_tos
    uint16_t reply_size
    uint16_t reply_ipid
    uint8_t icmp_type
    uint8_t icmp_code
    uint8_t icmp_q_ttl
    uint8_t icmp_q_tos
    uint16_t icmp_q_ipl
    uint16_t icmp_nhmtu
    timeval hop_tx
    timeval hop_rtt
ctypedef trace_hop trace_hop_t

cdef class TraceHop(BaseObj):
    cdef:
        trace_hop_t *hop

cdef struct trace:
    # /* source and destination addresses of the trace */
    char[4] src
    char[4] dst

    # /* when the trace commenced */
    timeval start

    # /* hops array, number of valid hops specified by hop_count */
    trace_hop_t  **hops
    uint16_t hop_count

    # /* number of probes sent for this traceroute */
    uint16_t probec

    # /* why the trace finished */
    uint8_t stop_reason
    uint8_t stop_data

    # /* trace parameters */
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

ctypedef trace trace_t

cdef class Trace(BaseObj):
    cdef:
        trace_t *trace
