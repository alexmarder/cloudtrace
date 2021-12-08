from cloudtrace.read.utils cimport *
from cloudtrace.read.pcap cimport Pcap
from cloudtrace.read.packet cimport *
from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval
from cloudtrace.read.linkedlist cimport *

cdef:
    public uint8_t TRACE_TYPE_ICMP_ECHO_PARIS, TRACE_TYPE_UDP_PARIS
    public uint8_t TRACE_STOP_GAPLIMIT, TRACE_STOP_COMPLETED, TRACE_STOP_UNREACH, TRACE_STOP_LOOP, TRACE_STOP_HOPLIMIT

cdef struct probe_id_s:
    char dst[4]
    unsigned char ttl
    unsigned short pid
ctypedef probe_id_s probe_id

# cdef unsigned short checksum(unsigned char *data, int length) except -1;

cdef class Convert:
    cdef:
        str infile, outfile, hostname
        public long total, nprobes, nreplies, skipped, pidprobe, pidreply, ttlhigh, wrote
        # LinkedList times
        LinkedList2 times
        dict probes, replies
        public writefile
        Pcap pcap
        bint more

    # cdef void write(self, Packet p, int delta) except *;
    cdef void write_dst(self, bytes dst_b) except *;
    cdef Reply next(self, Pcap pcap);
    # cdef ScamperTrace initialize_trace(self, Packet probe, scamper_list_t *slist, scamper_cycle_t *cycle);
    cdef void write_old(self, timeval *currtime, int delta)  except *;
    cdef void write_all(self) except *;

cdef int loop_check(Trace trace);
cdef str addr_tostr(char *addr);

cdef class ConvertTrace(Convert):
    cdef Trace initialize_trace(self, Packet probe);
    cpdef void convert_trace(self, bint fix, uint8_t verbose) except *;
    cdef dict hopdict(self, hop_t *hop);
    cdef dict tracedict(self, Trace trace);