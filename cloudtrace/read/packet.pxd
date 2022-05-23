from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval
from cloudtrace.read.utils cimport *
from cloudtrace.read.combine cimport *
from cloudtrace.read.pcap cimport *

cdef:
    public uint8_t ICMP_PROBE, UDP_PROBE, ECHO_REPLY, ICMP_REPLY

cdef class Packet:
    cdef:
        public uint8_t ptype
        public bint isprobe
        ip *iphdr
        public bytes dst
        timeval *time
        bytes pid_b, dst_b

    cdef uint8_t *get_dst_c(self);
    cpdef uint8_t probe_ttl(self);
    cpdef uint16_t get_pid(self);
    cpdef uint16_t ipid(self);
    cdef void set_ip(self, ip *iphdr);
    cpdef bytes get_dst(self);

cdef class ICMPProbe(Packet):
    cdef:
        icmp *icmphdr

    cpdef uint8_t get_type(self);
    cpdef uint8_t get_code(self);
    cdef void set_icmp(self, ip *iphdr, icmp *hdr);

cdef class UDPProbe(Packet):
    cdef:
        udp *udphdr

    cdef void set_udp(self, ip *iphdr, udp *hdr);

cdef class Reply(Packet):
    cdef:
        icmp *icmphdr
        Packet orig_probe

    cdef void _create_hop(self, hop_t *th);
    cpdef str addr(self);
    cdef void create_hop(self, hop_t *th);
    cpdef uint16_t probe_ipid(self);
    cpdef uint16_t probe_size(self);
    cpdef uint8_t reply_ttl(self);
    cpdef uint8_t get_type(self);
    cpdef uint8_t get_code(self);
    cpdef uint8_t get_icmp_q_ttl(self);
    cdef void set_icmp(self, ip *iphdr, icmp *hdr);

cdef class EchoReply(Reply):
    pass

cdef class ICMPReply(Reply):
    cdef:
        Packet probe
        # scamper_icmpext_t *ie

    cdef void create_pseudo(self, udppseudo *p, unsigned char *src);
    cpdef void set_probe(self, Packet probe);

cdef Packet disassemble_packet(char *packet, int incl_len);
cpdef Packet disassemble(Pcap pcap);
