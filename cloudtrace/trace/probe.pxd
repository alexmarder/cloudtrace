from cloudtrace.trace.utils cimport *

ctypedef struct pcapfix_global_hdr_s:
    unsigned int magic_number
    unsigned short version_major
    unsigned short version_minor
    int thiszone
    unsigned int sigfigs
    unsigned int snaplen
    unsigned int network

ctypedef struct pcapfix_packet_hdr_s:
    unsigned int ts_sec         #/* timestamp seconds */
    unsigned int ts_usec        #/* timestamp microseconds */
    unsigned int incl_len       #/* number of octets of packet saved in file */
    unsigned int orig_len       #/* actual length of packet */

cdef bint minsize(int proto) except -1;

cdef class Probe:
    cdef:
        void *buf
        ethhdr *etherhdr
        ip *iphdr

    cpdef void set_dst(self, bytes dst) except *;
    cpdef void set_src(self, bytes src) except *;
    cpdef bytes to_bytes(self);
    cpdef void set_ttl(self, uint8_t ttl) except *;
    cpdef void prepare(self);
    cdef void prepare_ip(self);
    cdef void copy_ether(self, void *ether);
    cpdef void create_ether(self, src, dst);
    cpdef void prep_trace(self, uint8_t num);

cdef class ICMPProbe(Probe):
    cdef:
        icmp *icmphdr
        void *data

    cpdef void set_icmp_id(self, uint16_t pid);

cdef class UDPProbe(Probe):
    cdef:
        udp *udphdr
        void *data
        udppseudo *pseudo

    cpdef void set_sport(self, uint16_t sport);
    cpdef void set_dport(self, uint16_t dport);

cpdef uint8_t proto_to_num(str proto);
cpdef Probe create_probe(str dst, uint8_t ipproto, uint16_t size, uint16_t pid);
cpdef bytes fill_packet_header(uint16_t size);
cpdef void write_pcap_header(f);
cpdef void craft(str targets, uint16_t pid, file=*, int minttl=*, int maxttl=*, int cycles=*, str proto=*, uint16_t size=*, bint randomize=*) except *;
cpdef void ping(list targets, uint16_t pid, file=*, int numpings=*, int cycles=*, str proto=*, uint16_t size=*);