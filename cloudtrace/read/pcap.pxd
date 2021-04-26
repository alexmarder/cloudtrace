from libc.stdint cimport uint8_t, uint16_t, uint32_t, int32_t, uint64_t

# /* Global header (http://v2.nat32.com/pcap.htm) */
cdef struct global_hdr_s:
    uint32_t magic_number   #/* magic number */
    uint16_t version_major  #/* major version number */
    uint16_t version_minor  #/* minor version number */
    int32_t thiszone       	#/* GMT to local correction */
    uint32_t sigfigs        #/* accuracy of timestamps */
    uint32_t snaplen        #/* max length of captured packets, in octets */
    uint32_t network        #/* data link type */
ctypedef global_hdr_s global_hdr_t

# /* Packet header (http://v2.nat32.com/pcap.htm) */
cdef struct packet_hdr_s:
    uint32_t ts_sec         #/* timestamp seconds */
    uint32_t ts_usec        #/* timestamp microseconds */
    uint32_t incl_len       #/* number of octets of packet saved in file */
    uint32_t orig_len       #/* actual length of packet */
ctypedef packet_hdr_s packet_hdr_t

cdef class Pcap:
    cdef:
        global_hdr_t *global_hdr
        packet_hdr_t *packet_hdr
        char *frame
        infile
        proc

    cpdef void close(self) except *;
    cpdef int next_packet(self);
    cpdef void read_all(self) except *;
