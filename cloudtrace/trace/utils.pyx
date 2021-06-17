import bz2
import gzip

import cython

@cython.cdivision(True)
@cython.boundscheck(False)
@cython.wraparound(False)
cdef unsigned short checksum(void *datav, int length) except -1:
    cdef:
        int total = 0
        int count_to = (length / 2) * 2
        int i
        unsigned short w
        unsigned char *data = <unsigned char *>datav
    # if length % 2 == 1:
    #     data += b'\x00'
    for i in range(0, count_to, 2):
        w = ((<uint8_t>data[i] << 8) & 0xFF00) + (data[i + 1] & 0xFF)
        total += w
    if count_to < length:
        total += <unsigned char>data[length-1] & 0xFF
    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)
    total = ~total
    return total & 0xFFFF

cdef void iptohost(ip *iphdr):
    iphdr.ip_len = ntohs(iphdr.ip_len)
    iphdr.id = ntohs(iphdr.id)
    iphdr.ip_off = ntohs(iphdr.ip_off)
    iphdr.ip_sum = ntohs(iphdr.ip_sum)

cdef void icmptohost(icmp *hdr):
    hdr.checksum = ntohs(hdr.checksum)
    if hdr.type == 0 or hdr.type == 8:
        hdr.un.echo.id = ntohs(hdr.un.echo.id)
        hdr.un.echo.seq = ntohs(hdr.un.echo.seq)

cdef void udptohost(udp *hdr):
    hdr.source = ntohs(hdr.source)
    hdr.dest = ntohs(hdr.dest)
    hdr.len = ntohs(hdr.len)
    hdr.check = ntohs(hdr.check)
