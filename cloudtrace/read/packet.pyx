from libc.string cimport memcpy, strcpy, memset, memcmp
from libc.stdlib cimport free, calloc

cdef:
    public int ICMP_PROBE = 1
    public int UDP_PROBE = 2
    public int ECHO_REPLY = 3
    public int ICMP_REPLY = 4

cdef class Packet:
    def __cinit__(self):
        self.iphdr = <ip *>calloc(1, sizeof(ip))
        self.time = <timeval *>calloc(1, sizeof(timeval))

    def __dealloc__(self):
        if self.iphdr is not NULL:
            free(self.iphdr)
        if self.time is not NULL:
            free(self.time)

    cdef uint8_t *get_dst_c(self):
        return self.iphdr.ip_dst

    cdef void set_ip(self, ip *iphdr):
        memcpy(self.iphdr, iphdr, sizeof(ip))

    def get_hdr(self):
        return self.iphdr[0]

    cpdef uint8_t probe_ttl(self):
        raise NotImplementedError()

    cpdef uint16_t get_pid(self):
        raise NotImplementedError()

    cpdef uint16_t ipid(self):
        return self.iphdr.id

    cpdef bytes get_dst(self):
        cdef:
            char dst[16]
        inet_ntop(AF_INET, self.get_dst_c(), dst, INET_ADDRSTRLEN)
        return <bytes> dst

cdef class ICMPProbe(Packet):
    def __cinit__(self):
        self.ptype = ICMP_PROBE
        self.isprobe = True
        self.icmphdr = <icmp *>calloc(1, sizeof(icmp))

    def __dealloc__(self):
        if self.icmphdr is not NULL:
            free(self.icmphdr)

    cpdef uint8_t probe_ttl(self):
        return self.icmphdr.un.echo.seq

    cpdef uint16_t get_pid(self):
        return self.icmphdr.un.echo.id

    cpdef uint8_t get_type(self):
        return self.icmphdr.type

    cpdef uint8_t get_code(self):
        return self.icmphdr.code

    cdef void set_icmp(self, ip *iphdr, icmp *hdr):
        cdef:
            char dst[16]
        self.set_ip(iphdr)
        memcpy(self.icmphdr, hdr, sizeof(icmp))
        inet_ntop(AF_INET, self.iphdr.ip_dst, dst, INET_ADDRSTRLEN)
        self.dst = <bytes>dst

cdef class UDPProbe(Packet):
    def __cinit__(self):
        self.ptype = UDP_PROBE
        self.isprobe = True
        self.udphdr = <udp *>calloc(1, sizeof(udp))

    def __dealloc__(self):
        if self.udphdr is not NULL:
            free(self.udphdr)

    cpdef uint8_t probe_ttl(self):
        return self.udphdr.check

    cpdef uint16_t get_pid(self):
        return self.udphdr.source

    cdef void set_udp(self, ip *iphdr, udp *hdr):
        cdef:
            char dst[16]
        self.set_ip(iphdr)
        memcpy(self.udphdr, hdr, sizeof(udp))
        inet_ntop(AF_INET, self.iphdr.ip_dst, dst, INET_ADDRSTRLEN)
        self.dst = <bytes>dst

cdef class Reply(Packet):
    def __cinit__(self):
        self.isprobe = False
        self.icmphdr = <icmp *>calloc(1, sizeof(icmp))
        self.orig_probe = None

    def __dealloc__(self):
        if self.icmphdr is not NULL:
            free(self.icmphdr)

    cdef void _create_hop(self, hop_t *th):
        pass

    cpdef str addr(self):
        cdef:
            char dst[16]
        inet_ntop(AF_INET, self.iphdr.ip_src, dst, 16)
        return (<bytes>dst).decode()

    cpdef uint16_t probe_ipid(self):
        raise NotImplementedError()

    cpdef uint16_t probe_size(self):
        raise NotImplementedError()

    cpdef uint8_t reply_ttl(self):
        return self.iphdr.ip_ttl

    cpdef uint8_t get_type(self):
        return self.icmphdr.type

    cpdef uint8_t get_code(self):
        return self.icmphdr.code

    cpdef uint8_t get_icmp_q_ttl(self):
        raise NotImplementedError()

    cdef void set_icmp(self, ip *iphdr, icmp *hdr):
        self.set_ip(iphdr)
        memcpy(self.icmphdr, hdr, sizeof(icmp))

    cdef void create_hop(self, hop_t *th):
        cdef:
            Packet probe = self.orig_probe
        memcpy(th.hop_addr, self.iphdr.ip_src, sizeof(th.hop_addr))
        th.hop_flags = 0
        th.hop_probe_id = probe.iphdr.id
        th.hop_probe_ttl = probe.iphdr.ip_ttl
        th.hop_probe_size = probe.iphdr.ip_len
        th.hop_reply_ttl = self.iphdr.ip_ttl
        th.hop_reply_tos = self.iphdr.ip_tos
        th.hop_reply_size = self.iphdr.ip_len
        th.hop_reply_ipid = self.iphdr.id
        th.hop_icmp_type = self.icmphdr.type
        th.hop_icmp_code = self.icmphdr.code
        memcpy(&th.hop_tx, probe.time, sizeof(timeval))
        timersub(self.time, probe.time, &th.hop_rtt)
        self._create_hop(th)

cdef class EchoReply(Reply):
    def __cinit__(self):
        self.ptype = ECHO_REPLY

    cdef uint8_t *get_dst_c(self):
        return self.iphdr.ip_src

    cpdef uint8_t probe_ttl(self):
        return self.icmphdr.un.echo.seq

    cpdef uint16_t get_pid(self):
        return self.icmphdr.un.echo.id

    cpdef uint16_t probe_ipid(self):
        return self.ipid()

    cpdef uint16_t probe_size(self):
        return self.iphdr.ip_len

    cpdef uint8_t get_icmp_q_ttl(self):
        return 1

    cdef void set_icmp(self, ip *iphdr, icmp *hdr):
        self.set_ip(iphdr)
        memcpy(self.icmphdr, hdr, sizeof(icmp))

cdef class ICMPReply(Reply):
    def __cinit__(self):
        self.ptype = ICMP_REPLY
        self.probe = None
        # self.ie = NULL

    def __dealloc__(self):
        pass
        # if self.ie is not NULL:
        #     scamper_icmpext_free(self.ie)

    cdef void _create_hop(self, hop_t *th):
        th.hop_icmp_q_ttl = self.probe.iphdr.ip_ttl
        th.hop_icmp_q_tos = self.probe.iphdr.ip_tos
        th.hop_icmp_q_ipl = self.probe.iphdr.ip_len
        # if self.ie is not NULL:
        #     th.hop_icmpext = scamper_icmpext_alloc(self.ie.ie_cn, self.ie.ie_ct, self.ie.ie_dl, self.ie.ie_data)

    cdef uint8_t *get_dst_c(self):
        if self.probe is None:
            raise Exception('Probe is not set yet.')
        return self.probe.iphdr.ip_dst

    cdef void create_pseudo(self, udppseudo *p, unsigned char *src):
        cdef:
            ip *iphdr = (<UDPProbe>self.probe).iphdr
            udp *udphdr = (<UDPProbe>self.probe).udphdr
        memcpy(p.src, src, 4)
        memcpy(p.dst, iphdr.ip_dst, 4)
        p.zeros = 0
        p.proto = IPPROTO_UDP
        p.length = htons(udphdr.len)
        p.sport = htons(udphdr.source)
        p.dport = htons(udphdr.dest)
        p.length2 = htons(udphdr.len)
        p.chksum = 0

    cpdef uint8_t probe_ttl(self):
        cdef:
            udppseudo *np
            udppseudo *op
            UDPProbe probe
            unsigned short oc, ttl
        if self.probe.ptype == ICMP_PROBE:
            return self.probe.probe_ttl()
        probe = <UDPProbe>self.probe
        np = <udppseudo *>calloc(1, sizeof(udppseudo))
        op = <udppseudo *>calloc(1, sizeof(udppseudo))
        self.create_pseudo(np, probe.iphdr.ip_src)
        self.create_pseudo(op, self.iphdr.ip_dst)
        oc = htons(checksum(<unsigned char *>op, 20))
        memcpy(np.data, &oc, 2)
        ttl = probe.udphdr.check - checksum(<unsigned char *>np, 22)
        if np is not NULL:
            free(np)
        if op is not NULL:
            free(op)
        return ttl

    cpdef uint16_t probe_size(self):
        return self.probe.iphdr.ip_len

    cpdef uint16_t get_pid(self):
        return self.probe.get_pid()

    cpdef uint16_t probe_ipid(self):
        return self.probe.ipid()

    cpdef uint8_t get_icmp_q_ttl(self):
        return self.iphdr.ip_ttl

    cpdef void set_probe(self, Packet probe):
        self.probe = probe

cpdef Packet disassemble_packet(char *packet, int incl_len):
    cdef:
        char *packet_orig = packet
        ip *iphdr
        unsigned int iphdr_len
        icmp *icmphdr
        Packet probe
        Reply reply
        icmpexthdr *icmpexthdr_s
        icmpext *icmpext_s
    if incl_len < <int>sizeof(ip):
        return None
    # memcpy(iphdr, packet, sizeof(ip))
    iphdr = <ip *>packet
    iptohost(iphdr)
    iphdr_len = (iphdr.ip_hl & 0x0f) * 4
    packet += iphdr_len
    incl_len -= iphdr_len
    if iphdr.ip_p == IPPROTO_ICMP:
        if incl_len < <int>sizeof(icmp):
            return None
        icmphdr = <icmp *>packet
        icmptohost(icmphdr)
        if icmphdr.type == 8:
            probe = ICMPProbe.__new__(ICMPProbe)
            (<ICMPProbe>probe).set_icmp(iphdr, icmphdr)
            return probe
        elif icmphdr.type == 0:
            reply = EchoReply.__new__(EchoReply)
            (<EchoReply>reply).set_icmp(iphdr, icmphdr)
            return reply
        elif icmphdr.type == 3 or icmphdr.type == 11:
            packet += sizeof(icmp)
            incl_len -= sizeof(icmp)
            probe = disassemble_packet(packet, incl_len)
            if probe is None:
                return None
            reply = ICMPReply.__new__(ICMPReply)
            (<ICMPReply>reply).set_icmp(iphdr, icmphdr)
            (<ICMPReply>reply).probe = probe
            # if iphdr.ip_len >= 136 + sizeof(icmpexthdr) + sizeof(icmpext):
            #     icmpext_s = <icmpext *>(packet_orig + 136 + sizeof(icmpexthdr))
            #     # print(icmpext_s.classnum, icmpext_s.ctype, icmpext_s.length)
            #     if icmpext_s.classnum == 1 and icmpext_s.ctype == 1:
            #         (<ICMPReply>reply).ie = scamper_icmpext_alloc(icmpext_s.classnum, icmpext_s.ctype, ntohs(icmpext_s.length), packet_orig + 136 + sizeof(icmpexthdr) + sizeof(icmpext))
            return reply
    elif iphdr.ip_p == IPPROTO_UDP:
        if incl_len < <int>sizeof(udp):
            return None
        udphdr = <udp *>packet
        udptohost(udphdr)
        probe = UDPProbe.__new__(UDPProbe)
        (<UDPProbe>probe).set_udp(iphdr, udphdr)
        return probe
    return None

cpdef Packet disassemble(Pcap pcap):
    cdef:
        uint32_t incl_len = pcap.packet_hdr.incl_len
        char *packet = pcap.frame
        Packet pkt = None
        timeval time
    if incl_len < sizeof(ethhdr):
        return None
    packet += sizeof(ethhdr)
    incl_len -= sizeof(ethhdr)
    pkt = disassemble_packet(packet, incl_len)
    if pkt is None:
        return None
    # time.tv_sec = pcap.ts_sec
    # time.tv_usec = pcap.ts_usec
    # memcpy(&pkt.time, &time, sizeof(timeval))
    pkt.time.tv_sec = pcap.packet_hdr.ts_sec
    pkt.time.tv_usec = pcap.packet_hdr.ts_usec
    return pkt