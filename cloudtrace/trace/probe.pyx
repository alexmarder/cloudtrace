import random
import struct
import time

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import IP as sIP, ICMP as sICMP
from scapy.layers.l2 import getmacbyip, Ether

from file2 import fopen

cdef bint minsize(int proto) except -1:
    cdef:
        uint16_t size = sizeof(ip)
    if proto == IPPROTO_UDP:
        return size + sizeof(udp) + 4
    else:
        return size + sizeof(icmp) + 2

cdef class Probe:
    def __cinit__(self, uint16_t size=64):
        self.buf = calloc(1, sizeof(ethhdr) + size)
        self.etherhdr = <ethhdr *>self.buf
        self.iphdr = <ip *>(self.buf + sizeof(ethhdr))
        self.iphdr.ip_hl = 0x45
        self.iphdr.ip_off = htons(0x4000)
        self.iphdr.ip_len = htons(size)
        self.iphdr.ip_ttl = 64

    def __dealloc__(self):
        if self.buf is not NULL:
            free(self.buf)

    cdef void copy_ether(self, void *ether):
        memcpy(self.etherhdr, ether, sizeof(ethhdr))

    cpdef void create_ether(self, src, dst):
        cdef:
            bytes ether
        e = Ether(src=src, dst=dst) / sIP(dst='192.172.226.78') / sICMP()
        ether = bytes(e)[:sizeof(ethhdr)]
        self.copy_ether(<unsigned char *>ether)

    cpdef void set_dst(self, bytes dst) except *:
        inet_pton(AF_INET, dst, self.iphdr.ip_dst)

    cpdef void set_src(self, bytes src) except *:
        inet_pton(AF_INET, src, self.iphdr.ip_src)

    cpdef bytes to_bytes(self):
        return <bytes>((<char *>self.buf)[:ntohs(self.iphdr.ip_len) + sizeof(ethhdr)])

    cpdef void set_ttl(self, uint8_t ttl) except *:
        self.iphdr.ip_ttl = ttl

    cpdef void prepare(self):
        self.prepare_ip()

    cdef void prepare_ip(self):
        self.iphdr.ip_sum = 0
        self.iphdr.ip_sum = htons(checksum(self.iphdr, sizeof(ip)))

    cpdef void prep_trace(self, uint8_t num):
        pass

cdef class ICMPProbe(Probe):
    def __cinit__(self, uint16_t size=1500):
        self.icmphdr = <icmp *>(self.buf + sizeof(ethhdr) + sizeof(ip))
        self.iphdr.ip_p = IPPROTO_ICMP
        self.icmphdr.type = 8
        self.data = self.buf + sizeof(ethhdr) + sizeof(ip) + sizeof(icmp)

    cpdef void set_icmp_id(self, uint16_t pid):
        self.icmphdr.un.echo.id = htons(pid)

    cpdef void prepare(self):
        self.prepare_ip()
        self.icmphdr.checksum = 0
        self.icmphdr.checksum = htons(checksum(self.icmphdr, ntohs(self.iphdr.ip_len) - sizeof(ip)))

    cpdef void prep_trace(self, uint8_t num):
        cdef:
            uint16_t data = 0x0608 - num
        self.icmphdr.un.echo.seq = htons(num)
        data = htons(data)
        memcpy(self.data, &data, 2)

cdef class UDPProbe(Probe):
    def __cinit__(self, uint16_t size=1500):
        cdef:
            uint16_t length = htons(size - sizeof(ip))
        self.udphdr = <udp *>(self.buf + sizeof(ethhdr) + sizeof(ip))
        self.iphdr.ip_p = IPPROTO_UDP
        self.data = self.buf + sizeof(ethhdr) + sizeof(ip) + sizeof(udp) + 2
        self.pseudo = <udppseudo *>calloc(1, sizeof(udppseudo))
        self.pseudo.proto = self.iphdr.ip_p
        self.udphdr.len = length
        self.pseudo.length = length
        self.pseudo.length2 = length

    def __dealloc__(self):
        if self.pseudo is not NULL:
            free(self.pseudo)

    cpdef void prepare(self):
        self.prepare_ip()
        self.udphdr.check = 0
        self.udphdr.check = htons(checksum(self.pseudo, sizeof(udppseudo)))

    cpdef void prep_trace(self, uint8_t num):
        cdef:
            unsigned short data, chksum
            unsigned char[2] test
        chksum = checksum(self.pseudo, 20)
        data = htons(chksum - num)
        memcpy(self.data, &data, 2)
        memcpy(self.pseudo.data, &data, 2)

    cpdef void set_sport(self, uint16_t sport):
        self.udphdr.source = htons(sport)
        self.pseudo.sport = htons(sport)

    cpdef void set_dport(self, uint16_t dport):
        self.udphdr.dest = htons(dport)
        self.pseudo.dport = htons(dport)

    cpdef void set_dst(self, bytes dst) except *:
        inet_pton(AF_INET, dst, self.iphdr.ip_dst)
        memcpy(self.pseudo.dst, self.iphdr.ip_dst, 4)

    cpdef void set_src(self, bytes src) except *:
        inet_pton(AF_INET, src, self.iphdr.ip_src)
        memcpy(self.pseudo.src, self.iphdr.ip_src, 4)

cpdef uint8_t proto_to_num(str proto):
    if proto == 'icmp':
        return IPPROTO_ICMP
    elif proto == 'udp':
        return IPPROTO_UDP
    else:
        raise NotImplementedError()

cpdef Probe create_probe(str dst, uint8_t ipproto, uint16_t size, uint16_t pid):
    cdef:
        str iface, src, nexthop, macdst, srcmac
        Probe probe
        ICMPProbe iprobe
        UDPProbe uprobe
    iface, src, nexthop = conf.route.route(dst)
    macdst = getmacbyip(nexthop)
    srcmac = get_if_hwaddr(iface)
    
    if ipproto == IPPROTO_ICMP:
        iprobe = ICMPProbe(size)
        iprobe.set_icmp_id(pid)
        probe = iprobe
    elif ipproto == IPPROTO_UDP:
        uprobe = UDPProbe(size)
        uprobe.set_sport(pid)
        uprobe.set_dport(30000)
        probe = uprobe
    else:
        raise Exception('No TCP!')
    probe.create_ether(srcmac, macdst)
    probe.set_src(src.encode())
    return probe

cpdef bytes fill_packet_header(uint16_t size):
    cdef:
        uint32_t caplen = size + sizeof(ethhdr)
        pcapfix_packet_hdr_s ph
    ph.incl_len = caplen
    ph.orig_len = caplen
    return <bytes>(<unsigned char *>&ph)[:sizeof(pcapfix_packet_hdr_s)]

cpdef void write_pcap_header(f):
    cdef:
        pcapfix_global_hdr_s *gh = <pcapfix_global_hdr_s *>calloc(1, sizeof(pcapfix_global_hdr_s))
    gh.magic_number = 0xa1b2c3d4
    gh.version_major = 2
    gh.version_minor = 4
    gh.thiszone = 0
    gh.sigfigs = 0
    gh.snaplen = 0xffff
    gh.network = 1
    f.write(<bytes>((<unsigned char *>gh)[:sizeof(pcapfix_global_hdr_s)]))
    free(gh)

cpdef void craft(str targets, uint16_t pid, file=None, int minttl=1, int maxttl=32, int cycles=1, str proto='icmp', uint16_t size=64, bint randomize=False) except *:
    cdef:
        bytes dst
        uint8_t ttl
        Probe probe
        bytes pkt, caplen_line
        uint16_t ipproto
        uint32_t num_targets = 0

    ipproto = proto_to_num(proto)
    if size < minsize(ipproto):
        size = minsize(ipproto)
    elif size > 1500:
        size = 1500

    probe = create_probe('0.0.0.0', ipproto, size, pid)
    caplen_line = fill_packet_header(size)

    if isinstance(file, str):
        f = open(file, 'wb')
    else:
        f = file
    try:
        write_pcap_header(f)
        start = time.time()
        for _ in range(cycles):
            with fopen(targets, 'rb') as g:
                for line in g:
                    if randomize:
                        addr, _, _ = line.decode().rpartition('.')
                        addr = '{}.{}'.format(addr, random.randint(0, 255))
                        dst = '{}'.format(addr).encode()
                        # targets.append('{}'.format(addr).encode())
                    else:
                        dst = line.strip()
                        # targets.append(line.strip().encode())
                    probe.set_dst(dst)
                    for ttl in range(minttl, maxttl+1, 1):
                        probe.set_ttl(ttl)
                        probe.prep_trace(ttl)
                        probe.prepare()
                        pkt = probe.to_bytes()
                        f.write(caplen_line)
                        f.write(pkt)
                    num_targets += 1
    finally:
        f.close()
    end = time.time()
    duration = end - start
    if duration > 0:
        pps = num_targets * 32 / duration
        print('Time: {:,.2f} seconds. {:.2f} pps'.format(duration, pps))
    else:
        print('Too fast to time.')

cpdef void ping(list targets, uint16_t pid, file=None, int numpings=1, int cycles=1, str proto='icmp', uint16_t size=64):
    cdef:
        bytes dst
        uint8_t seq
        Probe probe
        bytes pkt, caplen_line
        uint16_t ipproto

    ipproto = proto_to_num(proto)
    ipproto = proto_to_num(proto)
    if size < minsize(ipproto):
        size = minsize(ipproto)
    elif size > 1500:
        size = 1500
    
    probe = create_probe(targets[0].decode(), ipproto, size, pid)
    caplen_line = fill_packet_header(size)

    if isinstance(file, str):
        f = open(file, 'wb')
    else:
        f = file
    try:
        write_pcap_header(f)
        start = time.time()
        for _ in range(cycles):
            for dst in targets:
                probe.set_dst(dst)
                for seq in range(numpings):
                    probe.prep_trace(seq)
                    probe.prepare()
                    pkt = probe.to_bytes()
                    f.write(caplen_line)
                    f.write(pkt)
                    # print(pkt)
    finally:
        f.close()
    end = time.time()
    duration = end - start
    if duration > 0:
        pps = len(targets) * 32 / duration
        print('Time: {:,.2f} seconds. {:.2f} pps'.format(duration, pps))
    else:
        print('Too fast to time.')
