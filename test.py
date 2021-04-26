#!/usr/bin/env python3
import socket
import time
from argparse import ArgumentParser
from scapy.sendrecv import send
from scapy.all import L3PacketSocket

from cloudtrace.probe import proto_to_num, create_probe, fill_packet_header

def minsize(proto):
    size = 20
    if proto == socket.IPPROTO_UDP:
        return size + 8 + 4
    else:
        return size + 8 + 2

def craft(targets, pid, minttl=1, maxttl=32, cycles=1, proto='icmp', size=64):

    ipproto = proto_to_num(proto)
    if size < minsize(ipproto):
        size = minsize(ipproto)
    elif size > 1500:
        size = 1500

    outs = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    outs.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    probe = create_probe(targets[0].decode(), ipproto, size, pid)

    start = time.time()
    for _ in range(cycles):
        for dst in targets:
            probe.set_dst(dst)
            for ttl in range(minttl, maxttl + 1, 1):
                probe.set_ttl(ttl)
                probe.prep_trace(ttl)
                probe.prepare()
                pkt = probe.to_bytes()
                print(pkt)
                outs.sendto(pkt, (dst.decode(), 0))

    end = time.time()
    duration = end - start
    if duration > 0:
        pps = len(targets) * 32 / duration
        print('Time: {:,.2f} seconds. {:.2f} pps'.format(duration, pps))
    else:
        print('Too fast to time.')

def main():
    parser = ArgumentParser()
    parser.add_argument('-a', '--addr', required=True)
    args = parser.parse_args()
    craft([args.addr.encode()], 1000)

if __name__ == '__main__':
    main()
