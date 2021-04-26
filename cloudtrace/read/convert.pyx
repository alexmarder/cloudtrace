import json
from collections import defaultdict
from time import sleep

from libc.string cimport memcpy, strcpy, memset, memcmp
from libc.stdlib cimport free, calloc
# from traceutils.file2.file2 import fopen
from cloudtrace.read.pcap import fopen

cdef:
    public uint8_t TRACE_TYPE_ICMP_ECHO_PARIS = 1
    public uint8_t TRACE_TYPE_UDP_PARIS = 2

    public uint8_t TRACE_STOP_GAPLIMIT = 1
    public uint8_t TRACE_STOP_COMPLETED = 2
    public uint8_t TRACE_STOP_UNREACH = 3
    public uint8_t TRACE_STOP_LOOP = 4
    public uint8_t TRACE_STOP_HOPLIMIT = 5

cdef class Convert:    
    def __cinit__(self, str infile, str outfile):
        self.total = 0
        self.nprobes = 0
        self.nreplies = 0
        self.skipped = 0
        self.pidprobe = 0
        self.pidreply = 0
        self.ttlhigh = 0
        self.wrote = 0
        # self.times = LinkedList.__new__(LinkedList)
        self.times = LinkedList2.__new__(LinkedList2)
        self.probes = {}
        self.replies = {}
        self.infile = infile
        self.outfile = outfile
        # print(outfile)
        self.writefile = fopen(outfile, 'wt')
        self.more = True

    def __dealloc__(self):
        pass

    def __repr__(self):
        return 'Total {:,d} Probes {:,d} Replies {:,d} PIDP {:,d} PIDR {:,d} Skipped {:,d} Wrote {:,d}'.format(self.total, self.nprobes, self.nreplies, self.pidprobe, self.pidreply, self.skipped, self.wrote)

    def close(self):
        self.writefile.close()

    cdef void write_dst(self, bytes dst_b) except *:
        raise NotImplementedError()

    cdef void write_old(self, timeval *currtime, int delta) except *:
        cdef:
            timeval tmptime
            # node *curr
            Node curr
            bytes dst_b
        while self.times.start is not None:
            timersub(currtime, &self.times.start.time, &tmptime)
            if tmptime.tv_sec >= delta:
                curr = self.times.pop()
                if curr is None:
                    break
                # dst_b = (<unsigned char *>curr.dst)[:curr.dstlen]
                dst_b = curr.dst
                self.write_dst(dst_b)
                del curr
                # free_node(curr)
            else:
                break

    cdef void write_all(self) except *:
        cdef:
            bytes dst_b
            list remaining = list(self.replies)
        for dst_b in remaining:
            self.write_dst(dst_b)

    cdef Reply next(self, Pcap pcap):
        cdef:
            int more
            Packet p, probe
            probe_id pid
            bytes pid_b, dst_b
            Reply reply = None
            dict dsts
        self.more = pcap.next_packet()
        if not self.more:
            # print('writing all')
            self.write_all()
            # print('done writing all')
            pcap.close()
            # print('closed')
            return None
        p = disassemble(pcap)
        self.total += 1
        if p is None:
            self.skipped += 1
            return None
        memcpy(pid.dst, p.get_dst_c(), 4)
        pid.ttl = p.probe_ttl()
        pid.pid = p.get_pid()
        pid_b = <bytes>(<unsigned char *>&pid)[:sizeof(probe_id)]
        dst_b = pid.dst[:4]
        if dst_b == b'\x00\x00\x00\x00':
            return None
        if p.isprobe:
            if dst_b in self.probes:
                dsts = self.probes[dst_b]
            else:
                dsts = {}
                self.probes[dst_b] = dsts
            dsts[pid_b] = p
            if p.probe_ttl() == 32:
                self.times.add(AF_INET, pid.dst, p.time)
            self.nprobes += 1
        else:
            if pid.ttl > 32 or pid.ttl == 0:
                self.ttlhigh += 1
            elif dst_b not in self.probes:
                self.pidreply += 1
            else:
                dsts = self.probes[dst_b]
                if pid_b not in dsts:
                    self.pidreply += 1
                else:
                    probe = dsts.pop(pid_b)
                    reply = <Reply>p
                    reply.orig_probe = probe
                    self.nreplies += 1
        self.write_old(p.time, 10)
        if reply is not None:
            return reply
        return None

cdef int loop_check(Trace trace):
    cdef:
        uint8_t i, j
        hop_t *hop1
        hop_t *hop2
    for i in range(trace.hop_count - 2):
        hop1 = trace.hops[i]
        if hop1 is not NULL:
            for j in range(i + 1, trace.hop_count):
                hop2 = trace.hops[j]
                if hop2 is not NULL:
                    if memcmp(hop1.hop_addr, hop2.hop_addr, 16) == 0:
                        if i == j - 1:
                            break
                        else:
                            return j + 1
    return -1

cdef str addr_tostr(char *addr):
    cdef:
        char dst[46]
    inet_ntop(AF_INET, addr, dst, INET6_ADDRSTRLEN)
    return (<bytes>dst).decode()

cdef class ConvertTrace(Convert):
    cdef dict hopdict(self, hop_t *hop):
        rtt = round(hop.hop_rtt.tv_sec * 1000 + (hop.hop_rtt.tv_usec / 1000), 3)
        return {
            "addr": addr_tostr(hop.hop_addr),
            "probe_ttl": hop.hop_probe_ttl,
            "probe_id": hop.hop_probe_id,
            "probe_size": hop.hop_probe_size,
            "tx": {"sec": hop.hop_tx.tv_sec, "usec": hop.hop_tx.tv_usec},
            "rtt": rtt,
            "reply_ttl": hop.hop_reply_ttl,
            "reply_tos": hop.hop_reply_tos,
            "reply_ipid": hop.hop_reply_ipid,
            "reply_size": hop.hop_reply_size,
            "icmp_type": hop.hop_icmp_type,
            "icmp_code": hop.hop_icmp_code,
            "icmp_q_ttl": hop.hop_icmp_q_ttl,
            "icmp_q_ipl": hop.hop_icmp_q_ipl,
            "icmp_q_tos": hop.hop_icmp_q_tos,
            # "icmpext": [
            #     {"ie_cn": 1,"ie_ct": 1,"ie_dl": 8,"mpls_labels":[
            #         {"mpls_ttl": 1,"mpls_s": 0,"mpls_exp": 0,"mpls_label": 102480},
            #         {"mpls_ttl": 1,"mpls_s": 1,"mpls_exp": 0,"mpls_label": 16743}
            #     ]}
            # ]
        }

    cdef dict tracedict(self, Trace trace):
        cdef:
            str method, stop_reason
            list hops = []
            hop_t *sh
            int i
        for i in range(trace.hop_count):
            sh = trace.hops[i]
            if sh is NULL:
                continue
            hops.append(self.hopdict(sh))
        if trace.type == TRACE_TYPE_ICMP_ECHO_PARIS:
            method = 'icmp-echo-paris'
        else:
            method = 'udp-paris'
        if trace.stop_reason == TRACE_STOP_GAPLIMIT:
            stop_reason = 'GAPLIMIT'
        elif trace.stop_reason == TRACE_STOP_COMPLETED:
            stop_reason = 'COMPLETED'
            # if addr_tostr(trace.dst) != hops[-1]['addr']:
            #     print('traceroute to {} ({} hops)'.format(addr_tostr(trace.dst), trace.hop_count))
            #     print('last hop: {}'.format(hops[-1]['addr']))
            #     for i in range(32):
            #         sh = trace.hops[i]
            #         if sh is NULL:
            #             print('{:02d}: *'.format(i))
            #         else:
            #             print('{:02d}: {:15} {} '.format(i, addr_tostr(sh.hop_addr), sh.hop_icmp_type))
            #     exit(1)
        elif trace.stop_reason == TRACE_STOP_UNREACH:
            stop_reason = 'UNREACH'
        elif trace.stop_reason == TRACE_STOP_LOOP:
            stop_reason = 'LOOP'
        else:
            stop_reason = 'HOPLIMIT'
        return {
            "type": "trace",
            "version": "0.1",
            "userid": 0,
            "method": method,
            "src": addr_tostr(trace.src),
            "dst": addr_tostr(trace.dst),
            "icmp_sum": 47652,
            "stop_reason": stop_reason,
            "stop_data": trace.stop_data,
            "start": {"sec": trace.start.tv_sec, "usec": trace.start.tv_usec, "ftime": "fake"},
            "hop_count": trace.hop_count,
            "attempts": trace.attempts,
            "hoplimit": trace.hoplimit,
            "firsthop": trace.firsthop,
            "wait": trace.wait,
            "wait_probe": trace.wait_probe,
            "tos": trace.tos,
            "probe_size": trace.probe_size,
            "probe_count": trace.probec,
            "hops": hops
        }

    cdef void write_dst(self, bytes dst_b) except *:
        cdef:
            timeval tmptime
            Trace trace
            int loop_hop
            dict output
        if dst_b not in self.probes:
            # print('{}: {} not in probes. odd.'.format(self.infile, dst_b))
            return
        del self.probes[dst_b]
        if dst_b in self.replies:
            trace = self.replies.pop(dst_b)
            loop_hop = loop_check(trace)
            if loop_hop > 0:
                trace.hop_count = loop_hop
                trace.stop_reason = TRACE_STOP_LOOP
            elif trace.hop_count == 32 and trace.stop_reason == TRACE_STOP_GAPLIMIT:
                trace.stop_reason = TRACE_STOP_HOPLIMIT
            output = self.tracedict(trace)
            # print(json.dumps(output))
            self.writefile.write('{}\n'.format(json.dumps(output)))
            trace.hop_count = 32
            self.wrote += 1
            del trace

    cdef Trace initialize_trace(self, Packet probe):
        cdef:
            Trace trace = Trace()
        memcpy(trace.src, probe.iphdr.ip_src, sizeof(trace.src))
        memcpy(trace.dst, probe.iphdr.ip_dst, sizeof(trace.dst))
        memcpy(&trace.start, &probe.time, sizeof(timeval))
        trace.probec = 32
        if probe.ptype == ICMP_PROBE:
            trace.type = TRACE_TYPE_ICMP_ECHO_PARIS
        elif probe.ptype == UDP_PROBE:
            trace.type = TRACE_TYPE_UDP_PARIS
            trace.sport = (<UDPProbe>probe).udphdr.source
            trace.dport = (<UDPProbe>probe).udphdr.dest
        trace.flags = 0
        trace.attempts = 1
        trace.hoplimit = 32
        trace.gaplimit = 0
        trace.gapaction = 0
        trace.firsthop = 1
        trace.tos = probe.iphdr.ip_tos
        trace.wait = 0
        trace.wait_probe = 0
        trace.loops = 1
        trace.loopaction = 1
        trace.confidence = 0
        trace.probe_size = probe.iphdr.ip_len
        trace.hop_count = 0
        trace.stop_reason = TRACE_STOP_GAPLIMIT
        return trace

    cpdef void convert_trace(self, bint fix, uint8_t verbose) except *:
        cdef:
            Pcap pcap = Pcap(self.infile, fix=fix, verbose=verbose)
            unsigned short ttl, ttlindex
            probe_id pid
            bytes pid_b, dst_b
            hop_t *hop
            Trace trace
            uint8_t icmptype
            Reply reply
            uint32_t loop = 0
        while True:
            loop += 1
            if verbose > 0 and loop % 1000000 == 0:
                print('Loop {:,d} Wrote {:,d}'.format(loop, self.wrote))
            reply = self.next(pcap)
            if not self.more:
                # print('breaking')
                break
            if reply is None:
                continue
            # print('packet')
            memcpy(pid.dst, reply.get_dst_c(), 4)
            pid.ttl = reply.probe_ttl()
            pid.pid = reply.get_pid()
            pid_b = <bytes>(<unsigned char *>&pid)[:sizeof(probe_id)]
            dst_b = pid.dst[:4]
            ttl = pid.ttl
            ttlindex = ttl - 1
            if dst_b in self.replies:
                trace = self.replies[dst_b]
            else:
                trace = self.initialize_trace(reply.orig_probe)
                self.replies[dst_b] = trace
            hop = trace.new_hop(pid.ttl)
            reply.create_hop(hop)
            icmptype = reply.icmphdr.type
            if icmptype == 0 or icmptype == 3:
                if ttl < trace.hop_count or trace.stop_reason == TRACE_STOP_GAPLIMIT:
                    trace.hop_count = ttl
                    if icmptype == 0:
                        trace.stop_reason = TRACE_STOP_COMPLETED
                    else:
                        trace.stop_reason = TRACE_STOP_UNREACH
            elif icmptype == 11:
                if ttl > trace.hop_count and trace.stop_reason == TRACE_STOP_GAPLIMIT:
                    trace.hop_count = ttl
        pcap.read_all()
        # print('closing')
        self.close()
        # print('done')
