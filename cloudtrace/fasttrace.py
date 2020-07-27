import os
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from multiprocessing.context import Process
from subprocess import Popen, PIPE, run
from time import sleep
from typing import List

from scapy.config import conf
from traceutils.file2 import fopen

import cloudtrace.probe
from cloudtrace.log import TraceLog


def craftandsend(targets, pid, pps, minttl=1, maxttl=32, proto=1, log: TraceLog = None):
    iface, src, nexthop = conf.route.route(targets[0])
    # transient.probe.craft(targets, pid, file='test.pcap', minttl=minttl, maxttl=maxttl, proto=proto)
    cmd = 'sudo tcpreplay --intf1={} --pps={} -'.format(iface, pps)
    tcpreplay = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
    cloudtrace.probe.craft(targets, pid, file=tcpreplay.stdin, minttl=minttl, maxttl=maxttl, proto=proto)
    tcpreplay.stdin = None
    out, _ = tcpreplay.communicate()
    out = out.decode()
    print(out.strip())
    if log is not None:
        log.rate = out
        log.write()

def trace(targets: List[str], outfile: str, pps, proto, pid, log=None, waittime=30):
    iface, src, nexthop = conf.route.route(targets[0])
    comp = None
    if outfile.endswith('.gz'):
        comp = Popen('gzip -c > {}'.format(outfile), shell=True, stdin=PIPE)
    elif outfile.endswith('.bz2'):
        comp = Popen('bzip2 -c > {}'.format(outfile), shell=True, stdin=PIPE)
    if comp is None:
        wflag = outfile
        stdout = None
    else:
        wflag = '-'
        stdout = comp.stdin
    if proto == 'icmp':
        send_filter = 'src {} and icmp and icmp[4:2] = {}'.format(src, pid)
    elif proto == 'udp':
        send_filter = 'src {} and udp and udp[0:2] = {}'.format(src, pid)
    else:
        raise NotImplementedError()
    recv_filter = 'icmp and dst {}'.format(src)
    cmd = r'sudo tcpdump -i {iface} -w {wflag} -v \( {send} \) or \( {recv} \)'.format(iface=iface, wflag=wflag, send=send_filter, recv=recv_filter)
    print(cmd)
    tcpdump = Popen(cmd, shell=True, stdout=stdout)
    proc = Process(target=craftandsend, args=(targets, pid, pps), kwargs={'proto': proto, 'log': log})
    proc.start()
    proc.join()
    print('Waiting {} seconds'.format(round(waittime)))
    sleep(waittime)
    run('sudo pkill tcpdump', shell=True)
    tcpdump.wait()
    if comp is not None:
        comp.stdin.flush()
        comp.stdin.close()
        comp.wait()

def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input')
    group.add_argument('-I', '--addr', nargs='*')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-o', '--output')
    group.add_argument('-d', '--default-output')
    parser.add_argument('-p', '--pps', default=8000, type=int, help='Packets per second.')
    parser.add_argument('-P', '--proto', default='icmp', choices=['icmp', 'udp'], help='Transport protocol.')
    parser.add_argument('--probe-pcap', action='store_true')
    parser.add_argument('--pid', type=int, default=os.getpid())
    parser.add_argument('-l', '--log', help='Log sqlite3 file.')
    parser.add_argument('-w', '--wait', type=float, default=30, help='Seconds to wait after sending all packets')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    args = parser.parse_args()

    pid = args.pid % 65535
    print('Using pid: {}'.format(pid))

    if args.input:
        with fopen(args.input, 'rb') as f:
            targets = [line.strip() for line in f]
    else:
        targets = [a.encode() for a in args.addr]
    print('Targets: {:,d}'.format(len(targets)))

    if args.output:
        filename = args.output
    else:
        dirname, basename = os.path.split(args.default_output)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        if basename:
            basename += '.'
        filename = os.path.join(dirname, '{}{}.{}.{}.pcap'.format(basename, args.proto, args.pps, pid))
        if args.gzip:
            filename += '.gz'
        elif args.bzip2:
            filename += '.bz2'
        print('Saving to {}'.format(filename))

    if args.log:
        log = TraceLog(args.log, pps=args.pps, pid=pid, proto=args.proto, targets=len(targets), output=filename)
    else:
        log = None

    trace(targets, filename, args.pps, args.proto, pid, log=log, waittime=args.wait)
