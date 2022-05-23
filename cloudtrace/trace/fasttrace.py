# import bz2
# import gzip
import json
import os
import platform
import tempfile
import time
import urllib.request
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from datetime import date
from glob import glob
from multiprocessing.context import Process
import socket
from subprocess import Popen, PIPE, run
from time import sleep

from scapy.config import conf

import cloudtrace.trace.probe
import cloudtrace.read.reader
from cloudtrace.trace.shuffle import shuf
from cloudtrace import __version__


def new_filename(default_output, proto, pps, ext, gzip=False, bzip2=False):
    hostname = platform.node()
    dirname, basename = os.path.split(default_output)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    if basename:
        basename += '.'
    timestamp = int(time.time())
    dt = date.fromtimestamp(timestamp)
    datestr = dt.strftime('%Y%m%d')
    filename = os.path.join(dirname, '{base}{host}.{date}.{time}.{proto}.{pps}.{ext}'.format(
        base=basename, host=hostname, date=datestr, time=timestamp, proto=proto, pps=pps, ext=ext))
    if gzip:
        filename += '.gz'
    elif bzip2:
        filename += '.bz2'
    return filename

def remote_notify(pattern, remote):
    # username = getpass.getuser()
    if 'SUDO_USER' in os.environ:
        username = os.environ['SUDO_USER']
    else:
        username = os.environ['USER']
    files = glob(pattern)
    for f in files:
        try:
            host, _, port = remote.partition(':')
            port = int(port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.send('{}:{}\n'.format(username, f).encode())
            s.close()
        except:
            print('Unable to connect to {}.'.format(remote))
            pass

def craftandsend(targets: str, pid, pps, minttl=1, maxttl=32, proto=1, timer='nano', randomize=False):
    iface, src, nexthop = conf.route.route('0.0.0.0')
    # transient.probe.craft(targets, pid, file='test.pcap', minttl=minttl, maxttl=maxttl, proto=proto)
    cmd = 'sudo tcpreplay -T {} --intf1={} --pps={} -'.format(timer, iface, pps)
    tcpreplay = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
    cloudtrace.trace.probe.craft(targets, pid, file=tcpreplay.stdin, minttl=minttl, maxttl=maxttl, proto=proto, randomize=randomize)
    tcpreplay.stdin = None
    out, _ = tcpreplay.communicate()
    out = out.decode()
    print(out.strip())

def trace(targets: str, outfile: str, pps, proto, pid, waittime=30, timer='nano', read=False, randomize=False):
    iface, src, nexthop = conf.route.route('0.0.0.0')
    comp = None

    if read:
        comp = Popen('fastread -i - -o {}'.format(outfile), shell=True, stdin=PIPE)
    else:
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
    cmd = r'sudo tcpdump -p -B 40960 -i {iface} -w {wflag} -v \( {send} \) or \( {recv} \)'.format(iface=iface, wflag=wflag, send=send_filter, recv=recv_filter)
    print(cmd)
    tcpdump = Popen(cmd, shell=True, stdout=stdout)
    proc = Process(target=craftandsend, args=(targets, pid, pps), kwargs={'proto': proto, 'timer': timer, 'randomize': randomize})
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
    parser.add_argument('-w', '--wait', type=float, default=30, help='Seconds to wait after sending all packets')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    parser.add_argument('-r', '--remote')
    parser.add_argument('-c', '--cycles', type=int, default=1)
    parser.add_argument('-T', '--timer', default='nano', choices=['nano', 'select', 'ioport', 'gtod'])
    parser.add_argument('-R', '--random', action='store_true')
    parser.add_argument('-S', '--shuffle', action='store_true')
    parser.add_argument('--read', action='store_true')
    # parser.add_argument('--tmp', default='.infile.tmp')
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args()

    if args.addr:
        f = tempfile.NamedTemporaryFile(mode='wt', delete=False)
        infile = f.name
        for addr in args.addr:
            f.write('{}\n'.format(addr))
        f.close()
    else:
        infile = args.input

    if args.shuffle:
        shuf(infile, inplace=True)

    try:
        cycle = 0
        while args.cycles == 0 or cycle < args.cycles:
            pid = args.pid % 65535
            print('Using pid: {}'.format(pid))

            if args.output:
                filename = args.output
                pattern = filename
            else:
                ext = 'pcap' if not args.read else 'jsonl'
                filename = new_filename(args.default_output, args.proto, args.pps, ext, gzip=args.gzip, bzip2=args.bzip2)
                print('Saving to {}'.format(filename))
                dirname, basename = os.path.split(args.default_output)
                pattern = os.path.join(dirname, '{}.{}*'.format(basename, ext))

            name = platform.node()
            addr = urllib.request.urlopen('https://api.ipify.org/').read().decode('utf8')

            sidefile = (filename.rpartition('.')[0] if filename.endswith('.gz') or filename.endswith('.bz2') else filename) + '.sidecar'
            with open(sidefile, 'wt') as f:
                header = {
                    "type": "cycle-start", "list_name": "default", "id": pid, "hostname": name,
                    "start_time": time.time(), 'addr': addr
                }
                f.write(json.dumps(header) + '\n')

                trace(infile, filename, args.pps, args.proto, pid, waittime=args.wait, timer=args.timer, read=args.read, randomize=args.random)

                stoptime = time.time()

                footer = {
                    "type": "cycle-stop", "list_name": "default", "id": pid, "hostname": name,
                    "stop_time": stoptime, 'addr': addr
                }
                f.write(json.dumps(footer) + '\n')

            if args.remote:
                remote_notify(pattern, args.remote)
            try:
                cycle += 1
            except OverflowError:
                cycle = 1

    finally:
        if args.addr:
            os.unlink(infile)
