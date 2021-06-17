import os
import random
import subprocess
import tempfile
import time
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from file2 import fopen

from cloudtrace.trace.fasttrace import new_filename, remote_notify

def cmd_trace(proto, pps, first_hop, tmp, write, ftype):
    if proto == 'icmp':
        proto = 'icmp-paris'
    elif proto == 'udp':
        proto = 'udp-paris'
    elif proto == 'tcp':
        proto = 'tcp'
    else:
        raise Exception('Unknown proto {}'.format(proto))
    cmd = 'sudo scamper -O {type} -p {pps} -c "trace -P {proto} -f {first}" -f {infile} {write}'.format(type=ftype, pps=pps, proto=proto, first=first_hop, infile=tmp, write=write)
    return cmd

def cmd_ping(proto, pps, tmp, write, ftype, options):
    if proto == 'icmp':
        proto = 'icmp-echo'
    elif proto == 'udp':
        proto = 'udp'
    elif proto == 'tcp':
        proto = 'tcp-syn'
    else:
        raise Exception('Unknown proto {}'.format(proto))
    if options is None:
        options = ''
    cmd = 'sudo scamper -O {type} -p {pps} -c "ping -P {proto}{options}" -f {infile} {write}'.format(type=ftype, pps=pps, proto=proto, options=options, infile=tmp, write=write)
    return cmd

def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input')
    group.add_argument('-I', '--addr', nargs='*')
    parser.add_argument('-p', '--pps', default=8000, type=int, help='Packets per second.')
    parser.add_argument('-P', '--proto', default='icmp', choices=['icmp', 'udp', 'tcp'], help='Transport protocol.')
    parser.add_argument('-d', '--default-output', required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    parser.add_argument('-r', '--remote')
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('-R', '--random', action='store_true')
    parser.add_argument('-e', '--extension', choices=['warts', 'jsonl'], default='jsonl')
    sp = parser.add_subparsers(required=True)
    trace = sp.add_parser('trace')
    trace.add_argument('-f', '--first-hop', type=int, default=1)
    trace.set_defaults(method='trace')
    ping = sp.add_parser('ping')
    ping.add_argument('-c', '--count', type=int, default=4)
    ping.add_argument('-o', '--replycount', type=int)
    ping.set_defaults(method='ping')
    args = parser.parse_args()

    cycle = 0
    while args.cycles == 0 or cycle < args.cycles:
        f = tempfile.NamedTemporaryFile(mode='wt', delete=False)
        tmp = f.name
        try:
            if args.input:
                with fopen(args.input, 'rt') as g:
                    for line in g:
                        if args.random:
                            addr, _, _ = line.rpartition('.')
                            addr = '{}.{}'.format(addr, random.randint(0, 255))
                        else:
                            addr = line.strip()
                        f.write('{}\n'.format(addr))
            else:
                f.writelines('{}\n'.format(addr) for addr in args.addr)
            f.close()

            if args.extension == 'warts':
                ftype = 'warts'
            else:
                ftype = 'json'
            filename = new_filename(args.default_output, args.proto, args.pps, args.extension, gzip=args.gzip, bzip2=args.bzip2)
            if args.gzip:
                write = '| gzip > {}'.format(filename)
            elif args.bzip2:
                write = '| bzip2 > {}'.format(filename)
            else:
                write = '-o {}'.format(filename)
            dirname, basename = os.path.split(args.default_output)
            pattern = os.path.join(dirname, '{}.warts*'.format(basename))
            if args.method == 'trace':
                cmd = cmd_trace(args.proto, args.pps, args.first_hop, tmp, write, ftype)
            elif args.method == 'ping':
                cmd = cmd_ping(args.proto, args.pps, tmp, write, ftype, args.options)
            else:
                raise Exception('Unknown method: {}'.format(args.method))
            print(cmd)
            start = time.time()
            subprocess.run(cmd, shell=True, check=False)
            end = time.time()
            secs = end - start
            mins = secs / 60
            hours = mins / 60
            print('Duration: {:,.2f} s {:,.2f} m {:,.2f} h'.format(secs, mins, hours))
            if args.remote:
                remote_notify(pattern, args.remote)
            try:
                cycle += 1
            except OverflowError:
                cycle = 1
        finally:
            os.unlink(tmp)
