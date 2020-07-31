import os
import platform
import socket
import subprocess
import time
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

from cloudtrace.fasttrace import fopen


def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input')
    group.add_argument('-I', '--addr', nargs='*')
    parser.add_argument('-f', '--first-hop', type=int, default=1)
    parser.add_argument('-p', '--pps', default=8000, type=int, help='Packets per second.')
    parser.add_argument('-P', '--proto', default='icmp', choices=['icmp', 'udp'], help='Transport protocol.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-o', '--output')
    group.add_argument('-d', '--default-output')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    parser.add_argument('-r', '--remote')
    parser.add_argument('-c', '--cycles', type=int, default=1)
    parser.add_argument('--tmp', default='.infile.tmp')
    args = parser.parse_args()

    cycle = 1
    while args.cycles == 0 or cycle < args.cycles:
        with open(args.tmp, 'w') as f:
            if args.input:
                with fopen(args.input, 'rt') as g:
                    for line in g:
                        f.write(line)
            else:
                f.writelines('{}\n'.format(addr) for addr in args.addr)
        if args.output:
            filename = args.output
        else:
            hostname = platform.node()
            dirname, basename = os.path.split(args.default_output)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
            if basename:
                basename += '.'
            timestamp = int(time.time())
            filename = os.path.join(dirname, '{}{}.{}.{}.{}.warts'.format(basename, hostname, timestamp, args.proto, args.pps))
            if args.gzip:
                filename += '.gz'
            elif args.bzip2:
                filename += '.bz2'
            print('Saving to {}'.format(filename))
        cmd = 'sudo scamper -O warts -p {} -c "trace -P icmp-paris -f {}" -f {} | gzip > {}'.format(args.pps, args.first_hop, args.tmp, filename)
        print(cmd)
        subprocess.call(cmd, shell=True)
        if args.remote:
            host, _, port = args.remote.partition(':')
            port = int(port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.send(filename.encode() + b'\n')
            s.close()
        try:
            cycle += 1
        except OverflowError:
            cycle = 1
