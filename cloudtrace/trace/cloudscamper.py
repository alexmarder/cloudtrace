import os
import random
import subprocess
import tempfile
import time
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import platform
from datetime import date

from file2 import fopen

from cloudtrace.scripts.shuffle import shuf
from cloudtrace.trace.fasttrace import remote_notify

def new_filename(default_output, pps, ext, gzip=False, bzip2=False):
    hostname = platform.node()
    dirname, basename = os.path.split(default_output)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    if basename:
        basename += '.'
    timestamp = int(time.time())
    dt = date.fromtimestamp(timestamp)
    datestr = dt.strftime('%Y%m%d')
    filename = os.path.join(dirname, '{base}{host}.{date}.{time}.{pps}.{ext}'.format(
        base=basename, host=hostname, date=datestr, time=timestamp, pps=pps, ext=ext))
    if gzip:
        filename += '.gz'
    elif bzip2:
        filename += '.bz2'
    return filename

def cmd_scamper(pps, tmp, write, ftype, sccmd):
    cmd = 'sudo scamper -O {ftype} -p {pps} -c "{sccmd}" -f {infile} {write}'.format(ftype=ftype, pps=pps, sccmd=sccmd, infile=tmp, write=write)
    return cmd

def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--input')
    group.add_argument('-i', '--addr', nargs='*')
    parser.add_argument('-p', '--pps', default=5000, type=int, help='Packets per second.')
    parser.add_argument('-o', '--default-output', required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')
    parser.add_argument('--remote')
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--random', action='store_true')
    parser.add_argument('--shuffle', action='store_true')
    parser.add_argument('-O', '--extension', choices=['warts', 'json'], default='json')
    subparsers = parser.add_subparsers()
    tparser = subparsers.add_parser('trace')
    tparser.set_defaults(cmd='trace')
    pparser = subparsers.add_parser('ping')
    pparser.set_defaults(cmd='ping')
    args, remaining = parser.parse_known_args()

    sccmd = args.cmd + ' ' + ' '.join(remaining)

    cycle = 0
    while args.cycles == 0 or cycle < args.cycles:
        infile = args.input
        if args.shuffle:
            shuf(infile, inplace=True)
        f = tempfile.NamedTemporaryFile(mode='wt', delete=False)
        tmp = f.name
        try:
            if args.input:
                with fopen(infile, 'rt') as g:
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

            ftype = args.extension
            filename = new_filename(args.default_output, args.pps, ftype, gzip=args.gzip, bzip2=args.bzip2)
            if args.gzip:
                write = '| gzip > {}'.format(filename)
            elif args.bzip2:
                write = '| bzip2 > {}'.format(filename)
            else:
                write = '-o {}'.format(filename)
            dirname, basename = os.path.split(args.default_output)
            pattern = os.path.join(dirname, '{}.warts*'.format(basename))
            cmd = cmd_scamper(args.pps, tmp, write, ftype, sccmd)
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
