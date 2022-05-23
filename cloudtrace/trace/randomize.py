import os
import random
from argparse import ArgumentParser
from multiprocessing import Pool
import pandas as pd

from file2 import fopen

_infile = None

def random_addr(addr):
    addr, _, _ = addr.rpartition('.')
    addr = '{}.{}'.format(addr, random.randint(0, 255))
    return addr

def random_dests(outfile, infile=None):
    if infile is None:
        infile = _infile
    with fopen(infile, 'rt') as f, fopen(outfile, 'wt') as g:
        for line in f:
            addr = random_addr(line)
            g.write('{}\n'.format(addr))

def random_order(outfile, infile=None):
    if infile is None:
        infile = _infile
    targets = []
    with fopen(infile, 'rt') as f:
        for line in f:
            addr = random_addr(line)
            targets.append(addr)
    random.shuffle(targets)
    with fopen(outfile, 'wt') as g:
        for addr in targets:
            g.write('{}\n'.format(addr))

def main():
    global _infile
    parser = ArgumentParser()
    parser.add_argument('-f', '--infile', required=True)
    parser.add_argument('-r', '--random-order', action='store_true')
    subparsers = parser.add_subparsers()
    single = subparsers.add_parser('single')
    single.add_argument('-o', '--outfile', required=True)
    excel = subparsers.add_parser('excel')
    excel.add_argument('-i', '--instances', required=True)
    excel.add_argument('-s', '--sheet', required=True)
    excel.add_argument('-p', '--processes', type=int, default=30)
    excel.add_argument('-d', '--dir', required=True)
    group = excel.add_mutually_exclusive_group()
    group.add_argument('-z', '--gzip', action='store_true')
    group.add_argument('-b', '--bzip2', action='store_true')

    args = parser.parse_args()
    _infile = args.infile
    if args.instances:
        df = pd.read_excel(args.instances, sheet_name=args.sheet)
        outfiles = []
        for row in df.itertuples():
            basename = '{}.targets'.format(row.Name)
            if args.gzip:
                basename += '.gz'
            elif args.bzip2:
                basename += '.bz2'
            outfile = os.path.join(args.dir, basename)
            outfiles.append(outfile)
        with Pool(args.processes) as pool:
            func = random_order if args.random_order else random_dests
            for _ in pool.imap_unordered(func, outfiles):
                pass
    else:
        if args.random_order:
            random_order(args.outfile, args.infile)
        else:
            random_dests(args.outfile, args.infile)
