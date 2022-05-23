#!/usr/bin/env python3
import random
from argparse import ArgumentParser
from ipaddress import ip_network
from multiprocessing import Pool

from traceutils.file2 import fopen2
from traceutils.file2.file2 import fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import create_private

from cloudtrace import __version__

_targets = None
_limit = None

def create_targets(filename, all24, exclude=None):
    prefixes = set()
    private = create_private()
    if exclude is not None:
        with open(exclude) as f:
            for line in f:
                line = line.strip()
                private.add_asn(line, asn=-2)
    pb = Progress(increment=100000, callback=lambda: '{:,d}'.format(len(prefixes)))
    with fopen(filename) as f:
        for line in pb.iterator(f):
            if line[0] == '#':
                continue
            net, plen, _ = line.split()
            net = ip_network(net + '/' + plen)
            if 8 <= net.prefixlen <= 24:
                node = private.search_best_prefix(str(net))
                if node is not None and node.asn < 0:
                    continue
                if all24:
                    prefixes.update(net.subnets(new_prefix=24))
                else:
                    prefixes.add(net)
    targets = list({str(p.network_address + 1) for p in prefixes})
    return targets

def _write_targets(output, targets=None, limit=None):
    if limit is not None:
        targets = targets[:limit]
    with fopen2(output, 'wt') as f:
        f.writelines('{}\n'.format(a) for a in targets)

def write_targets(output, targets, limit=None):
    random.shuffle(targets)
    _write_targets(output, targets, limit=limit)

def write_targets_sample(output, targets=None, limit=None):
    if targets is None:
        targets = _targets
    if limit is None:
        limit = _limit
    targets = random.sample(targets, len(targets))
    _write_targets(output, targets, limit=limit)

def write_targets_parallel(files, targets, limit=None, poolsize=20):
    global _targets, _limit
    _targets = targets
    _limit = limit
    with Pool(min(len(files), poolsize)) as pool:
        for _ in pool.imap_unordered(write_targets_sample, files):
            pass

def main():
    parser = ArgumentParser()
    parser.add_argument('-p', '--prefix', action='store_true')
    parser.add_argument('-l', '--limit', type=int)
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-e', '--exclude')
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args()
    all24 = not args.prefix
    targets = create_targets(args.filename, all24, args.exclude)
    write_targets(args.output, targets, limit=args.limit)

if __name__ == '__main__':
    main()
