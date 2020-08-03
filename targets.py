#!/usr/bin/env python3
import random
from argparse import ArgumentParser
from ipaddress import ip_network

from traceutils.file2 import fopen2
from traceutils.file2.file2 import fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import create_private


def main():
    parser = ArgumentParser()
    parser.add_argument('-p', '--prefix', action='store_true')
    parser.add_argument('-l', '--limit', type=int)
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()
    all24 = not args.prefix
    prefixes = set()
    private = create_private()
    pb = Progress(increment=100000, callback=lambda: '{:,d}'.format(len(prefixes)))
    with fopen2(args.filename) as f:
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
    random.shuffle(targets)
    if args.limit:
        targets = targets[:args.limit]
    with fopen2(args.output, 'wt') as f:
        f.writelines('{}\n'.format(a) for a in targets)

if __name__ == '__main__':
    main()
