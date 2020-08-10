#!/usr/bin/env python3
from argparse import ArgumentParser
from collections import defaultdict
from subprocess import Popen

import pandas as pd

parser = ArgumentParser()
parser.add_argument('-i', '--instances', required=True)
parser.add_argument('-s', '--sheet')
parser.add_argument('-e', '--exclude')
args, remaining = parser.parse_known_args()
remaining = ' '.join(arg if ' ' not in arg else '"{}"'.format(arg) for arg in remaining)
print(remaining)
exclude = set(args.exclude.split(',')) if args.exclude else set()
df = pd.read_excel(args.instances, sheet_name=args.sheet)
firsthops = defaultdict(list)
for row in df.itertuples():
    if row.Host in exclude or row.Name in exclude:
        continue
    host = '{}@{}'.format(row.User, row.Host)
    firsthops[row._asdict().get('First', 1)].append(host)
# hosts = ['{}@{}'.format(row.User, row.Host) for row in df.itertuples()]
for first, hosts in firsthops.items():
    cmd = 'SHMUX_SSH_OPTS=\'-o "StrictHostKeyChecking no" -T\' shmux -c {} {}'.format(remaining.replace('{first}', str(first)), ' '.join(hosts))
    print(cmd)
    p = Popen(cmd, shell=True)
    p.wait()
