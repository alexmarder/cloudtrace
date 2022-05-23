#!/usr/bin/env python3
from argparse import ArgumentParser
from collections import defaultdict
from subprocess import Popen

import pandas as pd

from cloudtrace import __version__

def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--instances', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--sheet')
    group.add_argument('-S', '--all-sheets', action='store_true')
    parser.add_argument('-e', '--exclude')
    parser.add_argument('-I', '--include')
    parser.add_argument('-c', '--country')
    parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    args, remaining = parser.parse_known_args()
    remaining = ' '.join(arg if ' ' not in arg else "'{}'".format(arg) for arg in remaining)
    print(remaining)
    exclude = set(args.exclude.split(',')) if args.exclude else set()
    include = set(args.include.split(',')) if args.include else None
    sheets = args.sheet.split(',') if not args.all_sheets else ['aws', 'azure', 'gcp']
    dfs = []
    for sheet in sheets:
        df = pd.read_excel(args.instances, sheet_name=sheet)
        if args.country:
            df = df[df.country == args.country]
        if include is not None:
            df = df[df.name.isin(include)]
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)
    firsthops = defaultdict(list)
    for row in df[pd.notnull(df.addr)].itertuples():
        if row.addr in exclude or row.name in exclude:
            continue
        host = '{}@{}'.format(row.user, row.addr)
        firsthops[row._asdict().get('First', 1)].append(host)
    # hosts = ['{}@{}'.format(row.User, row.Host) for row in df.itertuples()]
    for first, hosts in firsthops.items():
        cmd = 'SHMUX_SSH_OPTS=\'-o "StrictHostKeyChecking no" -T\' shmux -c {} {}'.format(remaining.replace('{first}', str(first)), ' '.join(hosts))
        print(cmd)
        p = Popen(cmd, shell=True)
        p.wait()

if __name__ == '__main__':
    main()
