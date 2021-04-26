#!/usr/bin/env python3
import sys
from argparse import ArgumentParser
from subprocess import Popen, TimeoutExpired

import pandas as pd

def excel_addrs(args):
    exclude = set(args.exclude.split(',')) if args.exclude else set()
    df = pd.read_excel(args.instances, sheet_name=args.sheet)
    hosts = []
    for row in df[pd.notnull(df.Host)].itertuples():
        if row.Name not in exclude:
            hosts.append(row.Host)
    return hosts

def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--instances', required=True)
    parser.add_argument('-s', '--sheet')
    parser.add_argument('-e', '--exclude')
    args, remaining = parser.parse_known_args()
    remaining = ' '.join(remaining)
    copycmd = 'rsync -e "ssh -o StrictHostKeyChecking=no"'
    if args.scp:
        copycmd = 'scp -o StrictHostKeyChecking=no'
    hosts = args.func(args)
    procs = []
    for host, name in hosts:
        cmd = '{} {}'.format(copycmd, remaining.replace('%MON', host).replace('%NAME', name))
        # cmd = cmd.replace('%MON', host).replace('%NAME', name)
        print(cmd)
        p = Popen(cmd, shell=True)
        procs.append((p, name))
    success = []
    failure = []
    while procs:
        i = 0
        while i < len(procs):
            p, name = procs[i]
            try:
                p.wait(1)
                procs.pop(i)
                if p.returncode == 0:
                    success.append(name)
                    # print('Done {}'.format(name))
                else:
                    failure.append(name)
                    # print('Fail {}'.format(name))
                print('Success {:,d}: {}'.format(len(success), ' '.join(success)))
                print('Fail {:,d}: {}'.format(len(failure), ' '.join(failure)))
            except TimeoutExpired:
                pass
            i += 1

if __name__ == '__main__':
    main()
