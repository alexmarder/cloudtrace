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
            host = '{}@{}'.format(row.User, row.Host)
            hosts.append((host, row.Name))
    return hosts

def list_addrs(args):
    hosts = []
    for addr in args.addrs.split(','):
        if ':' in addr:
            addr, _, name = addr.partition(':')
        else:
            name = addr
        hosts.append((addr, name))
    return hosts

def main():
    parser = ArgumentParser()
    parser.add_argument('-s', '--scp', action='store_true')
    subparsers = parser.add_subparsers()
    excel = subparsers.add_parser('excel')
    excel.add_argument('-i', '--instances', required=True)
    excel.add_argument('-s', '--sheet')
    excel.add_argument('-e', '--exclude')
    excel.set_defaults(func=excel_addrs)
    addrs = subparsers.add_parser('addrs')
    addrs.add_argument('-a', '--addrs', required=True)
    addrs.set_defaults(func=list_addrs)
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
