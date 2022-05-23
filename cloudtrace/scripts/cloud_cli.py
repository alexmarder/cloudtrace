from argparse import ArgumentParser
import cloudtrace.scripts.aws_cli
import cloudtrace.scripts.azure_cli
import cloudtrace.scripts.gcp_cli


def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers()
    sparser = subparsers.add_parser('start')
    sparser.set_defaults(command='start')
    sparser = subparsers.add_parser('stop')
    sparser.set_defaults(command='stop')
    sparser = subparsers.add_parser('state')
    sparser.set_defaults(command='state')
    sparser = subparsers.add_parser('addrs')
    sparser.set_defaults(command='addrs')
    sparser = subparsers.add_parser('write')
    sparser.add_argument('-o', '--outfile', required=True)
    sparser.add_argument('-s', '--sheet-name', default='aws')
    sparser.add_argument('-u', '--username', default='ubuntu')
    sparser.set_defaults(command='write')
    args = parser.parse_args(args=args)
    if args.command == 'start':
        run_all(start_region)
    elif args.command == 'stop':
        run_all(stop_region)
    elif args.command == 'addrs':
        public_ip_addresses()
    elif args.command == 'write':
        write(args.outfile, args.sheet_name, user=args.username)
    else:
        run_all(state_region)