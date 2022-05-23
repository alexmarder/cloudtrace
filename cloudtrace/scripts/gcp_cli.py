from argparse import ArgumentParser
from multiprocessing.pool import ThreadPool

from google.cloud import compute
from google.cloud.compute_v1 import NetworkInterface

import cloudtrace.cli.utils as cu

instances_client = compute.InstancesClient()
project = None

def get_public_ip_address(zname):
    addrs = []
    for instance in instances_client.list(project=project, zone=zname):
        status = instance.status.name
        if status == 'RUNNING':
            interface: NetworkInterface = instance.network_interfaces[0]
            access_config = interface.access_configs[0]
            addr = access_config.nat_i_p
            addrs.append((instance.name, addr))
    return addrs

class GCPCLI(cu.AbstractCLI):

    def public_ip_addresses(self, info=None):
        znames = self.get_region_names()
        with ThreadPool(min(50, len(znames))) as pool:
            for naddrs in pool.imap_unordered(get_public_ip_address, znames):
                for name, addr in naddrs:
                    if info is None:
                        print('{} {}'.format(name, addr))
                    else:
                        row = {'addr': addr, 'name': name}
                        info.append(row)

    def get_region_names(self):
        zones_client = compute.ZonesClient()
        return [zone.name for zone in zones_client.list(project=project)]

    def start_region(self, zname):
        for instance in instances_client.list(project=project, zone=zname):
            status = instance.status.name
            if status == 'TERMINATED':
                print('Starting {} {}'.format(zname, instance.name))
                instances_client.start(project=project, zone=zname, instance=instance.name)

    def state_region(self, zname):
        for instance in instances_client.list(project=project, zone=zname):
            status = instance.status.name
            print('{} {} {}'.format(zname, instance.name, status))

    def stop_region(self, zname):
        for instance in instances_client.list(project=project, zone=zname):
            status = instance.status.name
            if status == 'RUNNING':
                print('Stopping {} {}'.format(zname, instance.name))
                instances_client.stop(project=project, zone=zname, instance=instance.name)


def main(args=None):
    global project
    parser = ArgumentParser()
    parser.add_argument('-p', '--project', default='endless-dialect-257405')
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
    sparser.add_argument('-s', '--sheet-name', default='gcp')
    sparser.add_argument('-u', '--username', default='amarder')
    sparser.set_defaults(command='write')
    args = parser.parse_args(args=args)

    project = args.project

    cli = GCPCLI()

    if args.command == 'start':
        cli.run_all(cli.start_region)
    elif args.command == 'stop':
        cli.run_all(cli.stop_region)
    elif args.command == 'addrs':
        cli.public_ip_addresses()
    elif args.command == 'write':
        cli.write(args.outfile, args.sheet_name, user=args.username)
    else:
        cli.run_all(cli.state_region)

if __name__ == '__main__':
    main()
