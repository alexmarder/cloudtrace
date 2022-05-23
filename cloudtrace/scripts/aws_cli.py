from argparse import ArgumentParser
from multiprocessing.pool import ThreadPool

import boto3

import cloudtrace.cli.utils as cu

def get_region_client(region):
    if isinstance(region, str):
        return boto3.client('ec2', region_name=region)
    return region

class AWSCLI(cu.AbstractCLI):

    def get_region_names(self):
        ec2 = boto3.client('ec2')
        regs = ec2.describe_regions()['Regions']
        regnames = [reg['RegionName'] for reg in regs]
        return regnames

    @staticmethod
    def get_public_ip_address(regname):
        addrs = []
        tmp = boto3.client('ec2', region_name=regname)
        instances = tmp.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                state = inst['State']['Name']
                if state == 'running':
                    addrs.append((regname, inst['PublicIpAddress']))
        return addrs

    def public_ip_addresses(self, info=None):
        regnames = self.get_region_names()
        with ThreadPool(min(50, len(regnames))) as pool:
            for naddrs in pool.imap_unordered(self.get_public_ip_address, regnames):
                for vmname, addr in naddrs:
                    if info is None:
                        print(vmname, addr)
                    else:
                        row = {'addr': addr, 'name': vmname}
                        info.append(row)

    def start_region(self, region):
        region = get_region_client(region)
        regname = region.meta.region_name
        instances = region.describe_instances()
        inst_ids = []
        for res in instances['Reservations']:
            for inst in res['Instances']:
                state = inst['State']['Name']
                if state == 'stopped':
                    inst_ids.append(inst['InstanceId'])
        if inst_ids:
            print('Starting region {}: {}'.format(regname, ' '.join(inst_ids)))
            region.start_instances(InstanceIds=inst_ids)
        else:
            print('No instances to start in {}.'.format(regname))

    def state_region(self, region):
        region = get_region_client(region)
        regname = region.meta.region_name
        instances = region.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                state = inst['State']['Name']
                print('Region {}: {}'.format(regname, state))

    def stop_region(self, region):
        region = get_region_client(region)
        regname = region.meta.region_name
        instances = region.describe_instances()
        inst_ids = []
        for res in instances['Reservations']:
            for inst in res['Instances']:
                state = inst['State']['Name']
                if state == 'running':
                    inst_ids.append(inst['InstanceId'])
        if inst_ids:
            print('Stopping region {}: {}'.format(regname, ' '.join(inst_ids)))
            region.stop_instances(InstanceIds=inst_ids)
        else:
            print('No instances to stop in {}.'.format(regname))

def main(args=None):
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

    cli = AWSCLI()

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
