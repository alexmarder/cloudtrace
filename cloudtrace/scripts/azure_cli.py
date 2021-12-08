from argparse import ArgumentParser
from multiprocessing.pool import ThreadPool
from typing import Optional

from azure.identity import AzureCliCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

import cloudtrace.cli.utils as cu

compute_client: Optional[ComputeManagementClient] = None
network_client: Optional[NetworkManagementClient] = None

def get_info(rid):
    splits = rid.split('/')
    resource_group = splits[4]
    name = splits[-1]
    return resource_group, name

def get_public_ip_address(args):
    resource_group, ipname, vmname = args
    ip_address = network_client.public_ip_addresses.get(resource_group, ipname).ip_address
    return vmname, ip_address

class AzureCLI(cu.AbstractCLI):

    def public_ip_addresses(self, info=None):
        interfaces = []
        for interface in network_client.network_interfaces.list_all():
            if interface.virtual_machine is not None:
                vmname = interface.virtual_machine.id.rpartition('/')[2]
                ip_config = interface.ip_configurations[0]
                public_ip = ip_config.public_ip_address
                resource_group, ipname = get_info(public_ip.id)
                interfaces.append((resource_group, ipname, vmname))
        with ThreadPool(min(50, len(interfaces))) as pool:
            for vmname, addr in pool.imap_unordered(get_public_ip_address, interfaces):
                if info is None:
                    print(vmname, addr)
                else:
                    row = {'addr': addr, 'name': vmname}
                    info.append(row)

    def get_region_names(self):
        vmnames = []
        for vm in compute_client.virtual_machines.list_all():
            resource_group, vmname = get_info(vm.id)
            vmnames.append((resource_group, vmname))
        return vmnames

    def start_region(self, args):
        resource_group, vmname = args
        for s in compute_client.virtual_machines.instance_view(resource_group_name=resource_group, vm_name=vmname).statuses:
            name, state = s.code.split('/')
            if name == 'PowerState':
                if state == 'stopped':
                    print('Starting {}'.format(vmname))
                    vm_start = compute_client.virtual_machines.begin_start('traces', vmname)
                    vm_start.wait()
                else:
                    print('Already started {}'.format(vmname))

    def state_region(self, args):
        resource_group, vmname = args
        for s in compute_client.virtual_machines.instance_view(resource_group_name=resource_group, vm_name=vmname).statuses:
            name, state = s.code.split('/')
            if name == 'PowerState':
                print(vmname, state)

    def stop_region(self, args):
        resource_group, vmname = args
        for s in compute_client.virtual_machines.instance_view(resource_group_name=resource_group, vm_name=vmname).statuses:
            name, state = s.code.split('/')
            if name == 'PowerState':
                if state == 'running':
                    print('Shutting down {}'.format(vmname))
                    vm_start = compute_client.virtual_machines.begin_power_off('traces', vmname)
                    vm_start.wait()
                else:
                    print('Already shut down {}'.format(vmname))


def main(args=None):
    global compute_client, network_client
    parser = ArgumentParser()
    parser.add_argument('-s', '--subscription-id', default='5ae2eace-d6b8-40c6-843d-d7b6e7246304')
    parser.add_argument('-c', '--country')
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
    sparser.add_argument('-s', '--sheet-name', default='azure')
    sparser.add_argument('-u', '--username', default='amarder')
    sparser.set_defaults(command='write')
    args = parser.parse_args(args=None)

    credential = AzureCliCredential()
    compute_client = ComputeManagementClient(credential, args.subscription_id)
    network_client = NetworkManagementClient(credential, args.subscription_id)

    cli = AzureCLI()

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
