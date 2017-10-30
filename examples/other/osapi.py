#!/usr/bin/python

from keystoneauth1 import loading
from keystoneauth1 import session
import novaclient.client
import sys
import argparse
import os

def get_ip(vm_name, net_name):

    auth_url = os.environ['OS_AUTH_URL']
    username = os.environ['OS_USERNAME']
    password = os.environ['OS_PASSWORD']
    tenant_name = os.environ['OS_PROJECT_NAME']
    project_domain = os.environ['OS_PROJECT_DOMAIN_NAME']
    user_domain = os.environ['OS_USER_DOMAIN_NAME']

    """auth_url = "http://10.210.8.17/identity"
    username = "admin"
    password = "password"
    tenant_name = "admin"
    project_domain = "default"
    user_domain = "default"
    region_name = "RegionOne"
    """

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(username=username,
                                    password=password,
                                    project_name=tenant_name,
                                    project_domain_id=project_domain,
                                    auth_url=auth_url,
                                    user_domain_id=user_domain)

    sess = session.Session(auth=auth)

    nova = novaclient.client.Client('2', session=sess)

    server_id=None

    for server in nova.servers.list():
        if server.name == vm_name:
            server_id=server.id

    if server_id == None:
        print("Instance %s not found" % vm_name)
        exit(-1)

    vm = nova.servers.get(server_id)

    for ip in vm.networks[net_name]:
        print(ip)


if __name__== "__main__":
    parser = argparse.ArgumentParser(description='Python3 script to fetch ip of a VM in OpenStack',
                                     prog='osapi',
                                     usage='%(prog)s [options]',
                                     add_help=True)

    parser.add_argument('-v', '--vm_name',
                        help='Specify the name of the VM to get the ip from')
    parser.add_argument('-n', '--network_name',
                        help='Specify the network name attached to previous VM whose ip wants to be fetched')

    args = parser.parse_args()

    if (args.vm_name is None) or (args.network_name is None):
        parser.print_help()
        sys.exit(-1)


    get_ip(args.vm_name, args.network_name)

