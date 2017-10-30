#!/usr/bin/python

# Copyright 2017 Fortinet, Inc.
#
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

# the lib use python logging can get it if the following is set in your
# Ansible config.
# log_path = /var/log/ansible.log in your conf..

from keystoneauth1 import loading
from keystoneauth1 import session
from ansible.module_utils.basic import *
import novaclient.client
import cinderclient.client
import logging
import time

DOCUMENTATION = '''
---
module: fortiosconfig
short_description: Module to configure all aspects of \
fortinet products using the REST API
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   auth_url: "http://10.10.10.215:5000/v2.0/"
   username: "admin"
   password: "fortinet"
   tenant_name: "admin"
   region_name: "RegionOne"
  tasks:
  - name: Instantiate FortiGate in OpenStack
    fortiosbootstrap:
     action: "openstack-instantiate"
     auth_url:  "{{ auth_url }}"
     username: "{{ username }}"
     password: "{{ password }}"
     tenant_name: "{{ tenant_name }}"
     region_name: "{{ region_name }}"
     image_name: fortigate
     flavor_name: m1.fortigate
     network_name: netM
     user_data: file1.txt
     license_file: license.lic
'''

formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiosbootstrap')
hdlr = logging.FileHandler('/var/tmp/ansible-fortiosbootstrap.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


def fortigate_openstack_instantiate(data):

    auth_url = data['auth_url']
    username = data['username']
    password = data['password']
    tenant_name = data['tenant_name']
    project_domain = data['project_domain']
    user_domain = data['user_domain']
    region_name = data['region_name']
    server_name = data['name']
    image_name= data['image']
    flavor_name= data['flavor']
    network_list = data['networks']

    userdata_file = None
    license_file = None
    avzone = None

    if ('userdata' in data) and (data['userdata'] is not None):
        userdata_file = open(data['userdata'],'rb')

    if ('license' in data) and (data['license'] is not None):
        license_file = open(data['license'],'rb')

    if ('availability_zone' in data) and (data['availability_zone'] is not None):
        avzone = data['availability_zone']

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(username=username,
                         password=password,
                         project_name=tenant_name,
                         project_domain_id=project_domain,
                         auth_url=auth_url,
                         user_domain_id=user_domain)

    sess = session.Session(auth=auth)

    nova = novaclient.client.Client('2', session=sess)
    cinder = cinderclient.client.Client('2',session=sess)

    flavor_id = nova.flavors.find(name=flavor_name)

    image_id = nova.glance.find_image(image_name)

    nics = []

    for network in network_list:
        network_id = nova.neutron.find_network(network['net-name']).id
        nics.append({"net-id":network_id})



    volume = cinder.volumes.create(imageRef=image_id.id,
                                   size=2,
                                   availability_zone=avzone,
                                   name=server_name+"_vol")

    volume_userdata = cinder.volumes.create(size=1,
                                   availability_zone=avzone,
                                   name=server_name+"_vol_userdata")

    time.sleep(15) #Temporary: allow some time to create the disk: TODO replace with proper poll method

    result = nova.servers.create(name=server_name,
                        image=image_id,
                        block_device_mapping={"/dev/vda":str(volume.id)+"::2:1"},
                        flavor=flavor_id,
                        nics=nics,
                        availability_zone=avzone,
                        userdata=userdata_file,
                        files={"license":license_file} if license_file is not None else None)

    #TODO: Check Result and return proper code. For now it works ok cause it gives exception when fails

    return False, True, {
        'status': "200",
        'version': "v1",
        'result' : "None"
        }

def main():
    fields = {
        "auth_url": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "tenant_name": {"required": True, "type": "str"},
        "region_name": {"required": True, "type": "str"},
        "project_domain": {"required": True, "type": "str"},
        "user_domain": {"required": True, "type": "str"},
        "name": {"required": True, "type": "str"},
        "image": {"required": True, "type": "str"},
        "state": {"required": False, "type": "str"},
        "volume_size": {"required": False, "type": "str"},
        "flavor": {"required": True, "type": "str"},
        "ssh_key": {"required": False, "type": "str"},
        "availability_zone": {"required": False, "type": "str"},
        "networks": {"required": True, "type": "list"},
        "userdata": {"required": False, "type": "str"},
        "license": {"required": False, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    module.params['diff'] = module._diff
    is_error, has_changed, result = fortigate_openstack_instantiate(module.params)

    if not is_error:
        if (module._diff):
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
