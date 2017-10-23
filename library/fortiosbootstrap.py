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

from ansible.module_utils.basic import *
from novaclient import client
import logging

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
    region_name = data['region_name']
    server_name = data['server_name']
    image_name= data['image_name']
    flavor_name= data['flavor_name']
    network_name = data['network_name']



    nova = client.Client("2", username=username, password=password, project_name=tenant_name, project_domain_id="default", auth_url=auth_url, user_domain_id="default")


    print("Here I am")
    print(nova.servers.list())
    print(nova.flavors.list())
    nova.servers.create(name=server_name, image=image_name, flavor=flavor_name)#, nics=[{"network" : network_name}])



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
        "action": {"required": True, "choices": [ 'openstack-instantiate' ], "type": "str"},
        "server_name": {"required": True, "type": "str"},
        "image_name": {"required": True, "type": "str"},
        "flavor_name": {"required": True, "type": "str"},
        "network_name": {"required": True, "type": "str"},
        "user_data": {"required": False, "type": "str"},
        "license_file": {"required": False, "type": "str"}
    }

    choice_map = {
        "openstack-instantiate": fortigate_openstack_instantiate
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    module.params['diff'] = module._diff
    is_error, has_changed, result = choice_map.get(
        module.params['action'])(module.params)

    if not is_error:
        if (module._diff):
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
