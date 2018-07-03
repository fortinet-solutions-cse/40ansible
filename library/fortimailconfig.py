#!/usr/bin/env python

# Copyright 2018 Fortinet, Inc.
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
from fortimailapi import FortiMailAPI
import logging



DOCUMENTATION = '''
---
module: fortimailconfig
short_description: Module to configure FortiMail using REST API
'''

EXAMPLES = '''
- hosts: localhost
  vars:
    host: "192.168.122.12"
    username: "admin"
    password: ""
  tasks:
  - name: Get domain full info
    fortimailconfig:
      action: "get"
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      domain: "dsa.com"
'''

fml = FortiMailAPI()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortimailapi')
hdlr = logging.FileHandler('/var/tmp/ansible-fortimailconfig.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


def login(data):
    host = data['host']
    username = data['username']
    fml.debug('on')
    if 'force_https' in data and data['force_https']:
        fml.https('on')
    fml.login(host, username, '')


def fortimail_config_put(data):
    host = data['host']
    username = data['username']
    password = data['password']
    if 'force_https' in data and data['force_https']:
        fml.https('on')
    fml.login(host, username, password)

    resp = fml.put(data['resource'],
                    data['domain'],
                    data=data['data'])

    if "errorNumber" in  resp:
        return True, False, resp
    else:
        return False, True, resp


def fortimail_config_post(data):
    host = data['host']
    username = data['username']
    password = data['password']
    if 'force_https' in data and data['force_https']:
        fml.https('on')
    fml.login(host, username, password)

    resp = fml.post(data['resource'],
                    data['domain'],
                    data=json.dumps(data['data']))

    if "errorNumber" in  resp:
        return True, False, resp
    else:
        return False, True, resp


def fortimail_config_del(data):
    host = data['host']
    username = data['username']
    password = data['password']
    if 'force_https' in data and data['force_https']:
        fml.https('on')
    fml.login(host, username, password)

    resp = fml.delete(data['resource'],
                      data['domain'],
                      data=data['data'])

    if resp["errorType"] == 0:   # Success, item deleted
        return False, True, resp
    elif resp["errorType"]==11:  # Does not exist, didn't change anything
            return False, False, resp
    else:
            return True, True, resp


def fortimail_config_get(data):
    host = data['host']
    username = data['username']
    password = data['password']
    if 'force_https' in data and data['force_https']:
        fml.https('on')
    fml.login(host, username, password)

    resp = fml.get(data['resource'],
                      data['domain'])

    if "errorType" in resp:
        return True, False, resp
    else:
        return False, False, resp


def main():
    module_args = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str"},
        "domain": {"required": False, "type": "str"},
        "resource": {"required": False, "type": "str", "default": ""},
        "force_https": {"required": False, "type": "bool", "default": False},
        "action": {
            "default": "get",
            "choices": ['delete', 'put', 'post', 'get'],
            "type": 'str'
        },
        "data": {"required": False, "type":"dict"}
    }

    choice_map = {
        "delete": fortimail_config_del,
        "put": fortimail_config_put,
        "post": fortimail_config_post,
        "get": fortimail_config_get
    }

    module = AnsibleModule(argument_spec=module_args)

    is_error, has_changed, result = choice_map.get(
        module.params['action'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
