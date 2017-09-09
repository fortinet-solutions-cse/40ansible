#!/usr/bin/python

# Copyright 2015 Fortinet, Inc.
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
import json
from argparse import Namespace
import logging
import requests
import sys
import pprint
import socket, paramiko
logging.getLogger("paramiko").setLevel(logging.DEBUG)
logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
logger.setLevel(logging.DEBUG)



DOCUMENTATION = '''
---
module: fortimail
short_description: Module to configure all aspects of \
fortimail from frotinet 
'''

EXAMPLES = '''
- hosts: localhost
  strategy: debug
  vars:
   host: "192.168.40.8"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Set static route on the fortigate
    fortiosconfig:
     action: "set"
     host:  "{{  host }}"
     username: "{{  username}}"
     password: "{{ password }}"
     vdom:  "{{  vdom }}"
     config: "router static"
     config_parameters:
       seq-num: "8"
       dst: "10.10.32.0 255.255.255.0"
       device: "port2"
       gateway: "192.168.40.252"
  - name: Delete firewall address
    fortiosconfig:
     config: "firewall address"
     action: "delete"
     host:  "{{ host }}"
     username: "{{ username }}"
     password: "{{ password }}"
     vdom:  "{{  vdom }}"
     config_parameters:
       wildcard-fqdn: "*.test.ansible.com"
       name: "test-ansible"
       type: "wildcard-fqdn"
'''

formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
paramikolog = logging.getLogger("paramiko")
logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
hdlr.setFormatter(formatter)
paramikolog.addHandler(hdlr)
hdlr = logging.FileHandler('ansible-fortiosconfig.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


  def ssh(self, cmds, host, user, password=None):
        ''' Send a multi line string via ssh to the fortigate '''
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_system_host_keys()
        
        PORT = 22            # The same port as used by the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, PORT))
        t = paramiko.Transport(sock)
        t.start_client()
        t.auth_password(username=user, password=password, event=None, fallback=True)
        channel = t.open_channel("session")
        channel.invoke_shell()
        channel.set_combine_stderr(True)
        channel.send('\n')
        while not channel.recv_ready():
            time.sleep(1)
        out = channel.recv(999)
        channel.send('get system interface\n')
        while not channel.recv_ready():
            time.sleep(1)
            
        out = channel.recv(999)
        print(out.decode("ascii"))
        channel.close()
        # commands is a multiline string using the ''' string ''' format
        # must split the multiline and send cmd one by one.


def fortimail_config_ssh(data):
    host = data['host']
    username = data['username']
    password = data['password']
    vdom = data['vdom']
    cmds = data['commands']

    try:
        out, err = self.ssh(cmds,host,username,password=password)
        meta = {"out": out, "err": err,}
        return False, True, meta
    except:
        return True, False,  { "out": "n/a", "err": "at least one cmd returned an error"}

def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str"},
        "username": {"required": True, "type": "str"},
        "description": {"required": False, "type": "str"},
        "action": {
            "default": "ssh",
            "choices": ['ssh'],
            "type": 'str'
        },
        "commands": {"required": False, "type": "str"},
    }

    choice_map = {
        "ssh": fortimail_config_ssh,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(
        module.params['action'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
