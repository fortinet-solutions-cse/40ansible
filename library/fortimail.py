#!/usr/bin/env python

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


DOCUMENTATION = '''
---
module: fortimail
short_description: Module to configure all aspects of \
fortimail from Fortinet 
'''

EXAMPLES = '''
- hosts: localhost
#  strategy: debug
  vars:
   host: "192.168.122.42"
   username: "admin"
   password: ""
  tasks:
  - name: Try to pass cli cmd ssh
    fortimail:
     action: "ssh"
     host:  "{{  host }}"  
     username: "{{  username}}"  
     password: "{{ password }}"  
     commands: |
               get system interface

'''

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')

LOG = logging.getLogger("fortimail")

hdlr = logging.FileHandler('/var/tmp/ansible-fortimailconfig.log')
#logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
pLOG = logging.getLogger("paramiko")
pLOG.setLevel(logging.DEBUG)
hdlr.setFormatter(formatter)
pLOG.addHandler(hdlr)
LOG.addHandler(hdlr)

LOG.setLevel(logging.DEBUG)



def ssh( cmds, host, user, password=None):
    LOG.debug(''' Send a multi line string via ssh to the fortigate ''')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.load_system_host_keys()
    
    PORT = 22            # The same port as used by the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, PORT))
    LOG.debug("socket openned")
    t = paramiko.Transport(sock)
    t.start_client()
    t.auth_password(username=user, password=password, event=None, fallback=True)
    channel = t.open_channel("session")
    LOG.debug("logged move to shell")
    channel.invoke_shell()
    channel.set_combine_stderr(True)
    channel.send('\n')
    while not channel.recv_ready():
        time.sleep(1)
    out = channel.recv(999)
    for line in cmds.splitlines():
        channel.send(line+'\n')
        #channel.send('get system interface\n')
    while not channel.recv_ready():
        time.sleep(1)

    out = channel.recv(999)
    return out.decode("ascii")
    channel.close()
    # commands is a multiline string using the ''' string ''' format
    # must split the multiline and send cmd one by one.
    #for line in cmds.splitlines():
    #    channel.send(line+'\n')
    #should work


def fortimail_config_ssh(data):
    host = data['host']
    username = data['username']
    password = data['password']
    cmds = data['commands']
    LOG.debug("in fortimail_config")
    try:
        LOG.debug("calling ssh with host=%s, cmds=%s", host, cmds)
        out = ssh(cmds, host, username, password=password)
        LOG.debug("out :%s",out)
        meta = {"out": out} 
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
