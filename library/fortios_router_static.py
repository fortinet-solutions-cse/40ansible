#!/usr/bin/python
#the lib use python logging can get it if the following is set in your  Ansible config. 
#log_path = /var/log/ansible.log in your conf..

DOCUMENTATION = '''
---
module: fortios_router_static
short_description: Manage your fortigate
'''

EXAMPLES = '''
- name: Set a static route on a FortiGate
  fortios_status:
   password: "{{password}}"
   name: "Status"
   description: "Get status of the fortigate"
  register: result
- name: Delete that repo 
  github_repo:
    github_auth_key: "..."
    name: "Hello-World"
    state: absent
  register: result
'''

from ansible.module_utils.basic import *
import requests
from fortigateconf import FortiOSConf
import sys
import json
import pprint
from argparse import Namespace
import logging

fgt = FortiOSConf()
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.setLevel(logging.WARNING)

def json2obj(data):
    return json.loads(data, object_hook=lambda d: Namespace(**d))

def get( name, action=None, mkey=None, parameters=None):
    return json.loads(fgt.get('cmdb',name, action, mkey, parameters))

def login(data):
    host = data['host']
    username = data['username']
    fgt.debug('off')
    fgt.login(host,username,'')

def logout():
    fgt.logout()
    
def fortios_status(data):

    login(data)   
    resp = json.loads(fgt.get('system', 'interface'))
    fgt.logout()        

    # default: something went wrong
    meta = {"status": resp['status'], 'response': resp['version']}
    return False, False, meta


def fortios_webfilter(data):
 
    fgt = FortiOSREST()
    fgt.debug('off')
    fgt.login(host,username,'')
    resp = json.loads(fgt.get('cmdb','system', 'interface'))
    fgt.logout()   
    return True, False, resp['status']
    
def main():

    fields = {
        "host": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str"},
        "username": {"required": True, "type": "str"},
        "description": {"required": False, "type": "str"},
        "action": {
            "default": "status",
            "choices": ['status', 'webfilter'],
            "type": 'str'
        },
    }

    choice_map = {
        "status": fortios_status,
        "webfilter": fortios_webfilter,
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
