#!/usr/bin/python

DOCUMENTATION = '''
---
module: fortios_repo
short_description: Manage your fortigate
'''

EXAMPLES = '''
- name: Get status and license validation
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
from ftntlib import FortiOSREST
import sys
import json
import pprint
fgt = FortiOSREST()

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
    resp = json.loads(fgt.get('cmdb','system', 'interface'))
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
