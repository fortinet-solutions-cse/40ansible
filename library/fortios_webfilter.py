#!/usr/bin/python
# Copyright 2017 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# the lib use python logging can get it if the following is set in your
# Ansible config.

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_webfilter
short_description: Module to configure all aspects of fortios and fortigate.
description:
    - This module is able to configure a fortios or fortigate by \
    allowing the user to set every configuration endpoint from a fortios \
    or fortigate device. The module transforms the playbook into \
    the needed REST API calls.

version_added: "2.5"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - "Requires fortiosapi library developed by Fortinet"
    - "Run as a local_action in your playbook"
requirements:
    - fortiosapi>=0.9.8
options:
    host:
        description:
            - FortiOS or fortigate IP adress.
        required: true

    username:
        description:
            - FortiOS or fortigate username.
        required: true

    password:
        description:
            - FortiOS or fortigate password.

    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a \
            virtual instance of the fortigate that can be configured and \
            used as a different unit.
        default: root

    webfilter-url:
        description:
        default: []
        
        id:
            description:
        url:
            description:
        type:
            description:
        action:
            description:
        status:
            description:
        exempt:
            description:
        web-proxy-profile:
            description:
        referrer-host:
            description:
        state:
            description:
            required: false
            default: present
            choices:
            - absent
            - present

    webfilter-content:
        description:
            - 
        default: []
        name: "bet"
        pattern-type: "wildcard"
        status: "enable"
        lang: "western"
        score: 150
        action: block
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure url to be filtered by fortigate
    fortios_webfilter:
      host:  "{{  host }}"
      username: "{{  username}}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      webfilter_url:
        id: "5"
        url: "www.test45.com"
        type: "simple"
        action: "exempt"
        status: "enable"
        exempt: "pass"
        web-proxy-profile: ""
        referrrer-host: ""
        state: "present"

- hosts: localhost
  vars:
   host: "192.168.40.8"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure content to be used with webfilter feature
    fortios_webfilter:
      host:  "{{  host }}"
      username: "{{  username}}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      webfilter-content:
        name: "online-casino"
        pattern-type: "wildcard"
        status: "enable"
        lang: "western"
        score: 150
        action: "block"
        state: "present"
       
'''

RETURN = '''
results:
  description: Data returned by the endpoint operation
  returned: on sucess
  type: string
  sample: 'apply-to: admin-password ipsec-preshared-key'

status:
  description: Indication of the operation's result
  returned: always
  type: string
  sample: success

version:
  description: Version of the FortiGate
  returned: always
  type: string
  sample: v5.6.2

'''

from ansible.module_utils.basic import AnsibleModule

fos = None


def login(data):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    fos.https('off')

    fos.login(host, username, password)


def logout():
    fos.logout()


def extract_wf_url_data(json):

    dict = {}
    attr_list = ['id', 'url', 'type',
                 'action', 'status',
                 'exempt', 'web-proxy-profile',
                 'referrer-host']

    for attribute in attr_list:
        if attribute in json:
            dict[attribute] = json[attribute]

    return dict


def webfilter_url(data):

    vdom = data['vdom']
    wf_url_data = data['webfilter_url']
    url_data = extract_wf_url_data(wf_url_data)

    if wf_url_data['state'] == "present":
        return fos.set('webfilter/urlfilter/' + str(wf_url_data['urlfilter_id']),
                'entries',
                data=url_data,
                vdom=vdom)


def webfilter_content(data):
    return ""


def webfilter_profile(data):
    return ""


def fortios_webfilter(data):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['webfilter_url', 'webfilter_content', 'webfilter_profile']
    for method in methodlist:
        if data[method]:
            resp = eval(method)(data)
            break

    fos.logout()
#    resp = {'status': 'success', 'version': '5.6.3'}
#    meta = {"status": resp['status'], 'version': resp['version'], }
    if resp['status'] == "success":
        return False, True, resp
    else:
        return True, False, resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str"},
        "username": {"required": True, "type": "str"},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "webfilter_url": {"required": False, "type": "dict"},
        "webfilter_content": {"required": False, "type": "dict"},
        "webfilter_profile": {"required": False, "type": "dict"}
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    try:
        from fortiosapi import FortiOSAPI
    except ImportError:
        raise ImportError("fortiosapi module is required")

    global fos
    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_webfilter(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
