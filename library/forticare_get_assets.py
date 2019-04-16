#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
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

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_certificate_crl
short_description: Certificate Revocation List as a PEM file in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify certificate feature and crl category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.2
version_added: "2.8"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    token:
       description:
            - User token key required to access FortiCare.
       required: true
    version:
        description:
            - FortiOS or FortiGate username.
    serial_number:
        description:
            - FortiOS or FortiGate password.
    expire_before:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
    page_number:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: Get Assets
    forticare_get_assets:
      token: 394923-YOUR-TOKEN-f9394
      version:
      serial_number: "FGT%"
      expire_before: 20220110
      page_number: 1
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import requests

def forticare_get_assets(data):

    body_data = { 'Token': data['token']}
    if data['version']:
        body_data['Version'] = data['version']
    if data['serial_number']:
        body_data['Serial_number'] = data['serial_number']
    if data['expire_before']:
        body_data['Expire_before'] = data['expire_before']
    if data['page_number']:
        body_data['Page_Number'] = data['page_number']

    url = 'https://support.fortinet.com/RegistrationAPI/FCWS_RegistrationService.svc/REST/REST_GetAssets'

    r = requests.post(url, body_data, verify=True)

    print(r)
    return r.status_code != 200, False, r.content



def main():
    fields = {
        "token": {"required": True, "type": "str", "no_log": True},
        "version": {"required": False, "type": "str"},
        "serial_number": {"required": False, "type": "str"},
        "expire_before": {"required": False, "type": "str"},
        "page_number": {"required": False, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error, has_changed, result = forticare_get_assets(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()