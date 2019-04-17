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
module: forticare_get_assets
short_description: Get product list from FortiCare.
description:
    - This module is able to query the product list by serial number pattern
      (regular expression) and the support package expiration date
version_added: '2.9'
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
notes:
    - Run as a local_action in your playbook
requirements:
    - None
options:
    token:
       description:
            - User token required to access FortiCare.
       required: true
    version:
        description:
            - API version.
    serial_number:
        description:
            - Serial number to filter results (it accept patters).
    expire_before:
        description:
            - Set an expiration date filter. Ignores products expiring
              after selected date. Format ISO 8601
    page_number:
        description:
            - If multiple products are returned, paginate the result and
              select the desired page. Page size = 25.
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: Get Assets
    forticare_get_assets:
      token: 394923-YOUR-TOKEN-f9394
      version:
      serial_number: FGT%
      expire_before: 20220110
      page_number: 1
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import requests

def forticare_get_assets(data):

    body_data = { 'Token': data['token']}
    if 'version' in data:
        body_data['Version'] = data['version']
    if 'serial_number' in data:
        body_data['Serial_number'] = data['serial_number']
    if 'expire_before' in data:
        body_data['Expire_before'] = data['expire_before']
    if 'page_number' in data:
        body_data['Page_Number'] = data['page_number']

    url = 'https://support.fortinet.com/FCWS_RegistrationService.svc/REST/REST_GetAssets'

    r = requests.post(url, body_data, verify=True)
    return r.status_code != 200, False, r.content


def main():
    fields = {
        'token': {'required': True, 'type': 'str', 'no_log': True},
        'version': {'required': False, 'type': 'str'},
        'serial_number': {'required': False, 'type': 'str'},
        'expire_before': {'required': False, 'type': 'str'},
        'page_number': {'required': False, 'type': 'str'}
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error, has_changed, result = forticare_get_assets(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg='Error in repo', meta=result)


if __name__ == '__main__':
    main()