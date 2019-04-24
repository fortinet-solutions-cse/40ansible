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
      and the support package expiration date
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
            - Serial number to filter results (it accept patterns).
    expire_before:
        description:
            - Set an expiration date filter. Ignores products expiring
              after selected date. Format ISO 8601
    page_number:
        description:
            - If multiple products are returned, paginate the result and
              select the desired page. Default page size = 25.
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: Get Assets
    forticare_get_assets:
      token: YOUR_TOKEN
      version: 1.0
      serial_number: FGVM32%
      expire_before: "2029-09-20T10:11:11-8:00"
      page_number: 1
'''

RETURN = '''
status_code:
  description: HTTP status code given by FortiCare server for last API operation executed. 
  returned: always
  type: integer
  sample: 200
reason:
  description: Status explanation or reason of the failure. Returns 'OK' when successful
  returned: always
  type: str
  sample: 'OK'
content:
  description: Detailed information as dictionary format about the execution of the method and results of the query.
  returned: always
  type: str
  sample: '{"Build": "1.0", "Error": null, "Message": "Success", "Status": 0, "Token": "...", "Version": "1.0", "Assets": [....]'
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import json
import traceback


def forticare_get_assets(data):

    body_data = { 'Token': data['token']}
    if 'version' in data and data['version']:
        body_data['Version'] = data['version']

    if 'serial_number' in data and data['serial_number']:
        body_data['Serial_Number'] = data['serial_number']

    if 'expire_before' in data and data['expire_before']:
        body_data['Expire_Before'] = data['expire_before']

    if 'page_number' in data and data['page_number']:
        body_data['Page_Number'] = data['page_number']

    url = 'https://support.fortinet.com/ES/FCWS_RegistrationService.svc/REST/REST_GetAssets'

    try:
        r = requests.post(url, json=body_data, timeout=10, verify=True)

    except requests.exceptions.Timeout:
        return True, False, {"status_code": None,
                             "reason": "Timeout contacting FortiCare server",
                             "content": None}
    except Exception as e:
        return True, False, {"status_code": None,
                             "reason": "General exception when running POST on FortiCare server",
                             "content": str(e.__traceback__) + str(traceback.format_exc())}

    content = json.loads(r.content) if r and 'content' in dir(r) else None

    result = {"status_code": r.status_code if r and 'status_code' in dir(r) else None,
              "reason": r.reason if r and 'reason' in dir(r) else None,
              "content": content}

    return r.status_code != 200 or content['Status'] != 0 if content else True, False, result


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
