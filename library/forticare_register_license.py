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
module: forticare_register_license
short_description: Register license in FortiCare.
description:
    - This module is used for registering licenses in FortiCare, using license
      registration code as input.

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
        required: true
    serial_number:
        description:
            - Product serial number. If given, the license will be registered under it
    license_registration_code:
        description:
            - License registration code
        required: true
    description:
        description:
            - Description for new product
    additional_info:
        description:
            - It stores extra info for certain product registration, for example system ID, IP address etc.
    is_government:
        description:
            - Indicates if product will be used for government
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: Register license
    forticare_register_license:
      token: YOUR_TOKEN
      version: 1.0
      serial_number: FGT90EFKRI3948954
      license_registration_code: XXXXX-XXXXX-XXXXX-XXXX-XXXXX
      description: FGT0F23
      additional_info: systemid fgt0f23
      is_government: false
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


def forticare_register_license(data):
    body_data = {'Token': data['token'],
                 'Version': data['version'],
                 'License_Registration_Code': data['license_registration_code']}

    if 'serial_number' in data and data['serial_number']:
        body_data['Serial_Number'] = data['serial_number']

    if 'description' in data and data['description']:
        body_data['Description'] = data['description']

    if 'additional_info' in data and data['additional_info']:
        body_data['Additional_Info'] = data['additional_info']

    if 'is_government' in data and data['is_government']:
        body_data['Is_Government'] = data['is_government']

    url = 'https://support.fortinet.com/ES/FCWS_RegistrationService.svc/REST/REST_RegisterLicense'

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

    success = r.status_code != 200 or content['Status'] != 0 if content else True
    return success, not success, result


def main():
    fields = {
        'token': {'required': True, 'type': 'str', 'no_log': True},
        'version': {'required': True, 'type': 'str'},
        'serial_number': {'required': False, 'type': 'str'},
        'license_registration_code': {'required': True, 'type': 'str'},
        'description': {'required': False, 'type': 'str'},
        'additional_info': {'required': False, 'type': 'str'},
        'is_government': {'required': False, 'type': 'bool', 'default': False}
    }
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error, has_changed, result = forticare_register_license(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg='Error in repo', meta=result)


if __name__ == '__main__':
    main()
