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
module: forticare_download_license
short_description: Download license key file from FortiCare.
description:
    - This module is used for downloading already existing license key files
      from FortiCare.

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
            - Product serial number.
        required: true
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: Download license
    forticare_download_license:
      token: 9EYZ-YOUR-TOKEN-5NCS
      version: V1.0
      serial_number: FGT90EFKRI3948954
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
import requests


def forticare_download_license(data):
    body_data = {'Token': data['token'],
                 'Version': data['version'],
                 'Serial_Number': data['serial_number']}

    url = 'https://support.fortinet.com/RegistrationAPI/FCWS_RegistrationService.svc/REST/REST_DownloadLicense'

    r = requests.post(url, body_data, verify=True)

    return r.status_code != 200, False, r.content


def main():
    fields = {
        'token': {'required': True, 'type': 'str', 'no_log': True},
        'version': {'required': True, 'type': 'str'},
        'serial_number': {'required': True, 'type': 'str'},
    }
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    is_error, has_changed, result = forticare_download_license(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg='Error in repo', meta=result)


if __name__ == '__main__':
    main()
