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
# log_path = /var/tmp/ansible.log in your conf..

from ansible.module_utils.basic import *
from fortiosapi import FortiOSAPI
import json
from argparse import Namespace
import logging
import difflib
import re

DOCUMENTATION = '''
---
module: fortiosconfig
short_description: Module to configure all aspects of \
fortinet products using the REST API
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

fos = FortiOSAPI()
formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiosapi')
hdlr = logging.FileHandler('/var/tmp/ansible-fortiosconfig.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

AVAILABLE_CONF = [
    'system resource usage',
    'system vdom-resource',
    'alertemail setting',
    'antivirus heuristic',
    'antivirus profile',
    'antivirus quarantine',
    'antivirus settings',
    'application.casi profile',
    'application custom',
    'application internet-service',
    'application internet-service-custom',
    'application list',
    'application name',
    'application rule-settings',
    'certificate ca',
    'certificate crl',
    'certificate local',
    'dlp filepattern',
    'dlp fp-doc-source',
    'dlp fp-sensitivity',
    'dlp sensor',
    'dlp settings',
    'dnsfilter profile',
    'dnsfilter urlfilter',
    'endpoint-control client',
    'endpoint-control forticlient-registration-syn',
    'endpoint-control profile',
    'endpoint-control registered-forticlient',
    'endpoint-control settings',
    'extender-controller extender',
    'firewall.ipmacbinding setting',
    'firewall.ipmacbinding table',
    'firewall.schedule group',
    'firewall.schedule onetime',
    'firewall.schedule recurring',
    'firewall.service category',
    'firewall.service custom',
    'firewall.service group',
    'firewall.shaper per-ip-shaper',
    'firewall.shaper traffic-shaper',
    'firewall.ssl setting',
    'firewall DoS-policy',
    'firewall DoS-policy6',
    'firewall address',
    'firewall address6',
    'firewall addrgrp',
    'firewall addrgrp6',
    'firewall auth-portal',
    'firewall central-snat-map',
    'firewall dnstranslation',
    'firewall explicit-proxy-address',
    'firewall explicit-proxy-addrgrp',
    'firewall explicit-proxy-policy',
    'firewall identity-based-route',
    'firewall interface-policy',
    'firewall interface-policy6',
    'firewall ip-translation',
    'firewall ippool',
    'firewall ippool6',
    'firewall ipv6-eh-filter',
    'firewall ldb-monitor',
    'firewall local-in-policy',
    'firewall local-in-policy6',
    'firewall multicast-address',
    'firewall multicast-address6',
    'firewall multicast-policy',
    'firewall multicast-policy6',
    'firewall policy',
    'firewall policy46',
    'firewall policy6',
    'firewall policy64',
    'firewall profile-group',
    'firewall profile-protocol-options',
    'firewall shaping-policy',
    'firewall sniffer',
    'firewall ssl-server',
    'firewall ssl-ssh-profile',
    'firewall ttl-policy',
    'firewall vip',
    'firewall vip46',
    'firewall vip6',
    'firewall vip64',
    'firewall vipgrp',
    'firewall vipgrp46',
    'firewall vipgrp6',
    'firewall vipgrp64',
    'ftp-proxy explicit',
    'gui console',
    'icap profile',
    'icap server',
    'ips custom',
    'ips dbinfo',
    'ips decoder',
    'ips global',
    'ips rule',
    'ips rule-settings',
    'ips sensor',
    'ips settings',
    'log.disk filter',
    'log.disk setting',
    'log.fortianalyzer filter',
    'log.fortianalyzer override-filter',
    'log.fortianalyzer override-setting',
    'log.fortianalyzer setting',
    'log.fortianalyzer2 filter',
    'log.fortianalyzer2 setting',
    'log.fortianalyzer3 filter',
    'log.fortianalyzer3 setting',
    'log.fortiguard filter',
    'log.fortiguard override-filter',
    'log.fortiguard override-setting',
    'log.fortiguard setting',
    'log.memory filter',
    'log.memory global-setting',
    'log.memory setting',
    'log.null-device filter',
    'log.null-device setting',
    'log.syslogd filter',
    'log.syslogd override-filter',
    'log.syslogd override-setting',
    'log.syslogd setting',
    'log.syslogd2 filter',
    'log.syslogd2 setting',
    'log.syslogd3 filter',
    'log.syslogd3 setting',
    'log.syslogd4 filter',
    'log.syslogd4 setting',
    'log.webtrends filter',
    'log.webtrends setting',
    'log custom-field',
    'log eventfilter',
    'log gui-display',
    'log setting',
    'log threat-weight',
    'netscan assets',
    'netscan settings',
    'report chart',
    'report dataset',
    'report layout',
    'report setting',
    'report style',
    'report theme',
    'router access-list',
    'router access-list6',
    'router aspath-list',
    'router auth-path',
    'router bfd',
    'router bgp',
    'router community-list',
    'router isis',
    'router key-chain',
    'router multicast',
    'router multicast-flow',
    'router multicast6',
    'router ospf',
    'router ospf6',
    'router policy',
    'router policy6',
    'router prefix-list',
    'router prefix-list6',
    'router rip',
    'router ripng',
    'router route-map',
    'router setting',
    'router static',
    'router static6',
    'spamfilter bwl',
    'spamfilter bword',
    'spamfilter dnsbl',
    'spamfilter fortishield',
    'spamfilter iptrust',
    'spamfilter mheader',
    'spamfilter options',
    'spamfilter profile',
    'switch-controller managed-switch',
    'system.autoupdate push-update',
    'system.autoupdate schedule',
    'system.autoupdate tunneling',
    'system.dhcp server',
    'system.dhcp6 server',
    'system.replacemsg admin',
    'system.replacemsg alertmail',
    'system.replacemsg auth',
    'system.replacemsg device-detection-portal',
    'system.replacemsg ec',
    'system.replacemsg fortiguard-wf',
    'system.replacemsg ftp',
    'system.replacemsg http',
    'system.replacemsg mail',
    'system.replacemsg nac-quar',
    'system.replacemsg nntp',
    'system.replacemsg spam',
    'system.replacemsg sslvpn',
    'system.replacemsg traffic-quota',
    'system.replacemsg utm',
    'system.replacemsg webproxy',
    'system.snmp community',
    'system.snmp sysinfo',
    'system.snmp user',
    'system accprofile',
    'system admin',
    'system alarm',
    'system arp-table',
    'system auto-install',
    'system auto-script',
    'system central-management',
    'system cluster-sync',
    'system config backup',
    'system config restore',
    'system console',
    'system custom-language',
    'system ddns',
    'system dedicated-mgmt',
    'system dns',
    'system dns-database',
    'system dns-server',
    'system dscp-based-priority',
    'system email-server',
    'system fips-cc',
    'system fm',
    'system fortiguard',
    'system fortimanager',
    'system fortisandbox',
    'system fsso-polling',
    'system geoip-override',
    'system global',
    'system gre-tunnel',
    'system ha',
    'system ha-monitor',
    'system interface',
    'system ipip-tunnel',
    'system ips-urlfilter-dns',
    'system ipv6-neighbor-cache',
    'system ipv6-tunnel',
    'system link-monitor',
    'system mac-address-table',
    'system management-tunnel',
    'system mobile-tunnel',
    'system nat64',
    'system netflow',
    'system network-visibility',
    'system nst',
    'system ntp',
    'system object-tag',
    'system password-policy',
    'system password-policy-guest-admin',
    'system probe-response',
    'system proxy-arp',
    'system replacemsg-group',
    'system replacemsg-image',
    'system resource-limits',
    'system session-helper',
    'system session-ttl',
    'system settings',
    'system sflow',
    'system sit-tunnel',
    'system sms-server',
    'system storage',
    'system switch-interface',
    'system tos-based-priority',
    'system vdom',
    'system vdom-dns',
    'system vdom-link',
    'system vdom-netflow',
    'system vdom-property',
    'system vdom-radius-server',
    'system vdom-sflow',
    'system virtual-wan-link',
    'system virtual-wire-pair',
    'system vmlicense upload',
    'system wccp',
    'system zone',
    'user adgrp',
    'user device',
    'user device-access-list',
    'user device-category',
    'user device-group',
    'user fortitoken',
    'user fsso',
    'user fsso-polling',
    'user group',
    'user ldap',
    'user local',
    'user password-policy',
    'user peer',
    'user peergrp',
    'user pop3',
    'user radius',
    'user security-exempt-list',
    'user setting',
    'user tacacs+',
    'voip profile',
    'vpn.certificate ca',
    'vpn.certificate crl',
    'vpn.certificate local',
    'vpn.certificate ocsp-server',
    'vpn.certificate remote',
    'vpn.certificate setting',
    'vpn.ipsec concentrator',
    'vpn.ipsec forticlient',
    'vpn.ipsec manualkey',
    'vpn.ipsec manualkey-interface',
    'vpn.ipsec phase1',
    'vpn.ipsec phase1-interface',
    'vpn.ipsec phase2',
    'vpn.ipsec phase2-interface',
    'vpn.ssl.web host-check-software',
    'vpn.ssl.web portal',
    'vpn.ssl.web realm',
    'vpn.ssl.web user-bookmark',
    'vpn.ssl.web user-group-bookmark',
    'vpn.ssl.web virtual-desktop-app-list',
    'vpn.ssl settings',
    'vpn l2tp',
    'vpn pptp',
    'waf main-class',
    'waf profile',
    'waf signature',
    'waf sub-class',
    'wanopt auth-group',
    'wanopt peer',
    'wanopt profile',
    'wanopt settings',
    'wanopt storage',
    'wanopt webcache',
    'web-proxy debug-url',
    'web-proxy explicit',
    'web-proxy forward-server',
    'web-proxy forward-server-group',
    'web-proxy global',
    'web-proxy profile',
    'web-proxy url-match',
    'web-proxy wisp',
    'webfilter content',
    'webfilter content-header',
    'webfilter cookie-ovrd',
    'webfilter fortiguard',
    'webfilter ftgd-local-cat',
    'webfilter ftgd-local-rating',
    'webfilter ftgd-warning',
    'webfilter ips-urlfilter-cache-setting',
    'webfilter ips-urlfilter-setting',
    'webfilter override',
    'webfilter override-user',
    'webfilter profile',
    'webfilter search-engine',
    'webfilter urlfilter',
    'wireless-controller ap-status',
    'wireless-controller global',
    'wireless-controller setting',
    'wireless-controller timers',
    'wireless-controller vap',
    'wireless-controller vap-group',
    'wireless-controller wids-profile',
    'wireless-controller wtp',
    'wireless-controller wtp-group',
    'wireless-controller wtp-profile']


def json2obj(data):
    return json.loads(data, object_hook=lambda d: Namespace(**d))


def get(name, action=None, mkey=None, parameters=None):
    return json.loads(fos.get('cmdb', name, action, mkey, parameters))


def extract_path_and_name(url_segment_list):
    if len(url_segment_list) < 2:
        raise AssertionError('List should have a minimum of two items')
    path = '/'.join(url_segment_list[0:-1])
    name = url_segment_list[-1]
    return path, name


def login(data):
    host = data['host']
    username = data['username']
    password = data['password']
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')
    fos.debug('on')
    fos.login(host, username, password)


def logout():
    fos.logout()


def fortigate_config_put(data):
    login(data)

    functions = data['config'].split()

    schema = fos.schema(functions[0], functions[1])
    dataconf = data['config_parameters']

    mkey = None
    if schema and ('mkey' in schema):
        keyname = schema['mkey']
        if dataconf and (keyname in dataconf):
            mkey = dataconf[keyname]

    resp = fos.put(functions[0], functions[1], vdom=data['vdom'],
                   mkey=mkey, data=data['config_parameters'])

    logout()

    meta = {"status": resp['status'], 'http_status': resp['http_status']}
    if resp['status'] == "success":
        return False, True, meta
    else:
        return True, False, meta


def fortigate_config_post(data):
    login(data)

    functions = data['config'].split()

    resp = fos.post(functions[0], functions[1], vdom=data['vdom'],
                    data=data['config_parameters'])
    logout()

    meta = {"status": resp['status'], 'http_status': resp['http_status']}
    if resp['status'] == "success":
        return False, True, meta
    else:
        return True, False, meta


def fortigate_config_set(data):
    login(data)

    functions = data['config'].split()

    resp = fos.set(functions[0], functions[1], vdom=data['vdom'],
                   data=data['config_parameters'])
    logout()

    meta = {"status": resp['status'], 'http_status': resp['http_status']}
    if resp['status'] == "success":
        return False, True, meta
    elif resp['error'] == -5:
        return False, False, meta
    else:
        return True, False, meta


def fortigate_config_get(data):
    login(data)

    functions = data['config'].split()
    schema = fos.schema(functions[0], functions[1])
    dataconf = data['config_parameters']

    mkey = None
    if schema and ('mkey' in schema):
        keyname = schema['mkey']
        if dataconf and (keyname in dataconf):
            mkey = dataconf[keyname]

    resp = fos.get(functions[0], functions[1], mkey=mkey, vdom=data['vdom'])
    logout()

    if resp['status'] == "success":
        return False, False, {
            "status": resp['status'],
            'version': resp['version'], 'results': resp['results']
        }
    else:
        return True, False, {
            "status": resp['status'], 'version': resp['version']
        }


def fortigate_config_monitor(data):
    login(data)

    functions = data['config'].split()

    path, name = extract_path_and_name(functions)

    resp = fos.monitor(path, name, vdom=data['vdom'])
    logout()

    if resp['status'] == "success":
        return False, False, {
            "status": resp['status'], 'version': resp['version'],
            'results': resp['results']}
    else:
        return True, False, {
            "status": resp['status'], 'version': resp['version']}


def fortigate_config_del(data):
    vdom = data['vdom']
    login(data)

    functions = data['config'].split()
    schema = fos.schema(functions[0], functions[1])
    keyname = schema['mkey']
    dataconf = data['config_parameters']
    mkey = dataconf[keyname]

    resp = fos.delete(functions[0], functions[1], mkey=mkey, vdom=vdom)
    logout()

    meta = {"status": resp['status'], 'http_status': resp['http_status']}

    if resp['status'] == "success":
        return False, True, meta
    elif resp['http_status'] == 404:
        return False, False, meta
    else:
        return True, False, meta


def fortigate_config_ssh(data):
    host = data['host']
    username = data['username']
    password = data['password']
    cmds = data['commands']

    try:
        out, err = fos.ssh(cmds, host, username, password=password)
        meta = {"out": out, "err": err, }
        return False, True, meta
    except:
        return True, False, {"out": "n/a", "err": "at least one cmd returned an error"}


def remove_sensitive_data(string):
    while True:
        filtered_string = re.sub('set password ENC.*?==', '', string, flags=re.MULTILINE | re.DOTALL)
        if string == filtered_string:
            break
        else:
            string = filtered_string

    while True:
        filtered_string = re.sub('set passwd ENC.*?==', '', string, flags=re.MULTILINE | re.DOTALL)
        if string == filtered_string:
            break
        else:
            string = filtered_string

    while True:
        filtered_string = re.sub('set private-key.*?-----END ENCRYPTED PRIVATE KEY-----"',
                                 '',
                                 string,
                                 flags=re.MULTILINE | re.DOTALL)
        if string == filtered_string:
            break
        else:
            string = filtered_string

    while True:
        filtered_string = re.sub('set certificate.*?-----END CERTIFICATE-----"',
                                 '',
                                 string,
                                 flags=re.MULTILINE | re.DOTALL)
        if string == filtered_string:
            break
        else:
            string = filtered_string

    return filtered_string


def check_diff(data):
    login(data)

    parameters = {'destination': 'file',
                  'scope': 'global'}

    resp = fos.monitor('system/config',
                       'backup',
                       vdom=data['vdom'],
                       parameters=parameters)

    if resp['status'] != 'success':
        return True, False, {
            'status': resp['status'],
            'version': resp['version'],
            'results': resp['results']
        }

    remote_filename = resp['results']['DOWNLOAD_SOURCE_FILE']
    parameters = {'scope': 'global'}

    resp = fos.download('system/config',
                        'backup' + remote_filename,
                        vdom=data['vdom'],
                        parameters=parameters)
    version = fos.get_version()
    logout()

    if resp.status_code == 200:

        filtered_remote_config_file = remove_sensitive_data(resp.content)
        filtered_local_config_file = remove_sensitive_data(open(data['config_parameters']['filename'], 'r').read())

        remote_config_file = filtered_remote_config_file.strip().splitlines()
        local_config_file = filtered_local_config_file.strip().splitlines()

        differences = ""
        for line in difflib.unified_diff(local_config_file, remote_config_file, fromfile='local', tofile='fortigate',
                                         lineterm=''):
            differences += line + '\n'

        return False, True, {
            'status': resp.status_code,
            'version': version,
            'diff': differences
        }
    else:
        return True, False, {
            'status': resp.status_code,
            'version': version
        }


def fortigate_config_backup(data):
    login(data)

    functions = data['config'].split()

    parameters = {'destination': 'file',
                  'scope': 'global'}

    resp = fos.monitor(functions[0] + '/' + functions[1],
                       functions[2],
                       vdom=data['vdom'],
                       parameters=parameters)

    version = fos.get_version()
    backup_content = ""

    if 'status' in resp:  # Old versions use this mechanism
        if resp['status'] != 'success':
            return True, False, {
                'status': resp['status'],
                'version': resp['version'],
                'results': resp['results']
            }

        remote_filename = '/download?mkey=' + resp['results']['DOWNLOAD_SOURCE_FILE']
        parameters = {'scope': 'global'}

        resp = fos.download(functions[0] + '/' + functions[1],
                            functions[2] + remote_filename,
                            vdom=data['vdom'],
                            parameters=parameters)
        if resp.status_code == 200:
            backup_content = resp.content

    elif 'status_code' in dir(resp):
        if resp.status_code == 200:
            backup_content = resp.text

    else:
        return True, False, {
            'status': 500,
            'version': version
        }

    logout()

    file = open(data['config_parameters']['filename'], 'w')
    file.write(backup_content)
    file.close()

    return False, False, {
        'status': 200,
        'version': version,
        'backup': backup_content
        }



def fortigate_config_upload(data):
    login(data)

    if data['diff'] == True:
        return check_diff(data)

    functions = data['config'].split()

    parameters = {'global': '1'}
    upload_data = {'source': 'upload', 'scope': 'global'}
    files = {'file': ('backup_data', open(data['config_parameters']['filename'], 'r'), 'text/plain')}

    resp = fos.upload(functions[0] + '/' + functions[1], functions[2],
                      data=upload_data,
                      parameters=parameters,
                      files=files)
    version = fos.get_version()
    logout()

    if resp.status_code == 200:
        return False, True, {
            'status': resp.status_code,
            'version': version,
            'result': resp.content
        }
    else:
        return True, False, {
            'status': resp.status_code,
            'version': version,
            'result': resp.content
        }


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "username": {"required": True, "type": "str"},
        "description": {"required": False, "type": "str"},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "config": {"required": False, "choices": AVAILABLE_CONF, "type": "str"},
        "mkey": {"required": False, "type": "str"},
        "https": {"required": False, "type": "bool", "default": "True"},
        "action": {
            "default": "set",
            "choices": ['set', 'delete', 'put',
                        'post', 'get', 'monitor',
                        'ssh', 'backup', 'restore',
                        'upload'],
            "type": 'str'
        },
        "config_parameters": {"required": False, "type": "dict"},
        "commands": {"required": False, "type": "str"}
    }

    choice_map = {
        "set": fortigate_config_set,
        "delete": fortigate_config_del,
        "put": fortigate_config_put,
        "post": fortigate_config_post,
        "get": fortigate_config_get,
        "monitor": fortigate_config_monitor,
        "ssh": fortigate_config_ssh,
        "backup": fortigate_config_backup,
        "restore": fortigate_config_upload,
        "upload": fortigate_config_upload
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    module.params['diff'] = False
    try:
        module.params['diff'] = module._diff
    except:
        logger.warning("Diff mode is only available on Ansible 2.1 and later versions")
        pass

    is_error, has_changed, result = choice_map.get(
        module.params['action'])(module.params)

    if not is_error:
        if module.params['diff']:
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
