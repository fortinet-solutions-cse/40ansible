# 40ansible

This project contains Ansible modules for FortiGate and FortiMail

It depends on https://pypi.python.org/pypi/fortiosapi

You can install it with pip:

`pip install fortiosapi `

If your environment does not support pip installation the latest version is located in:

 https://github.com/fortinet-solutions-cse/fortiosapi/tree/master/fortiosapi

*Note: FortiGate versions are supported from 5.6 onwards*

# Quickstart

Follow next instructions:

`git clone https://github.com/fortinet-solutions-cse/40ansible.git`

`cd 40ansible`

Copy the file fortigate_mix.yml to your base dir:

`cp examples/fortigate_mix.yml .`

Adapt the IP of the Fortigate in fortigate_mix.yml to your environment

`ansible-playbook fortigate_mix.yml`

You can then write your own playbooks and use inventory.

Please note Ansible does not run on FortiGate, instead you must run it locally, on a
specific server or Docker image (dockerfile provided).

More complete documentation on modules in Ansible documentation:
http://docs.ansible.com/ansible/modules.html
