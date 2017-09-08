# 40ansible
Ansible modules for Fortigates

Depends on https://pypi.python.org/pypi/fortiosapi
prefer to use:
`pip install fortiosapi `

If your environment does not support pip installation there is a copy
in library on this project and you can copy it using Ansible itself as
with the following example:
` tasks:
  - name: Upload python module wrkaround when pip is not an option.
    copy: src=library/fortiosapi.py dest=/usr/local/lib/python2.7/dist-packages/fortiosapi.py
`

# Quickstart
`git clone https://github.com/thomnico/40ansible.git`

`cd 40ansible`

Adapt the IP of the Fortigate in play.yml to your environment

`ansible-playbook play.yml`

You can then write your own playbooks and use inventory of course.
Ansible do not run on the fortigate you must run locally, on a
specific server or Docker image (dockerfile provided). This Ansible
module use only the FortiOS API on a remote device, hardware or VM.

More complete documentation on modules in Ansible documentation:
http://docs.ansible.com/ansible/modules.html
