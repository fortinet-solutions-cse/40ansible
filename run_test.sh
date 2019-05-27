#!/usr/bin/env bash

set -x

cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )

trap ctrl_c SIGINT
trap ctrl_c SIGTERM

FGT_IP="192.168.122.40"

if [ ! -e license_file.lic ]; then
  echo "Need 'license_file.lic' in this directory in order to perform all tests."
  exit -1
fi

ssh-keygen -f "${HOME}/.ssh/known_hosts" -R "${FGT_IP}"

function remove_waste_files()
{
    rm -f $(pwd)/*.retry
    rm -f $(pwd)/*.https
    rm -f backup_config_001
}

function ctrl_c() {
    echo "** Interrupted by user **"
    echo -e "\n\n Results: \n  Success: "${success}"  Failed: "${failed}"\n"
    remove_waste_files
    exit -1
}

if [ ! -z $1 ] && [ "$1"="--https" ]; then
  https=true
fi

remove_waste_files

success=0
failed=0

function wait_until_fgt_is_up() {

    sleep 3
    until wget ${FGT_IP} -T1 -t1 -q -O /dev/null --no-check-certificate
    do
      sleep 1
      echo Waiting for FGT to get up
    done

}

function wait_until_fgt_validates_license() {

    until ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@${FGT_IP} get system status|grep "License Status: Valid"
    do
       sleep 1
       echo Waiting for FGT to validate license
    done
}

function modify_playbook_for_https() {

    cat $1 |sed 's/https: False/https: True/g' > $1.https
}

function run_example( ) {

    export ANSIBLE_LIBRARY=$(pwd)/library

    filename=$1
    cp ./examples/$1 .

    if [ "$https" = true ]; then
        modify_playbook_for_https ${filename}
        ansible-playbook ${filename}.https
        if [ $? == 0 ]; then
          success=$(($success+1))
        else
          failed=$(($failed+1))
        fi
        rm -f ${filename}.https
    else
        ansible-playbook ${filename}
        if [ $? == 0 ]; then
          success=$(($success+1))
        else
          failed=$(($failed+1))
        fi
    fi

    rm -f ${filename}
}


run_example fortigate_create_firewall_policy.yml
run_example fortigate_delete_firewall_policy.yml
run_example fortigate_create_firewall_vip.yml
run_example fortigate_mix.yml
run_example fortigate_monitor_system_resource_usage.yml
run_example fortigate_ssh.yml
run_example fortigate_backup_config.yml
run_example fortigate_restore_config.yml
wait_until_fgt_is_up
run_example fortigate_upload_license.yml
wait_until_fgt_is_up
https=true
wait_until_fgt_validates_license
run_example fortigate_disable_https_redirect.yml
run_example fortigate_create_firewall_policy.yml
run_example fortigate_delete_firewall_policy.yml
# Uncomment after 6.2.1 release, when vpn certificate is fixed in REST API
#run_example fortigate_vpn_certificate_csr_generate.yml
#run_example fortigate_vpn_certificate_csr_delete.yml

remove_waste_files

echo -e "\n\n Results: \n  Success: "${success}"  Failed: "${failed}"\n"

if [ ${failed} -ne 0 ]; then
  exit -1
fi