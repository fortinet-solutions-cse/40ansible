#!/bin/bash
#************************************************
#
# Use this script to start a FortiMail VM with
# LibVirt, no VIM required.
# This has support for cloud init, see below how
# to build cdrom with proper content
#
# Miguel Angel Muñoz <magonzalez at fortinet.com>
#
# ************************************************

#************************************************
# Check FortiMail VM existence
#************************************************

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Need location of FortiMail image and auxiliary disk"
  exit -1
fi
result=$(file $1)
result_aux=$(file $2)

if [[ $result == *"QEMU QCOW Image (v3)"* ]] && [[ $result_aux == *"QEMU QCOW Image (v3)"* ]] ; then
   echo "Supplied FortiMail image is in: $1"
   FortiMail_QCOW2=$1
   AuxDisk_QCOW2=$2
else
   echo "Supplied FortiMail image does not look a qcow2 file"
   exit -1
fi
if [[ "$(realpath $FortiMail_QCOW2)" == "$(pwd)/fortimail-kvm.qcow2" ]]; then
   echo "FortiMail image can not be named fortios.qcow2 in this directory. Choose different location/name"
   exit -1
fi

export SF2_NAME=FortiMail
export SF2_IP_ADMIN=192.168.122.50
export SF2_IP=192.168.70.50
export SF2_IP2=192.168.80.50
export SF2_MAC_ADMIN=08:00:27:4c:22:50
export SF2_MAC=08:00:27:4c:70:50
export SF2_MAC2=08:00:27:4c:80:50

rm -f fortimail-kvm.qcow2
rm -f aux_disk.qcow2
rm -rf cfg-drv-fgt
rm -rf ${SF2_NAME}-cidata.iso

cp ${FortiMail_QCOW2} ./fortimail-kvm.qcow2
cp ${AuxDisk_QCOW2} ./aux_disk.qcow2

mkdir -p cfg-drv-fgt/openstack/latest/
mkdir -p cfg-drv-fgt/openstack/content/

cat >cfg-drv-fgt/openstack/latest/user_data <<EOF
EOF

cat >cfg-drv-fgt/openstack/latest/meta_data.json <<EOF
{
    "files": [
        {"path": "mode", "content_path": "/content/0000"},
        {"path": "config", "content_path": "/content/0001"},
        {"path": "license", "content_path": "/content/0002"}
    ]
}
EOF

cat >cfg-drv-fgt/openstack/content/0000 <<EOF
config system global
  set operation-mode server
end
EOF

cat >cfg-drv-fgt/openstack/content/0001 <<EOF
config system interface
  edit "port1"
    set ip 192.168.122.50/24
    set allowaccess ping ssh snmp http https telnet
  next
end

config system global
   set rest-api enable
end

config system global
   set pki-mode enable
end

config system route
  edit 1
    set gateway 192.168.122.1
  next
end

config system dns
    set primary 8.8.8.8
    set secondary 8.8.4.4
end
EOF

cat >cfg-drv-fgt/openstack/content/0002 <<EOF
-----BEGIN FE VM LICENSE-----
Put your license here
-----END FE VM LICENSE-----
EOF

aux_name=$(basename $AuxDisk_QCOW2)

sudo mkisofs -publisher "OpenStack Nova 12.0.2" -J -R -V config-2 -o ${SF2_NAME}-cidata.iso cfg-drv-fgt
virt-install --connect qemu:///system --noautoconsole --filesystem ${PWD},shared_dir --import --name ${SF2_NAME} \
  --ram 2048 --vcpus 1 --disk fortimail-kvm.qcow2,size=3 --disk aux_disk.qcow2,size=${aux_name%.*} --disk ${SF2_NAME}-cidata.iso,device=cdrom,bus=ide,format=raw,cache=none --network bridge=virbr0,mac=${SF2_MAC_ADMIN},model=virtio

# Test FortiMail traffic with this simple script:
# sudo apt-get install -y swaks
# swaks -f a@agmail.com -t a@a.com -s 172.21.6.159
# while true; do sleep 1; swaks -f a@agmail.com -t a@a.com -s 172.21.6.159; done


#Deploy FortiMail in openstack: Note mode, config and license files (take examples from above)
# openstack server create --image "fortimail" --key-name t1 --flavor fortimail-flv \
#  --nic net-id=mgmt  --block-device-mapping sdb=t1 --block-device-mapping sdc=t2  \
#  --file mode=./mode --file config=./config --file license=./license   --config-drive True FortiMailVM


