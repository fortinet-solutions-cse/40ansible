#Docker to develop/try Ansible module for Fortigate
#Start with ubuntu 
FROM ubuntu:16.04
MAINTAINER Nicolas Thomas <thomnico@gmail.com>
#Update the Ubuntu software repository inside the dockerfile with the 'RUN' command.
# Update Ubuntu Software repository
RUN apt update && apt -y upgrade && apt -y install git python-pip software-properties-common zile byobu ansible
# python-setuptools libxml2-dev libxslt-dev   zlib1g-dev
# install ansible > 2.1 to get the debugguer 
#RUN apt-add-repository -y ppa:ansible/ansible && apt update && apt -y upgrade && apt -y install ansible
#RUN pip install --upgrade pip && pip install -i https://testpypi.python.org/pypi fortiosapi
RUN pip install --upgrade pip==9.0.3 && pip install fortiosapi
CMD ["/usr/bin/bash"]
