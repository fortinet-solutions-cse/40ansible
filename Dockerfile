#Docker to develop/try Ansible module for Fortigate
#Start with ubuntu 
FROM ubuntu:16.04
MAINTAINER Nicolas Thomas <thomnico@gmail.com>
#Update the Ubuntu software repository inside the dockerfile with the 'RUN' command.
# Update Ubuntu Software repository
RUN apt-get update && apt-get -y upgrade && apt-get -y install git python-pip ansible
# install fortiosclient

RUN pip install --upgrade pip && pip install --upgrade fortiosclient

CMD ["/usr/bin/bash"]