#!/usr/bin/python

from fortiosapi import FortiOSAPI
import sys
import json
import pprint
import json
from argparse import Namespace
import logging
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiosapi')
hdlr = logging.FileHandler('testapi.log')
paramikolog = logging.getLogger("paramiko")
logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
paramikolog.addHandler(hdlr)

logger.setLevel(logging.DEBUG)
paramikolog.setLevel(logging.DEBUG)


fgt = FortiOSAPI()


def main():
    # Login to the FGT ip
    fgt.debug('on')
    fgthost = '192.168.122.222'
    user = 'admin'
    passwd =''
    cmd = "get system interface"
    out,err = fgt.ssh(cmd, fgthost, user, password=passwd)
    print ("out:"+out)
    print ("err:"+err)


if __name__ == '__main__':
  main()
