#!/usr/bin/python

from fortigateconf import FortiOSConf
import sys
import json
import pprint
import json
from argparse import Namespace
import logging
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortinetconflib')
hdlr = logging.FileHandler('/var/tmp/testapi.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)

logger.debug('often makes a very good meal of %s', 'visiting tourists')

fgt = FortiOSConf()

def json2obj(data):
    return json.loads(data, object_hook=lambda d: Namespace(**d))


def main():
    # Login to the FGT ip
    fgt.debug('on')
    fgt.login('192.168.115.128','admin','adminpasswd')
    data = {
             "name": "port1",
             "allowaccess": "ping https ssh http fgfm snmp",
            "vdom":"root"
         }
    pp = pprint.PrettyPrinter(indent=4)
    d=json2obj(json.dumps(data))
    
    resp = fgt.set('system','interface', vdom="root", data=data)
    
    pp.pprint(resp)

    fgt.logout()


if __name__ == '__main__':
  main()
