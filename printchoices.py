#!/usr/bin/python
# got the list from ftntoolkit
# then copy/paste in file (csv) and awk '{ print $2 }' Schemas.csv |grep cmdb | awk -F "/" '{print $2 " " $3 }' > config-choices.txt 

import sys
import json
import pprint

d = [ ]
key = 0
with open("config-choices.txt") as f:
    for line in f:
       key = key +1
       d.append( line.strip())

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(d)

pp.pprint(d.count())
