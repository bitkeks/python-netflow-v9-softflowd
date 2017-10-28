#!/usr/bin/env python3

# Example analyzing script for saved exports

from datetime import datetime
import ipaddress
import json
import sys

if len(sys.argv) < 2:
    exit("Use {} <filename>.json".format(sys.argv[0]))

filename = sys.argv[1]

with open(filename, 'r') as fh:
    data = json.loads(fh.read())

for export in sorted(data):
    timestamp = datetime.fromtimestamp(float(export))
    print("\n{}".format(timestamp))

    flows = data[export]
    for flow in flows:
        count_bytes = flow['IN_BYTES']
        count_packets = flow['IN_PKTS']

        if flow['IP_PROTOCOL_VERSION'] == 4:
            src = ipaddress.ip_address(flow['IPV4_SRC_ADDR'])
            dest = ipaddress.ip_address(flow['IPV4_DST_ADDR'])

        elif flow['IP_PROTOCOL_VERSION'] == 6:
            src = ipaddress.ip_address(flow['IPV6_SRC_ADDR'])
            dest = ipaddress.ip_address(flow['IPV6_DST_ADDR'])

        print("Flow from {src} to {dest} with {packets} packets, size {size}".
            format(src=src, dest=dest, packets=count_packets, size=count_bytes))
