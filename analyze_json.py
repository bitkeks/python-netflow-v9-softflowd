#!/usr/bin/env python3

"""
Example analyzing script for saved exports (as JSON).
This file belongs to https://github.com/cooox/python-netflow-v9-softflowd.

Copyright 2017 Dominik Pataky <dom@netdecorator.org>
Licensed under MIT License. See LICENSE.
"""

from datetime import datetime
import ipaddress
import json
import os.path
import sys
import socket
from collections import namedtuple

Pair = namedtuple('Pair', 'src dest')

def getIPs(flow):
    if flow['IP_PROTOCOL_VERSION'] == 4:
        return Pair(
            ipaddress.ip_address(flow['IPV4_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV4_DST_ADDR']))

    elif flow['IP_PROTOCOL_VERSION'] == 6:
        return Pair(
            ipaddress.ip_address(flow['IPV6_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV6_DST_ADDR']))


class Connection:
    """Connection model for two flows.
    The direction of the data flow can be seen by looking at the size.

    'src' describes the peer which sends more data towards the other. This
    does NOT have to mean, that 'src' was the initiator of the connection.
    """
    def __init__(self, flow1, flow2):
        if flow1['IN_BYTES'] >= flow2['IN_BYTES']:
            src = flow1
            dest = flow2
        else:
            src = flow2
            dest = flow1

        ips = getIPs(src)
        self.src = ips.src
        self.dest = ips.dest
        self.src_port = src['L4_SRC_PORT']
        self.dest_port = src['L4_DST_PORT']
        self.size = src['IN_BYTES']

    def __repr__(self):
        return "<Connection from {} to {}, size {}>".format(
            self.src, self.dest, self.human_size)

    @property
    def human_size(self):
        # Calculate a human readable size of the traffic
        if self.size < 1024:
            return "%d" % self.size
        elif self.size / 1024. < 1024:
            return "%.2fK" % (self.size / 1024.)
        elif self.size / 1024.**2 < 1024:
            return "%.2fM" % (self.size / 1024.**2)
        else:
            return "%.2fG" % (self.size / 1024.**3)

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        return Pair(socket.getfqdn(self.src.exploded),
                    socket.getfqdn(self.dest.exploded))

    @property
    def service(self):
        # Resolve ports to their services, if known
        service = "unknown"
        try:
            service = socket.getservbyport(self.src_port)
        except OSError:
            pass

        if service == "unknown":
            # Resolving the sport did not work, trying dport
            try:
                service = socket.getservbyport(self.dest_port)
            except OSError:
                pass

        return service


if len(sys.argv) < 2:
    exit("Use {} <filename>.json".format(sys.argv[0]))
filename = sys.argv[1]
if not os.path.exists(filename):
    exit("File {} does not exist!".format(filename))
with open(filename, 'r') as fh:
    data = json.loads(fh.read())

for export in sorted(data):
    timestamp = datetime.fromtimestamp(float(export)).strftime("%Y-%m-%d %H:%M.%S")

    flows = data[export]
    pending = None  # Two flows normally appear together for duplex connection
    for flow in flows:
        count_bytes = flow['IN_BYTES']
        count_packets = flow['IN_PKTS']

        #~ ips = getIPs(flow)
        #~ src = ips.src
        #~ dest = ips.dest

        #~ print("Flow from {src} to {dest} with {packets} packets, size {size}".
            #~ format(src=src, dest=dest, packets=count_packets, size=count_bytes))

        if not pending:
            pending = flow
        else:
            con = Connection(pending, flow)
            if con.size > 1024**2:
                print("{timestamp}: {service} from {src_host} ({src}) to"\
                    " {dest_host} ({dest}) size {size}".format(
                    timestamp=timestamp, service=con.service.upper(), size=con.human_size,
                    src_host=con.hostnames.src, src=con.src,
                    dest_host=con.hostnames.dest, dest=con.dest))
            pending = None
