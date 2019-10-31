#!/usr/bin/env python3

"""
Example analyzing script for saved exports (by main.py, as JSON).
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2019 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import argparse
from collections import namedtuple
import contextlib
from datetime import datetime
import functools
import ipaddress
import json
import socket
import sys


Pair = namedtuple('Pair', ['src', 'dest'])


@functools.lru_cache(maxsize=128)
def resolve_hostname(ip):
    return socket.getfqdn(ip)


def fallback(d, keys):
    for k in keys:
        try:
            return d[k]
        except KeyError:
            pass
    raise KeyError(", ".join(keys))


class Connection:
    """Connection model for two flows.
    The direction of the data flow can be seen by looking at the size.

    'src' describes the peer which sends more data towards the other. This
    does NOT have to mean that 'src' was the initiator of the connection.
    """
    def __init__(self, flow1, flow2):
        if not flow1 or not flow2:
            raise Exception("A connection requires two flows")

        # Assume the size that sent the most data is the source
        # TODO: this might not always be right, maybe use earlier timestamp?
        size1 = fallback(flow1, ['IN_BYTES', 'IN_OCTETS'])
        size2 = fallback(flow2, ['IN_BYTES', 'IN_OCTETS'])
        if size1 >= size2:
            src = flow1
            dest = flow2
        else:
            src = flow2
            dest = flow1

        ips = self.get_ips(src)
        self.src = ips.src
        self.dest = ips.dest
        self.src_port = fallback(src, ['L4_SRC_PORT', 'SRC_PORT'])
        self.dest_port = fallback(dest, ['L4_DST_PORT', 'DST_PORT'])
        self.size = fallback(src, ['IN_BYTES', 'IN_OCTETS'])

        # Duration is given in milliseconds
        self.duration = src['LAST_SWITCHED'] - src['FIRST_SWITCHED']
        if self.duration < 0:
            # 32 bit int has its limits. Handling overflow here
            # TODO: Should be handled in the collection phase
            self.duration = (2**32 - src['FIRST_SWITCHED']) + src['LAST_SWITCHED']

    def __repr__(self):
        return "<Connection from {} to {}, size {}>".format(
            self.src, self.dest, self.human_size)

    @staticmethod
    def get_ips(flow):
        # TODO: These values should be parsed into strings in the collection phase.
        #       The floating point representation of an IPv6 address in JSON
        #       could lose precision.

        # IPv4
        if flow.get('IP_PROTOCOL_VERSION') == 4 \
                or 'IPV4_SRC_ADDR' in flow \
                or 'IPV4_DST_ADDR' in flow:
            return Pair(
                ipaddress.ip_address(flow['IPV4_SRC_ADDR']),
                ipaddress.ip_address(flow['IPV4_DST_ADDR'])
            )

        # IPv6
        return Pair(
            ipaddress.ip_address(flow['IPV6_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV6_DST_ADDR'])
        )

    @property
    def human_size(self):
        # Calculate a human readable size of the traffic
        if self.size < 1024:
            return "%dB" % self.size
        elif self.size / 1024. < 1024:
            return "%.2fK" % (self.size / 1024.)
        elif self.size / 1024.**2 < 1024:
            return "%.2fM" % (self.size / 1024.**2)
        else:
            return "%.2fG" % (self.size / 1024.**3)

    @property
    def human_duration(self):
        duration = self.duration // 1000  # uptime in milliseconds, floor it
        if duration < 60:
            # seconds
            return "%d sec" % duration
        if duration / 60 > 60:
            # hours
            return "%d:%02d.%02d hours" % (duration / 60**2, duration % 60**2 / 60, duration % 60)
        # minutes
        return "%02d:%02d min" % (duration / 60, duration % 60)

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        src_hostname = resolve_hostname(self.src.compressed)
        dest_hostname = resolve_hostname(self.dest.compressed)
        return Pair(src_hostname, dest_hostname)

    @property
    def service(self):
        # Resolve ports to their services, if known
        # Try source port, fallback to dest port, otherwise "unknown"
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.src_port)
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.dest_port)
        return "unknown"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Output a basic analysis of NetFlow data")
    parser.add_argument('filename', nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="The file to analyze (defaults to stdin if not provided)")
    args = parser.parse_args()

    data = json.load(args.filename)

    # Go through data and disect every flow saved inside the dump
    for key in sorted(data):
        timestamp = datetime.fromtimestamp(float(key)).strftime("%Y-%m-%d %H:%M.%S")

        flows = data[key]
        pending = None  # Two flows normally appear together for duplex connection
        for flow in flows:
            if not pending:
                pending = flow
                continue
            con = Connection(pending, flow)
            print("{timestamp}: {service:7} | {size:8} | {duration:9} | {src_host} ({src}) to {dest_host} ({dest})" \
                .format(timestamp=timestamp, service=con.service.upper(), src_host=con.hostnames.src, src=con.src,
                        dest_host=con.hostnames.dest, dest=con.dest, size=con.human_size, duration=con.human_duration))
            pending = None
