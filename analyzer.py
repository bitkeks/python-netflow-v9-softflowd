#!/usr/bin/env python3

"""
Example analyzing script for saved exports (by main.py, as JSON).
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import argparse
from collections import namedtuple
import contextlib
from datetime import datetime
import functools
import gzip
import ipaddress
import json
import logging
import os.path
import socket
import sys


Pair = namedtuple('Pair', ['src', 'dest'])
logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=None)
def resolve_hostname(ip):
    return socket.getfqdn(ip)


def fallback(d, keys):
    for k in keys:
        if k in d:
            return d[k]
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

        # TODO: this next approach uses the lower port as the service identifier
        # port1 = fallback(flow1, ['L4_SRC_PORT', 'SRC_PORT'])
        # port2 = fallback(flow2, ['L4_SRC_PORT', 'SRC_PORT'])
        #
        # src = flow1
        # dest = flow2
        # if port1 > port2:
        #     src = flow2
        #     dest = flow1

        self.src_flow = src
        self.dest_flow = dest
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
        # IPv4
        if flow.get('IP_PROTOCOL_VERSION') == 4 or \
                'IPV4_SRC_ADDR' in flow or 'IPV4_DST_ADDR' in flow:
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
        default = "({} {})".format(self.src_port, self.dest_port)
        if self.src_port > 10000:
            return default
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.src_port)
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.dest_port)
        return default

    @property
    def total_packets(self):
        return self.src_flow["IN_PKTS"] + self.dest_flow["IN_PKTS"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Output a basic analysis of NetFlow data")
    parser.add_argument('-f', '--file', dest='file', type=str, default=sys.stdin,
                        help="The file to analyze (defaults to stdin if not provided)")
    parser.add_argument('-p', '--packets', dest='packets_threshold', type=int, default=10,
                        help="Number of packets representing the lower bound in connections to be processed")
    args = parser.parse_args()

    # Using a file and using stdin differ in their further usage for gzip.open
    file = args.file
    mode = "rb"  # reading files
    if file != sys.stdin and not os.path.exists(file):
        exit("File {} does not exist!".format(file))

    if file == sys.stdin:
        file = sys.stdin.buffer
        mode = "rt"  # reading from stdin

    data = {}

    with gzip.open(file, mode) as gzipped:
        # "for line in" lazy-loads all lines in the file
        for line in gzipped:
            entry = json.loads(line)
            if len(entry.keys()) != 1:
                logger.warning("Line \"{}\" does not have exactly one timestamp key.")

            try:
                ts = list(entry)[0]  # timestamp from key
            except KeyError:
                logger.error("Saved line \"{}\" has no timestamp key!".format(line))
                continue

            data[ts] = entry[ts]

    # Go through data and dissect every flow saved inside the dump

    # The following dict holds flows which are looking for a peer, to analyze a duplex 'Connection'.
    # For each flow, the destination address is looked up. If the peer is not in the list of pending peers,
    # insert this flow, waiting for its peer. If found, take the waiting peer and create a Connection object.
    pending = {}
    skipped = 0
    skipped_threshold = args.packets_threshold

    for key in sorted(data):
        timestamp = datetime.fromtimestamp(float(key)).strftime("%Y-%m-%d %H:%M.%S")
        client = data[key]["client"]
        flows = data[key]["flows"]

        for flow in sorted(flows, key=lambda x: x["FIRST_SWITCHED"]):
            first_switched = flow["FIRST_SWITCHED"]

            if first_switched - 1 in pending:
                # TODO: handle fitting, yet mismatching (here: 1 second) pairs
                pass

            if first_switched not in pending:
                pending[first_switched] = {}

            # Find the peer for this connection
            if flow["IP_PROTOCOL_VERSION"] == 4:
                local_peer = flow["IPV4_SRC_ADDR"]
                remote_peer = flow["IPV4_DST_ADDR"]
            else:
                local_peer = flow["IPV6_SRC_ADDR"]
                remote_peer = flow["IPV6_DST_ADDR"]

            if remote_peer in pending[first_switched]:
                # The destination peer put itself into the pending dict, getting and removing entry
                peer_flow = pending[first_switched].pop(remote_peer)
                if len(pending[first_switched]) == 0:
                    del pending[first_switched]
            else:
                # Flow did not find a matching, pending peer - inserting itself
                pending[first_switched][local_peer] = flow
                continue

            con = Connection(flow, peer_flow)
            if con.total_packets < skipped_threshold:
                skipped += 1
                continue

            print("{timestamp}: {service:<14} | {size:8} | {duration:9} | {packets:5} | Between {src_host} ({src}) and {dest_host} ({dest})" \
                  .format(timestamp=timestamp, service=con.service.upper(), src_host=con.hostnames.src, src=con.src,
                          dest_host=con.hostnames.dest, dest=con.dest, size=con.human_size, duration=con.human_duration,
                          packets=con.total_packets))

    if skipped > 0:
        print(f"{skipped} connections skipped, because they had less than {skipped_threshold} packets.")

    if len(pending) > 0:
        print(f"There are {len(pending)} first_switched entries left in the pending dict!")
        all_noise = True
        for first_switched, flows in sorted(pending.items(), key=lambda x: x[0]):
            for peer, flow in flows.items():
                # Ignore all pings, SYN scans and other noise to find only those peers left over which need a fix
                if flow["IN_PKTS"] < skipped_threshold:
                    continue
                all_noise = False

                if flow["IP_PROTOCOL_VERSION"] == 4:
                    print(first_switched, peer, flow["IPV4_DST_ADDR"], flow["IN_PKTS"])
                else:
                    print(first_switched, peer, flow["IPV6_DST_ADDR"], flow["IN_PKTS"])

        if all_noise:
            print("They were all noise!")