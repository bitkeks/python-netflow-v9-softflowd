#!/usr/bin/env python3

"""
Netflow V5 collector and parser implementation in Python 3.
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.
Created purely for fun. Not battled tested nor will it be.

Reference: https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
This script is specifically implemented in combination with softflowd. See https://github.com/djmdjm/softflowd
"""

import struct

__all__ = ["V5DataFlow", "V5ExportPacket", "V5Header"]


class V5DataFlow:
    """Holds one v5 DataRecord
    """
    length = 48

    def __init__(self, data):
        pack = struct.unpack("!IIIHHIIIIHHxBBBHHBBxx", data)
        fields = [
            'IPV4_SRC_ADDR',
            'IPV4_DST_ADDR',
            'NEXT_HOP',
            'INPUT',
            'OUTPUT',
            'IN_PACKETS',
            'IN_OCTETS',
            'FIRST_SWITCHED',
            'LAST_SWITCHED',
            'SRC_PORT',
            'DST_PORT',
            # Byte 36 is used for padding
            'TCP_FLAGS',
            'PROTO',
            'TOS',
            'SRC_AS',
            'DST_AS',
            'SRC_MASK',
            'DST_MASK',
            # Word 46 is used for padding
        ]

        self.data = {}
        for idx, field in enumerate(fields):
            self.data[field] = pack[idx]
        self.__dict__.update(self.data)  # Make data dict entries accessible as object attributes

    def __repr__(self):
        return "<DataRecord with data {}>".format(self.data)


class V5Header:
    """The header of the V5ExportPacket
    """
    length = 24

    def __init__(self, data):
        pack = struct.unpack('!HHIIIIBBH', data[:self.length])
        self.version = pack[0]
        self.count = pack[1]
        self.uptime = pack[2]
        self.timestamp = pack[3]
        self.timestamp_nano = pack[4]
        self.sequence = pack[5]
        self.engine_type = pack[6]
        self.engine_id = pack[7]
        self.sampling_interval = pack[8]

    def to_dict(self):
        return self.__dict__


class V5ExportPacket:
    """The flow record holds the header and data flowsets.
    """

    def __init__(self, data):
        self.flows = []
        self.header = V5Header(data)

        offset = self.header.length
        for flow_count in range(0, self.header.count):
            end = offset + V5DataFlow.length
            flow = V5DataFlow(data[offset:end])
            self.flows.append(flow)
            offset += flow.length

    def __repr__(self):
        return "<ExportPacket v{} with {} records>".format(
            self.header.version, self.header.count)
