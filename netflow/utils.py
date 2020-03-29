#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2017-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import struct

from .v1 import V1ExportPacket
from .v5 import V5ExportPacket
from .v9 import V9ExportPacket


class UnknownNetFlowVersion(Exception):
    def __init__(self, data, version):
        self.data = data
        self.version = version
        r = repr(data)
        data_str = ("{:.25}..." if len(r) >= 28 else "{}").format(r)
        super().__init__(
            "Unknown NetFlow version {} for data {}".format(version, data_str)
        )


def get_netflow_version(data):
    return struct.unpack('!H', data[:2])[0]


def parse_packet(data, templates):
    version = get_netflow_version(data)
    if version == 1:
        return V1ExportPacket(data)
    elif version == 5:
        return V5ExportPacket(data)
    elif version == 9:
        return V9ExportPacket(data, templates)
    raise UnknownNetFlowVersion(data, version)