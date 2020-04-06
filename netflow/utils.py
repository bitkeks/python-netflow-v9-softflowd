#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.
"""

import struct
from typing import Union

from .v1 import V1ExportPacket
from .v5 import V5ExportPacket
from .v9 import V9ExportPacket
from .ipfix import IPFIXExportPacket


class UnknownExportVersion(Exception):
    def __init__(self, data, version):
        self.data = data
        self.version = version
        r = repr(data)
        data_str = ("{:.25}..." if len(r) >= 28 else "{}").format(r)
        super().__init__(
            "Unknown NetFlow version {} for data {}".format(version, data_str)
        )


def get_export_version(data):
    return struct.unpack('!H', data[:2])[0]


def parse_packet(data: Union[str, bytes], templates=None):
    if templates is None:  # compatibility for v1 and v5
        templates = {}

    if type(data) == str:
        # hex dump as string
        data = bytes.fromhex(data)
    elif type(data) == bytes:
        # check representation based on utf-8 decoding result
        try:
            # hex dump as bytes, but not hex
            dec = data.decode()
            data = bytes.fromhex(dec)
        except UnicodeDecodeError:
            # use data as given, assuming hex-formatted bytes
            pass

    version = get_export_version(data)
    if version == 1:
        return V1ExportPacket(data)
    elif version == 5:
        return V5ExportPacket(data)
    elif version == 9:
        return V9ExportPacket(data, templates["netflow"])
    elif version == 10:
        return IPFIXExportPacket(data, templates["ipfix"])
    raise UnknownExportVersion(data, version)
