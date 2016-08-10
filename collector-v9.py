#!/usr/bin/env python3

"""
Netflow V9 collector implementation in Python 3.
Created for learning purposes and unsatisfying alternatives.

(C) 2016 Dominik Pataky <dom@netdecorator.org>
"""

from collections import namedtuple
import socket
import struct

HOST = '0.0.0.0'
PORT = 9001

field_types = {
    1: 'IN_BYTES',
    2: 'IN_PKTS',
    3: 'FLOWS',
    4: 'PROTOCOL',
    5: 'SRC_TOS',
    6: 'TCP_FLAGS',
    7: 'L4_SRC_PORT',
    8: 'IPV4_SRC_ADDR',
    9: 'SRC_MASK',
    10: 'INPUT_SNMP',
    11: 'L4_DST_PORT',
    12: 'IPV4_DST_ADDR',
    13: 'DST_MASK',
    14: 'OUTPUT_SNMP',
    15: 'IPV4_NEXT_HOP',
    16: 'SRC_AS',
    17: 'DST_AS',
    18: 'BGP_IPV4_NEXT_HOP',
    19: 'MUL_DST_PKTS',
    20: 'MUL_DST_BYTES',
    21: 'LAST_SWITCHED',
    22: 'FIRST_SWITCHED',
    23: 'OUT_BYTES',
    24: 'OUT_PKTS',
    25: 'MIN_PKT_LNGTH',
    26: 'MAX_PKT_LNGTH',
    27: 'IPV6_SRC_ADDR',
    28: 'IPV6_DST_ADDR',
    29: 'IPV6_SRC_MASK',
    30: 'IPV6_DST_MASK',
    31: 'IPV6_FLOW_LABEL',
    32: 'ICMP_TYPE',
    33: 'MUL_IGMP_TYPE',
    34: 'SAMPLING_INTERVAL',
    35: 'SAMPLING_ALGORITHM',
    36: 'FLOW_ACTIVE_TIMEOUT',
    37: 'FLOW_INACTIVE_TIMEOUT',
    38: 'ENGINE_TYPE',
    39: 'ENGINE_ID',
    40: 'TOTAL_BYTES_EXP',
    41: 'TOTAL_PKTS_EXP',
    42: 'TOTAL_FLOWS_EXP',
    # 43 vendor proprietary
    44: 'IPV4_SRC_PREFIX',
    45: 'IPV4_DST_PREFIX',
    46: 'MPLS_TOP_LABEL_TYPE',
    47: 'MPLS_TOP_LABEL_IP_ADDR',
    48: 'FLOW_SAMPLER_ID',
    49: 'FLOW_SAMPLER_MODE',
    50: 'NTERVAL',
    # 51 vendor proprietary
    52: 'MIN_TTL',
    53: 'MAX_TTL',
    54: 'IPV4_IDENT',
    55: 'DST_TOS',
    56: 'IN_SRC_MAC',
    57: 'OUT_DST_MAC',
    58: 'SRC_VLAN',
    59: 'DST_VLAN',
    60: 'IP_PROTOCOL_VERSION',
    61: 'DIRECTION',
    62: 'IPV6_NEXT_HOP',
    63: 'BPG_IPV6_NEXT_HOP',
    64: 'IPV6_OPTION_HEADERS',
    # 65-69 vendor proprietary
    70: 'MPLS_LABEL_1',
    71: 'MPLS_LABEL_2',
    72: 'MPLS_LABEL_3',
    73: 'MPLS_LABEL_4',
    74: 'MPLS_LABEL_5',
    75: 'MPLS_LABEL_6',
    76: 'MPLS_LABEL_7',
    77: 'MPLS_LABEL_8',
    78: 'MPLS_LABEL_9',
    79: 'MPLS_LABEL_10',
    80: 'IN_DST_MAC',
    81: 'OUT_SRC_MAC',
    82: 'IF_NAME',
    83: 'IF_DESC',
    84: 'SAMPLER_NAME',
    85: 'IN_PERMANENT_BYTES',
    86: 'IN_PERMANENT_PKTS',
    # 87 vendor property
    88: 'FRAGMENT_OFFSET',
    89: 'FORWARDING STATUS',
}

# We need to save the templates our NetFlow device send over time. Templates
# are not resended every time a flow is sent to the collector.
templates = []

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print("Listening on interface {}:{}".format(HOST, PORT))

class DataRecord:
    """Should hold a 'data' dict with keys=field_type and value.
    """
    data = {}

class DataFlowSet:
    """
    """
    def __init__(self, data):
        pack = struct.unpack('!HH', data[:4])

        self.template_id = pack[0]  # flowset_id is reference to template_id
        self.length = pack[1]

        print("New DataFlowSet with template {}, length {}".format(self.template_id, self.length))

class TemplateField:
    """
    """
    def __init__(self, field_type, field_length):
        self.field_type = field_type  # integer
        self.field_length = field_length

class Template:
    """
    Template = namedtuple('Template', 'template_id field_count')
    """
    pass

class TemplateFlowSet:
    """A template flowset, which holds an id that is used by data flowsets to
    reference back to the template. The template then has fields which hold
    identifiers of data types ("IP_SRC_ADDR", "PKTS"). This way the flow sender
    can dynamically out together data flowsets.
    """
    def __init__(self, data):
        pack = struct.unpack('!HH', data[:4])
        self.flowset_id = pack[0]
        self.length = pack[1]  # total length including this header in bytes

        offset = 4
        field_size = 16 + 16
        while offset != self.length:
            pack = struct.unpack('!HH', data[offset:offset+4])
            template_id = pack[0]
            field_count = pack[1]

            # Set offset to next template_id field
            offset += 4 + (field_count * 4)

            print("id: {}, count: {}, new offset: {}".format(template_id, field_count, offset))


class Header:
    """The header of the flow record.
    """
    def __init__(self, data):
        pack = struct.unpack('!HHIIII', data)

        self.version = pack[0]
        self.count = pack[1]  # number of FlowSets in this record
        self.uptime = pack[2]
        self.timestamp = pack[3]
        self.sequence = pack[4]
        self.source_id = pack[5]


class ExportPacket:
    """The flow record holds the header and all template and data flowsets.
    """
    def __init__(self, data):
        self.header = Header(data[:20])

        flowsets_remaining = self.header.count
        self.templates = []
        self.data = []

        search_offset = 20
        while flowsets_remaining != 0:
            print("data flowsets remaining: {}".format(flowsets_remaining))

            flowset_id = struct.unpack('!H', data[search_offset:search_offset+2])[0]
            if flowset_id == 0:  # TemplateFlowSet always have id 0
                tfs = TemplateFlowSet(data[search_offset:])
                search_offset += tfs.length
            else:
                dfs = DataFlowSet(data[search_offset:])
                search_offset += dfs.length

                # Bug in softflowd?
                # https://github.com/djmdjm/softflowd/blob/master/netflow9.c#L477
                flowsets_remaining -= 1

    def __repr__(self):
        return "<ExportPacket version {} counting {} flowset records>".format(
            self.header.version, self.header.count)

while 1:
    (data, sender) = sock.recvfrom(8192)
    print("Received data from {}, length {}".format(sender, len(data)))

    export = ExportPacket(data)
    print(export)
