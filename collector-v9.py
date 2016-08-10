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

# The header of the whole export packet
#Header = namedtuple('Header', 'version count uptime timestamp sequence id')

# A template flowset, which holds an id that is used by data flowsets to
# reference back to the template. The template then has fields which hold
# identifiers of data types ("IP_SRC_ADDR", "PKTS"). This way the flow sender
# can dynamically out together data flowsets.
TemplateFlowset = namedtuple('TemplateFlowset', 'flowset_id length')

Template = namedtuple('Template', 'template_id field_count')
TemplateField = namedtuple('TemplateField', 'type length')

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


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print("Listening on interface {}:{}".format(HOST, PORT))

class TemplateField:
    pass

class Template:
    pass

class TemplateFlowSet:
    pass

class Header:
    """The header of the flow record.
    """
    def __init__(self, data):
        self.version, self.count = struct.unpack('!HH', data[0:4])
        (self.uptime, self.timestamp, self.sequence,
            self.source_id) = struct.unpack('!IIII', data[4:])


class FlowRecord:
    """The flow record holds the header and all template and data flowsets.
    """
    def __init__(self, data):
        self.header = Header(data[:20])

    def __repr__(self):
        return "<FlowRecord version {} counting {} flowset records>".format(
            self.header.version, self.header.count)

while 1:
    (data, sender) = sock.recvfrom(8192)
    print("Received data from {}, length {}".format(sender, len(data)))
    #header = Header(data[:20])
    #header = ExportHeaderV9._make(struct.unpack("!HHIIII", data[:20]))
    #template = ExportTemplateV9._make(struct.unpack("!HHHH", data[20:28]))

    record = FlowRecord(data)
    print(record)
